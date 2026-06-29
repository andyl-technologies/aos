//! Core evaluation entry points, scope/environment management, and module bookkeeping.

use super::*;

mod force_identity;
mod force_payload;
mod force_persistence;
mod module_env;

const FORCE_EXPRESSION_IDENTITY_DOMAIN_VERSION: &[u8] = b"aos-nix-force-expression-identity-v1";
const FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION: &[u8] = b"aos-nix-force-captured-value-hash-v1";
const FORCE_FIRST_CLASS_PRIMOP_CALL_IDENTITY_DOMAIN_VERSION: &[u8] =
    b"aos-nix-force-first-class-primop-call-identity-v1";
const FORCE_SYNTHETIC_BUILTIN_ATTR_IDENTITY_DOMAIN_VERSION: &[u8] =
    b"aos-nix-force-synthetic-builtin-attr-identity-v1";
const DERIVATION_ATERM_EXPRESSION_IDENTITY_DOMAIN_VERSION: &[u8] =
    b"aos-nix-derivation-aterm-expression-identity-v1";
const FORCE_CACHE_PAYLOAD_MAX_DEPTH: usize = 64;

impl ForceCacheOptionsIdentity {
    fn new(options: &TreeWalkOptions) -> Self {
        Self {
            store_dir: options.store_dir().to_vec(),
            home_dir: options.home_dir().map(<[u8]>::to_vec),
            current_system: options.current_system().map(<[u8]>::to_vec),
            current_time: options.current_time(),
            eval_mode: options.eval_mode(),
        }
    }

    fn update_cache_identity(&self, hasher: &mut blake3::Hasher) -> Option<()> {
        hasher.update(b"force-cache-options-v1");
        hasher.update(b"store-dir");
        TreeWalk::update_cache_identity_chunk(hasher, &self.store_dir)?;
        match &self.home_dir {
            Some(home_dir) => {
                hasher.update(b"home-dir");
                TreeWalk::update_cache_identity_chunk(hasher, home_dir)?;
            }
            None => {
                hasher.update(b"no-home-dir");
            }
        }
        match &self.current_system {
            Some(current_system) => {
                hasher.update(b"current-system");
                TreeWalk::update_cache_identity_chunk(hasher, current_system)?;
            }
            None => {
                hasher.update(b"no-current-system");
            }
        }
        match self.current_time {
            Some(current_time) => {
                hasher.update(b"current-time");
                hasher.update(&current_time.to_le_bytes());
            }
            None => {
                hasher.update(b"no-current-time");
            }
        }
        hasher.update(b"eval-mode");
        hasher.update(self.eval_mode_cache_identity_bytes());
        Some(())
    }

    const fn eval_mode_cache_identity_bytes(&self) -> &'static [u8] {
        match self.eval_mode {
            EvalMode::Impure => b"impure",
            EvalMode::Restricted => b"restricted",
            EvalMode::Pure => b"pure",
        }
    }
}

impl TreeWalk {
    /// Creates a tree-walk evaluator over `ir`.
    pub fn new(ir: &Ir) -> Self {
        Self::with_options(ir, TreeWalkOptions::default())
    }

    /// Creates a tree-walk evaluator over `ir` with explicit runtime options.
    pub fn with_options(ir: &Ir, options: TreeWalkOptions) -> Self {
        let eval_cache = Arc::new(Mutex::new(EvalCacheRuntime::from_enabled(
            options.eval_cache_enabled(),
        )));
        Self::with_options_and_eval_cache(ir, options, eval_cache)
    }

    /// Creates a tree-walk evaluator over `ir` with caller-owned cache state.
    ///
    /// The cache runtime stays advisory. Disabled runtimes are no-ops; enabled
    /// runtimes record source-backed or lowered-IR-backed forced inline thunk
    /// results and may reuse clean pure inline-scalar force results for a
    /// conservative IR subset. They also observe `derivationStrict` `.drv`
    /// ATerm comparison hashes after normal path computation. They do not
    /// perform general demand-graph memo lookup. When options configure a
    /// persistent-cache root, forced-expression observations may read verifying
    /// durable force-cache payloads, record demand, and write threshold-selected
    /// durable value/trace payloads.
    ///
    /// Direct [`TreeWalk::eval_root`] and [`TreeWalk::eval_node`] callers do not
    /// perform automatic persistent run-boundary advancement; the public
    /// `eval_*` free-function wrappers advance successful evaluation exits.
    pub fn with_options_and_eval_cache(
        ir: &Ir,
        options: TreeWalkOptions,
        eval_cache: Arc<Mutex<EvalCacheRuntime>>,
    ) -> Self {
        let path_literal_base = options.path_literal_base().map(<[u8]>::to_vec);
        let parse_cache = options.parse_cache_root().map(ParseCache::new);
        Self {
            modules: vec![TreeWalkModule {
                ir: ir.clone(),
                path_literal_base,
                force_cache_options: ForceCacheOptionsIdentity::new(&options),
                source: None,
            }],
            current_module: EvalModuleId::ROOT,
            symbols: ir.symbols.clone(),
            heap: EvalHeap::new(),
            env: Vec::new(),
            with_scopes: Vec::new(),
            scoped_globals: Vec::new(),
            options,
            stats: EvalStats::default(),
            trace_output: Vec::new(),
            warning_output: Vec::new(),
            impure_input_trace: Vec::new(),
            impure_input_trace_complete: true,
            force_cache_impure_trace_epoch: 0,
            active_memo_read_nodes: Vec::new(),
            persist_force_cache_hit_keys: Vec::new(),
            stderr: EvalStderr::default(),
            find_file_cache: BTreeMap::new(),
            find_file_cache_hits: 0,
            find_file_cache_misses: 0,
            known_derivations: BTreeMap::new(),
            import_cache: BTreeMap::new(),
            parse_cache,
            persist_cache: None,
            persist_cache_open_attempted: false,
            eval_cache,
            import_parse_cache_hits: 0,
            import_parse_cache_misses: 0,
            text_store: BTreeMap::new(),
            ifd_realizer: None,
            call_depth: 0,
            order_sensitive_binding_depth: 0,
            lazy_identity_thunks: BTreeSet::new(),
            lazy_foldl_initial_thunks: BTreeSet::new(),
        }
    }

    /// Creates a tree-walk evaluator with source provenance for the root IR.
    ///
    /// Use this constructor for file-backed root modules whose attribute
    /// positions should be visible through `builtins.unsafeGetAttrPos`.
    /// Source-less expression evaluation should use [`Self::with_options`],
    /// matching C++ Nix `--expr` behavior where root positions are unavailable.
    pub fn with_options_and_source(
        ir: &Ir,
        options: TreeWalkOptions,
        source_name: impl Into<Vec<u8>>,
        source: impl Into<Vec<u8>>,
    ) -> Self {
        let mut eval = Self::with_options(ir, options);
        eval.modules[EvalModuleId::ROOT.index()].source = Some(ModuleSource {
            name: source_name.into(),
            bytes: source.into(),
        });
        eval
    }

    /// Creates a source-backed tree-walk evaluator with caller-owned cache state.
    ///
    /// This is the cache-sharing variant of [`Self::with_options_and_source`].
    /// Source provenance is used instead of the lowered-IR fingerprint as the
    /// first expression-identity component for advisory demand-graph
    /// observations.
    pub fn with_options_and_source_and_eval_cache(
        ir: &Ir,
        options: TreeWalkOptions,
        source_name: impl Into<Vec<u8>>,
        source: impl Into<Vec<u8>>,
        eval_cache: Arc<Mutex<EvalCacheRuntime>>,
    ) -> Self {
        let mut eval = Self::with_options_and_eval_cache(ir, options, eval_cache);
        eval.modules[EvalModuleId::ROOT.index()].source = Some(ModuleSource {
            name: source_name.into(),
            bytes: source.into(),
        });
        eval
    }

    /// Returns the evaluator heap that owns heap-backed values.
    pub const fn heap(&self) -> &EvalHeap {
        &self.heap
    }

    /// Returns user-facing trace output emitted so far.
    pub fn trace_output(&self) -> &[EvalTraceOutput] {
        &self.trace_output
    }

    /// Returns user-facing warning output emitted so far.
    pub fn warning_output(&self) -> &[EvalWarningOutput] {
        &self.warning_output
    }

    /// Returns impure evaluator inputs observed so far.
    pub fn impure_input_trace(&self) -> &[ImpureInputFingerprint] {
        &self.impure_input_trace
    }

    /// Returns whether the impure input trace is complete and cache-usable.
    pub const fn impure_input_trace_complete(&self) -> bool {
        self.impure_input_trace_complete
    }

    /// Returns a snapshot of mirrored evaluator counters.
    pub fn stats(&self) -> EvalStats {
        self.stats_snapshot()
    }

    /// Evaluates the IR root to weak head normal form.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] if evaluation of the root node fails.
    pub fn eval_root(&mut self) -> Result<Value, TreeWalkError> {
        let root = self.current_ir().root;
        self.eval_node(root)
    }

    /// Evaluates a node to weak head normal form.
    ///
    /// This initial public node entry point is intentionally limited to scalar
    /// literal, list literal, static attrset literal, string and URI literal,
    /// control-flow, boolean operator, pipe application, string/list
    /// concatenation, attrset update, static
    /// attribute selection, lexical `let` environment, simple and formal-set
    /// lambda application, lazy `with` lookup, numeric arithmetic, numeric and
    /// string/list comparison, direct strict unary primops,
    /// scalar/string/function/list/attrset equality, and fact-guided thunk
    /// allocation nodes. Non-expression IR helper nodes return
    /// [`TreeWalkErrorKind::InvalidNodeKind`] when they are evaluated directly.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] if `id` does not address a node in this IR, if
    /// the node payload does not match its kind, if a scalar type check fails,
    /// if thunk forcing fails, or if the node kind is not yet implemented by
    /// this evaluator slice.
    pub fn eval_node(&mut self, id: IrId) -> Result<Value, TreeWalkError> {
        let node = *self
            .node(id)
            .map_err(|error| self.error_with_current_source(error))?;
        let value = match node.kind {
            IrKind::Int => {
                if let IrData::Int(value) = node.data {
                    Ok(Value::int(value))
                } else {
                    Err(self.invalid_payload(id, &node, "integer payload"))
                }
            }
            IrKind::Float => {
                if let IrData::Float(value) = node.data {
                    Ok(Value::float(value))
                } else {
                    Err(self.invalid_payload(id, &node, "float payload"))
                }
            }
            IrKind::Bool => {
                if let IrData::Bool(value) = node.data {
                    Ok(Value::bool(value))
                } else {
                    Err(self.invalid_payload(id, &node, "boolean payload"))
                }
            }
            IrKind::Null => {
                if node.data == IrData::None {
                    Ok(Value::null())
                } else {
                    Err(self.invalid_payload(id, &node, "empty payload"))
                }
            }
            IrKind::Str | IrKind::Uri => self.eval_string(id, &node),
            IrKind::Path => self.eval_path(id, &node),
            IrKind::SearchPath => self.eval_search_path(id, &node),
            IrKind::Interp => self.eval_interp(id, &node),
            IrKind::LocalVar => self.eval_local_var(id, &node),
            IrKind::UpvalVar => self.eval_upval_var(id, &node),
            IrKind::GlobalVar => self.eval_global_var(id, &node),
            IrKind::BuiltinAttr => self.eval_builtin_attr(id, &node),
            IrKind::List => self.eval_list(id, &node),
            IrKind::AttrSet => self.eval_attrset(id, &node),
            IrKind::Lambda => self.eval_lambda(id, &node),
            IrKind::Apply => self.eval_apply(id, &node),
            IrKind::PrimOp => self.eval_primop(id, &node),
            IrKind::Let => self.eval_let(id, &node),
            IrKind::With => self.eval_with(id, &node),
            IrKind::If => self.eval_if(id, &node),
            IrKind::Assert => self.eval_assert(id, &node),
            IrKind::UnaryOp => self.eval_unary(id, &node),
            IrKind::BinOp => self.eval_binary(id, &node),
            IrKind::Select => self.eval_select(id, &node),
            IrKind::HasAttr => self.eval_has_attr(id, &node),
            IrKind::ThunkAlloc => self.eval_thunk_alloc(id, &node),
            kind => Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidNodeKind { id, kind },
                node.span,
            )),
        }
        .map_err(|error| self.error_with_current_source(error))?;
        self.force_node_result(id, node.span, value)
            .map_err(|error| self.error_with_current_source(error))
    }

    fn error_with_current_source(&self, error: TreeWalkError) -> TreeWalkError {
        if error.source().is_some() {
            return error;
        }
        let Some(source) = self.error_source_for_current_module() else {
            return error;
        };
        error.with_source(source)
    }

    pub(super) fn context_with_current_source(&self, message: Vec<u8>) -> EvalErrorContext {
        let context = EvalErrorContext::new(message);
        match self.error_source_for_current_module() {
            Some(source) => context.with_source(source),
            None => context,
        }
    }

    fn error_source_for_current_module(&self) -> Option<EvalErrorSource> {
        let source = self
            .modules
            .get(self.current_module.index())
            .and_then(|module| module.source.as_ref())?;
        Some(EvalErrorSource::new(
            source.name.clone(),
            source.bytes.clone(),
        ))
    }

    pub(super) fn force_node_result(
        &mut self,
        id: IrId,
        span: Span,
        mut value: Value,
    ) -> Result<Value, TreeWalkError> {
        loop {
            if self.is_suspended_lazy_identity_thunk(id, span, value)? {
                return Ok(value);
            }
            if !value.is_thunk() {
                return Ok(value);
            }
            let forced = self.force_value(id, span, value)?;
            if forced.raw_eq(value) {
                return Ok(forced);
            }
            value = forced;
        }
    }

    pub(super) fn is_suspended_lazy_identity_thunk(
        &self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<bool, TreeWalkError> {
        if !value.is_thunk() || !self.lazy_identity_thunks.contains(&value.payload_bits()) {
            return Ok(false);
        }
        let thunk = self
            .heap
            .get_thunk(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let state = thunk
            .cell()
            .state()
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))?;
        Ok(state == ThunkState::Suspended)
    }

    pub(super) fn mark_lazy_identity_thunk(&mut self, value: Value) {
        if value.is_thunk() {
            self.lazy_identity_thunks.insert(value.payload_bits());
        }
    }

    pub(super) fn unmark_lazy_identity_thunk_payload(&mut self, payload: u64) {
        self.lazy_identity_thunks.remove(&payload);
        self.lazy_foldl_initial_thunks.remove(&payload);
    }

    pub(super) fn mark_lazy_foldl_initial_thunk(&mut self, value: Value) {
        self.mark_lazy_identity_thunk(value);
        if value.is_thunk() {
            self.lazy_foldl_initial_thunks.insert(value.payload_bits());
        }
    }

    pub(super) fn eval_lazy_identity_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if self.is_path_literal_thunk(id, span, value)? {
            return self.force_value(id, span, value);
        }
        self.mark_lazy_identity_thunk(value);
        Ok(value)
    }

    pub(super) fn eval_lazy_foldl_initial_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if self.is_path_literal_thunk(id, span, value)? {
            return self.force_value(id, span, value);
        }
        self.mark_lazy_foldl_initial_thunk(value);
        Ok(value)
    }

    pub(super) fn is_path_literal_thunk(
        &self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<bool, TreeWalkError> {
        if !value.is_thunk() {
            return Ok(false);
        }
        let thunk = self
            .heap
            .get_thunk(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let Some(body) = thunk.body_ref() else {
            return Ok(false);
        };
        Ok(self.node_in_module(body.module(), body.id())?.kind == IrKind::Path)
    }

    pub(super) fn consume_suspended_lazy_identity_thunk(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<bool, TreeWalkError> {
        if self.is_suspended_lazy_identity_thunk(id, span, value)? {
            self.unmark_lazy_identity_thunk_payload(value.payload_bits());
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) fn force_lazy_foldl_initial_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if self.is_suspended_lazy_identity_thunk(id, span, value)?
            && self
                .lazy_foldl_initial_thunks
                .contains(&value.payload_bits())
        {
            self.unmark_lazy_identity_thunk_payload(value.payload_bits());
            return self.force_value(id, span, value);
        }
        Ok(value)
    }

    pub(super) fn force_demanded_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if self.consume_suspended_lazy_identity_thunk(id, span, value)? {
            return self.force_value(id, span, value);
        }
        let value = self.force_value(id, span, value)?;
        if self.consume_suspended_lazy_identity_thunk(id, span, value)? {
            return self.force_value(id, span, value);
        }
        Ok(value)
    }

    pub(super) fn force_cache_subject_for_thunk(
        &self,
        site: EvalNodeRef,
        thunk: &EvalThunk,
    ) -> Option<ForceCacheSubject> {
        match thunk.kind() {
            EvalThunkKind::Node { body, env, .. } => {
                if !thunk.with_scope_env()?.scopes().is_empty()
                    || !thunk.scoped_global_env()?.scopes().is_empty()
                {
                    return None;
                }
                let free_var_value_hashes =
                    self.inline_free_var_value_hashes_for_body(*body, env)?;
                let lookup_identity = self.cache_lookup_identity_for_node(*body);
                let pure_observation_identity = self.cache_identity_for_node(*body);
                let impure_observation_identity = self.cache_observation_identity_for_node(*body);
                if lookup_identity.is_none()
                    && pure_observation_identity.is_none()
                    && impure_observation_identity.is_none()
                {
                    return None;
                }
                let memoization_admission = if free_var_value_hashes.is_empty() {
                    self.force_cache_memoization_admission_for_node(*body)
                } else {
                    ForceCacheMemoizationAdmission::SelectedSubstrate
                };
                Some(ForceCacheSubject {
                    lookup_identity,
                    pure_observation_identity,
                    impure_observation_identity,
                    metadata_identity: lookup_identity,
                    persistent_clear_identity: impure_observation_identity,
                    free_var_value_hashes,
                    replay_position_module: Some(body.module()),
                    memoization_admission,
                })
            }
            EvalThunkKind::BuiltinAttr { symbol, builtin } => {
                self.force_cache_subject_for_builtin_attr(site, *symbol, *builtin)
            }
            EvalThunkKind::Apply { .. }
            | EvalThunkKind::Apply2 { .. }
            | EvalThunkKind::Select { .. } => None,
        }
    }

    fn force_cache_memoization_admission_for_node(
        &self,
        body: EvalNodeRef,
    ) -> ForceCacheMemoizationAdmission {
        if self
            .force_cache_closed_composite_payload_for_node(body, 0)
            .is_some()
        {
            ForceCacheMemoizationAdmission::SelectedSubstrate
        } else {
            ForceCacheMemoizationAdmission::ConditionalThunk
        }
    }

    fn force_cache_closed_composite_payload_for_node(
        &self,
        body: EvalNodeRef,
        depth: usize,
    ) -> Option<CachedExpressionValue> {
        if depth > FORCE_CACHE_PAYLOAD_MAX_DEPTH {
            return None;
        }
        let module_id = body.module();
        let node_id = body.id();
        let node = *self
            .modules
            .get(module_id.index())?
            .ir
            .arena
            .node(node_id)?;
        match node.kind {
            IrKind::List | IrKind::AttrSet => {
                self.force_cache_payload_for_closed_ir_node(body, depth.saturating_add(1))
            }
            IrKind::ThunkAlloc => {
                let IrData::Node(child) = node.data else {
                    return None;
                };
                self.force_cache_closed_composite_payload_for_node(
                    EvalNodeRef::new(module_id, child),
                    depth.saturating_add(1),
                )
            }
            _ => None,
        }
    }

    fn force_cache_subject_for_builtin_attr(
        &self,
        site: EvalNodeRef,
        symbol: Symbol,
        builtin: Builtin,
    ) -> Option<ForceCacheSubject> {
        let execution = builtin.execution();
        let lookup_identity = if Self::builtin_execution_is_force_cache_lookup_safe(execution) {
            self.cache_synthetic_builtin_attr_identity(site, symbol, builtin)
        } else {
            None
        };
        let observation_identity =
            if Self::builtin_execution_is_force_cache_observation_safe(execution) {
                self.cache_synthetic_builtin_attr_identity(site, symbol, builtin)
            } else {
                None
            };
        if lookup_identity.is_none() && observation_identity.is_none() {
            return None;
        }
        Some(ForceCacheSubject {
            lookup_identity,
            pure_observation_identity: lookup_identity,
            impure_observation_identity: observation_identity,
            metadata_identity: lookup_identity,
            persistent_clear_identity: observation_identity,
            free_var_value_hashes: Vec::new(),
            replay_position_module: None,
            memoization_admission: ForceCacheMemoizationAdmission::SelectedSubstrate,
        })
    }

    pub(super) fn force_cache_subject_for_first_class_cacheable_impure_call(
        &self,
        id: IrId,
        builtin: Builtin,
        args: &[EvalPrimOpArg],
    ) -> Option<ForceCacheSubject> {
        if !Self::builtin_execution_is_cacheable_impure_call(builtin.execution(), args.len())
            || !self.with_scopes.is_empty()
            || !self.scoped_globals.is_empty()
        {
            return None;
        }
        let identity = self.cache_first_class_primop_call_identity_for_current_node(id, builtin)?;
        let mut free_var_value_hashes = Vec::new();
        free_var_value_hashes.try_reserve_exact(args.len()).ok()?;
        for arg in args {
            free_var_value_hashes.push(self.force_cache_free_var_value_hash(arg.value())?);
        }
        Some(ForceCacheSubject {
            lookup_identity: Some(identity),
            pure_observation_identity: None,
            impure_observation_identity: Some(identity),
            metadata_identity: Some(identity),
            persistent_clear_identity: Some(identity),
            free_var_value_hashes,
            replay_position_module: None,
            memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
        })
    }

    const fn builtin_execution_is_cacheable_impure_call(
        execution: BuiltinExecution,
        arity: usize,
    ) -> bool {
        matches!(
            (execution, arity),
            (
                BuiltinExecution::Import
                    | BuiltinExecution::PathExists
                    | BuiltinExecution::ReadDir
                    | BuiltinExecution::ReadFile
                    | BuiltinExecution::ReadFileType
                    | BuiltinExecution::StrictUnary {
                        primop: StrictUnaryPrimOp::GetEnv,
                        ..
                    },
                1,
            ) | (
                BuiltinExecution::StrictBinary {
                    primop: StrictBinaryPrimOp::HashFile,
                    ..
                },
                2,
            )
        )
    }
}
