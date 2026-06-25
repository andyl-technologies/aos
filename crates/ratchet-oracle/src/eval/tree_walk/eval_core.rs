//! Core evaluation entry points, scope/environment management, and module bookkeeping.

use super::*;

const FORCE_EXPRESSION_IDENTITY_DOMAIN_VERSION: &[u8] = b"aos-nix-force-expression-identity-v1";
const FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION: &[u8] = b"aos-nix-force-captured-value-hash-v1";

impl ForceCacheOptionsIdentity {
    fn new(options: &TreeWalkOptions) -> Self {
        Self {
            store_dir: options.store_dir().to_vec(),
            home_dir: options.home_dir().map(<[u8]>::to_vec),
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
    /// runtimes record source-backed forced inline thunk results and may reuse
    /// clean pure inline-scalar force results for a conservative IR subset.
    /// They do not perform general memo lookup or persistence.
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
            stderr: EvalStderr::default(),
            find_file_cache: BTreeMap::new(),
            find_file_cache_hits: 0,
            find_file_cache_misses: 0,
            known_derivations: BTreeMap::new(),
            import_cache: BTreeMap::new(),
            parse_cache,
            eval_cache,
            import_parse_cache_hits: 0,
            import_parse_cache_misses: 0,
            text_store: BTreeMap::new(),
            ifd_realizer: None,
            call_depth: 0,
            lazy_identity_thunks: BTreeSet::new(),
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
    /// Source provenance is also used as the first expression-identity
    /// component for advisory demand-graph observations.
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
    /// scalar/string/function/list/attrset equality, and conservative thunk
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
        let Some(source) = self
            .modules
            .get(self.current_module.index())
            .and_then(|module| module.source.as_ref())
        else {
            return None;
        };
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
            self.lazy_identity_thunks.remove(&value.payload_bits());
            return Ok(true);
        }
        Ok(false)
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

    pub(super) fn observe_forced_inline_expression_result(
        &mut self,
        subject: Option<ForceCacheSubject>,
        value: Value,
        trace: ImpureInputTraceSegment,
    ) {
        let Some(subject) = subject else {
            return;
        };
        let Some(payload) = self.force_cache_payload_for_value(value) else {
            return;
        };
        let identity = if trace.is_empty_complete() {
            self.cache_identity_for_node(subject.body)
        } else {
            self.cache_observation_identity_for_node(subject.body)
        };
        let Some(identity) = identity else {
            return;
        };

        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping forced expression observation"
            );
            return;
        };
        let observation = if trace.is_empty_complete() {
            cache
                .observe_inline_expression_payload(
                    identity,
                    subject.free_var_value_hashes.iter().copied(),
                    payload,
                )
                .map(|_| None)
        } else {
            cache
                .observe_inline_expression_payload_with_impure_inputs(
                    identity,
                    subject.free_var_value_hashes.iter().copied(),
                    payload,
                    &trace,
                )
                .map(Some)
        };
        match observation {
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator forced expression observation failed"
                );
            }
        }
    }

    fn force_cache_payload_for_value(&self, value: Value) -> Option<CachedExpressionValue> {
        if let Ok(value) = CachedExpressionValue::immediate(value) {
            return Some(value);
        }
        match value.tag() {
            ValueTag::String => {
                let string = self.heap.get_string(value).ok()?;
                if string.has_context() {
                    return None;
                }
                let bytes = try_clone_bytes(string.bytes()).ok()?;
                Some(CachedExpressionValue::context_free_string(bytes))
            }
            ValueTag::Path => {
                let path = self.heap.get_path(value).ok()?;
                if path.has_context() {
                    return None;
                }
                let bytes = try_clone_bytes(path.bytes()).ok()?;
                Some(CachedExpressionValue::path(bytes))
            }
            _ => None,
        }
    }

    pub(super) fn lookup_forced_inline_expression_result(
        &mut self,
        subject: Option<ForceCacheSubject>,
    ) -> Option<Value> {
        let Some(subject) = subject else {
            return None;
        };
        let Some(identity) = self.cache_observation_identity_for_node(subject.body) else {
            return None;
        };
        let mut revalidator = TreeWalkImpureInputRevalidator::new(&self.options);

        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping forced expression lookup"
            );
            return None;
        };
        if !cache.is_enabled() {
            return None;
        }
        match cache.lookup_inline_expression_payload_with_impure_inputs(
            identity,
            subject.free_var_value_hashes.iter().copied(),
            &mut revalidator,
        ) {
            Ok(Some(payload)) => {
                let trace = revalidator.into_revalidated_trace();
                drop(cache);
                let Some(value) = self.value_for_cached_expression_payload(payload) else {
                    self.increment_eval_cache_miss();
                    return None;
                };
                for fingerprint in trace {
                    self.record_impure_input(fingerprint);
                }
                self.increment_eval_cache_hit();
                Some(value)
            }
            Ok(None) => {
                drop(revalidator);
                drop(cache);
                self.increment_eval_cache_miss();
                None
            }
            Err(error) => {
                drop(revalidator);
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator forced expression lookup failed"
                );
                None
            }
        }
    }

    fn value_for_cached_expression_payload(
        &mut self,
        payload: CachedExpressionValue,
    ) -> Option<Value> {
        if let Some(value) = payload.immediate_value() {
            return Some(value);
        }
        if let Some(bytes) = payload.context_free_string_bytes() {
            let bytes = try_clone_bytes(bytes).ok()?;
            return self.heap.alloc_string(NixString::from_bytes(bytes)).ok();
        }
        let bytes = try_clone_bytes(payload.path_bytes()?).ok()?;
        self.heap.alloc_path(NixString::from_bytes(bytes)).ok()
    }

    pub(super) fn force_cache_subject_for_thunk(
        &self,
        thunk: &EvalThunk,
    ) -> Option<ForceCacheSubject> {
        let body = thunk.body_ref()?;
        let env = thunk.env()?;
        if !thunk.with_scope_env()?.scopes().is_empty()
            || !thunk.scoped_global_env()?.scopes().is_empty()
        {
            return None;
        }
        let free_var_value_hashes = self.inline_free_var_value_hashes_for_body(body, env)?;
        Some(ForceCacheSubject {
            body,
            free_var_value_hashes,
        })
    }

    fn inline_free_var_value_hashes_for_body(
        &self,
        body: EvalNodeRef,
        env: &EvalEnv,
    ) -> Option<Vec<DurableBlake3Hash>> {
        let frames = env.frames();
        if frames.is_empty() {
            return Some(Vec::new());
        }

        let module = self.modules.get(body.module().index())?;
        let slots = Self::captured_free_variable_slots(&module.ir, body.id(), frames.len())?;
        let mut hashes = Vec::new();
        hashes.try_reserve_exact(slots.len()).ok()?;
        for (frame_index, slot) in slots {
            let value = frames.get(frame_index)?.get(slot).ok()?;
            let hash = self.force_cache_free_var_value_hash(value)?;
            hashes.push(hash);
        }
        Some(hashes)
    }

    fn force_cache_free_var_value_hash(&self, value: Value) -> Option<DurableBlake3Hash> {
        if let Ok(hash) = ValueHash::from_inline_value(value) {
            return Some(hash.as_durable_hash());
        }
        match value.tag() {
            ValueTag::String => {
                let string = self.heap.get_string(value).ok()?;
                if string.has_context() {
                    return None;
                }
                let mut hasher = blake3::Hasher::new();
                hasher.update(FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"string");
                Self::update_cache_identity_chunk(&mut hasher, string.bytes())?;
                return Some(DurableBlake3Hash::from_hasher(hasher));
            }
            ValueTag::Path => {
                let path = self.heap.get_path(value).ok()?;
                if path.has_context() {
                    return None;
                }
                let mut hasher = blake3::Hasher::new();
                hasher.update(FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"path");
                Self::update_cache_identity_chunk(&mut hasher, path.bytes())?;
                return Some(DurableBlake3Hash::from_hasher(hasher));
            }
            _ => return None,
        }
    }

    fn captured_free_variable_slots(
        ir: &Ir,
        root: IrId,
        captured_frame_count: usize,
    ) -> Option<BTreeSet<(usize, u32)>> {
        let mut visited = BTreeSet::new();
        let mut slots = BTreeSet::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if !visited.insert(id.as_u32()) {
                continue;
            }
            let Some(node) = ir.arena.node(id) else {
                return None;
            };
            match node.data {
                IrData::Local { slot } => {
                    let frame_index = captured_frame_count.checked_sub(1)?;
                    slots.insert((frame_index, slot));
                }
                IrData::Upval { depth, slot } => {
                    let depth = depth as usize;
                    if depth >= captured_frame_count {
                        return None;
                    }
                    slots.insert((captured_frame_count - 1 - depth, slot));
                }
                IrData::Let { .. }
                | IrData::Lambda { .. }
                | IrData::FormalSet { .. }
                | IrData::Formal { .. }
                | IrData::AttrSet {
                    recursive: true, ..
                } => {
                    return None;
                }
                IrData::None
                | IrData::Int(_)
                | IrData::Float(_)
                | IrData::Bool(_)
                | IrData::Symbol(_)
                | IrData::SearchPath { .. }
                | IrData::Node(_)
                | IrData::Pair { .. }
                | IrData::Triple { .. }
                | IrData::Children(_)
                | IrData::Bindings(_)
                | IrData::Binary { .. }
                | IrData::Unary { .. }
                | IrData::Select { .. }
                | IrData::HasAttr { .. }
                | IrData::PrimOp { .. }
                | IrData::DialectNode { .. }
                | IrData::DialectScopeVar { .. }
                | IrData::AttrSet {
                    recursive: false, ..
                } => {
                    Self::push_ir_children(ir, node, &mut stack).then_some(())?;
                }
            }
        }
        Some(slots)
    }

    fn cache_identity_for_node(&self, body: EvalNodeRef) -> Option<CacheExprIdentity> {
        let module = self.modules.get(body.module().index())?;
        if !Self::subtree_is_speculable(&module.ir, body.id()) {
            return None;
        }
        Some(CacheExprIdentity::new(
            Self::cache_source_identity_hash(module)?,
            body.id(),
        ))
    }

    fn cache_observation_identity_for_node(&self, body: EvalNodeRef) -> Option<CacheExprIdentity> {
        let module = self.modules.get(body.module().index())?;
        if !Self::subtree_is_force_observation_safe(&module.ir, body.id()) {
            return None;
        }
        Some(CacheExprIdentity::new(
            Self::cache_source_identity_hash(module)?,
            body.id(),
        ))
    }

    fn subtree_is_speculable(ir: &Ir, root: IrId) -> bool {
        let mut visited = BTreeSet::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if !visited.insert(id.as_u32()) {
                continue;
            }
            let Some(node) = ir.arena.node(id) else {
                return false;
            };
            if !node.effect.is_speculable() {
                return false;
            }
            if !Self::node_kind_is_force_cache_safe(node.kind) {
                return false;
            }
            if !Self::push_ir_children(ir, node, &mut stack) {
                return false;
            }
        }
        true
    }

    fn node_kind_is_force_cache_safe(kind: IrKind) -> bool {
        matches!(
            kind,
            IrKind::Int
                | IrKind::Float
                | IrKind::Bool
                | IrKind::Null
                | IrKind::Str
                | IrKind::Uri
                | IrKind::Path
                | IrKind::LocalVar
                | IrKind::List
                | IrKind::AttrSet
                | IrKind::Let
                | IrKind::Assert
                | IrKind::If
                | IrKind::BinOp
                | IrKind::UnaryOp
                | IrKind::Interp
                | IrKind::Select
                | IrKind::HasAttr
                | IrKind::ThunkAlloc
        )
    }

    fn subtree_is_force_observation_safe(ir: &Ir, root: IrId) -> bool {
        let mut visited = BTreeSet::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if !visited.insert(id.as_u32()) {
                continue;
            }
            let Some(node) = ir.arena.node(id) else {
                return false;
            };
            if !Self::node_is_force_observation_safe(ir, node) {
                return false;
            }
            if !Self::push_ir_children(ir, node, &mut stack) {
                return false;
            }
        }
        true
    }

    fn node_is_force_observation_safe(ir: &Ir, node: &IrNode) -> bool {
        if node.effect.is_speculable() {
            return Self::node_kind_is_force_observation_safe(node.kind);
        }
        node.kind == IrKind::PrimOp && Self::primop_has_cacheable_impure_input_trace(ir, node)
    }

    fn node_kind_is_force_observation_safe(kind: IrKind) -> bool {
        Self::node_kind_is_force_cache_safe(kind)
    }

    fn primop_has_cacheable_impure_input_trace(ir: &Ir, node: &IrNode) -> bool {
        let IrData::PrimOp { symbol, .. } = node.data else {
            return false;
        };
        matches!(
            ir.symbols.resolve(symbol),
            Some(
                b"import" | b"getEnv" | b"pathExists" | b"readDir" | b"readFile" | b"readFileType",
            )
        )
    }

    fn push_ir_children(ir: &Ir, node: &IrNode, stack: &mut Vec<IrId>) -> bool {
        match node.data {
            IrData::None
            | IrData::Int(_)
            | IrData::Float(_)
            | IrData::Bool(_)
            | IrData::Symbol(_) => {}
            IrData::SearchPath { search_path, .. } => {
                stack.extend(search_path);
            }
            IrData::Node(child) => stack.push(child),
            IrData::Pair { first, second } => {
                stack.push(first);
                stack.push(second);
            }
            IrData::Triple {
                first,
                second,
                third,
            } => {
                stack.push(first);
                stack.push(second);
                stack.push(third);
            }
            IrData::Children(children) => {
                let Some(children) = ir.arena.child_slice(children) else {
                    return false;
                };
                stack.extend(children.iter().copied());
            }
            IrData::Bindings(bindings) => {
                if !Self::push_binding_children(ir, bindings, stack) {
                    return false;
                }
            }
            IrData::Binary { op, lhs, rhs } => {
                if matches!(op, BinOpKind::PipeLeft | BinOpKind::PipeRight) {
                    return false;
                }
                stack.push(lhs);
                stack.push(rhs);
            }
            IrData::Unary { operand, .. } => stack.push(operand),
            IrData::Select {
                receiver,
                path,
                default,
                ..
            } => {
                stack.push(receiver);
                stack.extend(default);
                if !Self::push_attr_path_children(ir, path, stack) {
                    return false;
                }
            }
            IrData::HasAttr { receiver, path, .. } => {
                stack.push(receiver);
                if !Self::push_attr_path_children(ir, path, stack) {
                    return false;
                }
            }
            IrData::PrimOp { args, .. } => {
                let Some(args) = ir.arena.child_slice(args) else {
                    return false;
                };
                stack.extend(args.iter().copied());
            }
            IrData::DialectNode { argument, .. } => stack.push(argument),
            IrData::DialectScopeVar { chain, .. } => {
                let Some(chain) = usize::try_from(chain)
                    .ok()
                    .and_then(|index| ir.with_chains.get(index))
                else {
                    return false;
                };
                stack.extend(chain.scopes.iter().copied());
            }
            IrData::Lambda { pattern, body, .. } => {
                stack.push(pattern);
                stack.push(body);
            }
            IrData::Let { bindings, body, .. } => {
                stack.push(body);
                if !Self::push_binding_children(ir, bindings, stack) {
                    return false;
                }
            }
            IrData::AttrSet { bindings, .. } => {
                if !Self::push_binding_children(ir, bindings, stack) {
                    return false;
                }
            }
            IrData::FormalSet { formals, .. } => {
                let Some(formals) = ir.arena.child_slice(formals) else {
                    return false;
                };
                stack.extend(formals.iter().copied());
            }
            IrData::Formal { default, .. } => {
                stack.extend(default);
            }
            IrData::Local { .. } | IrData::Upval { .. } => {}
        }
        true
    }

    fn push_binding_children(ir: &Ir, bindings: IrBindingSlice, stack: &mut Vec<IrId>) -> bool {
        let start = bindings.start as usize;
        let Some(end) = start.checked_add(bindings.len()) else {
            return false;
        };
        let Some(bindings) = ir.bindings.get(start..end) else {
            return false;
        };
        for binding in bindings {
            stack.push(binding.value);
            if let IrAttrPathSegment::Dynamic(segment) = binding.key {
                stack.push(segment);
            }
        }
        true
    }

    fn push_attr_path_children(ir: &Ir, path: IrAttrPathId, stack: &mut Vec<IrId>) -> bool {
        let Some(segments) = ir.attr_paths.get(path.index()) else {
            return false;
        };
        for segment in segments.as_ref() {
            if let IrAttrPathSegment::Dynamic(segment) = segment {
                stack.push(*segment);
            }
        }
        true
    }

    fn cache_source_identity_hash(module: &TreeWalkModule) -> Option<DurableBlake3Hash> {
        let source = module.source.as_ref()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(FORCE_EXPRESSION_IDENTITY_DOMAIN_VERSION);
        Self::update_cache_identity_chunk(&mut hasher, &source.name)?;
        Self::update_cache_identity_chunk(&mut hasher, &source.bytes)?;
        match &module.path_literal_base {
            Some(path_literal_base) => {
                hasher.update(b"path-literal-base");
                Self::update_cache_identity_chunk(&mut hasher, path_literal_base)?;
            }
            None => {
                hasher.update(b"no-path-literal-base");
            }
        };
        module
            .force_cache_options
            .update_cache_identity(&mut hasher)?;
        Some(DurableBlake3Hash::from_hasher(hasher))
    }

    fn update_cache_identity_chunk(hasher: &mut blake3::Hasher, chunk: &[u8]) -> Option<()> {
        let len = u64::try_from(chunk.len()).ok()?;
        hasher.update(&len.to_le_bytes());
        hasher.update(chunk);
        Some(())
    }

    pub(super) fn node(&self, id: IrId) -> Result<&IrNode, TreeWalkError> {
        self.node_in_module(self.current_module, id)
    }

    pub(super) fn node_in_module(
        &self,
        module: EvalModuleId,
        id: IrId,
    ) -> Result<&IrNode, TreeWalkError> {
        self.module_ir(module)?.arena.node(id).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidNodeId { id }, Span::default())
        })
    }

    pub(super) fn current_ir(&self) -> &Ir {
        &self.modules[self.current_module.index()].ir
    }

    pub(super) fn module_path_literal_base(
        &self,
        module: EvalModuleId,
        span: Span,
    ) -> Result<Option<&[u8]>, TreeWalkError> {
        self.modules
            .get(module.index())
            .map(|module| module.path_literal_base.as_deref())
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidModuleId {
                        module: module.as_u32(),
                    },
                    span,
                )
            })
    }

    pub(super) fn module_ir(&self, module: EvalModuleId) -> Result<&Ir, TreeWalkError> {
        self.modules
            .get(module.index())
            .map(|module| &module.ir)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidModuleId {
                        module: module.as_u32(),
                    },
                    Span::default(),
                )
            })
    }

    pub(super) fn module_source(
        &self,
        module: EvalModuleId,
        span: Span,
    ) -> Result<Option<&ModuleSource>, TreeWalkError> {
        self.modules
            .get(module.index())
            .map(|module| module.source.as_ref())
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidModuleId {
                        module: module.as_u32(),
                    },
                    span,
                )
            })
    }

    pub(super) fn with_current_module<T>(
        &mut self,
        module: EvalModuleId,
        f: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        self.module_ir(module)?;
        let saved = self.current_module;
        self.current_module = module;
        let result = f(self);
        self.current_module = saved;
        result
    }

    pub(super) fn push_module(
        &mut self,
        id: IrId,
        span: Span,
        ir: Ir,
        path_literal_base: Vec<u8>,
        source_name: Vec<u8>,
        source: Vec<u8>,
    ) -> Result<EvalModuleId, TreeWalkError> {
        let raw = u32::try_from(self.modules.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::TooManyModules {
                    id,
                    modules: self.modules.len(),
                },
                span,
            )
        })?;
        self.modules.push(TreeWalkModule {
            ir,
            path_literal_base: Some(path_literal_base),
            force_cache_options: ForceCacheOptionsIdentity::new(&self.options),
            source: Some(ModuleSource {
                name: source_name,
                bytes: source,
            }),
        });
        Ok(EvalModuleId::new(raw))
    }

    pub(super) fn binding_range(
        &self,
        id: IrId,
        slice: IrBindingSlice,
        span: Span,
    ) -> Result<std::ops::Range<usize>, TreeWalkError> {
        let start = slice.start as usize;
        let end = start.checked_add(slice.len()).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidBindingSlice { id, slice }, span)
        })?;
        if self.current_ir().bindings.get(start..end).is_none() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidBindingSlice { id, slice },
                span,
            ));
        }
        Ok(start..end)
    }

    pub(super) fn frame_info(
        &self,
        id: IrId,
        frame: FrameId,
        span: Span,
    ) -> Result<&crate::compile::FrameInfo, TreeWalkError> {
        self.current_ir().frames.get(frame.index()).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidFrameId {
                    id,
                    frame: frame.as_u32(),
                },
                span,
            )
        })
    }

    pub(super) fn capture_env(&self, id: IrId, span: Span) -> Result<EvalEnv, TreeWalkError> {
        EvalEnv::capture(&self.env)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span))
    }

    pub(super) fn capture_with_env(
        &self,
        id: IrId,
        span: Span,
    ) -> Result<EvalWithEnv, TreeWalkError> {
        EvalWithEnv::capture(&self.with_scopes)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span))
    }

    pub(super) fn capture_scoped_global_env(
        &self,
        id: IrId,
        span: Span,
    ) -> Result<EvalScopedGlobalEnv, TreeWalkError> {
        EvalScopedGlobalEnv::capture(&self.scoped_globals)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span))
    }

    pub(super) fn clone_env_frames(
        &self,
        id: IrId,
        env: &EvalEnv,
        span: Span,
    ) -> Result<Vec<Rc<EvalFrame>>, TreeWalkError> {
        let frames = env.frames();
        let mut cloned = Vec::new();
        cloned.try_reserve_exact(frames.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Env {
                    id,
                    source: EvalEnvError::CaptureAllocationFailed {
                        frames: frames.len(),
                    },
                },
                span,
            )
        })?;
        cloned.extend_from_slice(frames);
        Ok(cloned)
    }

    pub(super) fn clone_with_scopes(
        &self,
        id: IrId,
        env: &EvalWithEnv,
        span: Span,
    ) -> Result<Vec<EvalWithScope>, TreeWalkError> {
        let scopes = env.scopes();
        let mut cloned = Vec::new();
        cloned.try_reserve_exact(scopes.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Env {
                    id,
                    source: EvalEnvError::WithCaptureAllocationFailed {
                        scopes: scopes.len(),
                    },
                },
                span,
            )
        })?;
        cloned.extend_from_slice(scopes);
        Ok(cloned)
    }

    pub(super) fn clone_scoped_globals(
        &self,
        id: IrId,
        env: &EvalScopedGlobalEnv,
        span: Span,
    ) -> Result<Vec<Value>, TreeWalkError> {
        let scopes = env.scopes();
        let mut cloned = Vec::new();
        cloned.try_reserve_exact(scopes.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Env {
                    id,
                    source: EvalEnvError::ScopedGlobalCaptureAllocationFailed {
                        scopes: scopes.len(),
                    },
                },
                span,
            )
        })?;
        cloned.extend_from_slice(scopes);
        Ok(cloned)
    }

    pub(super) fn validate_attrset_shape(
        &self,
        id: IrId,
        shape: IrShapeId,
        shape_keys: &[Symbol],
        binding_range: std::ops::Range<usize>,
        span: Span,
    ) -> Result<(), TreeWalkError> {
        let mut binding_keys = 0usize;
        for binding_index in binding_range {
            let binding = self.current_ir().bindings[binding_index];
            let actual = match binding.key {
                IrAttrPathSegment::Static(symbol) => symbol,
                IrAttrPathSegment::Dynamic(_) => continue,
            };
            let Some(expected) = shape_keys.get(binding_keys).copied() else {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::AttrSetShapeLengthMismatch {
                        id,
                        shape,
                        shape_keys: shape_keys.len(),
                        binding_keys: binding_keys + 1,
                    },
                    span,
                ));
            };
            if expected != actual {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::AttrSetShapeKeyMismatch {
                        id,
                        shape,
                        index: binding_keys,
                        expected,
                        actual,
                    },
                    span,
                ));
            }
            binding_keys += 1;
        }

        if binding_keys != shape_keys.len() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::AttrSetShapeLengthMismatch {
                    id,
                    shape,
                    shape_keys: shape_keys.len(),
                    binding_keys,
                },
                span,
            ));
        }

        Ok(())
    }

    pub(super) fn attr_path(
        &self,
        id: IrId,
        path: IrAttrPathId,
        span: Span,
    ) -> Result<&[IrAttrPathSegment], TreeWalkError> {
        self.current_ir()
            .attr_paths
            .get(path.index())
            .map(|segments| segments.as_ref())
            .ok_or_else(|| {
                TreeWalkError::new(TreeWalkErrorKind::InvalidAttrPath { id, path }, span)
            })
    }

    pub(super) fn attr_path_len(
        &self,
        id: IrId,
        path: IrAttrPathId,
        span: Span,
    ) -> Result<usize, TreeWalkError> {
        self.attr_path(id, path, span)
            .map(|segments| segments.len())
    }

    pub(super) fn reject_empty_attr_path(
        &self,
        id: IrId,
        path: IrAttrPathId,
        span: Span,
    ) -> Result<(), TreeWalkError> {
        let len = self.attr_path_len(id, path, span)?;
        self.reject_empty_attr_path_len(id, path, span, len)
    }

    pub(super) fn reject_empty_attr_path_len(
        &self,
        id: IrId,
        path: IrAttrPathId,
        span: Span,
        len: usize,
    ) -> Result<(), TreeWalkError> {
        if len == 0 {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidAttrPath { id, path },
                span,
            ));
        }
        Ok(())
    }

    pub(super) fn attr_path_segment(
        &self,
        id: IrId,
        path: IrAttrPathId,
        index: usize,
        span: Span,
    ) -> Result<IrAttrPathSegment, TreeWalkError> {
        self.attr_path(id, path, span)?
            .get(index)
            .copied()
            .ok_or_else(|| {
                TreeWalkError::new(TreeWalkErrorKind::InvalidAttrPath { id, path }, span)
            })
    }

    pub(super) fn with_chain_scope_count(
        &self,
        id: IrId,
        chain: u32,
        span: Span,
    ) -> Result<usize, TreeWalkError> {
        self.current_ir()
            .with_chains
            .get(chain as usize)
            .map(|chain| chain.scopes.len())
            .ok_or_else(|| {
                TreeWalkError::new(TreeWalkErrorKind::InvalidWithChain { id, chain }, span)
            })
    }

    pub(super) fn with_chain_scope(
        &self,
        id: IrId,
        chain: u32,
        index: usize,
        span: Span,
    ) -> Result<IrId, TreeWalkError> {
        self.current_ir()
            .with_chains
            .get(chain as usize)
            .and_then(|chain| chain.scopes.get(index).copied())
            .ok_or_else(|| {
                TreeWalkError::new(TreeWalkErrorKind::InvalidWithChain { id, chain }, span)
            })
    }

    pub(super) fn with_chain_scope_ref(
        &self,
        id: IrId,
        chain: u32,
        index: usize,
        span: Span,
    ) -> Result<EvalNodeRef, TreeWalkError> {
        Ok(EvalNodeRef::new(
            self.current_module,
            self.with_chain_scope(id, chain, index, span)?,
        ))
    }

    pub(super) fn with_scope_value(
        &self,
        id: IrId,
        scope: EvalNodeRef,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        self.with_scopes
            .iter()
            .rev()
            .find(|active| active.scope_ref() == scope)
            .map(EvalWithScope::value)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::MissingWithScope {
                        id,
                        scope: scope.id(),
                    },
                    span,
                )
            })
    }

    pub(super) fn eval_global_fallback(
        &self,
        id: IrId,
        symbol: Symbol,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        if let Some(value) = self.scoped_global_value(id, symbol, span)? {
            return Ok(value);
        }
        match self.symbols.resolve(symbol) {
            Some(b"true") => Ok(Value::bool(true)),
            Some(b"false") => Ok(Value::bool(false)),
            Some(b"null") => Ok(Value::null()),
            Some(_) => Err(TreeWalkError::new(
                TreeWalkErrorKind::UnresolvedWithVar { id, symbol },
                span,
            )),
            None => Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol { id, symbol },
                span,
            )),
        }
    }

    pub(super) fn scoped_global_value(
        &self,
        id: IrId,
        symbol: Symbol,
        span: Span,
    ) -> Result<Option<Value>, TreeWalkError> {
        if self.symbols.resolve(symbol).is_none() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol { id, symbol },
                span,
            ));
        }

        for scope in self.scoped_globals.iter().rev().copied() {
            if scope.tag() != ValueTag::Attrs {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id,
                        expected: "attrs",
                        actual: scope.tag(),
                    },
                    span,
                ));
            }
            let selected = {
                let attrs = self.heap.get_attrs(scope).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                })?;
                attrs.get(symbol)
            };
            if let Some(value) = selected {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    pub(super) fn eval_global_var(
        &mut self,
        id: IrId,
        node: &IrNode,
    ) -> Result<Value, TreeWalkError> {
        let IrData::Symbol(symbol) = node.data else {
            return Err(self.invalid_payload(id, node, "global symbol payload"));
        };
        let Some(name) = self.symbols.resolve(symbol) else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol { id, symbol },
                node.span,
            ));
        };
        if name == CUR_POS_ATTR {
            return self.eval_current_position(id, node.span);
        }
        if name == NIX_PATH_ATTR {
            return self.eval_nix_path_value(id, node.span);
        }
        if let Some(value) = self.scoped_global_value(id, symbol, node.span)? {
            return Ok(value);
        }
        if !self.scoped_globals.is_empty()
            && name != b"builtins"
            && !is_unshadowable_global_name(name)
        {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnresolvedWithVar { id, symbol },
                node.span,
            ));
        }
        if name == b"builtins" {
            return self.eval_builtins_attrset(id, node.span);
        }
        if is_unshadowable_global_name(name) {
            if let Some(builtin) = lookup_builtin(name).filter(|builtin| builtin.is_available(self))
            {
                return self.eval_builtin_attrset_value(id, node.span, symbol, builtin);
            }
        }
        Err(TreeWalkError::new(
            TreeWalkErrorKind::UnresolvedGlobalVar { id, symbol },
            node.span,
        ))
    }

    pub(super) fn eval_builtin_attr(
        &mut self,
        id: IrId,
        node: &IrNode,
    ) -> Result<Value, TreeWalkError> {
        let IrData::Symbol(symbol) = node.data else {
            return Err(self.invalid_payload(id, node, "builtin attr symbol payload"));
        };
        let Some(builtin) = lookup_builtin_by_symbol(&self.symbols, symbol) else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedBuiltinAttr { id, symbol },
                node.span,
            ));
        };
        if !builtin.is_available(self) {
            if self.reject_unconfigured_impure_builtin_constant(builtin) {
                return Err(self.unsupported_ambient_builtin_constant(id, node.span));
            }
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::MissingAttribute { id, symbol },
                node.span,
            ));
        }
        builtin.select(self, id, node.span, symbol)
    }

    pub(super) fn eval_builtins_attrset(
        &mut self,
        id: IrId,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        let mut entries = Vec::new();
        entries.try_reserve_exact(BUILTINS.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed {
                        entries: BUILTINS.len(),
                    },
                },
                span,
            )
        })?;

        for builtin in BUILTINS.iter().copied() {
            if !builtin.is_available(self)
                && !self.reject_unconfigured_impure_builtin_constant(builtin)
            {
                continue;
            }
            let symbol = self.intern_builtin_attr_symbol(id, builtin.name(), span)?;
            let value = self.eval_builtin_attrset_value(id, span, symbol, builtin)?;
            entries.push(AttrEntry::new(symbol, value));
        }

        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    pub(super) fn eval_builtin_attrset_value(
        &mut self,
        id: IrId,
        span: Span,
        symbol: Symbol,
        builtin: Builtin,
    ) -> Result<Value, TreeWalkError> {
        if builtin.execution() == BuiltinExecution::BuiltinsValue {
            return self.alloc_thunk_for_node(id, id, span);
        }
        if builtin.execution() == BuiltinExecution::NixPathValue {
            return self.alloc_builtin_attr_thunk(id, span, symbol, builtin);
        }
        if self.reject_unconfigured_impure_builtin_constant(builtin) && !builtin.is_available(self)
        {
            return self.alloc_builtin_attr_thunk(id, span, symbol, builtin);
        }
        builtin.select(self, id, span, symbol)
    }
}
