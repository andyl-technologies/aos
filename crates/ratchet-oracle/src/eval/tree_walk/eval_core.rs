//! Core evaluation entry points, scope/environment management, and module bookkeeping.

use super::*;

const FORCE_EXPRESSION_IDENTITY_DOMAIN_VERSION: &[u8] = b"aos-nix-force-expression-identity-v1";
const FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION: &[u8] = b"aos-nix-force-captured-value-hash-v1";
const FORCE_SYNTHETIC_BUILTIN_ATTR_IDENTITY_DOMAIN_VERSION: &[u8] =
    b"aos-nix-force-synthetic-builtin-attr-identity-v1";
const DERIVATION_ATERM_EXPRESSION_IDENTITY_DOMAIN_VERSION: &[u8] =
    b"aos-nix-derivation-aterm-expression-identity-v1";
const FORCE_CACHE_PAYLOAD_MAX_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ForcePayloadPersistenceAction {
    Skip,
    Clear,
    Materialize { early_cutoff: bool },
    MaterializeWithTrace { early_cutoff: bool },
}

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
            if self.invalidate_cached_forced_expression_payload(&subject) {
                self.clear_persist_forced_expression_payload(&subject);
            }
            return;
        };
        let identity = if trace.is_empty_complete() {
            subject.pure_observation_identity
        } else {
            subject.impure_observation_identity
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
        let persistence_action = if trace.is_empty_complete() {
            match cache.observe_inline_expression_payload(
                identity,
                subject.free_var_value_hashes.iter().copied(),
                payload.clone(),
            ) {
                Ok(Some(reconsideration)) => Ok(ForcePayloadPersistenceAction::Materialize {
                    early_cutoff: reconsideration.decision() == CutoffDecision::CutOff,
                }),
                Ok(None) => Ok(ForcePayloadPersistenceAction::Skip),
                Err(error) => Err(error),
            }
        } else {
            match cache.observe_inline_expression_payload_with_impure_inputs(
                identity,
                subject.free_var_value_hashes.iter().copied(),
                payload.clone(),
                &trace,
            ) {
                Ok(Some(observation)) if observation.node().is_some() => {
                    Ok(ForcePayloadPersistenceAction::MaterializeWithTrace {
                        early_cutoff: observation
                            .payload_reconsideration()
                            .map(|reconsideration| {
                                reconsideration.decision() == CutoffDecision::CutOff
                            })
                            .unwrap_or(false),
                    })
                }
                Ok(Some(_)) => Ok(ForcePayloadPersistenceAction::Clear),
                Ok(None) => Ok(ForcePayloadPersistenceAction::Skip),
                Err(error) => Err(error),
            }
        };
        drop(cache);
        match persistence_action {
            Ok(ForcePayloadPersistenceAction::Materialize { early_cutoff }) => {
                if early_cutoff {
                    self.increment_early_cutoffs();
                }
                if let Some(value_hash) =
                    self.materialize_persist_forced_expression_payload(&subject, &payload)
                {
                    if !self.record_persist_forced_expression_pure_trace(&subject, value_hash) {
                        self.clear_persist_forced_expression_payload(&subject);
                    }
                }
            }
            Ok(ForcePayloadPersistenceAction::MaterializeWithTrace { early_cutoff }) => {
                if early_cutoff {
                    self.increment_early_cutoffs();
                }
                if let Some(value_hash) =
                    self.materialize_persist_forced_expression_payload(&subject, &payload)
                {
                    if !self.record_persist_forced_expression_trace(&subject, value_hash, &trace) {
                        self.clear_persist_forced_expression_payload(&subject);
                    }
                }
            }
            Ok(ForcePayloadPersistenceAction::Clear) => {
                self.clear_persist_forced_expression_payload(&subject);
            }
            Ok(ForcePayloadPersistenceAction::Skip) => {}
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator forced expression observation failed"
                );
            }
        }
    }

    fn invalidate_cached_forced_expression_payload(&mut self, subject: &ForceCacheSubject) -> bool {
        let Some(identity) = subject.lookup_identity else {
            return false;
        };
        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping forced expression invalidation"
            );
            return false;
        };
        match cache.invalidate_inline_expression_payload(
            identity,
            subject.free_var_value_hashes.iter().copied(),
        ) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator forced expression invalidation failed"
                );
                false
            }
        }
    }

    fn materialize_persist_forced_expression_payload(
        &mut self,
        subject: &ForceCacheSubject,
        payload: &CachedExpressionValue,
    ) -> Option<ValueHash> {
        if !self.options.eval_cache_enabled() {
            return None;
        }
        let Some(identity) = subject.metadata_identity else {
            return None;
        };
        self.open_persist_eval_cache();
        let Some(persist_cache) = &self.persist_cache else {
            return None;
        };
        let key = PersistNodeMetadataKey::for_expression(
            identity,
            subject.free_var_value_hashes.iter().copied(),
        );
        let signals = match persist_cache
            .node_materialization_signals(key, self.options.force_cache_materialization_costs())
        {
            Ok(signals) => signals,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent force materialization signals failed"
                );
                return None;
            }
        };
        if signals.decide() == MaterializationDecision::KeepInMemory {
            return None;
        }
        let value_hash = match payload.value_hash() {
            Ok(value_hash) => value_hash,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent force payload hashing failed"
                );
                return None;
            }
        };
        match persist_cache
            .materialize_cached_expression_node_value_indexed_with_signals(key, payload, signals)
        {
            Ok(PersistMaterialization::Materialized(_)) => Some(value_hash),
            Ok(PersistMaterialization::Skipped) => None,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent force payload materialization failed"
                );
                None
            }
        }
    }

    fn record_persist_forced_expression_pure_trace(
        &mut self,
        subject: &ForceCacheSubject,
        value_hash: ValueHash,
    ) -> bool {
        let payload = match PersistNodeTracePayload::from_impure_trace(std::iter::empty::<
            &ImpureInputFingerprint,
        >()) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator pure force trace could not be encoded for persistence"
                );
                return false;
            }
        };
        self.record_persist_forced_expression_trace_payload(subject, value_hash, &payload)
    }

    fn record_persist_forced_expression_trace(
        &mut self,
        subject: &ForceCacheSubject,
        value_hash: ValueHash,
        trace: &ImpureInputTraceSegment,
    ) -> bool {
        let payload = match PersistNodeTracePayload::from_impure_trace(trace.impure_input_trace()) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator accepted force trace could not be encoded for persistence"
                );
                return false;
            }
        };
        self.record_persist_forced_expression_trace_payload(subject, value_hash, &payload)
    }

    fn record_persist_forced_expression_trace_payload(
        &mut self,
        subject: &ForceCacheSubject,
        value_hash: ValueHash,
        payload: &PersistNodeTracePayload,
    ) -> bool {
        if !self.options.eval_cache_enabled() {
            return false;
        }
        let Some(identity) = subject.metadata_identity else {
            return false;
        };
        self.open_persist_eval_cache();
        let Some(persist_cache) = &self.persist_cache else {
            return false;
        };
        let key = PersistNodeMetadataKey::for_expression(
            identity,
            subject.free_var_value_hashes.iter().copied(),
        );
        match persist_cache.record_node_trace(key, value_hash, &payload) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent force trace writeback failed"
                );
                false
            }
        }
    }

    fn clear_persist_forced_expression_payload(&mut self, subject: &ForceCacheSubject) {
        if !self.options.eval_cache_enabled() {
            return;
        }
        let Some(identity) = subject.metadata_identity else {
            return;
        };
        self.open_persist_eval_cache();
        let Some(persist_cache) = &self.persist_cache else {
            return;
        };
        let key = PersistNodeMetadataKey::for_expression(
            identity,
            subject.free_var_value_hashes.iter().copied(),
        );
        if let Err(error) = persist_cache.clear_node_materialized_value_hash(key) {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent force payload clear failed"
            );
        }
        if let Err(error) = persist_cache.record_node_trace_tombstone(key) {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent force trace tombstone write failed"
            );
        }
    }

    fn force_cache_payload_for_value(&self, value: Value) -> Option<CachedExpressionValue> {
        self.force_cache_payload_for_value_with_depth(value, 0)
    }

    fn force_cache_payload_for_suspended_thunk(
        &self,
        thunk: &EvalThunk,
        depth: usize,
    ) -> Option<CachedExpressionValue> {
        let EvalThunkKind::Node {
            body,
            env,
            with_env,
            scoped_globals,
        } = thunk.kind()
        else {
            return None;
        };
        if !with_env.scopes().is_empty() || !scoped_globals.scopes().is_empty() {
            return None;
        }
        let module = self.modules.get(body.module().index())?;
        let slots = Self::captured_free_variable_slots(&module.ir, body.id(), env.frames().len())?;
        if !slots.is_empty() {
            return None;
        }
        self.force_cache_payload_for_closed_ir_node(*body, depth)
    }

    fn force_cache_payload_for_closed_ir_node(
        &self,
        id: EvalNodeRef,
        depth: usize,
    ) -> Option<CachedExpressionValue> {
        if depth > FORCE_CACHE_PAYLOAD_MAX_DEPTH {
            return None;
        }
        let module_id = id.module();
        let node_id = id.id();
        let node = *self
            .modules
            .get(module_id.index())?
            .ir
            .arena
            .node(node_id)?;
        if !node.effect.is_speculable() {
            return None;
        }
        match node.kind {
            IrKind::Int => {
                let IrData::Int(value) = node.data else {
                    return None;
                };
                CachedExpressionValue::immediate(Value::int(value)).ok()
            }
            IrKind::Float => {
                let IrData::Float(value) = node.data else {
                    return None;
                };
                CachedExpressionValue::immediate(Value::float(value)).ok()
            }
            IrKind::Bool => {
                let IrData::Bool(value) = node.data else {
                    return None;
                };
                CachedExpressionValue::immediate(Value::bool(value)).ok()
            }
            IrKind::Null => CachedExpressionValue::immediate(Value::null()).ok(),
            IrKind::Str | IrKind::Uri => {
                let IrData::Symbol(symbol) = node.data else {
                    return None;
                };
                let module = self.modules.get(module_id.index())?;
                let bytes = module.ir.symbols.resolve(symbol)?;
                Some(CachedExpressionValue::context_free_string(
                    try_clone_bytes(bytes).ok()?,
                ))
            }
            IrKind::Path => {
                let IrData::Symbol(symbol) = node.data else {
                    return None;
                };
                let module = self.modules.get(module_id.index())?;
                let bytes = module.ir.symbols.resolve(symbol)?;
                let path = self
                    .path_literal_bytes_for_module_node(module_id, node_id, node.span, bytes)
                    .ok()?;
                Some(CachedExpressionValue::path(path))
            }
            IrKind::List => {
                self.force_cache_payload_for_closed_ir_list(module_id, node_id, node.data, depth)
            }
            IrKind::AttrSet => {
                self.force_cache_payload_for_closed_ir_attrset(module_id, node_id, node.data, depth)
            }
            IrKind::ThunkAlloc => {
                let IrData::Node(child) = node.data else {
                    return None;
                };
                self.force_cache_payload_for_closed_ir_node(
                    EvalNodeRef::new(module_id, child),
                    depth.saturating_add(1),
                )
            }
            _ => None,
        }
    }

    fn force_cache_payload_for_closed_ir_list(
        &self,
        module_id: EvalModuleId,
        _id: IrId,
        data: IrData,
        depth: usize,
    ) -> Option<CachedExpressionValue> {
        let IrData::Children(children) = data else {
            return None;
        };
        let children = self
            .modules
            .get(module_id.index())?
            .ir
            .arena
            .child_slice(children)?
            .to_vec();
        let mut elements = Vec::new();
        elements.try_reserve_exact(children.len()).ok()?;
        for child in children {
            elements.push(self.force_cache_payload_for_closed_ir_node(
                EvalNodeRef::new(module_id, child),
                depth.saturating_add(1),
            )?);
        }
        Some(CachedExpressionValue::strict_list(elements))
    }

    fn force_cache_payload_for_closed_ir_attrset(
        &self,
        module_id: EvalModuleId,
        _id: IrId,
        data: IrData,
        depth: usize,
    ) -> Option<CachedExpressionValue> {
        let IrData::AttrSet {
            bindings,
            recursive,
            has_dynamic,
            ..
        } = data
        else {
            return None;
        };
        if recursive || has_dynamic {
            return None;
        }
        let entries = {
            let module = self.modules.get(module_id.index())?;
            let start = bindings.start as usize;
            let end = start.checked_add(bindings.len())?;
            let bindings = module.ir.bindings.get(start..end)?;
            let mut entries = Vec::new();
            entries.try_reserve_exact(bindings.len()).ok()?;
            for binding in bindings {
                let IrAttrPathSegment::Static(symbol) = binding.key else {
                    return None;
                };
                if binding.position.is_some() {
                    return None;
                }
                let name = try_clone_bytes(module.ir.symbols.resolve(symbol)?).ok()?;
                entries.push((name, binding.value));
            }
            entries
        };
        if entries.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return None;
        }
        let mut payload_entries = Vec::new();
        payload_entries.try_reserve_exact(entries.len()).ok()?;
        for (name, value) in entries {
            payload_entries.push((
                name,
                self.force_cache_payload_for_closed_ir_node(
                    EvalNodeRef::new(module_id, value),
                    depth.saturating_add(1),
                )?,
            ));
        }
        CachedExpressionValue::strict_attrs(payload_entries).ok()
    }

    fn force_cache_payload_for_value_with_depth(
        &self,
        value: Value,
        depth: usize,
    ) -> Option<CachedExpressionValue> {
        if depth > FORCE_CACHE_PAYLOAD_MAX_DEPTH {
            return None;
        }
        if let Ok(value) = CachedExpressionValue::immediate(value) {
            return Some(value);
        }
        match value.tag() {
            ValueTag::String => {
                let string = self.heap.get_string(value).ok()?;
                let bytes = try_clone_bytes(string.bytes()).ok()?;
                if string.has_context() {
                    let context = string.context().try_clone_context().ok()?;
                    Some(CachedExpressionValue::context_string(bytes, context))
                } else {
                    Some(CachedExpressionValue::context_free_string(bytes))
                }
            }
            ValueTag::Path => {
                let path = self.heap.get_path(value).ok()?;
                let bytes = try_clone_bytes(path.bytes()).ok()?;
                if path.has_context() {
                    let context = path.context().try_clone_context().ok()?;
                    Some(CachedExpressionValue::context_path(bytes, context))
                } else {
                    Some(CachedExpressionValue::path(bytes))
                }
            }
            ValueTag::List => {
                let list = self.heap.get_list(value).ok()?;
                if list.is_empty() {
                    Some(CachedExpressionValue::empty_list())
                } else {
                    let mut elements = Vec::new();
                    elements.try_reserve_exact(list.len()).ok()?;
                    for element in list {
                        elements.push(self.force_cache_payload_for_value_with_depth(
                            *element,
                            depth.saturating_add(1),
                        )?);
                    }
                    Some(CachedExpressionValue::strict_list(elements))
                }
            }
            ValueTag::Attrs => {
                let attrs = self.heap.get_attrs(value).ok()?;
                if attrs.is_empty() {
                    Some(CachedExpressionValue::empty_attrs())
                } else {
                    if attrs.source_order() != attrs.iteration_order() {
                        return None;
                    }
                    let mut entries = Vec::new();
                    entries.try_reserve_exact(attrs.len()).ok()?;
                    for entry in attrs.iter_lexicographic() {
                        if entry.position.is_some() {
                            return None;
                        }
                        let name = self.symbols.resolve(entry.key)?;
                        entries.push((
                            try_clone_bytes(name).ok()?,
                            self.force_cache_payload_for_value_with_depth(
                                entry.value,
                                depth.saturating_add(1),
                            )?,
                        ));
                    }
                    CachedExpressionValue::strict_attrs(entries).ok()
                }
            }
            ValueTag::Thunk => {
                let thunk = self.heap.get_thunk(value).ok()?;
                match thunk.cell().cached_value().ok()? {
                    Some(cached) if cached.is_thunk() => None,
                    Some(cached) => self
                        .force_cache_payload_for_value_with_depth(cached, depth.saturating_add(1)),
                    None => {
                        self.force_cache_payload_for_suspended_thunk(thunk, depth.saturating_add(1))
                    }
                }
            }
            _ => None,
        }
    }

    pub(super) fn record_force_cache_memoization_demand(
        &mut self,
        subject: &ForceCacheSubject,
    ) -> MemoizationDecision {
        let Some(identity) = subject.lookup_identity else {
            return MemoizationDecision::Admit;
        };
        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping forced expression memoization demand"
            );
            return MemoizationDecision::Admit;
        };
        let observed_decision = match cache.record_memoization_demand(
            identity,
            subject.free_var_value_hashes.iter().copied(),
            MemoizationSubject::Thunk,
            true,
        ) {
            Ok(Some(observation)) => Some(observation.decision()),
            Ok(None) => None,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator forced expression memoization demand failed"
                );
                None
            }
        };
        drop(cache);
        let mut decision = observed_decision.unwrap_or(MemoizationDecision::Admit);
        if subject.memoization_admission.admits_on_first_demand() {
            decision = MemoizationDecision::Admit;
        } else if decision == MemoizationDecision::Bypass
            && self.force_cache_has_prior_persistent_demand(subject)
        {
            decision = MemoizationDecision::Admit;
        }
        if observed_decision.is_some() {
            self.increment_force_cache_memoization_decision(decision);
        }
        decision
    }

    fn force_cache_has_prior_persistent_demand(&mut self, subject: &ForceCacheSubject) -> bool {
        if !self.options.eval_cache_enabled() {
            return false;
        }
        let Some(identity) = subject.metadata_identity else {
            return false;
        };
        self.open_persist_eval_cache();
        let Some(persist_cache) = &self.persist_cache else {
            return false;
        };
        let key = PersistNodeMetadataKey::for_expression(
            identity,
            subject.free_var_value_hashes.iter().copied(),
        );
        match persist_cache.lookup_node_materialization_reuse(key) {
            Ok(Some(reuse)) => reuse.likely_redemanded_across_runs(),
            Ok(None) => false,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent force memoization demand lookup failed"
                );
                false
            }
        }
    }

    pub(super) fn lookup_forced_inline_expression_result(
        &mut self,
        subject: Option<ForceCacheSubject>,
    ) -> Option<Value> {
        let Some(subject) = subject else {
            return None;
        };
        let Some(identity) = subject.lookup_identity else {
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
                self.record_forced_expression_demand(&subject);
                self.increment_eval_cache_hit();
                Some(value)
            }
            Ok(None) => {
                drop(revalidator);
                drop(cache);
                if let Some(value) = self.lookup_persist_forced_expression_result(&subject) {
                    return Some(value);
                }
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

    fn lookup_persist_forced_expression_result(
        &mut self,
        subject: &ForceCacheSubject,
    ) -> Option<Value> {
        if !self.options.eval_cache_enabled() {
            return None;
        }
        let Some(identity) = subject.metadata_identity else {
            return None;
        };
        self.open_persist_eval_cache();
        let persist_cache = self.persist_cache.as_ref()?;
        let key = PersistNodeMetadataKey::for_expression(
            identity,
            subject.free_var_value_hashes.iter().copied(),
        );
        let mut revalidator = TreeWalkImpureInputRevalidator::new(&self.options);
        let payload = match persist_cache
            .load_cached_expression_node_value_with_trace_revalidation(key, &mut revalidator)
        {
            Ok(Some(payload)) => payload,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent forced expression lookup failed"
                );
                return None;
            }
        };
        let trace = revalidator.into_revalidated_trace();
        let value = self.value_for_cached_expression_payload(payload.clone())?;
        self.observe_persist_forced_expression_runtime_hit(subject, payload, &trace);
        for fingerprint in trace {
            self.record_impure_input(fingerprint);
        }
        self.record_forced_expression_demand(subject);
        self.increment_eval_cache_hit();
        Some(value)
    }

    fn observe_persist_forced_expression_runtime_hit(
        &mut self,
        subject: &ForceCacheSubject,
        payload: CachedExpressionValue,
        trace: &[ImpureInputFingerprint],
    ) {
        let Some(identity) = subject.lookup_identity else {
            return;
        };
        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping persistent forced expression runtime observation"
            );
            return;
        };
        if !cache.is_enabled() {
            return;
        }
        let observation = if trace.is_empty() {
            cache
                .observe_inline_expression_payload(
                    identity,
                    subject.free_var_value_hashes.iter().copied(),
                    payload,
                )
                .map(|_| ())
        } else {
            let mut runtime_trace = Vec::new();
            if runtime_trace.try_reserve_exact(trace.len()).is_err() {
                tracing::warn!(
                    target: "aos_nix::cache",
                    "tree-walk evaluator persistent forced expression runtime trace allocation failed"
                );
                return;
            }
            runtime_trace.extend_from_slice(trace);
            let source = ImpureInputTraceSegment {
                trace: runtime_trace,
                complete: true,
            };
            cache
                .observe_inline_expression_payload_with_impure_inputs(
                    identity,
                    subject.free_var_value_hashes.iter().copied(),
                    payload,
                    &source,
                )
                .map(|_| ())
        };
        if let Err(error) = observation {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent forced expression runtime observation failed"
            );
        }
    }

    fn value_for_cached_expression_payload(
        &mut self,
        payload: CachedExpressionValue,
    ) -> Option<Value> {
        self.value_for_cached_expression_payload_with_depth(payload, 0)
    }

    fn value_for_cached_expression_payload_with_depth(
        &mut self,
        payload: CachedExpressionValue,
        depth: usize,
    ) -> Option<Value> {
        if depth > FORCE_CACHE_PAYLOAD_MAX_DEPTH {
            return None;
        }
        if let Some(value) = payload.immediate_value() {
            return Some(value);
        }
        if let Some(bytes) = payload.context_free_string_bytes() {
            let bytes = try_clone_bytes(bytes).ok()?;
            return self.heap.alloc_string(NixString::from_bytes(bytes)).ok();
        }
        if let Some((bytes, context)) = payload.context_string_parts() {
            let bytes = try_clone_bytes(bytes).ok()?;
            let context = context.try_clone_context().ok()?;
            return self.heap.alloc_string(NixString::new(bytes, context)).ok();
        }
        if let Some((bytes, context)) = payload.context_path_parts() {
            let bytes = try_clone_bytes(bytes).ok()?;
            let context = context.try_clone_context().ok()?;
            return self.heap.alloc_path(NixString::new(bytes, context)).ok();
        }
        if payload.is_empty_list() {
            return self.heap.alloc_list(NixList::empty()).ok();
        }
        if let Some(element_payloads) = payload.list_element_payloads() {
            let mut elements = Vec::new();
            elements.try_reserve_exact(element_payloads.len()).ok()?;
            for element in element_payloads {
                elements.push(self.value_for_cached_expression_payload_with_depth(
                    element,
                    depth.saturating_add(1),
                )?);
            }
            return self.heap.alloc_list(NixList::new(elements)).ok();
        }
        if payload.is_empty_attrs() {
            return self.heap.alloc_attrs(0, FlatAttrs::empty()).ok();
        }
        if let Some(attr_payloads) = payload.attrs_entries() {
            let mut entries = Vec::new();
            entries.try_reserve_exact(attr_payloads.len()).ok()?;
            for (name, value_payload) in attr_payloads {
                let symbol = self.symbols.intern(&name).ok()?;
                let value = self.value_for_cached_expression_payload_with_depth(
                    value_payload,
                    depth.saturating_add(1),
                )?;
                entries.push(AttrEntry::new(symbol, value));
            }
            let attrs = FlatAttrs::new(entries, &self.symbols).ok()?;
            return self.heap.alloc_attrs(0, attrs).ok();
        }
        let bytes = try_clone_bytes(payload.path_bytes()?).ok()?;
        self.heap.alloc_path(NixString::from_bytes(bytes)).ok()
    }

    pub(super) fn record_forced_expression_demand(&mut self, subject: &ForceCacheSubject) {
        if !self.options.eval_cache_enabled() {
            return;
        }
        let Some(identity) = subject.metadata_identity else {
            return;
        };
        self.open_persist_eval_cache();
        let Some(persist_cache) = &self.persist_cache else {
            return;
        };
        let key = PersistNodeMetadataKey::for_expression(
            identity,
            subject.free_var_value_hashes.iter().copied(),
        );
        if let Err(error) = persist_cache.record_node_current_demand(key) {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent force demand observation failed"
            );
        }
    }

    pub(super) fn advance_persist_eval_cache_run_boundary(&mut self) {
        if !self.options.eval_cache_enabled() {
            return;
        }
        let Some(persist_cache) = &self.persist_cache else {
            return;
        };
        if let Err(error) = persist_cache.advance_all_node_materialization_reuse_runs() {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent force demand run-boundary advancement failed"
            );
        }
    }

    pub(super) fn open_persist_eval_cache(&mut self) {
        if self.persist_cache.is_none() && !self.persist_cache_open_attempted {
            self.persist_cache_open_attempted = true;
            if let Some(root) = self.options.persist_cache_root().map(Path::to_path_buf) {
                self.persist_cache = PersistCache::open(root).ok();
            }
        }
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
                    free_var_value_hashes,
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
            free_var_value_hashes: Vec::new(),
            memoization_admission: ForceCacheMemoizationAdmission::SelectedSubstrate,
        })
    }

    fn inline_free_var_value_hashes_for_body(
        &self,
        body: EvalNodeRef,
        env: &EvalEnv,
    ) -> Option<Vec<DurableBlake3Hash>> {
        self.inline_free_var_value_hashes_for_frames(body, env.frames())
    }

    fn inline_free_var_value_hashes_for_current_node(
        &self,
        id: IrId,
    ) -> Option<Vec<DurableBlake3Hash>> {
        self.inline_free_var_value_hashes_for_frames(
            EvalNodeRef::new(self.current_module, id),
            &self.env,
        )
    }

    fn inline_free_var_value_hashes_for_frames(
        &self,
        body: EvalNodeRef,
        frames: &[Rc<EvalFrame>],
    ) -> Option<Vec<DurableBlake3Hash>> {
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

    pub(super) fn derivation_aterm_cache_subject_for_current_node(
        &self,
        id: IrId,
    ) -> Option<(CacheExprIdentity, Vec<DurableBlake3Hash>)> {
        if !self.with_scopes.is_empty() || !self.scoped_globals.is_empty() {
            return None;
        }
        let identity = self.derivation_aterm_cache_identity_for_current_node(id)?;
        let free_var_value_hashes = self.inline_free_var_value_hashes_for_current_node(id)?;
        Some((identity, free_var_value_hashes))
    }

    pub(super) fn static_derivation_outputs_cache_subject_for_current_node(
        &self,
        id: IrId,
    ) -> Option<(CacheExprIdentity, Vec<DurableBlake3Hash>)> {
        if !self.with_scopes.is_empty() || !self.scoped_globals.is_empty() {
            return None;
        }
        let identity = self.static_derivation_outputs_cache_identity_for_current_node(id)?;
        let free_var_value_hashes = self.inline_free_var_value_hashes_for_current_node(id)?;
        Some((identity, free_var_value_hashes))
    }

    pub(super) fn eval_cache_runtime_enabled(&self) -> bool {
        match self.eval_cache.lock() {
            Ok(cache) => cache.is_enabled(),
            Err(_) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    "tree-walk evaluator cache lock was poisoned; skipping cache observation"
                );
                false
            }
        }
    }

    pub(super) fn force_cache_free_var_value_hash(
        &self,
        value: Value,
    ) -> Option<DurableBlake3Hash> {
        if let Ok(hash) = ValueHash::from_inline_value(value) {
            return Some(hash.as_durable_hash());
        }
        match value.tag() {
            ValueTag::String => {
                let string = self.heap.get_string(value).ok()?;
                let mut hasher = blake3::Hasher::new();
                hasher.update(FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"string");
                Self::update_cache_identity_chunk(&mut hasher, string.bytes())?;
                if string.has_context() {
                    Self::update_force_capture_string_context(&mut hasher, string.context())?;
                }
                return Some(DurableBlake3Hash::from_hasher(hasher));
            }
            ValueTag::Path => {
                let path = self.heap.get_path(value).ok()?;
                let mut hasher = blake3::Hasher::new();
                hasher.update(FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"path");
                Self::update_cache_identity_chunk(&mut hasher, path.bytes())?;
                if path.has_context() {
                    Self::update_force_capture_string_context(&mut hasher, path.context())?;
                }
                return Some(DurableBlake3Hash::from_hasher(hasher));
            }
            ValueTag::List | ValueTag::Attrs => {
                let payload = self.force_cache_payload_for_value(value)?;
                let value_hash = payload.value_hash().ok()?;
                let mut hasher = blake3::Hasher::new();
                hasher.update(FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"composite");
                hasher.update(&value_hash.as_durable_hash().as_bytes());
                return Some(DurableBlake3Hash::from_hasher(hasher));
            }
            ValueTag::Thunk => {
                let cached = {
                    let thunk = self.heap.get_thunk(value).ok()?;
                    match thunk.cell().cached_value().ok()? {
                        Some(cached) => cached,
                        None => {
                            let payload = self.force_cache_payload_for_suspended_thunk(thunk, 0)?;
                            return Self::force_cache_free_var_payload_hash(&payload);
                        }
                    }
                };
                if cached.is_thunk() {
                    return None;
                }
                return self.force_cache_free_var_value_hash(cached);
            }
            _ => return None,
        }
    }

    fn force_cache_free_var_payload_hash(
        payload: &CachedExpressionValue,
    ) -> Option<DurableBlake3Hash> {
        if let Some(value) = payload.immediate_value() {
            return ValueHash::from_inline_value(value)
                .ok()
                .map(|hash| hash.as_durable_hash());
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION);
        if let Some(bytes) = payload.context_free_string_bytes() {
            hasher.update(b"string");
            Self::update_cache_identity_chunk(&mut hasher, bytes)?;
            return Some(DurableBlake3Hash::from_hasher(hasher));
        }
        if let Some((bytes, context)) = payload.context_string_parts() {
            hasher.update(b"string");
            Self::update_cache_identity_chunk(&mut hasher, bytes)?;
            Self::update_force_capture_string_context(&mut hasher, context)?;
            return Some(DurableBlake3Hash::from_hasher(hasher));
        }
        if let Some(bytes) = payload.path_bytes() {
            hasher.update(b"path");
            Self::update_cache_identity_chunk(&mut hasher, bytes)?;
            return Some(DurableBlake3Hash::from_hasher(hasher));
        }
        if let Some((bytes, context)) = payload.context_path_parts() {
            hasher.update(b"path");
            Self::update_cache_identity_chunk(&mut hasher, bytes)?;
            Self::update_force_capture_string_context(&mut hasher, context)?;
            return Some(DurableBlake3Hash::from_hasher(hasher));
        }

        let value_hash = payload.value_hash().ok()?;
        hasher.update(b"composite");
        hasher.update(&value_hash.as_durable_hash().as_bytes());
        Some(DurableBlake3Hash::from_hasher(hasher))
    }

    fn update_force_capture_string_context(
        hasher: &mut blake3::Hasher,
        context: &StringContext,
    ) -> Option<()> {
        hasher.update(b"context");
        let len = u64::try_from(context.len()).ok()?;
        hasher.update(&len.to_le_bytes());
        for element in context.elements() {
            match element.kind() {
                ContextKind::OpaquePath => {
                    hasher.update(b"opaque-path");
                    Self::update_cache_identity_chunk(hasher, element.path())?;
                }
                ContextKind::SingleOutput => {
                    hasher.update(b"single-output");
                    Self::update_cache_identity_chunk(hasher, element.path())?;
                    Self::update_cache_identity_chunk(hasher, element.output()?)?;
                }
                ContextKind::DeepDerivation => {
                    hasher.update(b"deep-derivation");
                    Self::update_cache_identity_chunk(hasher, element.path())?;
                }
            }
        }
        Some(())
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
        Self::cache_expression_identity_for_node(module, body.id())
    }

    fn cache_lookup_identity_for_node(&self, body: EvalNodeRef) -> Option<CacheExprIdentity> {
        let module = self.modules.get(body.module().index())?;
        if !Self::subtree_is_force_lookup_safe(&module.ir, body.id()) {
            return None;
        }
        Self::cache_expression_identity_for_node(module, body.id())
    }

    fn cache_observation_identity_for_node(&self, body: EvalNodeRef) -> Option<CacheExprIdentity> {
        let module = self.modules.get(body.module().index())?;
        if !Self::subtree_is_force_observation_safe(&module.ir, body.id()) {
            return None;
        }
        Self::cache_expression_identity_for_node(module, body.id())
    }

    fn cache_expression_identity_for_node(
        module: &TreeWalkModule,
        id: IrId,
    ) -> Option<CacheExprIdentity> {
        let module_hash = Self::cache_module_identity_hash(module)?;
        let node = module.ir.arena.node(id)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(FORCE_EXPRESSION_IDENTITY_DOMAIN_VERSION);
        hasher.update(b"node-v1");
        hasher.update(&module_hash.as_bytes());
        hasher.update(&node.span.start.to_le_bytes());
        hasher.update(&node.span.end.to_le_bytes());
        Some(CacheExprIdentity::new(
            DurableBlake3Hash::from_hasher(hasher),
            id,
        ))
    }

    fn derivation_aterm_cache_identity_for_current_node(
        &self,
        id: IrId,
    ) -> Option<CacheExprIdentity> {
        self.derivation_cache_identity_for_current_node(id, b"final-aterm-path-v1")
    }

    fn static_derivation_outputs_cache_identity_for_current_node(
        &self,
        id: IrId,
    ) -> Option<CacheExprIdentity> {
        self.derivation_cache_identity_for_current_node(id, b"static-output-paths-v1")
    }

    fn derivation_cache_identity_for_current_node(
        &self,
        id: IrId,
        stage: &[u8],
    ) -> Option<CacheExprIdentity> {
        let module = self.modules.get(self.current_module.index())?;
        let module_hash = Self::cache_module_identity_hash(module)?;
        let node = module.ir.arena.node(id)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(DERIVATION_ATERM_EXPRESSION_IDENTITY_DOMAIN_VERSION);
        hasher.update(b"node-v1");
        hasher.update(stage);
        hasher.update(&module_hash.as_bytes());
        hasher.update(&node.span.start.to_le_bytes());
        hasher.update(&node.span.end.to_le_bytes());
        Some(CacheExprIdentity::new(
            DurableBlake3Hash::from_hasher(hasher),
            id,
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
            if !Self::node_is_force_cache_lookup_safe(ir, node) {
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

    fn node_is_force_cache_lookup_safe(ir: &Ir, node: &IrNode) -> bool {
        if node.kind == IrKind::BuiltinAttr {
            return Self::builtin_attr_is_force_cache_lookup_safe(ir, node);
        }
        Self::node_kind_is_force_cache_safe(node.kind)
    }

    fn subtree_is_force_lookup_safe(ir: &Ir, root: IrId) -> bool {
        let mut visited = BTreeSet::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if !visited.insert(id.as_u32()) {
                continue;
            }
            let Some(node) = ir.arena.node(id) else {
                return false;
            };
            if !Self::node_is_force_lookup_safe(ir, node) {
                return false;
            }
            if !Self::push_ir_children(ir, node, &mut stack) {
                return false;
            }
        }
        true
    }

    fn node_is_force_lookup_safe(ir: &Ir, node: &IrNode) -> bool {
        if node.kind == IrKind::BuiltinAttr {
            return Self::builtin_attr_is_force_cache_lookup_safe(ir, node);
        }
        if node.effect.is_speculable() {
            return Self::node_kind_is_force_cache_safe(node.kind);
        }
        node.kind == IrKind::PrimOp && Self::primop_has_cacheable_impure_input_trace(ir, node)
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
        if node.kind == IrKind::BuiltinAttr {
            return Self::builtin_attr_is_force_cache_observation_safe(ir, node);
        }
        if node.effect.is_speculable() {
            return Self::node_kind_is_force_observation_safe(node.kind);
        }
        node.kind == IrKind::PrimOp && Self::primop_has_cacheable_impure_input_trace(ir, node)
    }

    fn node_kind_is_force_observation_safe(kind: IrKind) -> bool {
        Self::node_kind_is_force_cache_safe(kind)
    }

    fn builtin_attr_execution(ir: &Ir, node: &IrNode) -> Option<BuiltinExecution> {
        let IrData::Symbol(symbol) = node.data else {
            return None;
        };
        let builtin = lookup_builtin_by_symbol(&ir.symbols, symbol)?;
        Some(builtin.execution())
    }

    fn builtin_attr_is_force_cache_lookup_safe(ir: &Ir, node: &IrNode) -> bool {
        Self::builtin_attr_execution(ir, node)
            .is_some_and(Self::builtin_execution_is_force_cache_lookup_safe)
    }

    fn builtin_attr_is_force_cache_observation_safe(ir: &Ir, node: &IrNode) -> bool {
        Self::builtin_attr_execution(ir, node)
            .is_some_and(Self::builtin_execution_is_force_cache_observation_safe)
    }

    const fn builtin_execution_is_force_cache_lookup_safe(execution: BuiltinExecution) -> bool {
        matches!(
            execution,
            BuiltinExecution::TrueValue
                | BuiltinExecution::FalseValue
                | BuiltinExecution::NullValue
                | BuiltinExecution::CurrentSystemValue
                | BuiltinExecution::StoreDirValue
                | BuiltinExecution::NixVersionValue
                | BuiltinExecution::LangVersionValue
        )
    }

    const fn builtin_execution_is_force_cache_observation_safe(
        execution: BuiltinExecution,
    ) -> bool {
        Self::builtin_execution_is_force_cache_lookup_safe(execution)
            || matches!(execution, BuiltinExecution::CurrentTimeValue)
    }

    const fn builtin_execution_cache_identity_bytes(
        execution: BuiltinExecution,
    ) -> Option<&'static [u8]> {
        match execution {
            BuiltinExecution::TrueValue => Some(b"true"),
            BuiltinExecution::FalseValue => Some(b"false"),
            BuiltinExecution::NullValue => Some(b"null"),
            BuiltinExecution::CurrentSystemValue => Some(b"current-system"),
            BuiltinExecution::CurrentTimeValue => Some(b"current-time"),
            BuiltinExecution::StoreDirValue => Some(b"store-dir"),
            BuiltinExecution::NixVersionValue => Some(b"nix-version"),
            BuiltinExecution::LangVersionValue => Some(b"lang-version"),
            _ => None,
        }
    }

    pub(super) fn cache_synthetic_builtin_attr_identity(
        &self,
        site: EvalNodeRef,
        symbol: Symbol,
        builtin: Builtin,
    ) -> Option<CacheExprIdentity> {
        let module = self.modules.get(site.module().index())?;
        let module_hash = Self::cache_module_identity_hash(module)?;
        let site_node = module.ir.arena.node(site.id())?;
        let symbol_name = self
            .symbols
            .resolve(symbol)
            .unwrap_or_else(|| builtin.name());
        let execution = builtin.execution();
        let execution_bytes = Self::builtin_execution_cache_identity_bytes(execution)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(FORCE_SYNTHETIC_BUILTIN_ATTR_IDENTITY_DOMAIN_VERSION);
        hasher.update(&module_hash.as_bytes());
        hasher.update(&site.id().as_u32().to_le_bytes());
        hasher.update(&site_node.span.start.to_le_bytes());
        hasher.update(&site_node.span.end.to_le_bytes());
        Self::update_cache_identity_chunk(&mut hasher, symbol_name)?;
        Self::update_cache_identity_chunk(&mut hasher, execution_bytes)?;
        Some(CacheExprIdentity::new(
            DurableBlake3Hash::from_hasher(hasher),
            site.id(),
        ))
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

    fn cache_module_identity_hash(module: &TreeWalkModule) -> Option<DurableBlake3Hash> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(FORCE_EXPRESSION_IDENTITY_DOMAIN_VERSION);
        match &module.source {
            Some(source) => {
                hasher.update(b"source-v1");
                Self::update_cache_identity_chunk(&mut hasher, &source.name)?;
                Self::update_cache_identity_chunk(&mut hasher, &source.bytes)?;
            }
            None => {
                hasher.update(b"lowered-ir-v1");
                let ir_hash = lowered_ir_fingerprint(&module.ir).ok()?;
                let ir_hash_bytes = ir_hash.as_bytes();
                Self::update_cache_identity_chunk(&mut hasher, &ir_hash_bytes)?;
            }
        }
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
        if Self::builtin_execution_is_delayed_attrset_value(builtin.execution()) {
            return self.alloc_builtin_attr_thunk(id, span, symbol, builtin);
        }
        if self.reject_unconfigured_impure_builtin_constant(builtin) && !builtin.is_available(self)
        {
            return self.alloc_builtin_attr_thunk(id, span, symbol, builtin);
        }
        builtin.select(self, id, span, symbol)
    }

    const fn builtin_execution_is_delayed_attrset_value(execution: BuiltinExecution) -> bool {
        Self::builtin_execution_is_force_cache_observation_safe(execution)
            || matches!(execution, BuiltinExecution::NixPathValue)
    }
}
