//! Force-cache free-variable hashing, cache identities, and IR safety walks.

use super::*;

impl TreeWalk {
    pub(super) fn inline_free_var_value_hashes_for_body(
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

    pub(in crate::eval::tree_walk) fn derivation_aterm_cache_subject_for_current_node(
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

    pub(in crate::eval::tree_walk) fn static_derivation_outputs_cache_subject_for_current_node(
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

    pub(in crate::eval::tree_walk) fn eval_cache_runtime_enabled(&self) -> bool {
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

    pub(in crate::eval::tree_walk) fn force_cache_free_var_value_hash(
        &self,
        value: Value,
    ) -> Option<DurableBlake3Hash> {
        let mut seen_thunks = BTreeSet::new();
        self.force_cache_free_var_value_hash_with_seen(value, &mut seen_thunks, true)
    }

    pub(super) fn force_cache_free_var_value_hash_without_suspended_aliases(
        &self,
        value: Value,
    ) -> Option<DurableBlake3Hash> {
        let mut seen_thunks = BTreeSet::new();
        self.force_cache_free_var_value_hash_with_seen(value, &mut seen_thunks, false)
    }

    pub(super) fn force_cache_free_var_value_hash_with_seen(
        &self,
        value: Value,
        seen_thunks: &mut BTreeSet<u64>,
        allow_suspended_capture_aliases: bool,
    ) -> Option<DurableBlake3Hash> {
        if let Ok(hash) = ValueHash::from_inline_value(value) {
            return Some(hash.as_durable_hash());
        }
        if allow_suspended_capture_aliases
            && let Ok(Some(hash)) = self.heap.cached_captured_value_hash(value)
        {
            return Some(hash);
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
                self.cache_force_capture_hash(value, DurableBlake3Hash::from_hasher(hasher))
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
                self.cache_force_capture_hash(value, DurableBlake3Hash::from_hasher(hasher))
            }
            ValueTag::List | ValueTag::Attrs => {
                let payload = self.force_cache_payload_for_value_with_depth(
                    value,
                    0,
                    seen_thunks,
                    allow_suspended_capture_aliases,
                )?;
                let mut hasher = blake3::Hasher::new();
                hasher.update(FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION);
                self.update_force_capture_composite_payload_hash(&mut hasher, &payload)?;
                self.cache_force_capture_hash(value, DurableBlake3Hash::from_hasher(hasher))
            }
            ValueTag::Thunk => {
                let thunk_key = value.payload_bits();
                if !seen_thunks.insert(thunk_key) {
                    return None;
                }
                let result = (|| {
                    let thunk = self.heap.get_thunk(value).ok()?;
                    match thunk.cell().cached_value().ok()? {
                        Some(cached) => {
                            if cached.is_thunk() {
                                return None;
                            }
                            self.force_cache_free_var_value_hash_with_seen(
                                cached,
                                seen_thunks,
                                allow_suspended_capture_aliases,
                            )
                        }
                        None => {
                            if allow_suspended_capture_aliases {
                                if let Some(hash) = self
                                    .force_cache_hash_for_suspended_capture_alias_thunk(
                                        thunk,
                                        seen_thunks,
                                    )
                                {
                                    return Some(hash);
                                }
                            }
                            let payload = if allow_suspended_capture_aliases {
                                self.force_cache_payload_for_suspended_thunk_with_seen(
                                    thunk,
                                    0,
                                    seen_thunks,
                                )?
                            } else {
                                self.force_cache_payload_for_suspended_closed_thunk(thunk, 0)?
                            };
                            self.force_cache_free_var_payload_hash(&payload)
                        }
                    }
                })();
                seen_thunks.remove(&thunk_key);
                result
            }
            _ => None,
        }
    }

    fn force_cache_hash_for_suspended_capture_alias_thunk(
        &self,
        thunk: &EvalThunk,
        seen_thunks: &mut BTreeSet<u64>,
    ) -> Option<DurableBlake3Hash> {
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
        let frames = env.frames();
        let module = self.modules.get(body.module().index())?;
        let node = module.ir.arena.node(body.id())?;
        let (frame_index, slot) = match node.data {
            IrData::Local { slot } => (frames.len().checked_sub(1)?, slot),
            IrData::Upval { depth, slot } => {
                let depth = depth as usize;
                if depth >= frames.len() {
                    return None;
                }
                (frames.len() - 1 - depth, slot)
            }
            _ => return None,
        };
        let value = frames.get(frame_index)?.get(slot).ok()?;
        self.force_cache_free_var_value_hash_with_seen(value, seen_thunks, true)
    }

    fn cache_force_capture_hash(
        &self,
        value: Value,
        hash: DurableBlake3Hash,
    ) -> Option<DurableBlake3Hash> {
        self.heap.cache_captured_value_hash(value, hash).ok()?;
        Some(hash)
    }

    fn force_cache_free_var_payload_hash(
        &self,
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

        self.update_force_capture_composite_payload_hash(&mut hasher, payload)?;
        Some(DurableBlake3Hash::from_hasher(hasher))
    }

    fn update_force_capture_composite_payload_hash(
        &self,
        hasher: &mut blake3::Hasher,
        payload: &CachedExpressionValue,
    ) -> Option<()> {
        let value_hash = payload.value_hash().ok()?;
        hasher.update(b"composite");
        hasher.update(&value_hash.as_durable_hash().as_bytes());
        if !payload.retains_attr_positions() {
            hasher.update(b"no-attr-position-modules");
            return Some(());
        }

        let mut modules = BTreeSet::new();
        payload.collect_attr_position_modules(&mut modules);
        let len = u64::try_from(modules.len()).ok()?;
        hasher.update(b"attr-position-modules");
        hasher.update(&len.to_le_bytes());
        for module_id in modules {
            hasher.update(&module_id.to_le_bytes());
            let module_index = usize::try_from(module_id).ok()?;
            let module = self.modules.get(module_index)?;
            let module_hash = Self::cache_module_identity_hash(module)?;
            hasher.update(&module_hash.as_bytes());
        }
        Some(())
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

    pub(super) fn captured_free_variable_slots(
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
            let node = ir.arena.node(id)?;
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

    pub(super) fn cache_identity_for_node(&self, body: EvalNodeRef) -> Option<CacheExprIdentity> {
        let module = self.modules.get(body.module().index())?;
        if !Self::subtree_is_speculable(&module.ir, body.id()) {
            return None;
        }
        Self::cache_expression_identity_for_node(module, body.id())
    }

    pub(super) fn cache_lookup_identity_for_node(
        &self,
        body: EvalNodeRef,
    ) -> Option<CacheExprIdentity> {
        let module = self.modules.get(body.module().index())?;
        if module
            .ir
            .arena
            .node(body.id())
            .is_some_and(|node| Self::search_path_has_cacheable_origin(&module.ir, node))
        {
            return Self::cache_expression_identity_for_node(module, body.id());
        }
        if !Self::subtree_is_force_lookup_safe(&module.ir, body.id()) {
            return None;
        }
        Self::cache_expression_identity_for_node(module, body.id())
    }

    pub(super) fn cache_observation_identity_for_node(
        &self,
        body: EvalNodeRef,
    ) -> Option<CacheExprIdentity> {
        let module = self.modules.get(body.module().index())?;
        if module
            .ir
            .arena
            .node(body.id())
            .is_some_and(|node| Self::search_path_has_cacheable_origin(&module.ir, node))
        {
            return Self::cache_expression_identity_for_node(module, body.id());
        }
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
        Some(Self::cache_expression_identity_for_module_hash_and_span(
            module_hash,
            id,
            node.span,
        ))
    }

    fn cache_expression_identity_for_module_hash_and_span(
        module_hash: DurableBlake3Hash,
        id: IrId,
        span: Span,
    ) -> CacheExprIdentity {
        let mut hasher = blake3::Hasher::new();
        hasher.update(FORCE_EXPRESSION_IDENTITY_DOMAIN_VERSION);
        hasher.update(b"node-v1");
        hasher.update(&module_hash.as_bytes());
        hasher.update(&span.start.to_le_bytes());
        hasher.update(&span.end.to_le_bytes());
        CacheExprIdentity::new(DurableBlake3Hash::from_hasher(hasher), id)
    }

    /// Builds a node expression identity from a fixed module hash for tests.
    #[cfg(test)]
    pub(crate) fn test_cache_expression_identity_for_module_hash_and_span(
        module_hash: DurableBlake3Hash,
        id: IrId,
        span: Span,
    ) -> CacheExprIdentity {
        Self::cache_expression_identity_for_module_hash_and_span(module_hash, id, span)
    }

    pub(super) fn cache_first_class_primop_call_identity_for_current_node(
        &self,
        id: IrId,
        builtin: Builtin,
    ) -> Option<CacheExprIdentity> {
        let module = self.modules.get(self.current_module.index())?;
        let module_hash = Self::cache_module_identity_hash(module)?;
        let node = module.ir.arena.node(id)?;
        if node.kind != IrKind::Apply {
            return None;
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(FORCE_FIRST_CLASS_PRIMOP_CALL_IDENTITY_DOMAIN_VERSION);
        hasher.update(b"node-v1");
        hasher.update(&module_hash.as_bytes());
        hasher.update(&node.span.start.to_le_bytes());
        hasher.update(&node.span.end.to_le_bytes());
        Self::update_cache_identity_chunk(&mut hasher, builtin.name())?;
        Some(CacheExprIdentity::new(
            DurableBlake3Hash::from_hasher(hasher),
            id,
        ))
    }

    #[cfg(test)]
    pub(crate) fn test_cache_first_class_primop_call_identity_for_current_node(
        &self,
        id: IrId,
        builtin: Builtin,
    ) -> Option<CacheExprIdentity> {
        self.cache_first_class_primop_call_identity_for_current_node(id, builtin)
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

    pub(super) fn builtin_attr_execution(ir: &Ir, node: &IrNode) -> Option<BuiltinExecution> {
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

    pub(super) const fn builtin_execution_is_force_cache_lookup_safe(
        execution: BuiltinExecution,
    ) -> bool {
        matches!(
            execution,
            BuiltinExecution::TrueValue
                | BuiltinExecution::FalseValue
                | BuiltinExecution::NullValue
                | BuiltinExecution::CurrentSystemValue
                | BuiltinExecution::StoreDirValue
                | BuiltinExecution::NixVersionValue
                | BuiltinExecution::LangVersionValue
                | BuiltinExecution::NixPathValue
        )
    }

    pub(super) const fn builtin_execution_is_force_cache_observation_safe(
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
            BuiltinExecution::NixPathValue => Some(b"nix-path"),
            _ => None,
        }
    }

    pub(in crate::eval::tree_walk) fn cache_synthetic_builtin_attr_identity(
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
        match ir.symbols.resolve(symbol) {
            Some(b"findFile") => Self::primop_find_file_has_cacheable_search_path_arg(ir, node),
            Some(
                b"import" | b"getEnv" | b"hashFile" | b"pathExists" | b"readDir" | b"readFile"
                | b"readFileType",
            ) => true,
            _ => false,
        }
    }

    fn primop_find_file_has_cacheable_search_path_arg(ir: &Ir, node: &IrNode) -> bool {
        let IrData::PrimOp { args, .. } = node.data else {
            return false;
        };
        let Some(args) = ir.arena.child_slice(args) else {
            return false;
        };
        let Some(first_arg) = args.first() else {
            return false;
        };
        let Some(first_arg) = ir.arena.node(*first_arg) else {
            return false;
        };
        first_arg.kind == IrKind::List
            || Self::node_is_builtin_nix_path_attr(ir, first_arg)
            || Self::node_is_captured_search_path_value(first_arg)
    }

    fn node_is_builtin_nix_path_attr(ir: &Ir, node: &IrNode) -> bool {
        node.kind == IrKind::BuiltinAttr
            && Self::builtin_attr_execution(ir, node) == Some(BuiltinExecution::NixPathValue)
    }

    fn search_path_has_cacheable_origin(ir: &Ir, node: &IrNode) -> bool {
        let IrData::SearchPath { search_path, .. } = node.data else {
            return false;
        };
        let Some(search_path) = search_path else {
            return true;
        };
        ir.arena
            .node(search_path)
            .is_some_and(Self::node_is_captured_search_path_value)
    }

    fn node_is_captured_search_path_value(node: &IrNode) -> bool {
        matches!(node.data, IrData::Local { .. } | IrData::Upval { .. })
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
}
