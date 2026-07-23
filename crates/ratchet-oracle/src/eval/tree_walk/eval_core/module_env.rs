//! Module, environment, scope, attr-path, and scoped-global helpers.

use super::*;
use crate::cache::hashing::CacheDigestHasher;
use crate::compile::{FLAT_CAPTURE_MAX_SLOTS, IrInlineCacheSiteId, Upvalue};

impl TreeWalk {
    pub(super) fn cache_module_identity_hash(module: &TreeWalkModule) -> Option<DurableBlake3Hash> {
        let mut hasher = CacheDigestHasher::new();
        hasher.update(FORCE_EXPRESSION_IDENTITY_DOMAIN_VERSION);
        Self::update_cache_module_source_identity(&mut hasher, module, true)?;
        module
            .force_cache_options
            .update_cache_identity(&mut hasher)?;
        Some(DurableBlake3Hash::from_hasher(hasher))
    }

    pub(super) fn cache_synthetic_builtin_module_identity_hash(
        module: &TreeWalkModule,
        execution: BuiltinExecution,
    ) -> Option<DurableBlake3Hash> {
        let mut hasher = CacheDigestHasher::new();
        hasher.update(FORCE_EXPRESSION_IDENTITY_DOMAIN_VERSION);
        Self::update_cache_module_source_identity(&mut hasher, module, false)?;
        module
            .force_cache_options
            .update_synthetic_builtin_cache_identity(&mut hasher, execution)?;
        Some(DurableBlake3Hash::from_hasher(hasher))
    }

    pub(super) fn cache_first_class_primop_module_identity_hash(
        module: &TreeWalkModule,
        execution: BuiltinExecution,
    ) -> Option<DurableBlake3Hash> {
        let mut hasher = CacheDigestHasher::new();
        hasher.update(FORCE_EXPRESSION_IDENTITY_DOMAIN_VERSION);
        Self::update_cache_module_source_identity(&mut hasher, module, false)?;
        module
            .force_cache_options
            .update_first_class_primop_cache_identity(&mut hasher, execution)?;
        Some(DurableBlake3Hash::from_hasher(hasher))
    }

    fn update_cache_module_source_identity(
        hasher: &mut CacheDigestHasher,
        module: &TreeWalkModule,
        include_path_literal_base: bool,
    ) -> Option<()> {
        match &module.source {
            Some(source) => {
                hasher.update(b"source-v1");
                Self::update_cache_identity_chunk(hasher, &source.name)?;
                Self::update_cache_identity_chunk(hasher, &source.bytes)?;
            }
            None => {
                hasher.update(b"lowered-ir-v1");
                let ir_hash = lowered_ir_fingerprint(&module.ir).ok()?;
                let ir_hash_bytes = ir_hash.as_durable_hash().as_bytes();
                Self::update_cache_identity_chunk(hasher, &ir_hash_bytes)?;
            }
        }
        if include_path_literal_base {
            match &module.path_literal_base {
                Some(path_literal_base) => {
                    hasher.update(b"path-literal-base");
                    Self::update_cache_identity_chunk(hasher, path_literal_base)?;
                }
                None => {
                    hasher.update(b"no-path-literal-base");
                }
            }
        } else {
            hasher.update(b"path-literal-base-ignored");
        }
        Some(())
    }

    pub(super) fn update_cache_identity_chunk(
        hasher: &mut CacheDigestHasher,
        chunk: &[u8],
    ) -> Option<()> {
        let len = u64::try_from(chunk.len()).ok()?;
        hasher.update(&len.to_le_bytes());
        hasher.update(chunk);
        Some(())
    }

    pub(in crate::eval::tree_walk) fn node(&self, id: IrId) -> Result<&IrNode, TreeWalkError> {
        self.node_in_module(self.current_module, id)
    }

    pub(in crate::eval::tree_walk) fn node_in_module(
        &self,
        module: EvalModuleId,
        id: IrId,
    ) -> Result<&IrNode, TreeWalkError> {
        self.module_ir(module)?.arena.node(id).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidNodeId { id }, Span::default())
        })
    }

    pub(in crate::eval::tree_walk) fn current_ir(&self) -> &Ir {
        &self.modules[self.current_module.index()].ir
    }

    pub(in crate::eval::tree_walk) fn module_path_literal_base(
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

    pub(in crate::eval::tree_walk) fn module_ir(
        &self,
        module: EvalModuleId,
    ) -> Result<&Ir, TreeWalkError> {
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

    pub(in crate::eval::tree_walk) fn module_source(
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

    pub(in crate::eval::tree_walk) fn with_current_module<T>(
        &mut self,
        module: EvalModuleId,
        f: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        // Already-current is the common case: skip the save/restore and the
        // module validity re-fetch (the current module is already known valid).
        // Only a switch validates the new id (RFC-0007 §P1 ledger lever 6).
        if module == self.current_module {
            return f(self);
        }
        self.module_ir(module)?;
        let saved = self.current_module;
        self.current_module = module;
        let result = f(self);
        self.current_module = saved;
        result
    }

    pub(in crate::eval::tree_walk) fn push_module(
        &mut self,
        id: IrId,
        span: Span,
        ir: Ir,
        path_literal_base: Vec<u8>,
        source_name: Vec<u8>,
        source: Vec<u8>,
    ) -> Result<EvalModuleId, TreeWalkError> {
        let module = TreeWalkModule::new(
            ir,
            Some(path_literal_base),
            ForceCacheOptionsIdentity::new(&self.options),
            Some(ModuleSource {
                name: source_name,
                bytes: source,
            }),
        );
        let raw = if self.shared.is_some() {
            // Parallel mode: module ids are allocated from the shared
            // registry so any worker can resolve any worker's thunk bodies.
            self.publish_shared_module(module).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::TooManyModules {
                        id,
                        modules: self.modules.len(),
                    },
                    span,
                )
            })?
        } else {
            let raw = u32::try_from(self.modules.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::TooManyModules {
                        id,
                        modules: self.modules.len(),
                    },
                    span,
                )
            })?;
            self.modules.push(module);
            raw
        };
        Ok(EvalModuleId::new(raw))
    }

    pub(in crate::eval::tree_walk) fn omits_dead_binding(
        &self,
        let_node: IrId,
        binding_index: usize,
    ) -> bool {
        self.modules[self.current_module.index()]
            .dead_binding_eliminations
            .contains(let_node, binding_index)
    }

    pub(in crate::eval::tree_walk) fn binding_range(
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

    pub(in crate::eval::tree_walk) fn frame_info(
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

    pub(in crate::eval::tree_walk) fn capture_env(
        &mut self,
        id: IrId,
        span: Span,
    ) -> Result<(EvalEnv, Option<EvalFlatCaptureBuffer>), TreeWalkError> {
        // Depth-amplifier probe (RFC-0007): active depth at closure creation,
        // before the capture-path branches so every closure counts.
        if crate::eval::env::depth_probe_enabled() {
            crate::eval::env::note_capture_depth(self.active_env_frame_count());
        }
        #[cfg(test)]
        let runtime_conversion_enabled = self.capture_plan_validation.is_none();
        #[cfg(not(test))]
        let runtime_conversion_enabled = true;
        // FV-5a: a plan may copy values only after the enclosing binding form
        // has finished its order-sensitive assembly. During `let`/`rec` and
        // `__overrides` assembly, later slot writes must remain visible through
        // shared frames, so those allocations deliberately take the fallback.
        // The B2 record-placement proving ground likewise keeps shared frames:
        // its collector writebacks mutate captured slots and does not yet own a
        // flat-capture writeback protocol.
        if runtime_conversion_enabled
            && self.heap.supports_post_assembly_flat_capture()
            && let Some(CapturePlan::Flat(slots)) = self.current_ir().facts.capture_plan(id)
        {
            if slots.is_empty() {
                return Ok((EvalEnv::default(), None));
            }
            if slots.len() > FLAT_CAPTURE_MAX_SLOTS {
                let env = EvalEnv::capture_linked_with_flat_base(&self.env, self.flat_env.clone());
                return Ok((env, None));
            }
            let mut capture_slots = [Upvalue { depth: 0, slot: 0 }; FLAT_CAPTURE_MAX_SLOTS];
            let capture_len = slots.len();
            capture_slots[..capture_len].copy_from_slice(slots);
            let allocation_site = EvalNodeRef::new(self.current_module, id);
            let frame_count = self.active_env_frame_count();
            if self.order_sensitive_binding_depth != 0 {
                let env = EvalEnv::capture_linked_with_flat_base(&self.env, self.flat_env.clone());
                let buffer =
                    EvalFlatCaptureBuffer::pending(allocation_site, frame_count, capture_len)
                        .map_err(|source| {
                            TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span)
                        })?;
                return Ok((env, Some(buffer)));
            }
            let mut buffer = EvalFlatCaptureBuffer::new(allocation_site, frame_count);
            for capture_slot in &capture_slots[..capture_len] {
                let value = self
                    .active_env_value_at_depth(
                        usize::from(capture_slot.depth),
                        u32::from(capture_slot.slot),
                    )
                    .map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span)
                    })?;
                buffer.push(value).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span)
                })?;
            }
            return Ok((EvalEnv::default(), Some(buffer.finish())));
        }

        let env = EvalEnv::capture_linked_with_flat_base(&self.env, self.flat_env.clone());
        Ok((env, None))
    }

    /// Returns the conceptual active frame count, including a flat prefix.
    pub(in crate::eval::tree_walk) fn active_env_frame_count(&self) -> usize {
        self.active_env_ref().frame_count()
    }

    /// Returns whether the active composed environment captures no values.
    pub(in crate::eval::tree_walk) fn active_env_is_empty(&self) -> bool {
        self.active_env_ref().is_empty()
    }

    /// Returns a borrowed view over the active composed environment.
    pub(super) fn active_env_ref(&self) -> EvalEnvRef<'_> {
        EvalEnvRef {
            frames: EvalEnvFramesRef::Active(&self.env),
            flat_base: self.flat_env.as_ref(),
        }
    }

    /// Returns a borrowed view over one captured composed environment.
    pub(super) fn captured_env_ref<'a>(&self, env: &'a EvalEnv) -> EvalEnvRef<'a> {
        EvalEnvRef {
            frames: EvalEnvFramesRef::Captured(env.frames()),
            flat_base: env.flat_base(),
        }
    }

    /// Resolves one depth-relative slot from the active composed environment.
    pub(in crate::eval::tree_walk) fn active_env_value_at_depth(
        &self,
        depth: usize,
        slot: u32,
    ) -> Result<Value, EvalEnvError> {
        if depth < self.env.len() {
            return self.env[self.env.len() - 1 - depth].get(slot);
        }
        let Some(flat) = self.flat_env.as_ref() else {
            return Err(EvalEnvError::SlotOutOfBounds {
                slot,
                slots: self.env.len(),
            });
        };
        self.flat_capture_value(flat, depth - self.env.len(), slot)
            .ok_or(EvalEnvError::SlotOutOfBounds {
                slot,
                slots: flat.len(),
            })
    }

    /// Resolves one lexical read, using its closure-converted capture index.
    ///
    /// The constant-index arm is valid only when the active flat base is the
    /// allocation site recorded on the read fact. Hybrid conservative
    /// closures may execute the same node against an inherited flat base, so
    /// every mismatch retains coordinate lookup.
    #[inline]
    pub(in crate::eval::tree_walk) fn active_env_value_for_read(
        &self,
        id: IrId,
        depth: usize,
        slot: u32,
    ) -> Result<Value, EvalEnvError> {
        if depth >= self.env.len()
            && let Some(flat) = self.flat_env.as_ref()
            && let Some(access) = self.current_ir().facts.flat_capture_access(id)
            // The full module/site identity is load-bearing after annotation;
            // an unqualified direct-base shortcut can consume another fact.
            && EvalNodeRef::new(self.current_module, access.site) == flat.allocation_site()
            && let Some(value) = self.flat_capture_value_at_index(flat, usize::from(access.index))
        {
            return Ok(value);
        }
        self.active_env_value_at_depth(depth, slot)
    }

    /// Resolves one outermost-indexed slot from a captured composed env.
    pub(in crate::eval::tree_walk) fn captured_env_value_at_index(
        &self,
        env: &EvalEnv,
        frame_index: usize,
        slot: u32,
    ) -> Option<Value> {
        self.env_ref_value_at_index(self.captured_env_ref(env), frame_index, slot)
    }

    /// Resolves one outermost-indexed slot from a borrowed composed env.
    pub(super) fn env_ref_value_at_index(
        &self,
        env: EvalEnvRef<'_>,
        frame_index: usize,
        slot: u32,
    ) -> Option<Value> {
        let flat_count = env.flat_base.map_or(0, EvalFlatCapture::frame_count);
        if frame_index < flat_count {
            let depth = flat_count.checked_sub(frame_index + 1)?;
            return self.flat_capture_value(env.flat_base?, depth, slot);
        }
        env.frames.get(frame_index - flat_count)?.get(slot).ok()
    }

    /// Resolves one depth-relative slot from a captured composed env.
    pub(in crate::eval::tree_walk) fn captured_env_value_at_depth(
        &self,
        env: &EvalEnv,
        depth: usize,
        slot: u32,
    ) -> Option<Value> {
        let frame_index = env.frame_count().checked_sub(depth + 1)?;
        self.captured_env_value_at_index(env, frame_index, slot)
    }

    /// Looks up a copied value by the flat plan's canonical coordinate.
    #[inline]
    fn flat_capture_value(
        &self,
        capture: &EvalFlatCapture,
        depth: usize,
        slot: u32,
    ) -> Option<Value> {
        let site = capture.allocation_site();
        let module = self.modules.get(site.module().index())?;
        let CapturePlan::Flat(slots) = module.ir.facts.capture_plan(site.id())? else {
            return None;
        };
        let index = slots.iter().position(|capture| {
            usize::from(capture.depth) == depth && u32::from(capture.slot) == slot
        })?;
        self.flat_capture_values(capture)?.get(index).copied()
    }

    /// Copies one value through the closure tail's registry-index fast path.
    #[inline]
    fn flat_capture_value_at_index(
        &self,
        capture: &EvalFlatCapture,
        index: usize,
    ) -> Option<Value> {
        self.heap
            .flat_closure_capture_value_at(capture.inline_owner(), capture.tail_handle(), index)
            .ok()
            .flatten()
    }

    /// Resolves closure-inline capture values through the owning flat object.
    pub(in crate::eval::tree_walk) fn flat_capture_values<'a>(
        &'a self,
        capture: &'a EvalFlatCapture,
    ) -> Option<&'a [Value]> {
        let owner = capture.inline_owner();
        let values = self
            .heap
            .flat_closure_capture_values_at(owner, capture.tail_handle())
            .ok()
            .flatten()?;
        Some(values)
    }

    /// Pushes a lexical frame onto the active stack.
    #[inline]
    pub(in crate::eval::tree_walk) fn push_env_frame(&mut self, frame: Arc<EvalFrame>) {
        self.env.push(frame);
    }

    /// Pops the innermost lexical frame.
    #[inline]
    pub(in crate::eval::tree_walk) fn pop_env_frame(&mut self) {
        if let Some(frame) = self.env.pop() {
            // A frame popped with no surviving capture (the stack held the only
            // reference) is the population a frame pool could recycle; count it
            // so the pooling lever stays measure-gated.
            if Arc::strong_count(&frame) == 1 {
                crate::eval::env::capture_stats::note_env_frame_recyclable();
            }
        }
    }

    /// Replaces the active frame stack and returns the previous stack.
    #[inline]
    pub(in crate::eval::tree_walk) fn swap_env_frames(
        &mut self,
        env: impl Into<ActiveEvalEnv>,
    ) -> ActiveEvalEnv {
        let env = env.into();
        #[cfg(test)]
        self.capture_validation_on_swap(env.frame_count());
        let saved = ActiveEvalEnv {
            frames: std::mem::replace(&mut self.env, env.frames),
            flat_base: std::mem::replace(&mut self.flat_env, env.flat_base),
        };
        saved
    }

    /// Restores a frame stack previously returned by [`Self::swap_env_frames`].
    #[inline]
    pub(in crate::eval::tree_walk) fn restore_env_frames(&mut self, env: ActiveEvalEnv) {
        #[cfg(test)]
        self.capture_validation_on_restore();
        self.env = env.frames;
        self.flat_env = env.flat_base;
    }

    pub(in crate::eval::tree_walk) fn capture_with_env(
        &self,
        _id: IrId,
        _span: Span,
    ) -> Result<EvalWithEnv, TreeWalkError> {
        self.note_persistent_with_env_capture();
        Ok(EvalWithEnv::capture_persistent(&self.with_scopes))
    }

    pub(in crate::eval::tree_walk) fn capture_scoped_global_env(
        &self,
        _id: IrId,
        _span: Span,
    ) -> Result<EvalScopedGlobalEnv, TreeWalkError> {
        self.note_persistent_scoped_global_env_capture();
        Ok(EvalScopedGlobalEnv::capture_persistent(
            &self.scoped_globals,
        ))
    }

    pub(in crate::eval::tree_walk) fn clone_env_frames(
        &self,
        id: IrId,
        env: &EvalEnv,
        span: Span,
    ) -> Result<ActiveEvalEnv, TreeWalkError> {
        let frames = env.frames();
        // Env-flatten lever diagnostic (RFC-0007 §P1): record this install
        // against the captured environment's identity, only while stats
        // collection is active so a normal eval pays nothing.
        if self.options.eval_stats_dump() {
            crate::eval::env::note_env_install(frames.last());
        }
        // Depth-amplifier probe (RFC-0007): install depth = O(depth) work/apply.
        if crate::eval::env::depth_probe_enabled() {
            crate::eval::env::note_install_depth(frames.len());
        }
        if frames.is_empty() {
            return Ok(ActiveEvalEnv {
                frames: ActiveEvalFrames::new(),
                flat_base: env.flat_base().cloned(),
            });
        }
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
        // Single-pass `O(depth)` clone into the pre-reserved buffer, walking
        // the capture chain's parent links exactly once. Routing through
        // `frames.iter().cloned()` here would reintroduce the `O(depth^2)`
        // per-index chain walk on the hottest apply/force path.
        frames.clone_into(&mut cloned);
        Ok(ActiveEvalEnv {
            frames: ActiveEvalFrames::from_vec(cloned),
            flat_base: env.flat_base().cloned(),
        })
    }

    pub(in crate::eval::tree_walk) fn clone_with_scopes(
        &self,
        _id: IrId,
        env: &EvalWithEnv,
        _span: Span,
    ) -> Result<EvalWithEnv, TreeWalkError> {
        Ok(env.clone())
    }

    pub(in crate::eval::tree_walk) fn clone_scoped_globals(
        &self,
        _id: IrId,
        env: &EvalScopedGlobalEnv,
        _span: Span,
    ) -> Result<EvalScopedGlobalEnv, TreeWalkError> {
        Ok(env.clone())
    }

    pub(in crate::eval::tree_walk) fn validate_attrset_shape(
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

    pub(in crate::eval::tree_walk) fn attr_path(
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

    pub(in crate::eval::tree_walk) fn attr_path_len(
        &self,
        id: IrId,
        path: IrAttrPathId,
        span: Span,
    ) -> Result<usize, TreeWalkError> {
        self.attr_path(id, path, span)
            .map(|segments| segments.len())
    }

    pub(in crate::eval::tree_walk) fn reject_empty_attr_path(
        &self,
        id: IrId,
        path: IrAttrPathId,
        span: Span,
    ) -> Result<(), TreeWalkError> {
        let len = self.attr_path_len(id, path, span)?;
        self.reject_empty_attr_path_len(id, path, span, len)
    }

    pub(in crate::eval::tree_walk) fn reject_empty_attr_path_len(
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

    pub(in crate::eval::tree_walk) fn attr_path_segment(
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

    pub(in crate::eval::tree_walk) fn with_chain_scope_count(
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

    pub(in crate::eval::tree_walk) fn with_chain_scope(
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

    pub(in crate::eval::tree_walk) fn with_chain_scope_ref(
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

    pub(in crate::eval::tree_walk) fn with_scope_value(
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

    pub(in crate::eval::tree_walk) fn eval_global_fallback(
        &mut self,
        id: IrId,
        symbol: Symbol,
        span: Span,
        site: IrInlineCacheSiteId,
        path_index_base: usize,
    ) -> Result<Value, TreeWalkError> {
        if let Some(value) = self.scoped_global_value(id, symbol, span, site, path_index_base)? {
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

    pub(in crate::eval::tree_walk) fn scoped_global_value(
        &mut self,
        id: IrId,
        symbol: Symbol,
        span: Span,
        site: IrInlineCacheSiteId,
        path_index_base: usize,
    ) -> Result<Option<Value>, TreeWalkError> {
        if self.symbols.resolve(symbol).is_none() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol { id, symbol },
                span,
            ));
        }

        for index in (0..self.scoped_globals.len()).rev() {
            let scope = self.scoped_globals[index];
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
            let path_index = path_index_base + self.scoped_globals.len() - 1 - index;
            if let AttrSelectOutcome::Hit { value, .. } =
                self.select_static_attr_with_cache(id, span, scope, symbol, site, path_index)?
            {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    pub(in crate::eval::tree_walk) fn eval_global_var(
        &mut self,
        id: IrId,
        node: &IrNode,
    ) -> Result<Value, TreeWalkError> {
        let IrData::GlobalVar { site, symbol } = node.data else {
            return Err(self.invalid_payload(id, node, "global-var payload"));
        };
        let Some(name) = self.symbols.resolve(symbol) else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol { id, symbol },
                node.span,
            ));
        };
        let is_current_position = name == CUR_POS_ATTR;
        let is_nix_path = name == NIX_PATH_ATTR;
        let is_builtins = name == b"builtins";
        let is_unshadowable_global = is_unshadowable_global_name(name);
        let available_builtin = is_unshadowable_global
            .then(|| lookup_builtin(name).filter(|builtin| builtin.is_available(self)))
            .flatten();

        if is_current_position {
            return self.eval_current_position(id, node.span);
        }
        if is_nix_path {
            return self.eval_nix_path_value(id, node.span);
        }
        if let Some(value) = self.scoped_global_value(id, symbol, node.span, site, 0)? {
            return Ok(value);
        }
        if !self.scoped_globals.is_empty() && !is_builtins && !is_unshadowable_global {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnresolvedWithVar { id, symbol },
                node.span,
            ));
        }
        if is_builtins {
            return self.eval_builtins_attrset(id, node.span);
        }
        if let Some(builtin) = available_builtin {
            return self.eval_builtin_attrset_value(id, node.span, symbol, builtin);
        }
        Err(TreeWalkError::new(
            TreeWalkErrorKind::UnresolvedGlobalVar { id, symbol },
            node.span,
        ))
    }

    pub(in crate::eval::tree_walk) fn eval_builtin_attr(
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

    pub(in crate::eval::tree_walk) fn eval_builtins_attrset(
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
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }

    pub(in crate::eval::tree_walk) fn eval_builtin_attrset_value(
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
