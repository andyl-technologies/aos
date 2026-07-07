//! Force-cache free-variable hashing, cache identities, and IR safety walks.

use super::*;
use crate::cache::CacheExprSourceHash;
use crate::cache::hashing::{
    ForceCapturePositionSourceHash, ForceCapturedValueHash, StaticSelectPositionHash,
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum CapturedFreeVariableDependency {
    Slot {
        frame_index: usize,
        slot: u32,
    },
    StaticHasAttr {
        frame_index: usize,
        slot: u32,
        path: u32,
    },
    StaticSelect {
        frame_index: usize,
        slot: u32,
        path: u32,
        default: Option<DefaultSelectDependency>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DefaultSelectDependency {
    node: u32,
    nested_frame_count: usize,
    static_scopes: Box<[StaticBindingScope]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct StaticBindingScope {
    start: u32,
    len: u32,
}

impl From<IrBindingSlice> for StaticBindingScope {
    fn from(slice: IrBindingSlice) -> Self {
        Self {
            start: slice.start,
            len: slice.len,
        }
    }
}

impl StaticBindingScope {
    fn as_binding_slice(self) -> IrBindingSlice {
        IrBindingSlice::new(self.start, self.len)
    }
}

enum StaticSelectProjection {
    Present(ValueHash),
    Missing,
}

impl TreeWalk {
    pub(super) fn inline_free_var_value_hashes_for_body(
        &self,
        body: EvalNodeRef,
        env: &EvalEnv,
    ) -> Option<Vec<ValueHash>> {
        self.inline_free_var_value_hashes_for_frames(body, env.frames())
    }

    fn inline_free_var_value_hashes_for_current_node(&self, id: IrId) -> Option<Vec<ValueHash>> {
        self.inline_free_var_value_hashes_for_frames(
            EvalNodeRef::new(self.current_module, id),
            &self.env,
        )
    }

    fn inline_free_var_value_hashes_for_frames(
        &self,
        body: EvalNodeRef,
        frames: &[Arc<EvalFrame>],
    ) -> Option<Vec<ValueHash>> {
        if frames.is_empty() {
            return Some(Vec::new());
        }

        let module = self.modules.get(body.module().index())?;
        let dependencies =
            Self::captured_free_variable_dependencies(&module.ir, body.id(), frames.len())?;
        let mut hashes = Vec::new();
        hashes.try_reserve_exact(dependencies.len()).ok()?;
        for dependency in dependencies {
            let hash = match dependency {
                CapturedFreeVariableDependency::Slot { frame_index, slot } => {
                    let value = frames.get(frame_index)?.get(slot).ok()?;
                    self.force_cache_free_var_value_hash(value)?
                }
                CapturedFreeVariableDependency::StaticHasAttr {
                    frame_index,
                    slot,
                    path,
                } => {
                    let receiver = frames.get(frame_index)?.get(slot).ok()?;
                    self.force_cache_static_has_attr_value_hash(
                        body.module(),
                        receiver,
                        IrAttrPathId::new(path),
                    )
                    .or_else(|| self.force_cache_free_var_value_hash(receiver))?
                }
                CapturedFreeVariableDependency::StaticSelect {
                    frame_index,
                    slot,
                    path,
                    default,
                } => {
                    let receiver = frames.get(frame_index)?.get(slot).ok()?;
                    match default {
                        Some(default) => {
                            self.force_cache_static_select_default_value_hashes(
                                body.module(),
                                frames,
                                receiver,
                                IrAttrPathId::new(path),
                                &default,
                                &mut hashes,
                            )?;
                            continue;
                        }
                        None => self
                            .force_cache_static_select_value_hash(
                                body.module(),
                                receiver,
                                IrAttrPathId::new(path),
                            )
                            .or_else(|| self.force_cache_free_var_value_hash(receiver))?,
                    }
                }
            };
            hashes.push(hash);
        }
        Some(hashes)
    }

    pub(in crate::eval::tree_walk) fn derivation_aterm_cache_subject_for_current_node(
        &self,
        id: IrId,
    ) -> Option<(CacheExprIdentity, Vec<ValueHash>)> {
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
    ) -> Option<(CacheExprIdentity, Vec<ValueHash>)> {
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
    ) -> Option<ValueHash> {
        let mut seen_thunks = BTreeSet::new();
        self.force_cache_free_var_value_hash_with_seen(value, &mut seen_thunks, true)
    }

    pub(super) fn force_cache_static_select_value_hash(
        &self,
        module_id: EvalModuleId,
        receiver: Value,
        path: IrAttrPathId,
    ) -> Option<ValueHash> {
        match self.force_cache_static_select_projection(module_id, receiver, path)? {
            StaticSelectProjection::Present(hash) => Some(hash),
            StaticSelectProjection::Missing => None,
        }
    }

    fn force_cache_static_select_projection(
        &self,
        module_id: EvalModuleId,
        receiver: Value,
        path: IrAttrPathId,
    ) -> Option<StaticSelectProjection> {
        let module = self.modules.get(module_id.index())?;
        let segments = module.ir.attr_paths.get(path.index())?;
        if segments.is_empty() {
            return None;
        }

        let mut current = receiver;
        let mut seen_thunks = BTreeSet::new();
        let mut position_identities = BTreeSet::new();
        for (index, segment) in segments.iter().copied().enumerate() {
            let IrAttrPathSegment::Static(symbol) = segment else {
                return None;
            };
            let current_value = self
                .force_cache_cached_or_capture_alias_non_thunk_value(current, &mut seen_thunks)?;
            if current_value.tag() != ValueTag::Attrs {
                return Some(StaticSelectProjection::Missing);
            }
            let selected = {
                let attrs = self.heap.get_attrs(current_value).ok()?;
                let Some(entry) = attrs.get_entry(symbol) else {
                    return Some(StaticSelectProjection::Missing);
                };
                if let Some(position) = entry.position {
                    position_identities
                        .insert(self.force_cache_attr_position_identity_hash(position)?);
                }
                entry.value
            };
            if index + 1 == segments.len() {
                let selected_hash = self.force_cache_free_var_value_hash(selected)?;
                if position_identities.is_empty() {
                    return Some(StaticSelectProjection::Present(selected_hash));
                }
                let mut hasher = blake3::Hasher::new();
                hasher.update(FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"static-select");
                hasher.update(&selected_hash.as_durable_hash().as_bytes());
                let len = u64::try_from(position_identities.len()).ok()?;
                hasher.update(&len.to_le_bytes());
                for identity in position_identities {
                    hasher.update(&identity.as_durable_hash().as_bytes());
                }
                return Some(StaticSelectProjection::Present(
                    ValueHash::from_force_captured_value_hash(ForceCapturedValueHash::from_hasher(
                        hasher,
                    )),
                ));
            }
            current = selected;
        }

        None
    }

    fn force_cache_static_select_default_value_hashes(
        &self,
        module_id: EvalModuleId,
        frames: &[Arc<EvalFrame>],
        receiver: Value,
        path: IrAttrPathId,
        default: &DefaultSelectDependency,
        hashes: &mut Vec<ValueHash>,
    ) -> Option<()> {
        match self.force_cache_static_select_projection(module_id, receiver, path) {
            Some(StaticSelectProjection::Present(selected_hash)) => {
                hashes.push(Self::force_cache_static_select_default_branch_hash(
                    b"present",
                    Some(selected_hash),
                )?);
                Some(())
            }
            Some(StaticSelectProjection::Missing) => {
                hashes.push(Self::force_cache_static_select_default_branch_hash(
                    b"missing", None,
                )?);
                let default_dependencies =
                    self.captured_static_select_default_dependencies(module_id, frames, default)?;
                for dependency in default_dependencies {
                    self.push_captured_free_variable_dependency_hash(
                        module_id,
                        frames,
                        &dependency,
                        hashes,
                    )?;
                }
                Some(())
            }
            None => {
                hashes.push(self.force_cache_free_var_value_hash(receiver)?);
                let default_dependencies =
                    self.captured_static_select_default_dependencies(module_id, frames, default)?;
                for dependency in default_dependencies {
                    self.push_captured_free_variable_dependency_hash(
                        module_id,
                        frames,
                        &dependency,
                        hashes,
                    )?;
                }
                Some(())
            }
        }
    }

    fn captured_static_select_default_dependencies(
        &self,
        module_id: EvalModuleId,
        frames: &[Arc<EvalFrame>],
        default: &DefaultSelectDependency,
    ) -> Option<BTreeSet<CapturedFreeVariableDependency>> {
        let module = self.modules.get(module_id.index())?;
        Self::captured_free_variable_dependencies_from_with_static_scopes(
            &module.ir,
            IrId::new(default.node),
            frames.len(),
            default.nested_frame_count,
            &default.static_scopes,
        )
    }

    fn push_captured_free_variable_dependency_hash(
        &self,
        module_id: EvalModuleId,
        frames: &[Arc<EvalFrame>],
        dependency: &CapturedFreeVariableDependency,
        hashes: &mut Vec<ValueHash>,
    ) -> Option<()> {
        let hash = match dependency {
            CapturedFreeVariableDependency::Slot { frame_index, slot } => {
                let value = frames.get(*frame_index)?.get(*slot).ok()?;
                self.force_cache_free_var_value_hash(value)?
            }
            CapturedFreeVariableDependency::StaticHasAttr {
                frame_index,
                slot,
                path,
            } => {
                let receiver = frames.get(*frame_index)?.get(*slot).ok()?;
                self.force_cache_static_has_attr_value_hash(
                    module_id,
                    receiver,
                    IrAttrPathId::new(*path),
                )
                .or_else(|| self.force_cache_free_var_value_hash(receiver))?
            }
            CapturedFreeVariableDependency::StaticSelect {
                frame_index,
                slot,
                path,
                default,
            } => {
                let receiver = frames.get(*frame_index)?.get(*slot).ok()?;
                if let Some(default) = default {
                    self.force_cache_static_select_default_value_hashes(
                        module_id,
                        frames,
                        receiver,
                        IrAttrPathId::new(*path),
                        default,
                        hashes,
                    )?;
                    return Some(());
                }
                self.force_cache_static_select_value_hash(
                    module_id,
                    receiver,
                    IrAttrPathId::new(*path),
                )
                .or_else(|| self.force_cache_free_var_value_hash(receiver))?
            }
        };
        hashes.push(hash);
        Some(())
    }

    fn force_cache_static_select_default_branch_hash(
        branch: &[u8],
        selected_hash: Option<ValueHash>,
    ) -> Option<ValueHash> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION);
        hasher.update(b"static-select-default");
        Self::update_cache_identity_chunk(&mut hasher, branch)?;
        if let Some(selected_hash) = selected_hash {
            hasher.update(&selected_hash.as_durable_hash().as_bytes());
        }
        Some(ValueHash::from_force_captured_value_hash(
            ForceCapturedValueHash::from_hasher(hasher),
        ))
    }

    fn force_cache_static_has_attr_value_hash(
        &self,
        module_id: EvalModuleId,
        receiver: Value,
        path: IrAttrPathId,
    ) -> Option<ValueHash> {
        let module = self.modules.get(module_id.index())?;
        let segments = module.ir.attr_paths.get(path.index())?;
        if segments.is_empty() {
            return None;
        }

        let mut current = receiver;
        let mut seen_thunks = BTreeSet::new();
        for (index, segment) in segments.iter().copied().enumerate() {
            let IrAttrPathSegment::Static(symbol) = segment else {
                return None;
            };
            let current_value = self
                .force_cache_cached_or_capture_alias_non_thunk_value(current, &mut seen_thunks)?;
            if current_value.tag() != ValueTag::Attrs {
                return Self::force_cache_static_has_attr_result_hash(false);
            }
            let selected = {
                let attrs = self.heap.get_attrs(current_value).ok()?;
                attrs.get(symbol)
            };
            let Some(value) = selected else {
                return Self::force_cache_static_has_attr_result_hash(false);
            };
            if index + 1 == segments.len() {
                return Self::force_cache_static_has_attr_result_hash(true);
            }
            current = value;
        }

        None
    }

    fn force_cache_static_has_attr_result_hash(present: bool) -> Option<ValueHash> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION);
        hasher.update(b"static-has-attr");
        hasher.update(&[u8::from(present)]);
        Some(ValueHash::from_force_captured_value_hash(
            ForceCapturedValueHash::from_hasher(hasher),
        ))
    }

    fn force_cache_attr_position_identity_hash(
        &self,
        position: AttrPosition,
    ) -> Option<StaticSelectPositionHash> {
        let module = self
            .modules
            .get(EvalModuleId::new(position.module).index())?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION);
        hasher.update(b"static-select-position");
        match &module.source {
            Some(source) => {
                hasher.update(b"source-name");
                Self::update_cache_identity_chunk(&mut hasher, &source.name)?;
            }
            None => {
                hasher.update(b"module-id");
                hasher.update(&position.module.to_le_bytes());
            }
        }
        hasher.update(&position.span.start.to_le_bytes());
        hasher.update(&position.span.end.to_le_bytes());
        Some(StaticSelectPositionHash::from_durable_hash(
            DurableBlake3Hash::from_hasher(hasher),
        ))
    }

    fn force_cache_cached_or_capture_alias_non_thunk_value(
        &self,
        value: Value,
        seen_thunks: &mut BTreeSet<u64>,
    ) -> Option<Value> {
        if value.tag() != ValueTag::Thunk {
            return Some(value);
        }
        let thunk_key = value.payload_bits();
        if !seen_thunks.insert(thunk_key) {
            return None;
        }
        let result = (|| {
            let thunk = self.heap.get_thunk(value).ok()?;
            match thunk.cell().cached_value().ok()? {
                Some(cached) => {
                    if cached.is_thunk() {
                        self.force_cache_cached_or_capture_alias_non_thunk_value(
                            cached,
                            seen_thunks,
                        )
                    } else {
                        Some(cached)
                    }
                }
                None => {
                    let target = self.force_cache_suspended_capture_alias_target(thunk)?;
                    self.force_cache_cached_or_capture_alias_non_thunk_value(target, seen_thunks)
                }
            }
        })();
        seen_thunks.remove(&thunk_key);
        result
    }

    pub(super) fn force_cache_free_var_value_hash_without_suspended_aliases(
        &self,
        value: Value,
    ) -> Option<ValueHash> {
        let mut seen_thunks = BTreeSet::new();
        self.force_cache_free_var_value_hash_with_seen(value, &mut seen_thunks, false)
    }

    pub(super) fn force_cache_free_var_value_hash_with_seen(
        &self,
        value: Value,
        seen_thunks: &mut BTreeSet<u64>,
        allow_suspended_capture_aliases: bool,
    ) -> Option<ValueHash> {
        if let Ok(hash) = ValueHash::from_inline_value(value) {
            return Some(hash);
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
                self.cache_force_capture_hash(value, ForceCapturedValueHash::from_hasher(hasher))
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
                self.cache_force_capture_hash(value, ForceCapturedValueHash::from_hasher(hasher))
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
                self.cache_force_capture_hash(value, ForceCapturedValueHash::from_hasher(hasher))
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
    ) -> Option<ValueHash> {
        let value = self.force_cache_suspended_capture_alias_target(thunk)?;
        self.force_cache_free_var_value_hash_with_seen(value, seen_thunks, true)
    }

    pub(super) fn force_cache_closed_hash_for_suspended_capture_alias_target(
        &self,
        value: Value,
    ) -> Option<ValueHash> {
        if !value.is_thunk() {
            return None;
        }
        let thunk_key = value.payload_bits();
        let mut seen_thunks = BTreeSet::new();
        seen_thunks.insert(thunk_key);
        let thunk = self.heap.get_thunk(value).ok()?;
        if thunk.cell().cached_value().ok()?.is_some() {
            return None;
        }
        let target = self.force_cache_suspended_capture_alias_target(thunk)?;
        if !target.is_thunk() {
            return self.force_cache_materialized_primop_arg_alias_target_hash(target);
        }
        let target_thunk = self.heap.get_thunk(target).ok()?;
        if target_thunk.cell().cached_value().ok()?.is_some() {
            let payload = self.force_cache_payload_for_suspended_closed_thunk(target_thunk, 0)?;
            return self.force_cache_free_var_payload_hash(&payload);
        }
        self.force_cache_free_var_value_hash_with_seen(target, &mut seen_thunks, false)
    }

    fn force_cache_materialized_primop_arg_alias_target_hash(
        &self,
        value: Value,
    ) -> Option<ValueHash> {
        match value.tag() {
            ValueTag::String => {
                let string = self.heap.get_string(value).ok()?;
                if string.has_context() {
                    return None;
                }
            }
            ValueTag::Path => {
                let path = self.heap.get_path(value).ok()?;
                if path.has_context() {
                    return None;
                }
            }
            _ => return None,
        }
        self.force_cache_free_var_value_hash_with_seen(value, &mut BTreeSet::new(), false)
    }

    fn force_cache_suspended_capture_alias_target(&self, thunk: &EvalThunk) -> Option<Value> {
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
        frames.get(frame_index)?.get(slot).ok()
    }

    fn cache_force_capture_hash(
        &self,
        value: Value,
        hash: ForceCapturedValueHash,
    ) -> Option<ValueHash> {
        let hash = ValueHash::from_force_captured_value_hash(hash);
        self.heap.cache_captured_value_hash(value, hash).ok()?;
        Some(hash)
    }

    fn force_cache_free_var_payload_hash(
        &self,
        payload: &CachedExpressionValue,
    ) -> Option<ValueHash> {
        if let Some(value) = payload.immediate_value() {
            return ValueHash::from_inline_value(value).ok();
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION);
        if let Some(bytes) = payload.context_free_string_bytes() {
            hasher.update(b"string");
            Self::update_cache_identity_chunk(&mut hasher, bytes)?;
            return Some(ValueHash::from_force_captured_value_hash(
                ForceCapturedValueHash::from_hasher(hasher),
            ));
        }
        if let Some((bytes, context)) = payload.context_string_parts() {
            hasher.update(b"string");
            Self::update_cache_identity_chunk(&mut hasher, bytes)?;
            Self::update_force_capture_string_context(&mut hasher, context)?;
            return Some(ValueHash::from_force_captured_value_hash(
                ForceCapturedValueHash::from_hasher(hasher),
            ));
        }
        if let Some(bytes) = payload.path_bytes() {
            hasher.update(b"path");
            Self::update_cache_identity_chunk(&mut hasher, bytes)?;
            return Some(ValueHash::from_force_captured_value_hash(
                ForceCapturedValueHash::from_hasher(hasher),
            ));
        }
        if let Some((bytes, context)) = payload.context_path_parts() {
            hasher.update(b"path");
            Self::update_cache_identity_chunk(&mut hasher, bytes)?;
            Self::update_force_capture_string_context(&mut hasher, context)?;
            return Some(ValueHash::from_force_captured_value_hash(
                ForceCapturedValueHash::from_hasher(hasher),
            ));
        }

        self.update_force_capture_composite_payload_hash(&mut hasher, payload)?;
        Some(ValueHash::from_force_captured_value_hash(
            ForceCapturedValueHash::from_hasher(hasher),
        ))
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
            let module_hash = self.force_capture_position_source_hash_for_module(module_id)?;
            hasher.update(&module_hash.as_durable_hash().as_bytes());
        }
        Some(())
    }

    fn force_capture_position_source_hash_for_module(
        &self,
        module_id: u32,
    ) -> Option<ForceCapturePositionSourceHash> {
        let module_index = usize::try_from(module_id).ok()?;
        Some(ForceCapturePositionSourceHash::from_durable_hash(
            Self::cache_module_identity_hash(self.modules.get(module_index)?)?,
        ))
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

    pub(in crate::eval::tree_walk) fn captured_free_variable_slots(
        ir: &Ir,
        root: IrId,
        captured_frame_count: usize,
    ) -> Option<BTreeSet<(usize, u32)>> {
        let mut visited = BTreeSet::new();
        let mut slots = BTreeSet::new();
        let mut stack = vec![(root, 0usize)];
        while let Some((id, nested_frame_count)) = stack.pop() {
            if !visited.insert((id.as_u32(), nested_frame_count)) {
                continue;
            }
            let node = ir.arena.node(id)?;
            match node.data {
                IrData::Local { slot } => {
                    if nested_frame_count > 0 {
                        continue;
                    }
                    let frame_index = captured_frame_count.checked_sub(1)?;
                    slots.insert((frame_index, slot));
                }
                IrData::Upval { depth, slot } => {
                    let depth = depth as usize;
                    if depth < nested_frame_count {
                        continue;
                    }
                    let captured_depth = depth - nested_frame_count;
                    if captured_depth >= captured_frame_count {
                        return None;
                    }
                    slots.insert((captured_frame_count - 1 - captured_depth, slot));
                }
                IrData::Let { bindings, body, .. } => {
                    let nested_frame_count = nested_frame_count.checked_add(1)?;
                    stack.push((body, nested_frame_count));
                    Self::push_reachable_static_binding_values_with_scope(
                        ir,
                        bindings,
                        body,
                        nested_frame_count,
                        &mut stack,
                    )
                    .then_some(())?;
                }
                IrData::Lambda { .. }
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
                | IrData::GlobalVar { .. }
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
                    let mut children = Vec::new();
                    Self::push_ir_children(ir, node, &mut children).then_some(())?;
                    stack.extend(
                        children
                            .into_iter()
                            .map(|child| (child, nested_frame_count)),
                    );
                }
            }
        }
        Some(slots)
    }

    fn captured_free_variable_dependencies(
        ir: &Ir,
        root: IrId,
        captured_frame_count: usize,
    ) -> Option<BTreeSet<CapturedFreeVariableDependency>> {
        Self::captured_free_variable_dependencies_from(ir, root, captured_frame_count, 0)
    }

    fn captured_free_variable_dependencies_from(
        ir: &Ir,
        root: IrId,
        captured_frame_count: usize,
        initial_nested_frame_count: usize,
    ) -> Option<BTreeSet<CapturedFreeVariableDependency>> {
        Self::captured_free_variable_dependencies_from_with_static_scopes(
            ir,
            root,
            captured_frame_count,
            initial_nested_frame_count,
            &[],
        )
    }

    fn captured_free_variable_dependencies_from_with_static_scopes(
        ir: &Ir,
        root: IrId,
        captured_frame_count: usize,
        initial_nested_frame_count: usize,
        initial_static_scopes: &[StaticBindingScope],
    ) -> Option<BTreeSet<CapturedFreeVariableDependency>> {
        let mut visited = BTreeSet::new();
        let mut dependencies = BTreeSet::new();
        let mut stack = vec![(
            root,
            initial_nested_frame_count,
            initial_static_scopes.to_vec(),
        )];
        while let Some((id, nested_frame_count, static_scopes)) = stack.pop() {
            if !visited.insert((id.as_u32(), nested_frame_count, static_scopes.clone())) {
                continue;
            }
            let node = ir.arena.node(id)?;
            match node.data {
                IrData::Local { slot } => {
                    if nested_frame_count > 0 {
                        let binding = Self::static_scope_binding(ir, &static_scopes, 0, slot)?;
                        stack.push((binding.value, nested_frame_count, static_scopes));
                        continue;
                    }
                    let frame_index = captured_frame_count.checked_sub(1)?;
                    dependencies.insert(CapturedFreeVariableDependency::Slot { frame_index, slot });
                }
                IrData::Upval { depth, slot } => {
                    let depth = depth as usize;
                    if depth < nested_frame_count {
                        let binding = Self::static_scope_binding(ir, &static_scopes, depth, slot)?;
                        let nested_frame_count = nested_frame_count.checked_sub(depth)?;
                        let static_scopes = static_scopes.get(depth..)?.to_vec();
                        stack.push((binding.value, nested_frame_count, static_scopes));
                        continue;
                    }
                    let captured_depth = depth - nested_frame_count;
                    if captured_depth >= captured_frame_count {
                        return None;
                    }
                    dependencies.insert(CapturedFreeVariableDependency::Slot {
                        frame_index: captured_frame_count - 1 - captured_depth,
                        slot,
                    });
                }
                IrData::Select {
                    receiver,
                    path,
                    default,
                    ..
                } => {
                    if let Some(dependency) = Self::captured_static_select_dependency(
                        ir,
                        receiver,
                        path,
                        default,
                        captured_frame_count,
                        nested_frame_count,
                        &static_scopes,
                    ) {
                        dependencies.insert(dependency);
                        continue;
                    }

                    let mut children = Vec::new();
                    Self::push_ir_children(ir, node, &mut children).then_some(())?;
                    Self::extend_dependency_walk_stack(
                        &mut stack,
                        children,
                        nested_frame_count,
                        &static_scopes,
                    )?;
                }
                IrData::HasAttr { receiver, path, .. } => {
                    if let Some(dependency) = Self::captured_static_has_attr_dependency(
                        ir,
                        receiver,
                        path,
                        captured_frame_count,
                        nested_frame_count,
                    ) {
                        dependencies.insert(dependency);
                        continue;
                    }

                    let mut children = Vec::new();
                    Self::push_ir_children(ir, node, &mut children).then_some(())?;
                    Self::extend_dependency_walk_stack(
                        &mut stack,
                        children,
                        nested_frame_count,
                        &static_scopes,
                    )?;
                }
                IrData::Let { bindings, body, .. } => {
                    let nested_frame_count = nested_frame_count.checked_add(1)?;
                    let static_scopes = Self::static_scopes_with_scope(&static_scopes, bindings)?;
                    stack.push((body, nested_frame_count, static_scopes.clone()));
                    Self::push_reachable_static_binding_values_with_dependency_scope(
                        ir,
                        bindings,
                        body,
                        nested_frame_count,
                        &static_scopes,
                        &mut stack,
                    )
                    .then_some(())?;
                }
                IrData::Lambda { .. }
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
                | IrData::GlobalVar { .. }
                | IrData::SearchPath { .. }
                | IrData::Node(_)
                | IrData::Pair { .. }
                | IrData::Triple { .. }
                | IrData::Children(_)
                | IrData::Bindings(_)
                | IrData::Binary { .. }
                | IrData::Unary { .. }
                | IrData::PrimOp { .. }
                | IrData::DialectNode { .. }
                | IrData::DialectScopeVar { .. }
                | IrData::AttrSet {
                    recursive: false, ..
                } => {
                    let mut children = Vec::new();
                    Self::push_ir_children(ir, node, &mut children).then_some(())?;
                    Self::extend_dependency_walk_stack(
                        &mut stack,
                        children,
                        nested_frame_count,
                        &static_scopes,
                    )?;
                }
            }
        }
        Some(dependencies)
    }

    fn captured_static_has_attr_dependency(
        ir: &Ir,
        receiver: IrId,
        path: IrAttrPathId,
        captured_frame_count: usize,
        nested_frame_count: usize,
    ) -> Option<CapturedFreeVariableDependency> {
        let segments = ir.attr_paths.get(path.index())?;
        if segments.is_empty()
            || !segments
                .iter()
                .all(|segment| matches!(segment, IrAttrPathSegment::Static(_)))
        {
            return None;
        }
        let (frame_index, slot) = Self::captured_frame_slot_for_node(
            ir,
            receiver,
            captured_frame_count,
            nested_frame_count,
        )?;
        Some(CapturedFreeVariableDependency::StaticHasAttr {
            frame_index,
            slot,
            path: path.as_u32(),
        })
    }

    fn captured_static_select_dependency(
        ir: &Ir,
        receiver: IrId,
        path: IrAttrPathId,
        default: Option<IrId>,
        captured_frame_count: usize,
        nested_frame_count: usize,
        static_scopes: &[StaticBindingScope],
    ) -> Option<CapturedFreeVariableDependency> {
        let segments = ir.attr_paths.get(path.index())?;
        if segments.is_empty()
            || !segments
                .iter()
                .all(|segment| matches!(segment, IrAttrPathSegment::Static(_)))
        {
            return None;
        }
        let (frame_index, slot) = Self::captured_frame_slot_for_node(
            ir,
            receiver,
            captured_frame_count,
            nested_frame_count,
        )?;
        let default = default.map(|default| DefaultSelectDependency {
            node: default.as_u32(),
            nested_frame_count,
            static_scopes: static_scopes.to_vec().into_boxed_slice(),
        });
        Some(CapturedFreeVariableDependency::StaticSelect {
            frame_index,
            slot,
            path: path.as_u32(),
            default,
        })
    }

    fn captured_frame_slot_for_node(
        ir: &Ir,
        id: IrId,
        captured_frame_count: usize,
        nested_frame_count: usize,
    ) -> Option<(usize, u32)> {
        let node = ir.arena.node(id)?;
        match node.data {
            IrData::Node(child) if node.kind == IrKind::ThunkAlloc => {
                Self::captured_frame_slot_for_node(
                    ir,
                    child,
                    captured_frame_count,
                    nested_frame_count,
                )
            }
            IrData::Local { slot } => {
                if nested_frame_count > 0 {
                    return None;
                }
                Some((captured_frame_count.checked_sub(1)?, slot))
            }
            IrData::Upval { depth, slot } => {
                let depth = depth as usize;
                if depth < nested_frame_count {
                    return None;
                }
                let captured_depth = depth - nested_frame_count;
                if captured_depth >= captured_frame_count {
                    return None;
                }
                Some((captured_frame_count - 1 - captured_depth, slot))
            }
            _ => None,
        }
    }

    pub(super) fn cache_identity_for_node(&self, body: EvalNodeRef) -> Option<CacheExprIdentity> {
        let module = self.modules.get(body.module().index())?;
        if !Self::subtree_is_speculable(&module.ir, &self.symbols, body.id()) {
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
        if !Self::subtree_is_force_lookup_safe(&module.ir, &self.symbols, body.id()) {
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
        if !Self::subtree_is_force_observation_safe(&module.ir, &self.symbols, body.id()) {
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
        CacheExprIdentity::new(
            CacheExprSourceHash::from_durable_hash(DurableBlake3Hash::from_hasher(hasher)),
            id,
        )
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
        let module_hash =
            Self::cache_first_class_primop_module_identity_hash(module, builtin.execution())
                .or_else(|| Self::cache_module_identity_hash(module))?;
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
            CacheExprSourceHash::from_durable_hash(DurableBlake3Hash::from_hasher(hasher)),
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
            CacheExprSourceHash::from_durable_hash(DurableBlake3Hash::from_hasher(hasher)),
            id,
        ))
    }

    fn subtree_is_speculable(ir: &Ir, symbols: &SymbolTable, root: IrId) -> bool {
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
            if !Self::node_is_force_cache_lookup_safe(symbols, node) {
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
                | IrKind::UpvalVar
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

    fn node_is_force_cache_lookup_safe(symbols: &SymbolTable, node: &IrNode) -> bool {
        if node.kind == IrKind::BuiltinAttr {
            return Self::builtin_attr_is_force_cache_lookup_safe(symbols, node);
        }
        Self::node_kind_is_force_cache_safe(node.kind)
    }

    fn subtree_is_force_lookup_safe(ir: &Ir, symbols: &SymbolTable, root: IrId) -> bool {
        let mut visited = BTreeSet::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if !visited.insert(id.as_u32()) {
                continue;
            }
            let Some(node) = ir.arena.node(id) else {
                return false;
            };
            if !Self::node_is_force_lookup_safe(ir, symbols, node) {
                return false;
            }
            if !Self::push_ir_children(ir, node, &mut stack) {
                return false;
            }
        }
        true
    }

    fn node_is_force_lookup_safe(ir: &Ir, symbols: &SymbolTable, node: &IrNode) -> bool {
        if node.kind == IrKind::BuiltinAttr {
            return Self::builtin_attr_is_force_cache_lookup_safe(symbols, node);
        }
        if node.kind == IrKind::SearchPath {
            return Self::search_path_has_cacheable_origin(ir, node);
        }
        if node.effect.is_speculable() {
            return Self::node_kind_is_force_cache_safe(node.kind);
        }
        node.kind == IrKind::PrimOp
            && Self::primop_has_cacheable_impure_input_trace(ir, symbols, node)
    }

    fn subtree_is_force_observation_safe(ir: &Ir, symbols: &SymbolTable, root: IrId) -> bool {
        let mut visited = BTreeSet::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if !visited.insert(id.as_u32()) {
                continue;
            }
            let Some(node) = ir.arena.node(id) else {
                return false;
            };
            if !Self::node_is_force_observation_safe(ir, symbols, node) {
                return false;
            }
            if !Self::push_ir_children(ir, node, &mut stack) {
                return false;
            }
        }
        true
    }

    fn node_is_force_observation_safe(ir: &Ir, symbols: &SymbolTable, node: &IrNode) -> bool {
        if node.kind == IrKind::BuiltinAttr {
            return Self::builtin_attr_is_force_cache_observation_safe(symbols, node);
        }
        if node.kind == IrKind::SearchPath {
            return Self::search_path_has_cacheable_origin(ir, node);
        }
        if node.effect.is_speculable() {
            return Self::node_kind_is_force_observation_safe(node.kind);
        }
        node.kind == IrKind::PrimOp
            && Self::primop_has_cacheable_impure_input_trace(ir, symbols, node)
    }

    fn node_kind_is_force_observation_safe(kind: IrKind) -> bool {
        Self::node_kind_is_force_cache_safe(kind)
    }

    pub(super) fn builtin_attr_execution(
        symbols: &SymbolTable,
        node: &IrNode,
    ) -> Option<BuiltinExecution> {
        let IrData::Symbol(symbol) = node.data else {
            return None;
        };
        debug_assert!(
            symbols.resolve(symbol).is_some(),
            "force-cache builtin symbol is absent from the live symbol table"
        );
        let builtin = lookup_builtin_by_symbol(symbols, symbol)?;
        Some(builtin.execution())
    }

    fn builtin_attr_is_force_cache_lookup_safe(symbols: &SymbolTable, node: &IrNode) -> bool {
        Self::builtin_attr_execution(symbols, node)
            .is_some_and(Self::builtin_execution_is_force_cache_lookup_safe)
    }

    fn builtin_attr_is_force_cache_observation_safe(symbols: &SymbolTable, node: &IrNode) -> bool {
        Self::builtin_attr_execution(symbols, node)
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
        let site_node = module.ir.arena.node(site.id())?;
        let symbol_name = self
            .symbols
            .resolve(symbol)
            .unwrap_or_else(|| builtin.name());
        let execution = builtin.execution();
        let module_hash = Self::cache_synthetic_builtin_module_identity_hash(module, execution)?;
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
            CacheExprSourceHash::from_durable_hash(DurableBlake3Hash::from_hasher(hasher)),
            site.id(),
        ))
    }

    pub(in crate::eval::tree_walk) fn cache_synthetic_select_identity(
        &self,
        select: EvalNodeRef,
        path: IrAttrPathId,
    ) -> Option<CacheExprIdentity> {
        let module = self.modules.get(select.module().index())?;
        let module_hash = Self::cache_module_identity_hash(module)?;
        let select_node = module.ir.arena.node(select.id())?;
        let segments = module.ir.attr_paths.get(path.index())?;
        if segments.is_empty() {
            return None;
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(FORCE_SYNTHETIC_SELECT_IDENTITY_DOMAIN_VERSION);
        hasher.update(&module_hash.as_bytes());
        hasher.update(&select.id().as_u32().to_le_bytes());
        hasher.update(&select_node.span.start.to_le_bytes());
        hasher.update(&select_node.span.end.to_le_bytes());
        let len = u64::try_from(segments.len()).ok()?;
        hasher.update(&len.to_le_bytes());
        for segment in segments.iter().copied() {
            let IrAttrPathSegment::Static(symbol) = segment else {
                return None;
            };
            debug_assert!(
                self.symbols.resolve(symbol).is_some(),
                "force-cache select symbol is absent from the live symbol table"
            );
            let name = self.symbols.resolve(symbol)?;
            Self::update_cache_identity_chunk(&mut hasher, name)?;
        }
        Some(CacheExprIdentity::new(
            CacheExprSourceHash::from_durable_hash(DurableBlake3Hash::from_hasher(hasher)),
            select.id(),
        ))
    }

    fn primop_has_cacheable_impure_input_trace(
        ir: &Ir,
        symbols: &SymbolTable,
        node: &IrNode,
    ) -> bool {
        let IrData::PrimOp { symbol, .. } = node.data else {
            return false;
        };
        debug_assert!(
            symbols.resolve(symbol).is_some(),
            "force-cache primop symbol is absent from the live symbol table"
        );
        match symbols.resolve(symbol) {
            Some(b"findFile") => {
                Self::primop_find_file_has_cacheable_search_path_arg(ir, symbols, node)
            }
            Some(
                b"import" | b"getEnv" | b"hashFile" | b"pathExists" | b"readDir" | b"readFile"
                | b"readFileType",
            ) => true,
            _ => false,
        }
    }

    fn primop_find_file_has_cacheable_search_path_arg(
        ir: &Ir,
        symbols: &SymbolTable,
        node: &IrNode,
    ) -> bool {
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
            || Self::node_is_builtin_nix_path_attr(symbols, first_arg)
            || Self::node_is_captured_search_path_value(first_arg)
    }

    fn node_is_builtin_nix_path_attr(symbols: &SymbolTable, node: &IrNode) -> bool {
        node.kind == IrKind::BuiltinAttr
            && Self::builtin_attr_execution(symbols, node) == Some(BuiltinExecution::NixPathValue)
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
            | IrData::Symbol(_)
            | IrData::GlobalVar { .. } => {}
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

    fn push_static_binding_values_with_scope(
        ir: &Ir,
        bindings: IrBindingSlice,
        nested_frame_count: usize,
        stack: &mut Vec<(IrId, usize)>,
    ) -> bool {
        let start = bindings.start as usize;
        let Some(end) = start.checked_add(bindings.len()) else {
            return false;
        };
        let Some(bindings) = ir.bindings.get(start..end) else {
            return false;
        };
        for binding in bindings {
            if !matches!(binding.key, IrAttrPathSegment::Static(_)) {
                return false;
            }
            stack.push((binding.value, nested_frame_count));
        }
        true
    }

    fn extend_dependency_walk_stack(
        stack: &mut Vec<(IrId, usize, Vec<StaticBindingScope>)>,
        children: Vec<IrId>,
        nested_frame_count: usize,
        static_scopes: &[StaticBindingScope],
    ) -> Option<()> {
        stack.try_reserve_exact(children.len()).ok()?;
        for child in children {
            stack.push((child, nested_frame_count, static_scopes.to_vec()));
        }
        Some(())
    }

    fn static_scopes_with_scope(
        parent: &[StaticBindingScope],
        bindings: IrBindingSlice,
    ) -> Option<Vec<StaticBindingScope>> {
        let mut scopes = Vec::new();
        scopes
            .try_reserve_exact(parent.len().checked_add(1)?)
            .ok()?;
        scopes.push(StaticBindingScope::from(bindings));
        scopes.extend_from_slice(parent);
        Some(scopes)
    }

    fn static_scope_binding<'a>(
        ir: &'a Ir,
        static_scopes: &[StaticBindingScope],
        depth: usize,
        slot: u32,
    ) -> Option<&'a IrBinding> {
        let scope = static_scopes.get(depth)?.as_binding_slice();
        let bindings = Self::binding_slice(ir, scope)?;
        bindings.get(slot as usize)
    }

    fn push_reachable_static_binding_values_with_dependency_scope(
        ir: &Ir,
        bindings: IrBindingSlice,
        body: IrId,
        nested_frame_count: usize,
        static_scopes: &[StaticBindingScope],
        stack: &mut Vec<(IrId, usize, Vec<StaticBindingScope>)>,
    ) -> bool {
        let Some(binding_values) = Self::binding_slice(ir, bindings) else {
            return false;
        };
        if !binding_values
            .iter()
            .all(|binding| matches!(binding.key, IrAttrPathSegment::Static(_)))
        {
            return false;
        }
        let Some(reachable) =
            Self::reachable_let_binding_slots_for_dependencies(ir, body, binding_values)
        else {
            stack.extend(
                binding_values
                    .iter()
                    .map(|binding| (binding.value, nested_frame_count, static_scopes.to_vec())),
            );
            return true;
        };
        for slot in reachable {
            let Some(binding) = binding_values.get(slot) else {
                return false;
            };
            stack.push((binding.value, nested_frame_count, static_scopes.to_vec()));
        }
        true
    }

    fn push_reachable_static_binding_values_with_scope(
        ir: &Ir,
        bindings: IrBindingSlice,
        body: IrId,
        nested_frame_count: usize,
        stack: &mut Vec<(IrId, usize)>,
    ) -> bool {
        let Some(binding_values) = Self::binding_slice(ir, bindings) else {
            return false;
        };
        if !binding_values
            .iter()
            .all(|binding| matches!(binding.key, IrAttrPathSegment::Static(_)))
        {
            return false;
        }
        let Some(reachable) = Self::reachable_let_binding_slots(ir, body, binding_values) else {
            return Self::push_static_binding_values_with_scope(
                ir,
                bindings,
                nested_frame_count,
                stack,
            );
        };
        for slot in reachable {
            let Some(binding) = binding_values.get(slot) else {
                return false;
            };
            stack.push((binding.value, nested_frame_count));
        }
        true
    }

    fn reachable_let_binding_slots(
        ir: &Ir,
        body: IrId,
        bindings: &[IrBinding],
    ) -> Option<BTreeSet<usize>> {
        let mut reachable = BTreeSet::new();
        let mut visited_nodes = BTreeSet::new();
        let mut stack = vec![body];
        while let Some(id) = stack.pop() {
            if !visited_nodes.insert(id.as_u32()) {
                continue;
            }
            let node = ir.arena.node(id)?;
            match node.data {
                IrData::Local { slot } => {
                    let slot = slot as usize;
                    if slot >= bindings.len() {
                        return None;
                    }
                    if reachable.insert(slot) {
                        stack.push(bindings.get(slot)?.value);
                    }
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
                _ => {
                    let mut children = Vec::new();
                    if !Self::push_ir_children(ir, node, &mut children) {
                        return None;
                    }
                    stack.extend(children);
                }
            }
        }
        Some(reachable)
    }

    fn reachable_let_binding_slots_for_dependencies(
        ir: &Ir,
        body: IrId,
        bindings: &[IrBinding],
    ) -> Option<BTreeSet<usize>> {
        let mut reachable = BTreeSet::new();
        let mut visited_nodes = BTreeSet::new();
        let mut stack = vec![body];
        while let Some(id) = stack.pop() {
            if !visited_nodes.insert(id.as_u32()) {
                continue;
            }
            let node = ir.arena.node(id)?;
            match node.data {
                IrData::Local { slot } => {
                    let slot = slot as usize;
                    if slot >= bindings.len() {
                        return None;
                    }
                    if reachable.insert(slot) {
                        stack.push(bindings.get(slot)?.value);
                    }
                }
                IrData::Select {
                    receiver,
                    path,
                    default: Some(_),
                    ..
                } if Self::attr_path_is_static(ir, path)? => {
                    stack.push(receiver);
                    if !Self::push_attr_path_children(ir, path, &mut stack) {
                        return None;
                    }
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
                _ => {
                    let mut children = Vec::new();
                    if !Self::push_ir_children(ir, node, &mut children) {
                        return None;
                    }
                    stack.extend(children);
                }
            }
        }
        Some(reachable)
    }

    fn attr_path_is_static(ir: &Ir, path: IrAttrPathId) -> Option<bool> {
        let segments = ir.attr_paths.get(path.index())?;
        Some(
            !segments.is_empty()
                && segments
                    .iter()
                    .all(|segment| matches!(segment, IrAttrPathSegment::Static(_))),
        )
    }

    fn binding_slice(ir: &Ir, bindings: IrBindingSlice) -> Option<&[IrBinding]> {
        let start = bindings.start as usize;
        let end = start.checked_add(bindings.len())?;
        ir.bindings.get(start..end)
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
