//! Force-cache free-variable hashing, cache identities, and IR safety walks.

use crate::cache::hashing::CacheDigestHasher;
use super::*;
use crate::cache::CacheExprSourceHash;
use crate::cache::hashing::{
    ForceCapturePositionSourceHash, ForceCapturedValueHash, StaticSelectPositionHash,
};

mod deps;
mod identity;
mod static_walk;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum CapturedFreeVariableDependency {
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
pub(super) struct DefaultSelectDependency {
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
        self.inline_free_var_value_hashes_for_env(body, self.captured_env_ref(env))
    }

    fn inline_free_var_value_hashes_for_current_node(&self, id: IrId) -> Option<Vec<ValueHash>> {
        self.inline_free_var_value_hashes_for_env(
            EvalNodeRef::new(self.current_module, id),
            self.active_env_ref(),
        )
    }

    fn inline_free_var_value_hashes_for_env(
        &self,
        body: EvalNodeRef,
        env: EvalEnvRef<'_>,
    ) -> Option<Vec<ValueHash>> {
        if env.is_empty() {
            return Some(Vec::new());
        }

        let module = self.modules.get(body.module().index())?;
        let dependencies =
            Self::captured_free_variable_dependencies(&module.ir, body.id(), env.frame_count())?;
        let mut hashes = Vec::new();
        hashes.try_reserve_exact(dependencies.len()).ok()?;
        for dependency in dependencies {
            let hash = match dependency {
                CapturedFreeVariableDependency::Slot { frame_index, slot } => {
                    let value = self.env_ref_value_at_index(env, frame_index, slot)?;
                    self.force_cache_free_var_value_hash(value)?
                }
                CapturedFreeVariableDependency::StaticHasAttr {
                    frame_index,
                    slot,
                    path,
                } => {
                    let receiver = self.env_ref_value_at_index(env, frame_index, slot)?;
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
                    let receiver = self.env_ref_value_at_index(env, frame_index, slot)?;
                    match default {
                        Some(default) => {
                            self.force_cache_static_select_default_value_hashes(
                                body.module(),
                                env,
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
                let mut hasher = CacheDigestHasher::new();
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
        env: EvalEnvRef<'_>,
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
                    self.captured_static_select_default_dependencies(module_id, env, default)?;
                for dependency in default_dependencies {
                    self.push_captured_free_variable_dependency_hash(
                        module_id,
                        env,
                        &dependency,
                        hashes,
                    )?;
                }
                Some(())
            }
            None => {
                hashes.push(self.force_cache_free_var_value_hash(receiver)?);
                let default_dependencies =
                    self.captured_static_select_default_dependencies(module_id, env, default)?;
                for dependency in default_dependencies {
                    self.push_captured_free_variable_dependency_hash(
                        module_id,
                        env,
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
        env: EvalEnvRef<'_>,
        default: &DefaultSelectDependency,
    ) -> Option<BTreeSet<CapturedFreeVariableDependency>> {
        let module = self.modules.get(module_id.index())?;
        Self::captured_free_variable_dependencies_from_with_static_scopes(
            &module.ir,
            IrId::new(default.node),
            env.frame_count(),
            default.nested_frame_count,
            &default.static_scopes,
        )
    }

    fn push_captured_free_variable_dependency_hash(
        &self,
        module_id: EvalModuleId,
        env: EvalEnvRef<'_>,
        dependency: &CapturedFreeVariableDependency,
        hashes: &mut Vec<ValueHash>,
    ) -> Option<()> {
        let hash = match dependency {
            CapturedFreeVariableDependency::Slot { frame_index, slot } => {
                let value = self.env_ref_value_at_index(env, *frame_index, *slot)?;
                self.force_cache_free_var_value_hash(value)?
            }
            CapturedFreeVariableDependency::StaticHasAttr {
                frame_index,
                slot,
                path,
            } => {
                let receiver = self.env_ref_value_at_index(env, *frame_index, *slot)?;
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
                let receiver = self.env_ref_value_at_index(env, *frame_index, *slot)?;
                if let Some(default) = default {
                    self.force_cache_static_select_default_value_hashes(
                        module_id,
                        env,
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
        let mut hasher = CacheDigestHasher::new();
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

    pub(super) fn force_cache_static_has_attr_value_hash(
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
        let mut hasher = CacheDigestHasher::new();
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
        let mut hasher = CacheDigestHasher::new();
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
        let thunk_key = value.address_identity_bits();
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
                let mut hasher = CacheDigestHasher::new();
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
                let mut hasher = CacheDigestHasher::new();
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
                let mut hasher = CacheDigestHasher::new();
                hasher.update(FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION);
                self.update_force_capture_composite_payload_hash(&mut hasher, &payload)?;
                self.cache_force_capture_hash(value, ForceCapturedValueHash::from_hasher(hasher))
            }
            ValueTag::Thunk => {
                let thunk_key = value.address_identity_bits();
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
        let thunk_key = value.address_identity_bits();
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
            dynamic_env,
        } = thunk.kind()
        else {
            return None;
        };
        if dynamic_env.is_some() {
            return None;
        }
        let module = self.modules.get(body.module().index())?;
        let node = module.ir.arena.node(body.id())?;
        let (depth, slot) = match node.data {
            IrData::Local { slot } => (0, slot),
            IrData::Upval { depth, slot } => {
                let depth = depth as usize;
                if depth >= env.frame_count() {
                    return None;
                }
                (depth, slot)
            }
            _ => return None,
        };
        self.captured_env_value_at_depth(env, depth, slot)
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
        if payload.scalar_value().is_some() {
            return payload.value_hash().ok();
        }

        let mut hasher = CacheDigestHasher::new();
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
        hasher: &mut CacheDigestHasher,
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
        hasher: &mut CacheDigestHasher,
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
}
