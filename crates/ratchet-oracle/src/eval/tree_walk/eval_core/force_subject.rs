//! Force-cache subject construction for thunks, selects, and builtin calls.
//!
//! Decides which forced expressions are cacheable and assembles their
//! [`ForceCacheSubject`] identities: pure/impure observation identities,
//! free-variable value hashes, and memoization admission hints. Includes the
//! first-class cacheable-impure-call classification for builtin executions.

use super::*;

impl TreeWalk {
    pub(in crate::eval::tree_walk) fn force_cache_subject_for_thunk(
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
                    replay_allocation_node: Some(*body),
                    memoization_admission,
                })
            }
            EvalThunkKind::BuiltinAttr { symbol, builtin } => {
                self.force_cache_subject_for_builtin_attr(site, *symbol, *builtin)
            }
            EvalThunkKind::Select {
                select,
                receiver,
                path,
            } => self.force_cache_subject_for_select(*select, *receiver, *path),
            // Force-cache subjects are computed while forcing a claimed thunk,
            // before its captures can be shed; a released kind has no work to
            // cache and admits nothing.
            EvalThunkKind::Apply { .. }
            | EvalThunkKind::Apply2 { .. }
            | EvalThunkKind::Released => None,
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

    fn force_cache_subject_for_select(
        &self,
        select: EvalNodeRef,
        receiver: Value,
        path: IrAttrPathId,
    ) -> Option<ForceCacheSubject> {
        let identity = self.cache_synthetic_select_identity(select, path)?;
        let selected_hash =
            self.force_cache_static_select_value_hash(select.module(), receiver, path)?;
        Some(ForceCacheSubject {
            lookup_identity: Some(identity),
            pure_observation_identity: Some(identity),
            impure_observation_identity: None,
            metadata_identity: Some(identity),
            persistent_clear_identity: Some(identity),
            free_var_value_hashes: vec![selected_hash],
            replay_position_module: None,
            replay_allocation_node: None,
            memoization_admission: ForceCacheMemoizationAdmission::SelectedSubstrate,
        })
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
            replay_allocation_node: None,
            memoization_admission: ForceCacheMemoizationAdmission::SelectedSubstrate,
        })
    }

    pub(in crate::eval::tree_walk) fn force_cache_subject_for_first_class_cacheable_impure_call(
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
        for (index, arg) in args.iter().enumerate() {
            free_var_value_hashes
                .push(self.force_cache_free_var_value_hash_for_primop_arg(builtin, index, arg)?);
        }
        Some(ForceCacheSubject {
            lookup_identity: Some(identity),
            pure_observation_identity: None,
            impure_observation_identity: Some(identity),
            metadata_identity: Some(identity),
            persistent_clear_identity: Some(identity),
            free_var_value_hashes,
            replay_position_module: None,
            replay_allocation_node: Some(EvalNodeRef::new(self.current_module, id)),
            memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
        })
    }

    fn force_cache_free_var_value_hash_for_primop_arg(
        &self,
        builtin: Builtin,
        index: usize,
        arg: &EvalPrimOpArg,
    ) -> Option<ValueHash> {
        if builtin.execution() == BuiltinExecution::FindFile && index == 0 {
            if let Some(hash) = self.force_cache_builtin_nix_path_arg_hash(arg.value()) {
                return Some(hash);
            }
        }
        if builtin.execution() == BuiltinExecution::FindFile {
            self.force_cache_free_var_value_hash(arg.value())
        } else {
            if Self::builtin_execution_allows_closed_alias_primop_arg(builtin.execution(), index)
                && let Some(hash) =
                    self.force_cache_closed_hash_for_suspended_capture_alias_target(arg.value())
            {
                return Some(hash);
            }
            self.force_cache_free_var_value_hash_without_suspended_aliases(arg.value())
        }
    }

    #[cfg(test)]
    pub(crate) fn test_first_class_primop_arg_hashes_for_current_apply(
        &mut self,
        id: IrId,
        builtin: Builtin,
    ) -> Option<Vec<ValueHash>> {
        let arity = builtin.first_class_arity()?;
        let mut argument_ids = Vec::new();
        let mut current = id;
        loop {
            let node = *self.node(current).ok()?;
            let IrData::Pair { first, second } = node.data else {
                return None;
            };
            argument_ids.push(second);
            let first_node = self.node(first).ok()?;
            if first_node.kind != IrKind::Apply {
                break;
            }
            current = first;
        }
        argument_ids.reverse();

        if argument_ids.len() == arity {
            let mut hashes = Vec::new();
            hashes.try_reserve_exact(argument_ids.len()).ok()?;
            for (index, argument_id) in argument_ids.iter().copied().enumerate() {
                let argument_span = self.node(argument_id).ok()?.span;
                let argument = self.eval_lazy_node(argument_id).ok()?;
                let argument = EvalPrimOpArg::new_in_module(
                    self.current_module,
                    argument_id,
                    argument_span,
                    argument,
                );
                hashes.push(
                    self.force_cache_free_var_value_hash_for_primop_arg(builtin, index, &argument)?,
                );
            }
            return Some(hashes);
        }

        if builtin.execution() != BuiltinExecution::FindFile || argument_ids.len() != 1 {
            return None;
        }
        let argument_id = argument_ids[0];
        let argument_span = self.node(argument_id).ok()?.span;
        let argument = self.eval_lazy_node(argument_id).ok()?;
        let argument =
            EvalPrimOpArg::new_in_module(self.current_module, argument_id, argument_span, argument);
        let mut hashes = Vec::new();
        hashes.try_reserve_exact(2).ok()?;
        hashes.push(self.force_cache_visible_nix_path_arg_hash()?);
        hashes.push(self.force_cache_free_var_value_hash_for_primop_arg(builtin, 1, &argument)?);
        Some(hashes)
    }

    fn force_cache_builtin_nix_path_arg_hash(&self, value: Value) -> Option<ValueHash> {
        let thunk = self.heap.get_thunk(value).ok()?;
        if !self.thunk_is_builtin_nix_path(thunk) {
            return None;
        }
        self.force_cache_visible_nix_path_arg_hash()
    }

    fn force_cache_visible_nix_path_arg_hash(&self) -> Option<ValueHash> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION);
        hasher.update(b"synthetic-builtin-nix-path-v1");
        let len = u64::try_from(self.visible_nix_path().len()).ok()?;
        hasher.update(&len.to_le_bytes());
        for entry in self.visible_nix_path() {
            hasher.update(b"entry-prefix");
            Self::update_cache_identity_chunk(&mut hasher, entry.prefix())?;
            hasher.update(b"entry-path");
            Self::update_cache_identity_chunk(&mut hasher, entry.path())?;
        }
        Some(ValueHash::from_force_captured_value_hash(
            ForceCapturedValueHash::from_hasher(hasher),
        ))
    }

    fn thunk_is_builtin_nix_path(&self, thunk: &EvalThunk) -> bool {
        match thunk.kind() {
            EvalThunkKind::BuiltinAttr { builtin, .. } => {
                builtin.execution() == BuiltinExecution::NixPathValue
            }
            EvalThunkKind::Node { body, .. } => {
                let symbols = &self.symbols;
                self.modules
                    .get(body.module().index())
                    .is_some_and(|module| {
                        let Some(node) = module.ir.arena.node(body.id()) else {
                            return false;
                        };
                        node.kind == IrKind::BuiltinAttr
                            && Self::builtin_attr_execution(symbols, node)
                                == Some(BuiltinExecution::NixPathValue)
                    })
            }
            EvalThunkKind::Apply { .. }
            | EvalThunkKind::Apply2 { .. }
            | EvalThunkKind::Select { .. }
            | EvalThunkKind::Released => false,
        }
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
                } | BuiltinExecution::FindFile,
                2,
            )
        )
    }

    const fn builtin_execution_allows_closed_alias_primop_arg(
        execution: BuiltinExecution,
        index: usize,
    ) -> bool {
        matches!(
            (execution, index),
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
                0,
            ) | (
                BuiltinExecution::StrictBinary {
                    primop: StrictBinaryPrimOp::HashFile,
                    ..
                },
                0 | 1,
            )
        )
    }
}
