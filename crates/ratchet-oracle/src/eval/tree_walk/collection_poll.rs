//! No-collection preflight for a future explicit dispatcher safepoint.
//!
//! The current recursive tree walker has no mid-evaluation point where native
//! Rust continuations are completely represented by mutable evaluator-owned
//! storage. This module therefore exposes an idle-only preflight plus a
//! default-disabled coverage skeleton that calls the dispatcher-specific
//! proof only at its outer loop heads. The skeleton does not substitute
//! execution or collect; future target-directed continuations must spill every
//! live value before they can turn a covered loop head into a safepoint.
//!
//! A successful [`CollectionPollGuard`] owns an exact mutator-root snapshot and
//! proves that every enumerated root source reads back the snapshotted value and
//! has one mutable writeback target. It does not trace, move, retire, advise, or
//! otherwise mutate heap storage.

use super::*;

// The runtime door intentionally has no reader until a true dispatcher seam
// exists; retaining its exact spelling here keeps that future integration local.
#[allow(dead_code)]
const COLLECTION_POLL_ENV: &str = "AOS_NIX_COLLECTION_POLL_GUARD";

/// Evaluator state that prevents an exact moving-collection poll.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::eval) enum CollectionPollUnsafeState {
    /// A recursive Rust evaluator call is still active.
    NativeRecursiveContinuation,
    /// Root evaluation still owns a native continuation.
    RootEvaluation,
    /// The active lexical environment is not empty.
    ActiveEnvironment,
    /// An active inline-capture owner remains installed.
    ActiveFlatEnvironment,
    /// Dynamic `with` scopes remain active.
    ActiveWithScopes,
    /// Scoped-import globals remain active.
    ActiveScopedGlobals,
    /// Caller-owned transient value roots remain live.
    TransientValueRoots,
    /// Recursive force-continuation roots remain live.
    ForceContinuationRoots,
    /// First-class primop argument frames remain active.
    PrimopArgumentFrames,
    /// First-class primop argument roots remain active.
    PrimopArgumentRoots,
    /// Recursive evaluator environments remain suspended.
    SuspendedEnvironments,
    /// A memo read retains native traversal state.
    MemoReadNodes,
    /// Flat captures await their publication boundary.
    PendingFlatCaptures,
    /// A call-argument plan remains active.
    CallArgumentPlans,
    /// Composite construction retains native accumulator state.
    CompositeAccumulator,
    /// Order-sensitive binding assembly remains active.
    OrderSensitiveBinding,
    /// An import-cache miss lease remains active.
    ImportCacheLeases,
    /// An imported-module context lease remains active.
    ImportModuleLeases,
    /// An ordinary thunk force lease remains active.
    ForceLeases,
    /// Detached typed-thunk work remains outside its stable head.
    TypedThunkWorkLeases,
    /// A lambda-call context lease remains active.
    LambdaCallLeases,
    /// The packed STG runtime has not reached a declared suspended poll.
    StgRuntime,
    /// The session evaluator still owns control.
    StgSession,
    /// GC-stress accumulator allocation retains a native local.
    GcStressAccumulator,
    /// GC-stress primop argument admission retains caller-owned roots.
    GcStressPrimopAdmission,
    /// A derivation trace cursor remains active.
    DerivationTraceCursors,
    /// The remembered set has not been reconciled for moving publication.
    RememberedSet,
    /// The card table still contains dirty source cards.
    CardTable,
    /// Parallel evaluation shares heap state with other mutators.
    SharedEvaluation,
}

/// A structured reason why no collection poll guard was produced.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub(in crate::eval) enum CollectionPollDecline {
    /// The compile-time probe exists, but its runtime door is closed.
    #[allow(dead_code)]
    #[error("collection-poll guard is disabled")]
    Disabled,
    /// Unsafe evaluator-owned state remains live.
    #[error("collection-poll guard rejected {state:?} ({active} active)")]
    UnsafeState {
        /// The state class that prevents an exact poll.
        state: CollectionPollUnsafeState,
        /// The number of active entries, or one for a boolean condition.
        active: usize,
    },
    /// Exact mutator roots could not be enumerated.
    #[error("collection-poll root enumeration failed: {0}")]
    RootEnumeration(#[from] TreeWalkSafepointRootError),
    /// Enumerated roots did not form a readable, writable source bijection.
    #[error("collection-poll root/writeback bijection failed: {0}")]
    RootBijection(#[from] TreeWalkSafepointRootWritebackError),
}

/// A no-collection proof token for one exact evaluator state.
#[derive(Debug)]
pub(in crate::eval) struct CollectionPollGuard {
    roots: EvalRootSet,
}

impl CollectionPollGuard {
    /// Returns the exact mutator roots verified by the preflight.
    pub(in crate::eval) const fn roots(&self) -> &EvalRootSet {
        &self.roots
    }

    /// Returns the number of verified mutable root sources.
    pub(in crate::eval) fn root_count(&self) -> usize {
        self.roots.len()
    }

    /// Consumes the proof token and returns its exact writable root snapshot.
    ///
    /// A moving-publication transaction takes ownership of this snapshot so
    /// the coordinates it prevalidates are the same coordinates it later
    /// rewrites. Re-enumerating roots after destination construction would
    /// weaken that bijection.
    pub(in crate::eval) fn into_roots(self) -> EvalRootSet {
        self.roots
    }
}

impl TreeWalk {
    /// Proves one suspended whole-demand dispatcher loop head.
    ///
    /// Unlike the idle-only preflight, this admits evaluator-owned lexical
    /// roots and continuation leases after validating their exact token
    /// bijection. It still performs no collection or mutation.
    pub(in crate::eval) fn dispatcher_collection_poll_preflight(
        &self,
    ) -> Result<CollectionPollGuard, CollectionPollDecline> {
        self.dispatcher_collection_poll_structure_preflight()?;
        let roots = self.mutator_root_set()?;
        self.validate_collection_poll_root_bijection(&roots)?;
        Ok(CollectionPollGuard { roots })
    }

    /// Proves dispatcher loop-head structure without materializing roots.
    ///
    /// This is sufficient at loop heads that have no pending completion and
    /// therefore cannot poll for collection. Rooted candidate polls use
    /// [`Self::dispatcher_collection_poll_preflight`] instead.
    pub(in crate::eval) fn dispatcher_collection_poll_structure_preflight(
        &self,
    ) -> Result<(), CollectionPollDecline> {
        let runtime = &self.whole_demand_dispatcher;
        let unsafe_state = if !runtime
            .loop_head_structure_matches(self.transient_value_stack_roots.len())
        {
            Some((CollectionPollUnsafeState::StgSession, 1))
        } else if !runtime.ownership_matches(
            &self.active_force_leases,
            &self.active_lambda_call_leases,
            &self.active_import_module_leases,
        ) {
            Some((CollectionPollUnsafeState::ForceLeases, 1))
        } else if self.active_force_roots.len() != self.active_force_leases.len().saturating_mul(2)
        {
            Some((
                CollectionPollUnsafeState::ForceContinuationRoots,
                self.active_force_roots.len(),
            ))
        } else if runtime
            .value_slots
            .iter()
            .any(|slot| *slot >= self.transient_value_stack_roots.len())
        {
            Some((
                CollectionPollUnsafeState::TransientValueRoots,
                runtime.value_slots.len(),
            ))
        } else if self.call_depth != self.active_lambda_call_leases.len() {
            Some((
                CollectionPollUnsafeState::LambdaCallLeases,
                self.active_lambda_call_leases.len(),
            ))
        } else {
            [
                (
                    CollectionPollUnsafeState::PrimopArgumentFrames,
                    self.active_primop_arg_frames.len(),
                ),
                (
                    CollectionPollUnsafeState::PrimopArgumentRoots,
                    self.active_primop_arg_roots.len(),
                ),
                (
                    CollectionPollUnsafeState::MemoReadNodes,
                    self.active_memo_read_nodes.len(),
                ),
                (
                    CollectionPollUnsafeState::PendingFlatCaptures,
                    self.pending_flat_captures.len(),
                ),
                (
                    CollectionPollUnsafeState::CallArgumentPlans,
                    self.active_call_argument_plans.len(),
                ),
                (
                    CollectionPollUnsafeState::CompositeAccumulator,
                    self.active_composite_accumulator_depth,
                ),
                (
                    CollectionPollUnsafeState::OrderSensitiveBinding,
                    self.order_sensitive_binding_depth,
                ),
                (
                    CollectionPollUnsafeState::ImportCacheLeases,
                    self.active_import_cache_leases.len(),
                ),
                (
                    CollectionPollUnsafeState::TypedThunkWorkLeases,
                    self.active_typed_thunk_work_leases.len(),
                ),
                (
                    CollectionPollUnsafeState::StgRuntime,
                    usize::from(!self.stg_apply_runtime.is_idle()),
                ),
                (
                    CollectionPollUnsafeState::StgSession,
                    usize::from(self.stg_session_active),
                ),
                (
                    CollectionPollUnsafeState::GcStressAccumulator,
                    usize::from(self.active_gc_stress_accumulator_allocation_node.is_some()),
                ),
                (
                    CollectionPollUnsafeState::GcStressPrimopAdmission,
                    self.active_gc_stress_primop_arg_root_admission_depth,
                ),
                (
                    CollectionPollUnsafeState::DerivationTraceCursors,
                    self.active_derivation_trace_cursors.len(),
                ),
                (
                    CollectionPollUnsafeState::RememberedSet,
                    self.thunk_resolve_remembered_set.len(),
                ),
                (
                    CollectionPollUnsafeState::CardTable,
                    self.thunk_resolve_card_table.len(),
                ),
                (
                    CollectionPollUnsafeState::SharedEvaluation,
                    usize::from(self.shared.is_some()),
                ),
            ]
            .into_iter()
            .find(|(_, active)| *active != 0)
        };
        if let Some((state, active)) = unsafe_state {
            return Err(CollectionPollDecline::UnsafeState { state, active });
        }
        Ok(())
    }

    /// Attempts the default-disabled no-collection dispatcher preflight.
    ///
    /// This idle-only method has deliberately no production call site. The
    /// coverage skeleton uses [`Self::dispatcher_collection_poll_preflight`]
    /// instead.
    ///
    /// # Errors
    ///
    /// Returns [`CollectionPollDecline`] when the environment door is closed,
    /// unsafe evaluator state remains, roots cannot be enumerated, or root
    /// readback/writeback is not bijective.
    #[allow(dead_code)]
    pub(in crate::eval) fn maybe_collection_poll_guard(
        &self,
    ) -> Result<CollectionPollGuard, CollectionPollDecline> {
        if !collection_poll_enabled(std::env::var_os(COLLECTION_POLL_ENV).as_deref()) {
            return Err(CollectionPollDecline::Disabled);
        }
        self.collection_poll_preflight()
    }

    /// Runs the no-collection preflight without consulting the runtime door.
    ///
    /// This separation lets focused tests exercise the proof without mutating
    /// process-global environment state. It remains unavailable unless the
    /// compile-time `collection_poll_probe` feature is enabled.
    ///
    /// # Errors
    ///
    /// Returns [`CollectionPollDecline`] for unsafe evaluator state, root
    /// enumeration failure, or a non-bijective root/writeback mapping.
    pub(in crate::eval) fn collection_poll_preflight(
        &self,
    ) -> Result<CollectionPollGuard, CollectionPollDecline> {
        if let Some((state, active)) = first_unsafe_state(self.collection_poll_states()) {
            return Err(CollectionPollDecline::UnsafeState { state, active });
        }
        let roots = self.mutator_root_set()?;
        self.validate_collection_poll_root_bijection(&roots)?;
        Ok(CollectionPollGuard { roots })
    }

    fn collection_poll_states(&self) -> [(CollectionPollUnsafeState, usize); 29] {
        use CollectionPollUnsafeState as State;
        [
            (State::NativeRecursiveContinuation, self.call_depth),
            (
                State::RootEvaluation,
                usize::from(self.active_root_eval_node.is_some()),
            ),
            (State::ActiveEnvironment, self.env.len()),
            (
                State::ActiveFlatEnvironment,
                usize::from(self.flat_env.is_some()),
            ),
            (State::ActiveWithScopes, self.with_scopes.len()),
            (State::ActiveScopedGlobals, self.scoped_globals.len()),
            (
                State::TransientValueRoots,
                self.transient_value_stack_roots.len(),
            ),
            (State::ForceContinuationRoots, self.active_force_roots.len()),
            (
                State::PrimopArgumentFrames,
                self.active_primop_arg_frames.len(),
            ),
            (
                State::PrimopArgumentRoots,
                self.active_primop_arg_roots.len(),
            ),
            (State::SuspendedEnvironments, self.suspended_env_roots.len()),
            (State::MemoReadNodes, self.active_memo_read_nodes.len()),
            (State::PendingFlatCaptures, self.pending_flat_captures.len()),
            (
                State::CallArgumentPlans,
                self.active_call_argument_plans.len(),
            ),
            (
                State::CompositeAccumulator,
                self.active_composite_accumulator_depth,
            ),
            (
                State::OrderSensitiveBinding,
                self.order_sensitive_binding_depth,
            ),
            (
                State::ImportCacheLeases,
                self.active_import_cache_leases.len(),
            ),
            (
                State::ImportModuleLeases,
                self.active_import_module_leases.len(),
            ),
            (State::ForceLeases, self.active_force_leases.len()),
            (
                State::TypedThunkWorkLeases,
                self.active_typed_thunk_work_leases.len(),
            ),
            (
                State::LambdaCallLeases,
                self.active_lambda_call_leases.len(),
            ),
            (
                State::StgRuntime,
                usize::from(!self.stg_apply_runtime.is_idle()),
            ),
            (State::StgSession, usize::from(self.stg_session_active)),
            (
                State::GcStressAccumulator,
                usize::from(self.active_gc_stress_accumulator_allocation_node.is_some()),
            ),
            (
                State::GcStressPrimopAdmission,
                self.active_gc_stress_primop_arg_root_admission_depth,
            ),
            (
                State::DerivationTraceCursors,
                self.active_derivation_trace_cursors.len(),
            ),
            (
                State::RememberedSet,
                self.thunk_resolve_remembered_set.len(),
            ),
            (State::CardTable, self.thunk_resolve_card_table.len()),
            (State::SharedEvaluation, usize::from(self.shared.is_some())),
        ]
    }
}

fn collection_poll_enabled(setting: Option<&std::ffi::OsStr>) -> bool {
    setting.is_some_and(|value| value == "1")
}

fn first_unsafe_state<const N: usize>(
    states: [(CollectionPollUnsafeState, usize); N],
) -> Option<(CollectionPollUnsafeState, usize)> {
    states.into_iter().find(|(_, active)| *active != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::resolve as resolve_ast;
    use crate::syntax::parse_str;

    fn evaluator(source: &str) -> TreeWalk {
        let parsed = parse_str(source).expect("source parses");
        let resolved = resolve_ast(parsed).expect("source resolves");
        let ir = aos_nix_dialect::nix_lower(resolved).expect("source lowers");
        TreeWalk::with_options(&ir, TreeWalkOptions::default())
    }

    #[test]
    fn runtime_door_requires_exact_one_without_touching_process_environment() {
        assert!(!collection_poll_enabled(None));
        assert!(!collection_poll_enabled(Some(std::ffi::OsStr::new("0"))));
        assert!(!collection_poll_enabled(Some(std::ffi::OsStr::new("true"))));
        assert!(collection_poll_enabled(Some(std::ffi::OsStr::new("1"))));
    }

    #[test]
    fn clean_idle_evaluator_produces_an_empty_bijective_guard() {
        let evaluator = evaluator("1");
        let guard = evaluator
            .collection_poll_preflight()
            .expect("idle evaluator has a complete empty root set");
        assert_eq!(guard.root_count(), 0);
        assert!(guard.roots().is_empty());
    }

    #[test]
    fn ready_import_cache_root_is_readable_and_writable() {
        let mut evaluator = evaluator("1");
        let value = evaluator
            .heap
            .alloc_string(NixString::from_bytes(b"ready".to_vec()))
            .expect("root value allocates");
        evaluator.import_cache.insert(
            PathBuf::from("/poll-ready.nix"),
            ImportCacheEntry::Ready {
                value,
                trace: None,
                force_cache_trace_complete: true,
            },
        );

        let guard = evaluator
            .collection_poll_preflight()
            .expect("ready import root has exact read/write storage");
        assert_eq!(guard.root_count(), 1);
        assert!(matches!(
            guard.roots().roots()[0].source(),
            crate::eval::heap::EvalRootSource::ImportCache { index: 0 }
        ));
    }

    #[test]
    fn duplicate_and_unsupported_root_sources_fail_the_bijection() {
        let mut evaluator = evaluator("1");
        let value = evaluator
            .heap
            .alloc_string(NixString::from_bytes(b"root".to_vec()))
            .expect("root value allocates");
        evaluator.import_cache.insert(
            PathBuf::from("/duplicate.nix"),
            ImportCacheEntry::Ready {
                value,
                trace: None,
                force_cache_trace_complete: true,
            },
        );

        let mut duplicate = EvalRootSet::new();
        duplicate
            .try_push_import_cache(0, value)
            .expect("first root appends");
        duplicate
            .try_push_import_cache(0, value)
            .expect("duplicate root appends");
        assert!(matches!(
            evaluator.validate_collection_poll_root_bijection(&duplicate),
            Err(TreeWalkSafepointRootWritebackError::DuplicateSource { .. })
        ));

        let mut unsupported = EvalRootSet::new();
        unsupported
            .try_push_tree_walk_flat_capture(0, value)
            .expect("unsupported root appends");
        let error = evaluator
            .validate_collection_poll_root_bijection(&unsupported)
            .expect_err("flat-capture copy has no mutable writeback target");
        assert!(
            matches!(
                error,
                TreeWalkSafepointRootWritebackError::UnsupportedSource { .. }
            ),
            "{error:?}"
        );
    }

    #[test]
    fn every_unsafe_state_has_an_exact_structured_decline() {
        use CollectionPollUnsafeState as State;
        let states = [
            State::NativeRecursiveContinuation,
            State::RootEvaluation,
            State::ActiveEnvironment,
            State::ActiveFlatEnvironment,
            State::ActiveWithScopes,
            State::ActiveScopedGlobals,
            State::TransientValueRoots,
            State::ForceContinuationRoots,
            State::PrimopArgumentFrames,
            State::PrimopArgumentRoots,
            State::SuspendedEnvironments,
            State::MemoReadNodes,
            State::PendingFlatCaptures,
            State::CallArgumentPlans,
            State::CompositeAccumulator,
            State::OrderSensitiveBinding,
            State::ImportCacheLeases,
            State::ImportModuleLeases,
            State::ForceLeases,
            State::TypedThunkWorkLeases,
            State::LambdaCallLeases,
            State::StgRuntime,
            State::StgSession,
            State::GcStressAccumulator,
            State::GcStressPrimopAdmission,
            State::DerivationTraceCursors,
            State::RememberedSet,
            State::CardTable,
            State::SharedEvaluation,
        ];
        for state in states {
            assert_eq!(first_unsafe_state([(state, 1)]), Some((state, 1)));
        }
    }

    #[test]
    fn recursive_native_continuation_declines_before_root_enumeration() {
        let mut evaluator = evaluator("1");
        evaluator.call_depth = 1;
        assert!(matches!(
            evaluator.collection_poll_preflight(),
            Err(CollectionPollDecline::UnsafeState {
                state: CollectionPollUnsafeState::NativeRecursiveContinuation,
                active: 1,
            })
        ));
    }

    #[test]
    fn stg_owned_control_declines_until_a_real_suspended_poll_exists() {
        let mut evaluator = evaluator("1");
        evaluator.stg_apply_runtime.active = true;
        assert!(matches!(
            evaluator.collection_poll_preflight(),
            Err(CollectionPollDecline::UnsafeState {
                state: CollectionPollUnsafeState::StgRuntime,
                active: 1,
            })
        ));
    }

    #[test]
    fn transient_caller_owned_root_declines_even_though_it_is_enumerable() {
        let mut evaluator = evaluator("1");
        evaluator.transient_value_stack_roots.push(Value::int(1));
        assert!(matches!(
            evaluator.collection_poll_preflight(),
            Err(CollectionPollDecline::UnsafeState {
                state: CollectionPollUnsafeState::TransientValueRoots,
                active: 1,
            })
        ));
    }
}
