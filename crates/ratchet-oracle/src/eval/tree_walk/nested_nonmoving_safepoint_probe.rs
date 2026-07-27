//! Proof-only inventory for a nested nonmoving final-config safepoint.
//!
//! The runtime door selects one successful final-config completion ordinal.
//! At that completion this module builds a non-writeback root set, reconciles
//! the bounded mixed-force census, and reports every still-unrepresented state
//! class. It never traces, sweeps, retires, moves, advises, or mutates heap
//! storage.

use super::*;

const ORDINAL_ENV: &str = "AOS_NIX_NESTED_NONMOVING_PROOF_ORDINAL";

/// Counts roots added only for a proof-only nested nonmoving attempt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct NestedNonmovingRootInventory {
    /// Total roots in the resulting non-writeback set.
    pub(super) total_roots: usize,
    /// Whether the final-config result contributed a heap root.
    pub(super) result_roots: usize,
    /// Number of pending flat-closure values recorded.
    pub(super) pending_values: usize,
    /// Number of pending lexical frame slots recorded.
    pub(super) pending_env_values: usize,
    /// Number of pending flat-capture owners recorded.
    pub(super) pending_flat_owners: usize,
    /// Number of explicit native-continuation shadow values recorded.
    pub(super) native_shadow_values: usize,
}

/// Bounded process-local state for one selected proof attempt.
#[derive(Clone, Debug)]
pub(super) struct NestedNonmovingSafepointProbe {
    selected_ordinal: u64,
    completions: u64,
    attempts: u64,
    refusals: u64,
    snapshot: Option<NestedNonmovingProofSnapshot>,
}

impl NestedNonmovingSafepointProbe {
    /// Creates the probe only for one positive selected completion ordinal.
    pub(super) fn from_env() -> Option<Self> {
        let selected_ordinal = std::env::var(ORDINAL_ENV)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|ordinal| *ordinal != 0)?;
        Some(Self::new(selected_ordinal))
    }

    const fn new(selected_ordinal: u64) -> Self {
        Self {
            selected_ordinal,
            completions: 0,
            attempts: 0,
            refusals: 0,
            snapshot: None,
        }
    }
}

/// One selected completion's complete read-only proof inventory.
#[derive(Clone, Copy, Debug, Default)]
struct NestedNonmovingProofSnapshot {
    ordinal: u64,
    proof_refusal: bool,
    root_error: bool,
    roots: NestedNonmovingRootInventory,
    force: super::whole_demand_corridor_census::CorridorNonmovingProof,
    native: super::native_continuation_shadow::NativeContinuationSnapshot,
    combined_diagnostic_bytes: usize,
    unshadowed_native_continuation: usize,
    pending_flat_captures: usize,
    composite_accumulators: usize,
    order_sensitive_bindings: usize,
    primop_frames: usize,
    primop_roots: usize,
    call_argument_plans: usize,
    import_cache_leases: usize,
    import_module_leases: usize,
    force_leases: usize,
    lambda_leases: usize,
    typed_work: usize,
    stg_runtime: usize,
    stg_session: usize,
    shared_evaluation: usize,
    tier1: usize,
    force_cache: usize,
    memo_cache: usize,
    persistent_cache: usize,
    transient_roots: usize,
    active_env_frames: usize,
    suspended_envs: usize,
    call_depth: usize,
    ifd: usize,
    impure_inputs: usize,
    text_store_realizations: usize,
}

impl NestedNonmovingProofSnapshot {
    fn blocker_count(self) -> usize {
        usize::from(self.root_error)
            .saturating_add(usize::from(!self.force.reconciled()))
            .saturating_add(self.unshadowed_native_continuation)
            .saturating_add(usize::from(
                self.combined_diagnostic_bytes
                    > super::native_continuation_shadow::COMBINED_DIAGNOSTIC_CAP_BYTES,
            ))
            .saturating_add(self.composite_accumulators)
            .saturating_add(self.order_sensitive_bindings)
            .saturating_add(self.primop_frames)
            .saturating_add(self.primop_roots)
            .saturating_add(self.call_argument_plans)
            .saturating_add(self.import_cache_leases)
            .saturating_add(self.import_module_leases)
            .saturating_add(self.force_leases)
            .saturating_add(self.lambda_leases)
            .saturating_add(self.typed_work)
            .saturating_add(self.stg_runtime)
            .saturating_add(self.stg_session)
            .saturating_add(self.shared_evaluation)
            .saturating_add(self.tier1)
            .saturating_add(self.force_cache)
            .saturating_add(self.memo_cache)
            .saturating_add(self.persistent_cache)
    }
}

impl TreeWalk {
    /// Returns the exact non-root blocker count used by the completed nested
    /// nonmoving proof.
    pub(super) fn nested_nonmoving_runtime_blocker_count(&self) -> usize {
        let force = self
            .whole_demand_dispatcher
            .corridor_census
            .nonmoving_proof(
                self.active_force_roots.len(),
                self.active_force_leases.len(),
                self.active_typed_thunk_work_leases.len(),
            );
        let native = self.native_continuation_snapshot();
        let combined_diagnostic_bytes = self
            .whole_demand_dispatcher
            .modeled_storage_bytes()
            .saturating_add(native.modeled_storage_bytes);
        usize::from(!force.reconciled())
            .saturating_add(usize::from(!native.reconciled()))
            .saturating_add(usize::from(
                combined_diagnostic_bytes
                    > super::native_continuation_shadow::COMBINED_DIAGNOSTIC_CAP_BYTES,
            ))
            .saturating_add(self.active_composite_accumulator_depth)
            .saturating_add(self.order_sensitive_binding_depth)
            .saturating_add(self.active_primop_arg_frames.len())
            .saturating_add(self.active_primop_arg_roots.len())
            .saturating_add(self.active_call_argument_plans.len())
            .saturating_add(self.active_import_cache_leases.len())
            .saturating_add(self.active_import_module_leases.len())
            .saturating_add(self.active_force_leases.len())
            .saturating_add(self.active_lambda_call_leases.len())
            .saturating_add(self.active_typed_thunk_work_leases.len())
            .saturating_add(usize::from(!self.stg_apply_runtime.is_idle()))
            .saturating_add(usize::from(self.stg_session_active))
            .saturating_add(usize::from(self.shared.is_some()))
            .saturating_add(usize::from(self.tier1_engine.is_some()))
            .saturating_add(usize::from(self.force_cache_active))
            .saturating_add(usize::from(
                self.options.memo_active() || self.options.boundary_memo_active(),
            ))
            .saturating_add(usize::from(
                self.persist_cache.is_some()
                    || !self.persist_secondary_caches.is_empty()
                    || self.options.persist_cache_root().is_some(),
            ))
    }

    /// Inventories one selected final-config completion without collecting.
    pub(super) fn note_nested_nonmoving_final_config_completion(&mut self, result: Value) {
        let Some(probe) = self.nested_nonmoving_safepoint_probe.as_mut() else {
            return;
        };
        probe.completions = probe.completions.saturating_add(1);
        let ordinal = probe.completions;
        if ordinal != probe.selected_ordinal || probe.snapshot.is_some() {
            return;
        }

        let force = self
            .whole_demand_dispatcher
            .corridor_census
            .nonmoving_proof(
                self.active_force_roots.len(),
                self.active_force_leases.len(),
                self.active_typed_thunk_work_leases.len(),
            );
        let roots = self.nested_nonmoving_root_set(result);
        let (roots, root_error) = match roots {
            Ok((_, inventory)) => (inventory, false),
            Err(_) => (NestedNonmovingRootInventory::default(), true),
        };
        let runtime = &self.whole_demand_dispatcher;
        let native = self.native_continuation_snapshot();
        let combined_diagnostic_bytes = runtime
            .modeled_storage_bytes()
            .saturating_add(native.modeled_storage_bytes);
        let mut snapshot = NestedNonmovingProofSnapshot {
            ordinal,
            proof_refusal: false,
            root_error,
            roots,
            force,
            native,
            combined_diagnostic_bytes,
            // This first slice deliberately refuses until every active central
            // recursive edge has a semantic permit and all shadow invariants
            // reconcile. Generic oracle depth alone is no longer treated as
            // evidence that the native locals are represented.
            unshadowed_native_continuation: usize::from(!native.reconciled()),
            pending_flat_captures: self.pending_flat_captures.len(),
            composite_accumulators: self.active_composite_accumulator_depth,
            order_sensitive_bindings: self.order_sensitive_binding_depth,
            primop_frames: self.active_primop_arg_frames.len(),
            primop_roots: self.active_primop_arg_roots.len(),
            call_argument_plans: self.active_call_argument_plans.len(),
            import_cache_leases: self.active_import_cache_leases.len(),
            import_module_leases: self.active_import_module_leases.len(),
            force_leases: self.active_force_leases.len(),
            lambda_leases: self.active_lambda_call_leases.len(),
            typed_work: self.active_typed_thunk_work_leases.len(),
            stg_runtime: usize::from(!self.stg_apply_runtime.is_idle()),
            stg_session: usize::from(self.stg_session_active),
            shared_evaluation: usize::from(self.shared.is_some()),
            tier1: usize::from(self.tier1_engine.is_some()),
            force_cache: usize::from(self.force_cache_active),
            memo_cache: usize::from(
                self.options.memo_active() || self.options.boundary_memo_active(),
            ),
            persistent_cache: usize::from(
                self.persist_cache.is_some()
                    || !self.persist_secondary_caches.is_empty()
                    || self.options.persist_cache_root().is_some(),
            ),
            transient_roots: self.transient_value_stack_roots.len(),
            active_env_frames: self.env.len(),
            suspended_envs: self.suspended_env_roots.len(),
            call_depth: self.call_depth,
            ifd: usize::from(self.ifd_realizer.is_some()),
            impure_inputs: self.impure_input_trace.len(),
            text_store_realizations: self.text_store.len(),
        };
        snapshot.proof_refusal =
            snapshot.root_error || self.nested_nonmoving_runtime_blocker_count() != 0;
        debug_assert_eq!(snapshot.proof_refusal, snapshot.blocker_count() != 0);
        if let Some(shadow) = self.native_continuation_shadow.as_ref() {
            shadow.emit_selected_active_frames(ordinal);
        }

        let Some(probe) = self.nested_nonmoving_safepoint_probe.as_mut() else {
            return;
        };
        probe.attempts = probe.attempts.saturating_add(1);
        if snapshot.proof_refusal {
            probe.refusals = probe.refusals.saturating_add(1);
        }
        probe.snapshot = Some(snapshot);
    }

    /// Emits completion conservation and the selected proof refusal.
    pub(super) fn emit_nested_nonmoving_safepoint_probe_report(&self) {
        let Some(probe) = self.nested_nonmoving_safepoint_probe.as_ref() else {
            return;
        };
        if let Some(snapshot) = probe.snapshot {
            eprintln!(
                "aos_nix_nested_nonmoving_proof_attempt \
                 ordinal={} proof_refusal={} blockers={} root_error={} \
                 roots={} result_roots={} pending_flat_captures={} \
                 pending_values={} pending_env_values={} pending_flat_owners={} \
                 native_shadow_values={} \
                 unshadowed_native_continuation={} composite_accumulators={} \
                 order_sensitive_bindings={} primop_frames={} primop_roots={} \
                 call_argument_plans={} import_cache_leases={} import_module_leases={} \
                 force_leases={} lambda_leases={} typed_work={} stg_runtime={} \
                 stg_session={} shared={} tier1={} force_cache={} memo_cache={} \
                 persistent_cache={} transient_roots={} active_env_frames={} \
                 suspended_envs={} call_depth={} ifd={} impure_inputs={} \
                 text_store_realizations={} collection=false mutation=false",
                snapshot.ordinal,
                snapshot.proof_refusal,
                snapshot.blocker_count(),
                snapshot.root_error,
                snapshot.roots.total_roots,
                snapshot.roots.result_roots,
                snapshot.pending_flat_captures,
                snapshot.roots.pending_values,
                snapshot.roots.pending_env_values,
                snapshot.roots.pending_flat_owners,
                snapshot.roots.native_shadow_values,
                snapshot.unshadowed_native_continuation,
                snapshot.composite_accumulators,
                snapshot.order_sensitive_bindings,
                snapshot.primop_frames,
                snapshot.primop_roots,
                snapshot.call_argument_plans,
                snapshot.import_cache_leases,
                snapshot.import_module_leases,
                snapshot.force_leases,
                snapshot.lambda_leases,
                snapshot.typed_work,
                snapshot.stg_runtime,
                snapshot.stg_session,
                snapshot.shared_evaluation,
                snapshot.tier1,
                snapshot.force_cache,
                snapshot.memo_cache,
                snapshot.persistent_cache,
                snapshot.transient_roots,
                snapshot.active_env_frames,
                snapshot.suspended_envs,
                snapshot.call_depth,
                snapshot.ifd,
                snapshot.impure_inputs,
                snapshot.text_store_realizations,
            );
            eprintln!(
                "aos_nix_native_continuation_shadow \
                 active_frames={} active_overflow_frames={} active_roots={} covered_frames={} \
                 uncovered_active={} uncovered_entries={} imbalances={} overflows={} \
                 active_primop_contexts={} primop_context_coalesced_entries={} \
                 primop_context_overflows={} \
                 primop_context_module_mismatches={} \
                 modeled_storage_bytes={} storage_cap_bytes={} \
                 combined_diagnostic_bytes={} combined_cap_bytes={} reconciled={}",
                snapshot.native.active_frames,
                snapshot.native.active_overflow_frames,
                snapshot.native.active_roots,
                snapshot.native.covered_frames,
                snapshot.native.uncovered_active,
                snapshot.native.uncovered_entries,
                snapshot.native.imbalances,
                snapshot.native.overflows,
                snapshot.native.active_primop_contexts,
                snapshot.native.primop_context_coalesced_entries,
                snapshot.native.primop_context_overflows,
                snapshot.native.primop_context_module_mismatches,
                snapshot.native.modeled_storage_bytes,
                snapshot.native.storage_cap_bytes,
                snapshot.combined_diagnostic_bytes,
                super::native_continuation_shadow::COMBINED_DIAGNOSTIC_CAP_BYTES,
                snapshot.native.reconciled(),
            );
            eprintln!(
                "aos_nix_nested_nonmoving_force_proof \
                 session_active={} outer_active={} failed_closed={} \
                 coordinates={} owners={} expected_roots={} actual_roots={} \
                 expected_leases={} actual_leases={} expected_typed={} actual_typed={} \
                 unstable_coordinates={} nonordinary_flags={} nonordinary_owners={} \
                 reconciled={}",
                snapshot.force.session_active,
                snapshot.force.outer_active,
                snapshot.force.failed_closed,
                snapshot.force.coordinates,
                snapshot.force.owners,
                snapshot.force.expected_roots,
                snapshot.force.actual_roots,
                snapshot.force.expected_leases,
                snapshot.force.actual_leases,
                snapshot.force.expected_typed,
                snapshot.force.actual_typed,
                snapshot.force.unstable_coordinates,
                snapshot.force.nonordinary_flags,
                snapshot.force.nonordinary_owners,
                snapshot.force.reconciled(),
            );
        }
        eprintln!(
            "aos_nix_nested_nonmoving_proof_refusal \
             selected_ordinal={} completions={} attempts={} refusals={} \
             selected_observed={} conserved={} collection=false mutation=false",
            probe.selected_ordinal,
            probe.completions,
            probe.attempts,
            probe.refusals,
            probe.snapshot.is_some(),
            probe.attempts <= 1 && probe.refusals <= probe.attempts,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lower(source: &str) -> crate::compile::Ir {
        aos_nix_dialect::nix_lower(
            crate::compile::resolve(crate::syntax::parse_str(source).expect("source parses"))
                .expect("source resolves"),
        )
        .expect("source lowers")
    }

    #[test]
    fn positive_ordinal_selects_exactly_one_completion() {
        let mut probe = NestedNonmovingSafepointProbe::new(3);
        probe.completions = 3;
        probe.attempts = 1;
        probe.refusals = 1;
        assert_eq!(probe.selected_ordinal, 3);
        assert_eq!(probe.completions, 3);
        assert_eq!(probe.attempts, 1);
        assert_eq!(probe.refusals, 1);
    }

    #[test]
    fn unshadowed_native_continuation_is_a_refusal() {
        let snapshot = NestedNonmovingProofSnapshot {
            unshadowed_native_continuation: 1,
            ..NestedNonmovingProofSnapshot::default()
        };
        assert_ne!(snapshot.blocker_count(), 0);
    }

    #[test]
    fn ordinary_reconciled_force_stack_is_not_itself_a_blocker() {
        let snapshot = NestedNonmovingProofSnapshot {
            force: super::super::whole_demand_corridor_census::CorridorNonmovingProof {
                session_active: true,
                outer_active: true,
                coordinates: 2,
                owners: 2,
                expected_roots: 2,
                actual_roots: 2,
                ..super::super::whole_demand_corridor_census::CorridorNonmovingProof::default()
            },
            ..NestedNonmovingProofSnapshot::default()
        };
        assert_eq!(snapshot.blocker_count(), 0);
    }

    #[test]
    fn every_unenumerated_state_class_refuses() {
        let snapshots = [
            NestedNonmovingProofSnapshot {
                composite_accumulators: 1,
                ..NestedNonmovingProofSnapshot::default()
            },
            NestedNonmovingProofSnapshot {
                order_sensitive_bindings: 1,
                ..NestedNonmovingProofSnapshot::default()
            },
            NestedNonmovingProofSnapshot {
                call_argument_plans: 1,
                ..NestedNonmovingProofSnapshot::default()
            },
            NestedNonmovingProofSnapshot {
                typed_work: 1,
                ..NestedNonmovingProofSnapshot::default()
            },
            NestedNonmovingProofSnapshot {
                shared_evaluation: 1,
                ..NestedNonmovingProofSnapshot::default()
            },
            NestedNonmovingProofSnapshot {
                force_cache: 1,
                ..NestedNonmovingProofSnapshot::default()
            },
        ];
        assert!(
            snapshots
                .into_iter()
                .all(|snapshot| snapshot.blocker_count() != 0)
        );
    }

    #[test]
    fn nonwriteback_roots_include_result_value() {
        let ir = lower("null");
        let mut evaluator = TreeWalk::new(&ir);
        let result = evaluator
            .heap
            .alloc_string(NixString::from_bytes(b"nested-result".to_vec()))
            .expect("result allocates");
        let (roots, inventory) = evaluator
            .nested_nonmoving_root_set(result)
            .expect("nonmoving roots build");
        assert_eq!(inventory.result_roots, 1);
        assert!(roots.roots().iter().any(|root| root.value().raw_eq(result)));
    }

    #[test]
    fn nonwriteback_roots_include_pending_value_env_and_flat_owner() {
        let mut ir = lower("let captured = \"flat\"; in x: captured");
        crate::compile::annotate_ir(&mut ir).expect("analysis succeeds");
        let mut evaluator = TreeWalk::new(&ir);
        let closure = evaluator.eval_root().expect("closure evaluates");
        let lambda = evaluator.heap.clone_lambda(closure).expect("lambda clones");
        let flat_env = lambda.env().clone();
        let tail = flat_env
            .flat_base()
            .expect("closure has a flat capture")
            .tail_handle();

        let env_value = evaluator
            .heap
            .alloc_string(NixString::from_bytes(b"pending-env".to_vec()))
            .expect("environment value allocates");
        let frame = EvalFrame::new(1).expect("frame allocates");
        frame.set(0, env_value).expect("frame value sets");
        let framed_env = EvalEnv::capture(&[frame]).expect("environment captures");
        let site = EvalNodeRef::new(EvalModuleId::ROOT, ir.root);
        evaluator.test_push_pending_flat_capture(site, closure, tail, framed_env);
        evaluator.test_push_pending_flat_capture(site, closure, tail, flat_env);

        let (roots, inventory) = evaluator
            .nested_nonmoving_root_set(closure)
            .expect("nonmoving roots build");
        assert_eq!(inventory.pending_values, 2);
        assert!(inventory.pending_env_values >= 1);
        assert!(inventory.pending_flat_owners >= 1);
        assert!(
            roots
                .roots()
                .iter()
                .any(|root| root.value().raw_eq(env_value))
        );
        assert!(
            roots
                .roots()
                .iter()
                .any(|root| root.value().raw_eq(closure))
        );
    }
}
