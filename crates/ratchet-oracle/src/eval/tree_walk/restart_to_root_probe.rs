//! Report-only eligibility falsifier for transactional restart at the API root.
//!
//! The probe samples exact callback-free final-config executions 160 and 192.
//! It asks whether a hypothetical private control signal could discard native
//! Rust continuations, run every evaluator-owned rollback in strict stack
//! order, and restart the whole pure demand from its API request. It never
//! signals, unwinds, rolls back, collects, or changes an evaluator value.

use super::*;

const ENABLE_ENV: &str = "AOS_NIX_RESTART_TO_ROOT_PROBE";
const SELECTED_EXECUTIONS: [usize; 2] = [160, 192];

/// One immutable snapshot of all restart eligibility doors.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RestartEligibilitySnapshot {
    execution: usize,
    pure_mode: bool,
    ifd_capable: bool,
    parallel_capable_or_active: bool,
    memo_or_persist_capable_or_active: bool,
    trace_events: usize,
    warning_events: usize,
    impure_input_events: usize,
    text_store_realizations: usize,
    source_store_realizations: usize,
    force_leases: usize,
    force_roots: usize,
    lambda_leases: usize,
    import_cache_leases: usize,
    import_module_leases: usize,
    typed_blackholes: usize,
    active_env_depth: usize,
    suspended_envs: usize,
    call_depth: usize,
    current_module_is_root: bool,
    pending_native_states: usize,
    terminal_root_present: bool,
}

impl RestartEligibilitySnapshot {
    /// Returns the cumulative observable-effect cursor at this epoch.
    const fn effect_cursor(self) -> usize {
        self.trace_events
            .saturating_add(self.warning_events)
            .saturating_add(self.impure_input_events)
            .saturating_add(self.text_store_realizations)
            .saturating_add(self.source_store_realizations)
    }

    /// Returns whether no observed or configured effect can be replayed.
    const fn effect_clean(self) -> bool {
        self.pure_mode
            && !self.ifd_capable
            && !self.parallel_capable_or_active
            && !self.memo_or_persist_capable_or_active
            && self.effect_cursor() == 0
    }

    /// Returns whether all blackholes and displaced contexts have cleanup owners.
    const fn rollback_owned(self) -> bool {
        self.force_roots == self.force_leases.saturating_mul(2)
            && self.typed_blackholes == 0
            && self.suspended_envs == self.lambda_leases.saturating_add(self.import_module_leases)
            && self.call_depth == self.lambda_leases
            && (self.current_module_is_root || self.import_module_leases != 0)
            && (self.active_env_depth == 0
                || self.lambda_leases != 0
                || self.import_module_leases != 0)
            && self.pending_native_states == 0
    }

    /// Returns the hard admission result for a report-only restart experiment.
    const fn eligible(self) -> bool {
        self.effect_clean() && self.rollback_owned() && self.terminal_root_present
    }
}

/// Per-evaluator state for the two-epoch falsifier.
#[derive(Debug, Default)]
pub(super) struct RestartToRootProbe {
    completions: usize,
    snapshots: [Option<RestartEligibilitySnapshot>; 2],
}

impl RestartToRootProbe {
    /// Opens the probe only for the exact default-off environment door.
    pub(super) fn from_env() -> Option<Self> {
        std::env::var(ENABLE_ENV)
            .is_ok_and(|value| value == "1")
            .then(Self::default)
    }

    fn selected_slot(execution: usize) -> Option<usize> {
        SELECTED_EXECUTIONS
            .iter()
            .position(|selected| *selected == execution)
    }
}

impl TreeWalk {
    /// Samples one callback-free final-config completion without changing it.
    pub(super) fn note_restart_to_root_final_config_completion(&mut self) {
        let execution = match self.restart_to_root_probe.as_mut() {
            Some(probe) => {
                probe.completions = probe.completions.saturating_add(1);
                probe.completions
            }
            None => return,
        };
        let Some(slot) = RestartToRootProbe::selected_slot(execution) else {
            return;
        };

        let pending_native_states = self
            .active_memo_read_nodes
            .len()
            .saturating_add(self.pending_flat_captures.len())
            .saturating_add(self.active_call_argument_plans.len())
            .saturating_add(self.active_composite_accumulator_depth)
            .saturating_add(self.order_sensitive_binding_depth)
            .saturating_add(self.active_primop_arg_frames.len())
            .saturating_add(self.active_primop_arg_roots.len())
            .saturating_add(self.transient_value_stack_roots.len())
            .saturating_add(self.active_derivation_trace_cursors.len())
            .saturating_add(self.persist_force_cache_hit_keys.len())
            .saturating_add(usize::from(!self.stg_apply_runtime.is_idle()))
            .saturating_add(usize::from(self.stg_session_active))
            .saturating_add(usize::from(
                self.active_gc_stress_accumulator_allocation_node.is_some(),
            ))
            .saturating_add(self.active_gc_stress_primop_arg_root_admission_depth);
        let parallel_capable_or_active = self.options.parallel_workers().is_some()
            || self.options.parallel_thunk_payloads_enabled()
            || self.shared.is_some();
        let memo_or_persist_capable_or_active = self.options.memo_active()
            || !self.options.memo_disk_locations().is_empty()
            || self.options.memo_net().is_some()
            || self.options.persist_cache_root().is_some()
            || self.force_cache_active
            || self.persist_cache.is_some()
            || !self.persist_secondary_caches.is_empty();
        let snapshot = RestartEligibilitySnapshot {
            execution,
            pure_mode: self.options.eval_mode() == EvalMode::Pure,
            ifd_capable: self.ifd_realizer.is_some(),
            parallel_capable_or_active,
            memo_or_persist_capable_or_active,
            trace_events: self.trace_output.len(),
            warning_events: self.warning_output.len(),
            impure_input_events: self.impure_input_trace.len(),
            text_store_realizations: self.text_store.len(),
            source_store_realizations: self.source_store_string_cache.len(),
            force_leases: self.active_force_leases.len(),
            force_roots: self.active_force_roots.len(),
            lambda_leases: self.active_lambda_call_leases.len(),
            import_cache_leases: self.active_import_cache_leases.len(),
            import_module_leases: self.active_import_module_leases.len(),
            typed_blackholes: self.active_typed_thunk_work_leases.len(),
            active_env_depth: self.env.len(),
            suspended_envs: self.suspended_env_roots.len(),
            call_depth: self.call_depth,
            current_module_is_root: self.current_module == EvalModuleId::ROOT,
            pending_native_states,
            terminal_root_present: self.active_root_eval_node.is_some(),
        };
        if let Some(probe) = self.restart_to_root_probe.as_mut() {
            probe.snapshots[slot] = Some(snapshot);
        }
    }

    /// Emits both epoch snapshots and the conjunctive hard-gate verdict.
    pub(super) fn emit_restart_to_root_probe_report(&self) {
        let Some(probe) = self.restart_to_root_probe.as_ref() else {
            return;
        };
        let sampled = probe.snapshots.iter().flatten().count();
        let both_eligible = sampled == SELECTED_EXECUTIONS.len()
            && probe
                .snapshots
                .iter()
                .flatten()
                .all(|snapshot| snapshot.eligible());
        for snapshot in probe.snapshots.iter().flatten() {
            eprintln!(
                "aos_nix_restart_to_root_epoch execution={} eligible={} \
                 effect_clean={} rollback_owned={} pure_mode={} ifd_capable={} \
                 parallel_capable_or_active={} memo_or_persist_capable_or_active={} \
                 effect_cursor={} trace_events={} warning_events={} impure_input_events={} \
                 text_store_realizations={} source_store_realizations={} \
                 force_leases={} force_roots={} lambda_leases={} \
                 import_cache_leases={} import_module_leases={} typed_blackholes={} \
                 active_env_depth={} suspended_envs={} call_depth={} \
                 current_module_is_root={} pending_native_states={} \
                 terminal_root_present={} report_only=true",
                snapshot.execution,
                snapshot.eligible(),
                snapshot.effect_clean(),
                snapshot.rollback_owned(),
                snapshot.pure_mode,
                snapshot.ifd_capable,
                snapshot.parallel_capable_or_active,
                snapshot.memo_or_persist_capable_or_active,
                snapshot.effect_cursor(),
                snapshot.trace_events,
                snapshot.warning_events,
                snapshot.impure_input_events,
                snapshot.text_store_realizations,
                snapshot.source_store_realizations,
                snapshot.force_leases,
                snapshot.force_roots,
                snapshot.lambda_leases,
                snapshot.import_cache_leases,
                snapshot.import_module_leases,
                snapshot.typed_blackholes,
                snapshot.active_env_depth,
                snapshot.suspended_envs,
                snapshot.call_depth,
                snapshot.current_module_is_root,
                snapshot.pending_native_states,
                snapshot.terminal_root_present,
            );
        }
        eprintln!(
            "aos_nix_restart_to_root_probe completions={} selected_epochs=2 \
             sampled_epochs={} both_epochs_eligible={} yield=false unwind=false \
             rollback=false collection=false semantic_change=false",
            probe.completions, sampled, both_eligible,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean_snapshot() -> RestartEligibilitySnapshot {
        RestartEligibilitySnapshot {
            execution: 160,
            pure_mode: true,
            force_leases: 2,
            force_roots: 4,
            lambda_leases: 1,
            import_cache_leases: 1,
            import_module_leases: 1,
            active_env_depth: 3,
            suspended_envs: 2,
            call_depth: 1,
            current_module_is_root: false,
            terminal_root_present: true,
            ..RestartEligibilitySnapshot::default()
        }
    }

    #[test]
    fn exact_two_epoch_schedule_is_stable() {
        assert_eq!(RestartToRootProbe::selected_slot(159), None);
        assert_eq!(RestartToRootProbe::selected_slot(160), Some(0));
        assert_eq!(RestartToRootProbe::selected_slot(192), Some(1));
        assert_eq!(RestartToRootProbe::selected_slot(193), None);
    }

    #[test]
    fn pure_owned_state_is_eligible() {
        let snapshot = clean_snapshot();
        assert!(snapshot.effect_clean());
        assert!(snapshot.rollback_owned());
        assert!(snapshot.eligible());
    }

    #[test]
    fn any_dynamic_effect_rejects_restart() {
        let mut snapshot = clean_snapshot();
        snapshot.warning_events = 1;
        assert!(!snapshot.effect_clean());
        assert!(!snapshot.eligible());
    }

    #[test]
    fn unowned_typed_blackhole_rejects_restart() {
        let mut snapshot = clean_snapshot();
        snapshot.typed_blackholes = 1;
        assert!(!snapshot.rollback_owned());
        assert!(!snapshot.eligible());
    }

    #[test]
    fn force_root_or_context_mismatch_rejects_restart() {
        let mut snapshot = clean_snapshot();
        snapshot.force_roots = 3;
        assert!(!snapshot.rollback_owned());
        snapshot.force_roots = 4;
        snapshot.suspended_envs = 1;
        assert!(!snapshot.rollback_owned());
    }

    #[test]
    fn configured_effect_capabilities_reject_restart() {
        let mut snapshot = clean_snapshot();
        snapshot.memo_or_persist_capable_or_active = true;
        assert!(!snapshot.effect_clean());
        snapshot.memo_or_persist_capable_or_active = false;
        snapshot.ifd_capable = true;
        assert!(!snapshot.effect_clean());
    }
}
