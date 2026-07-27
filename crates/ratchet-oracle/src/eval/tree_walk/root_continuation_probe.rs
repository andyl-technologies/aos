//! Root-session continuation coverage for a future whole-demand machine.
//!
//! This default-off diagnostic does not collect or relocate anything. It
//! records exact final-config canary completions while root evaluation is
//! active, then reconciles them only after [`TreeWalk::eval_root`] has fully
//! unwound. The report distinguishes this terminal root poll from a sound
//! mid-evaluation poll: arbitrary values can still live in recursive Rust
//! frames at the completion site, so a matched count is coverage evidence,
//! not a precise-root proof.

use super::*;

const ENABLE_ENV: &str = "AOS_NIX_ROOT_CONTINUATION_PROBE";

/// Dynamic counters for one evaluator's root-continuation shadow.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct RootContinuationProbe {
    active: bool,
    session_depth: usize,
    root_entries: u64,
    successful_root_returns: u64,
    failed_root_returns: u64,
    completions: u64,
    completions_inside_root: u64,
    completions_outside_root: u64,
    pending_root_completions: u64,
    returned_to_root_poll: u64,
    abandoned_before_root_poll: u64,
    min_call_depth: usize,
    max_call_depth: usize,
    max_transient_value_roots: usize,
    max_active_force_roots: usize,
    max_primop_frames: usize,
    max_suspended_envs: usize,
    max_composite_depth: usize,
    max_order_sensitive_depth: usize,
}

impl RootContinuationProbe {
    /// Constructs an enabled probe from the exact opt-in environment setting.
    pub(super) fn from_env() -> Option<Self> {
        std::env::var(ENABLE_ENV)
            .is_ok_and(|value| value == "1")
            .then(Self::default)
    }

    fn begin_root(&mut self) {
        if self.session_depth == 0 {
            self.root_entries = self.root_entries.saturating_add(1);
        }
        self.session_depth = self.session_depth.saturating_add(1);
        self.active = true;
    }

    fn finish_root(&mut self, succeeded: bool) {
        if self.session_depth == 0 {
            return;
        }
        self.session_depth -= 1;
        if self.session_depth != 0 {
            return;
        }
        if succeeded {
            self.successful_root_returns = self.successful_root_returns.saturating_add(1);
            self.returned_to_root_poll = self
                .returned_to_root_poll
                .saturating_add(self.pending_root_completions);
        } else {
            self.failed_root_returns = self.failed_root_returns.saturating_add(1);
            self.abandoned_before_root_poll = self
                .abandoned_before_root_poll
                .saturating_add(self.pending_root_completions);
        }
        self.pending_root_completions = 0;
        self.active = false;
    }

    #[allow(clippy::too_many_arguments)]
    fn note_completion(
        &mut self,
        call_depth: usize,
        transient_value_roots: usize,
        active_force_roots: usize,
        primop_frames: usize,
        suspended_envs: usize,
        composite_depth: usize,
        order_sensitive_depth: usize,
    ) {
        self.completions = self.completions.saturating_add(1);
        if self.active {
            self.completions_inside_root = self.completions_inside_root.saturating_add(1);
            self.pending_root_completions = self.pending_root_completions.saturating_add(1);
        } else {
            self.completions_outside_root = self.completions_outside_root.saturating_add(1);
        }
        if self.completions == 1 {
            self.min_call_depth = call_depth;
        } else {
            self.min_call_depth = self.min_call_depth.min(call_depth);
        }
        self.max_call_depth = self.max_call_depth.max(call_depth);
        self.max_transient_value_roots = self.max_transient_value_roots.max(transient_value_roots);
        self.max_active_force_roots = self.max_active_force_roots.max(active_force_roots);
        self.max_primop_frames = self.max_primop_frames.max(primop_frames);
        self.max_suspended_envs = self.max_suspended_envs.max(suspended_envs);
        self.max_composite_depth = self.max_composite_depth.max(composite_depth);
        self.max_order_sensitive_depth = self.max_order_sensitive_depth.max(order_sensitive_depth);
    }
}

impl TreeWalk {
    /// Opens one root-owned diagnostic session.
    pub(super) fn begin_root_continuation_probe(&mut self) {
        if let Some(probe) = self.root_continuation_probe.as_mut() {
            probe.begin_root();
        }
    }

    /// Reconciles nested completions after root evaluation has unwound.
    pub(super) fn finish_root_continuation_probe(&mut self, succeeded: bool) {
        if let Some(probe) = self.root_continuation_probe.as_mut() {
            probe.finish_root(succeeded);
        }
    }

    /// Records one exact final-config completion and its explicit evaluator state.
    pub(super) fn note_root_continuation_final_config_completion(&mut self) {
        let Some(probe) = self.root_continuation_probe.as_mut() else {
            return;
        };
        probe.note_completion(
            self.call_depth,
            self.transient_value_stack_roots.len(),
            self.active_force_roots.len(),
            self.active_primop_arg_frames.len(),
            self.suspended_env_roots.len(),
            self.active_composite_accumulator_depth,
            self.order_sensitive_binding_depth,
        );
    }

    /// Emits the root-session coverage and native-continuation caveat.
    pub(super) fn emit_root_continuation_probe_report(&self) {
        let Some(probe) = self.root_continuation_probe.as_ref() else {
            return;
        };
        eprintln!(
            "aos_nix_root_continuation_probe \
             root_entries={} successful_root_returns={} failed_root_returns={} \
             completions={} completions_inside_root={} completions_outside_root={} \
             pending_root_completions={} returned_to_root_poll={} \
             abandoned_before_root_poll={} min_call_depth={} max_call_depth={} \
             max_transient_value_roots={} max_active_force_roots={} \
             max_primop_frames={} max_suspended_envs={} max_composite_depth={} \
             max_order_sensitive_depth={} native_rust_continuations=unscanned \
             mid_evaluation_collection_safe=false",
            probe.root_entries,
            probe.successful_root_returns,
            probe.failed_root_returns,
            probe.completions,
            probe.completions_inside_root,
            probe.completions_outside_root,
            probe.pending_root_completions,
            probe.returned_to_root_poll,
            probe.abandoned_before_root_poll,
            probe.min_call_depth,
            probe.max_call_depth,
            probe.max_transient_value_roots,
            probe.max_active_force_roots,
            probe.max_primop_frames,
            probe.max_suspended_envs,
            probe.max_composite_depth,
            probe.max_order_sensitive_depth,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::resolve as resolve_ast;
    use crate::eval::heap::EvalRootSource;
    use crate::syntax::parse_str;

    fn lower(source: &str) -> Ir {
        nix_lower(resolve_ast(parse_str(source).expect("source parses")).expect("source resolves"))
            .expect("source lowers")
    }

    #[test]
    fn successful_root_reconciles_only_its_pending_completions() {
        let mut probe = RootContinuationProbe::default();
        probe.begin_root();
        probe.note_completion(7, 2, 3, 1, 4, 5, 6);
        probe.note_completion(9, 1, 8, 2, 3, 7, 4);
        probe.finish_root(true);

        assert_eq!(probe.completions, 2);
        assert_eq!(probe.completions_inside_root, 2);
        assert_eq!(probe.returned_to_root_poll, 2);
        assert_eq!(probe.pending_root_completions, 0);
        assert_eq!(probe.min_call_depth, 7);
        assert_eq!(probe.max_call_depth, 9);
        assert_eq!(probe.max_active_force_roots, 8);
        assert!(!probe.active);
    }

    #[test]
    fn nested_eval_root_does_not_poll_before_whole_demand_returns() {
        let mut probe = RootContinuationProbe::default();
        probe.begin_root();
        probe.begin_root();
        probe.finish_root(true);
        probe.note_completion(3, 0, 0, 0, 0, 0, 0);

        assert!(probe.active);
        assert_eq!(probe.root_entries, 1);
        assert_eq!(probe.returned_to_root_poll, 0);
        probe.finish_root(true);
        assert_eq!(probe.returned_to_root_poll, 1);
        assert!(!probe.active);
    }

    #[test]
    fn failed_root_does_not_count_as_a_complete_poll() {
        let mut probe = RootContinuationProbe::default();
        probe.begin_root();
        probe.note_completion(1, 0, 0, 0, 0, 0, 0);
        probe.finish_root(false);
        probe.note_completion(0, 0, 0, 0, 0, 0, 0);

        assert_eq!(probe.returned_to_root_poll, 0);
        assert_eq!(probe.abandoned_before_root_poll, 1);
        assert_eq!(probe.completions_outside_root, 1);
    }

    #[test]
    fn mutator_roots_include_registered_transient_shadow_slots() {
        let ir = lower("null");
        let mut evaluator = TreeWalk::new(&ir);
        let value = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(ir.root))
            .expect("shadow-slot thunk allocates");
        evaluator.transient_value_stack_roots.push(value);

        let roots = evaluator
            .mutator_root_set()
            .expect("mutator roots build with a shadow slot");

        assert!(roots.roots().iter().any(|root| {
            root.source() == &EvalRootSource::ValueStack { slot: 0 } && root.value().raw_eq(value)
        }));
    }
}
