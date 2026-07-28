//! Report-only exact-identity Pending/Ready census for formal-set applications.
//!
//! This benchmark probe asks whether a serial, in-process application cache
//! could reuse completed formal-set calls without paying durable capture
//! hashing. It deliberately does not implement such a cache: keys contain only
//! def-site numbers, value tags, and transient representation identities, while
//! entries contain only lifecycle counters and wall-clock measurements. The
//! probe never retains a [`Value`], traverses an attrset, forces an argument, or
//! serves a result.
//!
//! Activation is default-off and requires both
//! `AOS_NIX_FORMAL_SET_READY_CENSUS=1` and the exact local-Ready monotonic
//! identity gate exposed by
//! [`TreeWalkOptions::local_ready_monotonic_identity_eligible`].

use super::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::Instant;

/// Integer-only identity of one formal-set application.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FormalSetReadyKey {
    module: u32,
    body: u32,
    function_tag: u8,
    function_identity: u64,
    argument_tag: u8,
    argument_identity: u64,
}

impl FormalSetReadyKey {
    /// Captures transient identities without retaining either evaluator value.
    fn from_values(function: Value, lambda: &EvalLambda, argument: Value) -> Self {
        Self {
            module: lambda.module().as_u32(),
            body: lambda.body().as_u32(),
            function_tag: function.tag() as u8,
            function_identity: function.transient_identity_bits(),
            argument_tag: argument.tag() as u8,
            argument_identity: argument.transient_identity_bits(),
        }
    }
}

/// Lifecycle state retained for an exact application key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApplicationState {
    /// The first application is still evaluating.
    Pending,
    /// At least one application completed successfully.
    Ready { first_body_wall_ns: u64 },
}

/// Aggregate report fields.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FormalSetReadyReport {
    absent: u64,
    recursive_pending: u64,
    strict_ready: u64,
    failed_first: u64,
    failed_strict_ready: u64,
    first_body_wall_ns: u64,
    strict_ready_body_wall_ns: u64,
    projected_strict_ready_saved_wall_ns: u64,
    distinct_ready: u64,
    pending: u64,
}

/// Mutable census contents shared with application drop guards.
#[derive(Debug, Default)]
struct FormalSetReadyState {
    entries: HashMap<FormalSetReadyKey, ApplicationState>,
    report: FormalSetReadyReport,
}

/// Evaluator-local census handle.
#[derive(Clone, Debug, Default)]
pub(super) struct FormalSetReadyCensus {
    state: Rc<RefCell<FormalSetReadyState>>,
}

impl FormalSetReadyCensus {
    /// Creates an empty census.
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Starts one exact application lifecycle.
    fn begin(&self, key: FormalSetReadyKey) -> FormalSetReadyApplication {
        let kind = {
            let mut state = self.state.borrow_mut();
            match state.entries.get(&key).copied() {
                None => {
                    state.report.absent = state.report.absent.saturating_add(1);
                    state.entries.insert(key, ApplicationState::Pending);
                    ApplicationKind::Absent
                }
                Some(ApplicationState::Pending) => {
                    state.report.recursive_pending =
                        state.report.recursive_pending.saturating_add(1);
                    ApplicationKind::RecursivePending
                }
                Some(ApplicationState::Ready { first_body_wall_ns }) => {
                    state.report.strict_ready = state.report.strict_ready.saturating_add(1);
                    state.report.projected_strict_ready_saved_wall_ns = state
                        .report
                        .projected_strict_ready_saved_wall_ns
                        .saturating_add(first_body_wall_ns);
                    ApplicationKind::StrictReady
                }
            }
        };
        FormalSetReadyApplication {
            state: Rc::clone(&self.state),
            key,
            kind,
            started: Instant::now(),
            completed: false,
        }
    }

    /// Returns a reconciled snapshot.
    fn report(&self) -> FormalSetReadyReport {
        let state = self.state.borrow();
        let mut report = state.report;
        for entry in state.entries.values() {
            match entry {
                ApplicationState::Pending => {
                    report.pending = report.pending.saturating_add(1);
                }
                ApplicationState::Ready { .. } => {
                    report.distinct_ready = report.distinct_ready.saturating_add(1);
                }
            }
        }
        report
    }
}

/// The state observed when an application begins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApplicationKind {
    Absent,
    RecursivePending,
    StrictReady,
}

/// Drop guard that prevents a failed first evaluation leaving stale Pending.
#[derive(Debug)]
pub(super) struct FormalSetReadyApplication {
    state: Rc<RefCell<FormalSetReadyState>>,
    key: FormalSetReadyKey,
    kind: ApplicationKind,
    started: Instant,
    completed: bool,
}

impl FormalSetReadyApplication {
    /// Publishes successful completion and records measured body wall.
    pub(super) fn complete(mut self) {
        let elapsed = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        if let Ok(mut state) = self.state.try_borrow_mut() {
            match self.kind {
                ApplicationKind::Absent => {
                    state.entries.insert(
                        self.key,
                        ApplicationState::Ready {
                            first_body_wall_ns: elapsed,
                        },
                    );
                    state.report.first_body_wall_ns =
                        state.report.first_body_wall_ns.saturating_add(elapsed);
                }
                ApplicationKind::RecursivePending => {}
                ApplicationKind::StrictReady => {
                    state.report.strict_ready_body_wall_ns = state
                        .report
                        .strict_ready_body_wall_ns
                        .saturating_add(elapsed);
                }
            }
            self.completed = true;
        }
    }
}

impl Drop for FormalSetReadyApplication {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let Ok(mut state) = self.state.try_borrow_mut() else {
            return;
        };
        match self.kind {
            ApplicationKind::Absent => {
                if state.entries.get(&self.key) == Some(&ApplicationState::Pending) {
                    state.entries.remove(&self.key);
                }
                state.report.failed_first = state.report.failed_first.saturating_add(1);
            }
            ApplicationKind::RecursivePending => {}
            ApplicationKind::StrictReady => {
                state.report.failed_strict_ready =
                    state.report.failed_strict_ready.saturating_add(1);
            }
        }
    }
}

impl TreeWalk {
    /// Begins a census application when the exact monotonic gate admitted it.
    pub(super) fn begin_formal_set_ready_census_application(
        &self,
        function: Value,
        lambda: &EvalLambda,
        argument: Value,
    ) -> Option<FormalSetReadyApplication> {
        self.formal_set_ready_census
            .as_ref()
            .map(|census| census.begin(FormalSetReadyKey::from_values(function, lambda, argument)))
    }

    /// Emits the report or an explicit safety-gate refusal.
    pub(super) fn emit_formal_set_ready_census_report(&self) {
        if !self.options.memo_options().formal_set_ready_census_enabled {
            return;
        }
        let Some(census) = self.formal_set_ready_census.as_ref() else {
            eprintln!(
                "aos_nix_formal_set_ready_census_refusal \
                 {{\"reason\":\"requires local-Ready monotonic identity eligibility\"}}"
            );
            return;
        };
        let report = census.report();
        eprintln!(
            "aos_nix_formal_set_ready_census \
             {{\"absent\":{},\"recursive_pending\":{},\"strict_ready\":{},\
             \"failed_first\":{},\"failed_strict_ready\":{},\
             \"distinct_ready\":{},\"pending\":{},\
             \"first_body_wall_ns\":{},\"strict_ready_body_wall_ns\":{},\
             \"projected_strict_ready_saved_wall_ns\":{}}}",
            report.absent,
            report.recursive_pending,
            report.strict_ready,
            report.failed_first,
            report.failed_strict_ready,
            report.distinct_ready,
            report.pending,
            report.first_body_wall_ns,
            report.strict_ready_body_wall_ns,
            report.projected_strict_ready_saved_wall_ns,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(function_identity: u64, argument_identity: u64) -> FormalSetReadyKey {
        FormalSetReadyKey {
            module: 7,
            body: 11,
            function_tag: ValueTag::Lambda as u8,
            function_identity,
            argument_tag: ValueTag::Attrs as u8,
            argument_identity,
        }
    }

    #[test]
    fn same_exact_key_progresses_from_absent_to_strict_ready() {
        let census = FormalSetReadyCensus::new();
        census.begin(key(1, 2)).complete();
        census.begin(key(1, 2)).complete();
        let report = census.report();
        assert_eq!(report.absent, 1);
        assert_eq!(report.strict_ready, 1);
        assert_eq!(report.distinct_ready, 1);
        assert_eq!(report.pending, 0);
    }

    #[test]
    fn distinct_function_and_argument_identities_do_not_alias() {
        let census = FormalSetReadyCensus::new();
        census.begin(key(1, 2)).complete();
        census.begin(key(3, 2)).complete();
        census.begin(key(1, 4)).complete();
        let report = census.report();
        assert_eq!(report.absent, 3);
        assert_eq!(report.strict_ready, 0);
        assert_eq!(report.distinct_ready, 3);
    }

    #[test]
    fn recursive_overlap_is_pending_not_ready() {
        let census = FormalSetReadyCensus::new();
        let outer = census.begin(key(1, 2));
        let inner = census.begin(key(1, 2));
        inner.complete();
        assert_eq!(census.report().recursive_pending, 1);
        assert_eq!(census.report().strict_ready, 0);
        assert_eq!(census.report().pending, 1);
        outer.complete();
        assert_eq!(census.report().distinct_ready, 1);
        assert_eq!(census.report().pending, 0);
    }

    #[test]
    fn failed_first_body_removes_pending_and_allows_retry() {
        let census = FormalSetReadyCensus::new();
        drop(census.begin(key(1, 2)));
        let failed = census.report();
        assert_eq!(failed.failed_first, 1);
        assert_eq!(failed.pending, 0);
        census.begin(key(1, 2)).complete();
        let retried = census.report();
        assert_eq!(retried.absent, 2);
        assert_eq!(retried.distinct_ready, 1);
    }

    #[test]
    fn census_reuses_the_local_ready_monotonic_safety_gate() {
        let mut options = TreeWalkOptions::default();
        assert!(
            options.local_ready_monotonic_identity_eligible(),
            "the default serial nonmoving arena admits transient identities"
        );
        options.set_gc_mode(EvalGcMode::Sweep);
        assert!(
            !options.local_ready_monotonic_identity_eligible(),
            "a reclaiming heap must refuse both local Ready and this census"
        );
    }
}
