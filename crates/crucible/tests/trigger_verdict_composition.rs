//! Checks T-TRIG-17 pass/fail trigger verdict composition.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Action, AssertionId, AssertionRunVerdict, AssertionVerdictFailure, ComposedRunVerdict,
    ComposedRunVerdictFailure, ConditionLeaf, ConditionLeafOracle, Event, EventGraph,
    EventGraphState, EventId, SchedulerEventLogEntry, SchedulerLivenessScenario, Shift, SimInstant,
    SingleScheduler, TriggerActionState, VirtualTime,
};

fn event_id(name: &str) -> EventId {
    EventId::from_name(name)
}

fn assertion_id(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn shift(bits: u8) -> Shift {
    Shift { bits }
}

fn scenario(name: &str) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        name,
        shift(0),
        16,
        SimInstant { nanos: 100 },
        Vec::new(),
        Vec::new(),
    )
}

fn assertion_failure(name: &str, at: u64, reason: &str) -> AssertionVerdictFailure {
    AssertionVerdictFailure::new(assertion_id(name), time(at), reason)
}

struct NoLeaves;

impl ConditionLeafOracle for NoLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("verdict composition tests use only entrypoint triggers")
            }
        }
    }
}

fn apply_entrypoint_action(action: Action) -> (TriggerActionState, Vec<SchedulerEventLogEntry>) {
    let graph = EventGraph::new(vec![Event::once(event_id("verdict"), None, action)])
        .expect("verdict graph should build");
    let mut scheduler =
        SingleScheduler::new(scenario("trigger-verdict")).expect("scheduler should build");
    let mut state = EventGraphState::new();
    let firings = scheduler.evaluate_event_graph(&graph, &mut state, NoLeaves);
    let append = scheduler
        .apply_trigger_firings(&firings)
        .expect("verdict action should apply");
    (scheduler.trigger_actions().clone(), append.entries)
}

#[test]
fn explicit_fail_is_sticky_over_later_pass() {
    let (state, _) = apply_entrypoint_action(Action::Group(vec![
        Action::Fail {
            reason: String::from("invariant violated"),
        },
        Action::Pass,
    ]));

    assert!(state.termination_requested);
    let verdict = state.compose_run_verdict(AssertionRunVerdict::passed());
    let ComposedRunVerdict::Failed { failures } = verdict else {
        panic!("explicit Fail should fail the composed verdict");
    };
    assert_eq!(failures.len(), 1);
    let ComposedRunVerdictFailure::Trigger(trigger) = &failures[0] else {
        panic!("failure should come from the trigger verdict");
    };
    assert_eq!(trigger.event.name, "verdict");
    assert_eq!(trigger.failed_reason.as_deref(), Some("invariant violated"));
}

#[test]
fn pass_updates_until_a_failure_becomes_sticky() {
    let (state, _) = apply_entrypoint_action(Action::Group(vec![Action::Pass, Action::Pass]));
    assert!(state.termination_requested);
    let verdict = state.compose_run_verdict(AssertionRunVerdict::passed());

    let ComposedRunVerdict::Passed {
        trigger: Some(trigger),
    } = verdict
    else {
        panic!("explicit pass with passed assertions should pass");
    };
    assert_eq!(trigger.sequence, 1);
    assert_eq!(trigger.failed_reason, None);
}

#[test]
fn explicit_pass_cannot_mask_assertion_failure() {
    let (state, _) = apply_entrypoint_action(Action::Pass);
    let verdict = state.compose_run_verdict(AssertionRunVerdict::failed(vec![assertion_failure(
        "always-safe",
        7,
        "Always assertion violated",
    )]));

    let ComposedRunVerdict::Failed { failures } = verdict else {
        panic!("assertion failure should override explicit Pass");
    };
    assert_eq!(
        failures,
        vec![ComposedRunVerdictFailure::Assertion(assertion_failure(
            "always-safe",
            7,
            "Always assertion violated",
        ))]
    );
}

#[test]
fn trigger_fail_and_assertion_failures_compose_deterministically() {
    let (state, event_log_entries) = apply_entrypoint_action(Action::Fail {
        reason: String::from("explicit fail"),
    });
    let assertions = AssertionRunVerdict::Failed {
        failures: vec![
            assertion_failure("zeta", 9, "later failure"),
            assertion_failure("alpha", 3, "earlier failure"),
        ],
    };

    let online = state.compose_run_verdict(assertions.clone());
    let offline =
        TriggerActionState::compose_run_verdict_from_event_log(&event_log_entries, assertions)
            .expect("logged trigger verdict should replay");

    assert_eq!(online, offline);
    let ComposedRunVerdict::Failed { failures } = online else {
        panic!("combined failures should fail the run");
    };
    assert_eq!(
        failures,
        vec![
            ComposedRunVerdictFailure::Assertion(assertion_failure("alpha", 3, "earlier failure",)),
            ComposedRunVerdictFailure::Assertion(assertion_failure("zeta", 9, "later failure",)),
            ComposedRunVerdictFailure::Trigger(
                state.verdict.expect("trigger fail should be recorded")
            ),
        ]
    );
}

#[test]
fn passed_assertions_and_trigger_pass_compose_to_pass() {
    let (state, event_log_entries) = apply_entrypoint_action(Action::Pass);
    let verdict = state.compose_run_verdict(AssertionRunVerdict::passed());
    assert_eq!(
        verdict,
        TriggerActionState::compose_run_verdict_from_event_log(
            &event_log_entries,
            AssertionRunVerdict::passed(),
        )
        .expect("logged trigger pass should replay")
    );

    let ComposedRunVerdict::Passed {
        trigger: Some(trigger),
    } = verdict
    else {
        panic!("explicit pass with passed assertions should pass");
    };
    assert_eq!(trigger.event.name, "verdict");
    assert_eq!(trigger.failed_reason, None);
}
