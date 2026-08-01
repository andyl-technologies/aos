//! Checks the T-SCHED-5 scheduler horizon composition.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    ExactLocalEvent, Icount, NetworkLookahead, NodeCounter, NodeId, QuantumLoop, QuantumRequest,
    SchedulerHorizon, SchedulerHorizonLimit, SchedulerHorizonSource, SchedulerLivenessScenario,
    SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode, SchedulingNodeKind, Shift,
    SimDuration, SimInstant, SingleScheduler, VirtualTime, horizon_from_network_lookahead,
};

#[test]
fn scheduler_horizon_adds_network_lookahead_to_current_time() {
    let horizon = horizon_from_network_lookahead(
        SimInstant { nanos: 30 },
        finite_lookahead(7),
        ExactLocalEvent::NoArmedTimer,
        shift(0),
    );

    assert_eq!(
        horizon,
        Ok(SchedulerHorizon {
            limit: SchedulerHorizonLimit::Finite {
                virtual_time: SimInstant { nanos: 37 },
                ceiling: Icount { retired: 37 },
            },
            source: SchedulerHorizonSource::NetworkLookahead,
        })
    );
}

#[test]
fn scheduler_horizon_uses_exact_local_event_without_conservative_slack() {
    let horizon = horizon_from_network_lookahead(
        SimInstant { nanos: 30 },
        finite_lookahead(10),
        ExactLocalEvent::TimerDeadline {
            virtual_time: SimInstant { nanos: 33 },
        },
        shift(0),
    );

    assert_eq!(
        horizon,
        Ok(SchedulerHorizon {
            limit: SchedulerHorizonLimit::Finite {
                virtual_time: SimInstant { nanos: 33 },
                ceiling: Icount { retired: 33 },
            },
            source: SchedulerHorizonSource::ExactLocalTimer,
        })
    );
}

#[test]
fn scheduler_horizon_is_unbounded_without_network_or_local_event() {
    let horizon = horizon_from_network_lookahead(
        SimInstant { nanos: 30 },
        NetworkLookahead::Infinite,
        ExactLocalEvent::NoArmedTimer,
        shift(0),
    );

    assert_eq!(horizon, Ok(SchedulerHorizon::infinite_network()));
}

#[test]
fn scheduler_horizon_exact_local_event_bounds_infinite_network() {
    let horizon = horizon_from_network_lookahead(
        SimInstant { nanos: 30 },
        NetworkLookahead::Infinite,
        ExactLocalEvent::TimerDeadline {
            virtual_time: SimInstant { nanos: 34 },
        },
        shift(1),
    );

    assert_eq!(
        horizon,
        Ok(SchedulerHorizon {
            limit: SchedulerHorizonLimit::Finite {
                virtual_time: SimInstant { nanos: 34 },
                ceiling: Icount { retired: 17 },
            },
            source: SchedulerHorizonSource::ExactLocalTimer,
        })
    );
}

#[test]
fn single_scheduler_uses_current_time_plus_network_lookahead() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "horizon-current-plus-lookahead",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![scenario_node(
            "node-a",
            3,
            finite_lookahead(4),
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    );

    let outcome = drive_one_quantum(scenario);

    assert_eq!(outcome.advanced_node, Some(scheduler_node("node-a")));
    assert_eq!(outcome.frontier, VirtualTime { ticks: 7 });
}

#[test]
fn single_scheduler_caps_unbounded_network_horizon_at_time_limit() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "horizon-infinite-network-time-limit",
        shift(0),
        8,
        SimInstant { nanos: 9 },
        vec![scenario_node(
            "node-a",
            3,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    );

    let outcome = drive_one_quantum(scenario);

    assert_eq!(outcome.advanced_node, Some(scheduler_node("node-a")));
    assert_eq!(outcome.frontier, VirtualTime { ticks: 9 });
}

fn drive_one_quantum(scenario: SchedulerLivenessScenario) -> crucible::QuantumOutcome {
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should be valid");
    let request = QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    };
    scheduler
        .drive_quantum(request)
        .expect("scheduler should drive one quantum")
}

fn scenario_node(
    name: &str,
    counter: u64,
    network_lookahead: NetworkLookahead,
    exact_local_event: ExactLocalEvent,
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name),
        counter: NodeCounter { ticks: counter },
        activity: SchedulerNodeActivity::Runnable,
        network_lookahead,
        exact_local_event,
    }
}

fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind: SchedulingNodeKind::Vm,
    }
}

fn finite_lookahead(nanos: u64) -> NetworkLookahead {
    NetworkLookahead::Finite(SimDuration { nanos })
}

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}
