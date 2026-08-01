//! Implements `gate:scheduler-liveness` under `--features test-double`.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BackendInput, ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId, QuantumLoop,
    QuantumOutcome, QuantumRequest, ScheduledEvent, ScheduledEventKey, ScheduledEventPayload,
    SchedulerLivenessError, SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId,
    SchedulerScenarioNode, SchedulerTerminal, SchedulingNodeKind, Shift, SimDouble,
    SimDoubleConfig, SimDuration, SimInstant, SimulationBackend, SingleScheduler, VirtualTime,
    check_scheduler_liveness,
};
use crucible_protocol::{CONTROL_PROTOCOL_VERSION, HostMsg, control_encode_host_msg};
use std::fmt::Debug;

const SCHEDULER_LIVENESS_BACKEND: &str = "crucible::SimDouble liveness harness";
const SCHEDULER_LIVENESS_REQUIRES_REAL_QEMU: bool = false;
const FIDELITY_PROPERTIES_REQUIRING_QEMU: [&str; 3] =
    ["contract-a", "guest-non-mutation", "patch-inertness"];

struct SimDoubleLivenessHarness {
    backend: SimDouble,
}

impl SimDoubleLivenessHarness {
    fn new() -> Self {
        Self {
            backend: ready_sim_double(),
        }
    }

    fn check_scheduler_liveness(
        &mut self,
        scenario: SchedulerLivenessScenario,
    ) -> Result<crucible::SchedulerLivenessReport, SchedulerLivenessError> {
        SimulationBackend::step_to(
            &mut self.backend,
            VirtualTime {
                ticks: scenario.time_limit.nanos,
            },
        )
        .unwrap_or_else(|error| panic!("SimDouble liveness backend should step: {error}"));
        check_scheduler_liveness(scenario)
    }
}

fn ready_sim_double() -> SimDouble {
    let mut backend = SimDouble::new(SimDoubleConfig::default())
        .unwrap_or_else(|error| panic!("SimDouble liveness backend should build: {error}"));
    complete_sim_double_setup(&mut backend);
    backend
}

fn complete_sim_double_setup(backend: &mut SimDouble) {
    let hello_ack = control_encode_host_msg(&HostMsg::HelloAck {
        proto_version: CONTROL_PROTOCOL_VERSION,
        abi_version: backend.shmem_header_snapshot().abi_version,
        slot_index: 0,
        node_count: backend.shmem_layout().node_count,
    });
    if let Err(error) = backend.accept_host_control_frame(&hello_ack) {
        panic!("SimDouble hello acknowledgement should succeed: {error}");
    }

    let setup = control_encode_host_msg(&HostMsg::Setup {
        region_len: backend.shmem_layout().region_size,
    });
    match backend.accept_host_control_frame(&setup) {
        Ok(Some(_setup_ack)) => {}
        Ok(None) => panic!("SimDouble setup should return a setup acknowledgement"),
        Err(error) => panic!("SimDouble setup should succeed: {error}"),
    }
}

#[test]
fn gate_scheduler_liveness_declares_in_process_sim_double_backend() {
    assert_eq!(
        SCHEDULER_LIVENESS_BACKEND,
        "crucible::SimDouble liveness harness"
    );
    const { assert!(!SCHEDULER_LIVENESS_REQUIRES_REAL_QEMU) };
    assert_eq!(
        FIDELITY_PROPERTIES_REQUIRING_QEMU,
        ["contract-a", "guest-non-mutation", "patch-inertness"]
    );
}

#[test]
fn gate_scheduler_liveness_generated_scenarios_terminate() {
    let scenarios = generated_scheduler_liveness_scenarios();
    assert!(
        scenarios.len() >= 32,
        "scheduler liveness gate must cover a generated corpus"
    );

    for (index, scenario) in scenarios.into_iter().enumerate() {
        let budget = scenario.quantum_budget;
        let report = assert_scheduler_liveness(scenario);

        assert!(
            matches!(
                report.terminal,
                SchedulerTerminal::Quiescent | SchedulerTerminal::TimeLimitReached
            ),
            "scenario {index} did not reach a valid terminal"
        );
        assert!(
            report.quanta <= budget,
            "scenario {index} exceeded quantum budget: {} > {budget}",
            report.quanta
        );
        assert!(
            report.yielded_between_quanta,
            "scenario {index} advanced a node without yielding the scheduler lock"
        );
        assert!(
            report.final_configuration.schedule.len() <= report.event_log_entries,
            "scenario {index} recorded decisions without canonical event-log entries"
        );
    }
}

#[test]
fn gate_scheduler_liveness_reaches_time_limit_terminal() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "time-limit-negative-space",
        shift(0),
        16,
        SimInstant { nanos: 1 },
        vec![scenario_node("node-a", 0, 8, ExactLocalEvent::NoArmedTimer)],
        Vec::new(),
    );

    let report = assert_scheduler_liveness(scenario);

    assert_eq!(report.terminal, SchedulerTerminal::TimeLimitReached);
    assert_eq!(report.frontier, VirtualTime { ticks: 1 });
    assert_eq!(report.quanta, 1);
}

#[test]
fn gate_scheduler_liveness_picks_global_minimum_horizon_before_current_time_order() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "global-minimum-horizon-before-current-time-order",
        shift(0),
        8,
        SimInstant { nanos: 16 },
        vec![
            scenario_node("early-high-horizon", 0, 10, ExactLocalEvent::NoArmedTimer),
            scenario_node("late-low-horizon", 3, 1, ExactLocalEvent::NoArmedTimer),
        ],
        Vec::new(),
    );

    let outcome = drive_one_quantum(scenario);

    assert_eq!(
        outcome.advanced_node,
        Some(scheduler_node("late-low-horizon", SchedulingNodeKind::Vm))
    );
}

#[test]
fn gate_scheduler_liveness_breaks_equal_horizon_ties_by_node_id() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "global-minimum-horizon-node-id-tie",
        shift(0),
        8,
        SimInstant { nanos: 16 },
        vec![
            scenario_node("node-b", 0, 5, ExactLocalEvent::NoArmedTimer),
            scenario_node("node-a", 2, 3, ExactLocalEvent::NoArmedTimer),
        ],
        Vec::new(),
    );

    let outcome = drive_one_quantum(scenario);

    assert_eq!(
        outcome.advanced_node,
        Some(scheduler_node("node-a", SchedulingNodeKind::Vm))
    );
}

#[test]
fn gate_scheduler_liveness_rejects_due_event_deadlock() {
    let consumer = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let producer = scheduler_node("node-b", SchedulingNodeKind::Vm);
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "deadlock-due-event",
        shift(0),
        8,
        SimInstant { nanos: 8 },
        vec![idle_scenario_node(
            "node-a",
            0,
            0,
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 0 },
            },
        )],
        vec![backend_event(0, &consumer, &producer, 7, b"due")],
    );

    let error = match check_scheduler_liveness(scenario) {
        Ok(report) => panic!("due-event deadlock should fail, got {report:?}"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        SchedulerLivenessError::Deadlock {
            frontier: VirtualTime { ticks: 0 },
            pending_events: 1,
        }
    ));
}

#[test]
fn gate_scheduler_liveness_rejects_stalled_runnable_livelock() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "stalled-runnable-node",
        shift(0),
        8,
        SimInstant { nanos: 8 },
        vec![scenario_node(
            "node-a",
            0,
            0,
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 0 },
            },
        )],
        Vec::new(),
    );

    let error = match check_scheduler_liveness(scenario) {
        Ok(report) => panic!("stalled runnable node should fail, got {report:?}"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        SchedulerLivenessError::Livelock {
            quantum: 0,
            counter: NodeCounter { ticks: 0 },
            ..
        }
    ));
}

fn generated_scheduler_liveness_scenarios() -> Vec<SchedulerLivenessScenario> {
    (0..48)
        .map(|seed| {
            let shift_bits = (seed % 3) as u8;
            let shift = shift(shift_bits);
            let scale = 1_u64 << shift_bits;
            let node_count = 2 + (seed % 4);
            let nodes = (0..node_count)
                .map(|node_index| {
                    let start = u64::from((seed + node_index) % 3);
                    let span = u64::from(3 + ((seed * 7 + node_index * 5) % 6));
                    let network_lookahead = span * scale;
                    let exact_local_event = if (seed + node_index) % 5 == 0 {
                        ExactLocalEvent::TimerDeadline {
                            virtual_time: SimInstant {
                                nanos: (start + 1 + span / 2) * scale,
                            },
                        }
                    } else {
                        ExactLocalEvent::NoArmedTimer
                    };

                    scenario_node(
                        &format!("node-{node_index}"),
                        start,
                        network_lookahead,
                        exact_local_event,
                    )
                })
                .collect::<Vec<_>>();
            let time_limit = if seed % 7 == 0 {
                SimInstant { nanos: 4 * scale }
            } else {
                SimInstant { nanos: 24 * scale }
            };
            let pending_events = generated_events(seed, &nodes, scale);

            SchedulerLivenessScenario::from_canonical_material(
                &format!("generated-seed-{seed}"),
                shift,
                96,
                time_limit,
                nodes,
                pending_events,
            )
        })
        .collect()
}

fn generated_events(seed: u32, nodes: &[SchedulerScenarioNode], scale: u64) -> Vec<ScheduledEvent> {
    nodes
        .iter()
        .enumerate()
        .filter_map(|(index, node)| {
            let producer = &nodes[(index + 1) % nodes.len()].id;
            let due_tick = node.counter.ticks + 1 + u64::from((seed + index as u32) % 2);
            let due_time = due_tick * scale;
            let current_time = node
                .counter
                .to_virtual(shift_for_scale(scale))
                .expect("generated counter should project");
            let horizon = current_time.nanos
                + node
                    .network_lookahead
                    .finite_duration()
                    .expect("generated scenario uses finite lookahead")
                    .nanos;

            (due_time <= horizon).then(|| {
                backend_event(
                    due_time,
                    &node.id,
                    producer,
                    100 + seed as u64 + index as u64,
                    b"generated",
                )
            })
        })
        .collect()
}

fn assert_scheduler_liveness(
    scenario: SchedulerLivenessScenario,
) -> crucible::SchedulerLivenessReport {
    let mut double = SimDoubleLivenessHarness::new();
    assert_twice_reduce_canonical_digest(|| double.check_scheduler_liveness(scenario.clone()))
}

fn drive_one_quantum(scenario: SchedulerLivenessScenario) -> QuantumOutcome {
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
    network_lookahead: u64,
    exact_local_event: ExactLocalEvent,
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name, SchedulingNodeKind::Vm),
        counter: NodeCounter { ticks: counter },
        activity: SchedulerNodeActivity::Runnable,
        network_lookahead: finite_lookahead(network_lookahead),
        exact_local_event,
    }
}

fn idle_scenario_node(
    name: &str,
    counter: u64,
    network_lookahead: u64,
    exact_local_event: ExactLocalEvent,
) -> SchedulerScenarioNode {
    let mut node = scenario_node(name, counter, network_lookahead, exact_local_event);
    node.activity = SchedulerNodeActivity::Idle;
    node
}

fn scheduler_node(name: &str, kind: SchedulingNodeKind) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind,
    }
}

fn backend_event(
    virtual_time: u64,
    consumer: &SchedulerNodeId,
    producer: &SchedulerNodeId,
    sequence: u64,
    payload: &[u8],
) -> ScheduledEvent {
    ScheduledEvent {
        key: ScheduledEventKey::from_parts(
            VirtualTime {
                ticks: virtual_time,
            },
            consumer.clone(),
            producer.clone(),
            sequence,
        ),
        payload: ScheduledEventPayload::BackendInput(BackendInput {
            node: consumer.node.clone(),
            payload: payload.to_vec(),
        }),
    }
}

fn assert_twice_reduce_canonical_digest<T, E, F>(mut reduce: F) -> T
where
    T: Debug + PartialEq,
    E: Debug,
    F: FnMut() -> Result<T, E>,
{
    let first = match reduce() {
        Ok(value) => value,
        Err(error) => panic!("first scheduler liveness reduction failed: {error:?}"),
    };
    let second = match reduce() {
        Ok(value) => value,
        Err(error) => panic!("second scheduler liveness reduction failed: {error:?}"),
    };
    assert_eq!(first, second);
    first
}

fn shift(bits: u8) -> Shift {
    match Shift::new(bits) {
        Ok(shift) => shift,
        Err(error) => panic!("test shift should be valid: {error}"),
    }
}

fn shift_for_scale(scale: u64) -> Shift {
    let bits = scale.trailing_zeros() as u8;
    shift(bits)
}

fn finite_lookahead(nanos: u64) -> NetworkLookahead {
    NetworkLookahead::Finite(SimDuration { nanos })
}
