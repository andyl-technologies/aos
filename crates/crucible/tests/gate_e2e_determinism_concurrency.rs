//! Implements the scheduler half of `gate:e2e-determinism` for host-level
//! concurrency (RFC-0010 T-SCHED-25, [SCHED-40], [SCHED-41], §8.12) on the REAL
//! scheduler RESOLVE path.
//!
//! Lookahead is the parallelism budget: nodes whose horizons cannot constrain
//! each other within the conservative lookahead window may run in parallel on the
//! host, while RESOLVE and EMIT stay serialized through the single scheduler in
//! the §8.6 total order ([SCHED-40]). The headline invariant proven here: a serial
//! drive ([`crucible::QuantumLoop::drive_quantum`], one RUN at a time) and a
//! full-budget host-concurrent drive
//! ([`crucible::ConcurrentQuantumLoop::drive_concurrent_quantum`], every
//! independent RUN dispatched at once) produce BIT-IDENTICAL results — the same
//! configuration content hash `S`, the same ordered decisions, the same
//! resolved-event log, and the same per-delivery icounts `T`.
//!
//! # Anchored to the authoritative path
//!
//! The real reference is the committed authoritative quantum
//! ([`crucible::QuantumLoop::drive_quantum`]), not another concurrent run. The
//! `..._anchored_to_authoritative_path` and `..._with_control_op` gates drive the
//! identical scenario through the authoritative path AND the concurrent path and
//! assert the same fingerprint, so a systematic defect in the concurrent dispatch
//! path (which a concurrent-vs-concurrent comparison would let cancel out) is
//! caught.
//!
//! # Non-vacuous by construction
//!
//! The concurrent drive genuinely batches. The two-VM ring used here has a
//! lookahead window wide enough that BOTH nodes are independent at the same step,
//! so `drive_concurrent_quantum` dispatches a run set of size two (asserted). If
//! host RUN dispatch leaked into RESOLVE/EMIT, the concurrent run's fingerprint
//! would diverge and this gate would go red. It stays green because RUN
//! parallelism never touches the serialized RESOLVE/EMIT order — the [SCHED-40]
//! claim that parallelism is a speed property, never a correctness property.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    AssertionDef, AssertionId, AssertionQuantifierKind, AssertionRunVerdict, BackendInput,
    ComposedRunVerdict, ConcurrentQuantumLoop, ConditionEventLogPrefix, ConditionLeaf, ContentHash,
    ControlOperation, ControlOperationKind, Decision, DeviceId, DeviceSchedulingSubNode,
    EventDiagnosticPayload, EventLevel, HostAssertionEvaluator, HostAssertionOutcomeKind,
    HostAssertionPredicate, HostAssertionReport, Icount, LintedHostAssertionOracle,
    NetworkLookahead, NodeCounter, NodeId, ObservedOrderingFact, ObservedState,
    OfflineAssertionChecker, Predicate, Properties, Property, QuantumLoop, QuantumRequest,
    RecordedAssertionLog, ScheduledEvent, ScheduledEventKey, ScheduledEventPayload,
    ScheduledEventResolveClass, SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry,
    SchedulerEventLogPayload, SchedulerLivenessScenario, SchedulerLookaheadEdge,
    SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode, SchedulingNodeKind, Seed, Shift,
    SimDuration, SimInstant, SingleScheduler, TriggerActionState, VirtualTime, World,
    compare_event_log_determinism,
};
use crucible_device::{BaseImage, BlockDevice, BlockLatency, BlockRequest, IoCore};

/// The determinism-relevant fingerprint of one full run, independent of the
/// concurrency degree and the host RUN dispatch order.
///
/// Equality over `RunFingerprint` is exactly the `S`/resolved-log/delivery-icount
/// invariant the gate compares between serial and concurrent drives.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RunFingerprint {
    /// The final configuration content hash (the recorded decision stream `S`).
    config_hash: ContentHash,
    /// The ordered decisions appended across the run (the explicit `S` stream).
    decisions: Vec<Decision>,
    /// The ordered resolved events (by content).
    resolved: Vec<ScheduledEvent>,
    /// Each resolved event's delivery virtual time paired with its icount under
    /// the fixed shift (`T` / [SCHED-13]).
    deliveries: Vec<(u64, Icount)>,
    /// The session-control sequences applied across the run, in order.
    control_sequences: Vec<u64>,
}

/// Assertion coverage derived from the scheduler event log of one full run.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AssertionGateCoverage {
    /// Online assertion report for the passing gate properties.
    assertion_pass_online: HostAssertionReport,
    /// Offline re-grade of the retained event log for the passing gate properties.
    assertion_pass_offline: HostAssertionReport,
    /// Final run verdict composed from the passing assertion report and trigger log.
    assertion_pass_composed: ComposedRunVerdict,
    /// Online assertion report for the failing gate properties.
    assertion_fail_online: HostAssertionReport,
    /// Offline re-grade of the retained event log for the failing gate properties.
    assertion_fail_offline: HostAssertionReport,
    /// Final run verdict composed from the failing assertion report and trigger log.
    assertion_fail_composed: ComposedRunVerdict,
}

/// How a run drove the scheduler, used to prove the concurrent mode is live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RunStats {
    /// The number of quanta/rounds driven (a serial drive uses strictly more).
    quanta: u64,
    /// The widest independent RUN dispatch observed across the run.
    max_batch: usize,
}

/// How a run drives the scheduler: through the committed authoritative quantum, or
/// through the host-concurrent round.
#[derive(Clone, Copy, Debug)]
enum DriveMode {
    /// The committed reference path: `drive_quantum`, one RUN at a time.
    Authoritative,
    /// The modeled host-concurrent path: `drive_concurrent_quantum` at full budget.
    Concurrent,
}

fn shift() -> Shift {
    match Shift::new(0) {
        Ok(shift) => shift,
        Err(error) => panic!("shift 0 is valid: {error}"),
    }
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: node_id(name),
        kind: SchedulingNodeKind::Vm,
    }
}

fn runnable_node(name: &str) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name),
        counter: NodeCounter { ticks: 0 },
        activity: SchedulerNodeActivity::Runnable,
        network_lookahead: NetworkLookahead::Infinite,
        exact_local_event: crucible::ExactLocalEvent::NoArmedTimer,
    }
}

/// Builds the disk sub-node for VM `a` with a single in-flight read completion so
/// the e2e scenario carries a deterministic I/O delivery alongside the peer
/// frames.
fn disk_sub_node(seed: Seed) -> DeviceSchedulingSubNode {
    let core = match IoCore::new(0, 1, 16, 16) {
        Ok(core) => core,
        Err(error) => panic!("io core should construct: {error}"),
    };
    let base = BaseImage::new(vec![0x5a; 4096]);
    let device = BlockDevice::new(core, base, BlockLatency::default());
    let mut sub_node = DeviceSchedulingSubNode::new(
        SchedulerNodeId {
            node: node_id("disk-a"),
            kind: SchedulingNodeKind::Disk,
        },
        node_id("a"),
        DeviceId {
            name: String::from("disk-a"),
        },
        device,
        seed,
    );
    sub_node
        .submit(0, &BlockRequest::read(1, 0, 8))
        .unwrap_or_else(|error| panic!("disk submit should succeed: {error}"));
    sub_node
}

/// Builds a fresh two-VM ring scheduler with cross-node deliveries and a disk
/// completion, exactly matching the serial and concurrent drives.
fn fresh_scheduler(seed: Seed) -> SingleScheduler {
    let a = scheduler_node("a");
    let b = scheduler_node("b");
    // Peer frames both directions so both VMs are independent within the lookahead
    // window (so the concurrent dispatch genuinely contains two RUNs).
    let pending = vec![
        ScheduledEvent {
            key: ScheduledEventKey::from_parts(VirtualTime { ticks: 12 }, a.clone(), b.clone(), 0),
            payload: ScheduledEventPayload::BackendInput(BackendInput {
                node: node_id("a"),
                payload: b"b-to-a".to_vec(),
            }),
        },
        ScheduledEvent {
            key: ScheduledEventKey::from_parts(VirtualTime { ticks: 16 }, b.clone(), a.clone(), 0),
            payload: ScheduledEventPayload::BackendInput(BackendInput {
                node: node_id("b"),
                payload: b"a-to-b".to_vec(),
            }),
        },
    ];
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "concurrency-determinism-corpus",
        shift(),
        8192,
        SimInstant { nanos: 4096 },
        vec![runnable_node("a"), runnable_node("b")],
        pending,
    );
    // A wide lookahead (latency 8) so both nodes are independent within the same
    // window and the concurrent dispatch genuinely contains two members.
    let edges = vec![
        SchedulerLookaheadEdge::new(a.clone(), b.clone(), SimDuration { nanos: 8 }),
        SchedulerLookaheadEdge::new(b.clone(), a.clone(), SimDuration { nanos: 8 }),
    ];
    let scenario = scenario.with_effective_topology_edges(edges);
    match SingleScheduler::new(scenario) {
        Ok(scheduler) => scheduler.with_device_sub_node(disk_sub_node(seed)),
        Err(error) => panic!("scheduler should construct: {error}"),
    }
}

/// Drives the scheduler to quiescence under a drive mode, optionally injecting
/// `control` on the FIRST quantum, returning the fingerprint and run stats.
///
/// The authoritative mode is the real reference: re-anchoring the concurrent path
/// to it (rather than to another concurrent run) is what catches a systematic
/// defect in the host-concurrent dispatch path — a bug present in both concurrent
/// arms would otherwise cancel out.
fn drive_with_assertions(
    mode: DriveMode,
    control: Vec<ControlOperation>,
) -> (
    RunFingerprint,
    RunStats,
    AssertionGateCoverage,
    Vec<SchedulerEventLogEntry>,
) {
    let seed = Seed::from_u64(0xe2e_d171);
    let mut scheduler = fresh_scheduler(seed);
    let mut decisions = Vec::new();
    let mut resolved = Vec::new();
    let mut deliveries = Vec::new();
    let mut event_log_segments = Vec::new();
    let mut max_batch = 0usize;
    let mut quanta = 0u64;
    let mut pending_control = Some(control);
    let mut guard = 0u64;

    loop {
        if scheduler
            .quiescence()
            .unwrap_or_else(|error| panic!("quiescence should compute: {error}"))
            .is_quiescent()
        {
            break;
        }
        assert!(guard < 8192, "run must terminate, not spin");
        guard += 1;
        let request = QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: pending_control.take().unwrap_or_default(),
        };
        let outcomes =
            match mode {
                DriveMode::Authoritative => {
                    vec![scheduler.drive_quantum(request).unwrap_or_else(|error| {
                        panic!("authoritative quantum should drive: {error}")
                    })]
                }
                DriveMode::Concurrent => {
                    let round = scheduler
                        .drive_concurrent_quantum(request, usize::MAX)
                        .unwrap_or_else(|error| panic!("concurrent quantum should drive: {error}"));
                    max_batch = max_batch.max(round.run_set.candidates.len());
                    round.outcomes
                }
            };

        quanta = quanta.saturating_add(1);
        let made_progress = outcomes
            .iter()
            .any(|outcome| outcome.advanced_node.is_some());
        for outcome in outcomes {
            event_log_segments.push(outcome.event_log_entries.clone());
            decisions.extend(outcome.decisions);
            for event in &outcome.resolved_events {
                let vt = event.key.virtual_time().ticks;
                resolved.push(event.clone());
                let icount = match (SimInstant { nanos: vt }).to_icount_ceil(shift()) {
                    Ok(icount) => icount,
                    Err(error) => panic!("delivery vt should convert: {error}"),
                };
                deliveries.push((vt, icount));
            }
        }
        if !made_progress {
            break;
        }
    }

    resolved.sort_by(|left, right| left.key.cmp(&right.key));
    deliveries.sort();
    let control_sequences = scheduler
        .control_applications()
        .iter()
        .map(|application| application.operation.sequence)
        .collect();
    let assertion_world = assertion_gate_world();
    let passing_properties = assertion_gate_passing_properties(&assertion_world);
    let failing_properties = assertion_gate_failing_properties(&assertion_world);
    let (assertion_pass_online, assertion_pass_offline, assertion_pass_composed) =
        assertion_gate_reports(&passing_properties, &event_log_segments);
    let (assertion_fail_online, assertion_fail_offline, assertion_fail_composed) =
        assertion_gate_reports(&failing_properties, &event_log_segments);
    let event_log = event_log_segments
        .iter()
        .flat_map(|segment| segment.iter().cloned())
        .collect::<Vec<_>>();
    (
        RunFingerprint {
            config_hash: scheduler.configuration().content_hash(),
            decisions,
            resolved,
            deliveries,
            control_sequences,
        },
        RunStats { quanta, max_batch },
        AssertionGateCoverage {
            assertion_pass_online,
            assertion_pass_offline,
            assertion_pass_composed,
            assertion_fail_online,
            assertion_fail_offline,
            assertion_fail_composed,
        },
        event_log,
    )
}

fn drive(mode: DriveMode, control: Vec<ControlOperation>) -> (RunFingerprint, RunStats) {
    let (fingerprint, stats, _, _) = drive_with_assertions(mode, control);
    (fingerprint, stats)
}

fn assertion_id(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn assertion_gate_world() -> World {
    World::from_nodes(Vec::new()).expect("assertion e2e world should build")
}

fn assertion_gate_passing_properties(world: &World) -> Properties {
    Properties::from_assertions_for_world(
        world,
        vec![
            AssertionDef {
                id: assertion_id("e2e-saw-frame-delivery"),
                message: String::from("frame delivery is observed"),
                property: Property::Sometimes {
                    predicate: Predicate::named("saw-frame-delivery"),
                },
            },
            AssertionDef {
                id: assertion_id("e2e-saw-delivery-order"),
                message: String::from("delivery order decision is observed"),
                property: Property::Sometimes {
                    predicate: Predicate::named("saw-delivery-order"),
                },
            },
        ],
    )
    .expect("e2e assertion gate properties should validate")
}

fn assertion_gate_failing_properties(world: &World) -> Properties {
    Properties::from_assertions_for_world(
        world,
        vec![AssertionDef {
            id: assertion_id("e2e-no-frame-delivery"),
            message: String::from("frame deliveries are forbidden by this negative corpus"),
            property: Property::Always {
                predicate: Predicate::named("no-frame-delivery"),
            },
        }],
    )
    .expect("e2e assertion gate failure properties should validate")
}

#[derive(Clone, Copy, Debug)]
struct SchedulerFactOracle;

impl HostAssertionPredicate for SchedulerFactOracle {
    fn leaf_is_true(&self, observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool {
        let ConditionLeaf::Named { name, nodes } = leaf else {
            return false;
        };
        if !nodes.is_empty() {
            return false;
        }

        match name {
            "saw-frame-delivery" => saw_frame_delivery(observed),
            "saw-delivery-order" => observed
                .ordering_facts()
                .iter()
                .any(|fact| matches!(fact, ObservedOrderingFact::DeliveryOrder { .. })),
            "no-frame-delivery" => !saw_frame_delivery(observed),
            _ => false,
        }
    }
}

fn saw_frame_delivery(observed: ObservedState<'_>) -> bool {
    observed.ordering_facts().iter().any(|fact| {
        matches!(
            fact,
            ObservedOrderingFact::ResolvedHappening {
                class: ScheduledEventResolveClass::FrameDelivery,
                ..
            }
        )
    })
}

fn scheduler_fact_oracle() -> LintedHostAssertionOracle<SchedulerFactOracle> {
    crucible::test_support::unchecked_host_assertion_oracle_for_test(SchedulerFactOracle)
}

fn assertion_gate_online_report(
    properties: &Properties,
    event_log: &[SchedulerEventLogEntry],
) -> HostAssertionReport {
    let mut evaluator = HostAssertionEvaluator::new(properties);
    let mut oracle = scheduler_fact_oracle();

    for prefix_len in 1..event_log.len() {
        let prefix = crucible::test_support::condition_prefix_from_scheduler_entries_for_test(
            event_log[..prefix_len].to_vec(),
        )
        .expect("online assertion prefix should be checkable");
        evaluator.observe_prefix(&prefix, &mut oracle);
    }
    let terminal_prefix = if event_log.is_empty() {
        ConditionEventLogPrefix::genesis()
    } else {
        crucible::test_support::condition_prefix_from_scheduler_entries_for_test(event_log.to_vec())
            .expect("terminal assertion prefix should be checkable")
    };
    evaluator.finalize_prefix(&terminal_prefix, &mut oracle)
}

fn assertion_gate_reports(
    properties: &Properties,
    event_log_segments: &[Vec<SchedulerEventLogEntry>],
) -> (HostAssertionReport, HostAssertionReport, ComposedRunVerdict) {
    let event_log = event_log_segments
        .iter()
        .flat_map(|segment| segment.iter().cloned())
        .collect::<Vec<_>>();
    let recorded_log = RecordedAssertionLog::from_segments(event_log_segments.iter().cloned())
        .expect("assertion e2e retained event log should fold");
    let online = assertion_gate_online_report(properties, &event_log);
    let mut offline_oracle = scheduler_fact_oracle();
    let offline = OfflineAssertionChecker::new()
        .check_run_with_oracle(properties, &recorded_log, &mut offline_oracle)
        .expect("assertion e2e offline report should grade");
    let composed = TriggerActionState::compose_run_verdict_from_event_log(
        &event_log,
        online.verdict().clone(),
    )
    .expect("assertion verdict should compose with trigger event log");

    (online, offline, composed)
}

fn assertion_outcome_signature(
    report: &HostAssertionReport,
) -> Vec<(
    AssertionId,
    AssertionQuantifierKind,
    VirtualTime,
    HostAssertionOutcomeKind,
    String,
)> {
    report
        .outcomes()
        .iter()
        .map(|outcome| {
            (
                outcome.assertion.clone(),
                outcome.quantifier,
                outcome.at,
                outcome.kind,
                outcome.reason.clone(),
            )
        })
        .collect()
}

#[test]
fn gate_e2e_determinism_serial_equals_concurrent_bit_identical() {
    // T-SCHED-25 / SCHED-40,41: a serial drive (one RUN at a time) and a
    // full-budget concurrent drive (every independent RUN dispatched at once) are
    // BIT-IDENTICAL in S, the resolved-event log, and the per-delivery icounts.
    // Concurrency of RUN never changes the serialized RESOLVE/EMIT order.
    let (serial, serial_stats) = drive(DriveMode::Authoritative, Vec::new());
    let (concurrent, concurrent_stats) = drive(DriveMode::Concurrent, Vec::new());

    assert_eq!(
        serial, concurrent,
        "serial and concurrent drives must be bit-identical (S/resolved-log/T)"
    );
    assert!(
        !serial.decisions.is_empty(),
        "the corpus must record some decisions to be meaningful"
    );
    assert!(
        !serial.resolved.is_empty(),
        "the corpus must resolve at least one cross-node event"
    );

    // Non-vacuous: the concurrent drive genuinely dispatched independent RUNs (a
    // round of two), so it drove strictly fewer quanta than the serial drive while
    // reaching the identical fingerprint. If the concurrent mode never batched, the
    // proof would be vacuous.
    assert!(
        concurrent_stats.max_batch >= 2,
        "the concurrent drive must dispatch an independent round of >= 2 RUNs: saw {}",
        concurrent_stats.max_batch
    );
    assert_eq!(
        serial_stats.max_batch, 0,
        "the authoritative drive never reports a concurrent round"
    );
    assert!(
        concurrent_stats.quanta < serial_stats.quanta,
        "concurrency must collapse independent RUNs into fewer rounds: {} !< {}",
        concurrent_stats.quanta,
        serial_stats.quanta
    );
}

#[test]
fn gate_e2e_determinism_uses_causal_event_log_projection() {
    let expected_log = vec![
        crucible::test_support::condition_boundary_entry_for_test(
            0,
            VirtualTime { ticks: 8 },
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
        crucible::test_support::condition_boundary_entry_for_test(
            1,
            VirtualTime { ticks: 16 },
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
    ];
    let reproduced_log = vec![
        crucible::test_support::condition_payload_entry_for_test(
            0,
            VirtualTime { ticks: 8 },
            SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
                "gate:e2e-determinism.observation",
                EventLevel::Debug,
                std::collections::BTreeMap::new(),
            )),
        ),
        crucible::test_support::condition_boundary_entry_for_test(
            1,
            VirtualTime { ticks: 8 },
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
        crucible::test_support::condition_boundary_entry_for_test(
            2,
            VirtualTime { ticks: 16 },
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
    ];
    let comparison = compare_event_log_determinism(&expected_log, &reproduced_log);

    assert!(comparison.passes());
    assert_eq!(
        comparison.expected().canonical_bytes(),
        comparison.reproduced().canonical_bytes(),
        "gate:e2e-determinism compares renumbered causal event-log bytes"
    );
}

#[test]
fn gate_e2e_determinism_compares_actual_causal_event_log_projection() {
    let (_, _, _, first_log) = drive_with_assertions(DriveMode::Authoritative, Vec::new());
    let (_, _, _, second_log) = drive_with_assertions(DriveMode::Authoritative, Vec::new());
    let comparison = compare_event_log_determinism(&first_log, &second_log);

    assert!(
        !comparison.expected().is_empty(),
        "the e2e workload must produce causal event-log entries"
    );
    assert!(comparison.passes());
    assert_eq!(
        comparison.expected().canonical_bytes(),
        comparison.reproduced().canonical_bytes(),
        "gate:e2e-determinism compares actual e2e causal event-log bytes"
    );
}

#[test]
fn gate_e2e_determinism_compares_actual_concurrent_causal_event_log_projection() {
    let (_, _, _, first_log) = drive_with_assertions(DriveMode::Concurrent, Vec::new());
    let (_, _, _, second_log) = drive_with_assertions(DriveMode::Concurrent, Vec::new());
    let comparison = compare_event_log_determinism(&first_log, &second_log);

    assert!(
        !comparison.expected().is_empty(),
        "the concurrent e2e workload must produce causal event-log entries"
    );
    assert!(comparison.passes());
    assert_eq!(
        comparison.expected().canonical_bytes(),
        comparison.reproduced().canonical_bytes(),
        "gate:e2e-determinism compares actual concurrent causal event-log bytes"
    );
}

#[test]
fn gate_e2e_determinism_covers_assertion_online_offline_outcomes_and_verdict() {
    let (_, _, authoritative, _) = drive_with_assertions(DriveMode::Authoritative, Vec::new());
    let (_, _, concurrent, _) = drive_with_assertions(DriveMode::Concurrent, Vec::new());

    assert_eq!(
        authoritative.assertion_pass_online, authoritative.assertion_pass_offline,
        "gate:e2e-determinism must compare identical assertion outcome sets online/offline"
    );
    assert_eq!(
        concurrent.assertion_pass_online, concurrent.assertion_pass_offline,
        "gate:e2e-determinism must compare identical assertion outcome sets online/offline"
    );
    assert_eq!(
        authoritative.assertion_pass_online, concurrent.assertion_pass_online,
        "authoritative and concurrent assertion outcome sets must match"
    );
    assert_eq!(
        authoritative.assertion_pass_online.verdict(),
        &AssertionRunVerdict::Passed
    );
    assert_eq!(
        authoritative.assertion_pass_composed, concurrent.assertion_pass_composed,
        "deterministic run-verdict composition must match for passing assertions"
    );

    assert_eq!(
        authoritative.assertion_fail_online, authoritative.assertion_fail_offline,
        "gate:e2e-determinism must compare identical failed assertion outcome sets online/offline"
    );
    assert_eq!(
        concurrent.assertion_fail_online, concurrent.assertion_fail_offline,
        "gate:e2e-determinism must compare identical failed assertion outcome sets online/offline"
    );
    assert_eq!(
        assertion_outcome_signature(&authoritative.assertion_fail_online),
        assertion_outcome_signature(&concurrent.assertion_fail_online),
        "authoritative and concurrent failed assertion outcome sets must match"
    );
    assert_eq!(
        authoritative.assertion_fail_online.verdict(),
        concurrent.assertion_fail_online.verdict(),
        "authoritative and concurrent failed assertion verdicts must match"
    );
    assert!(
        authoritative.assertion_fail_online.verdict().is_failed(),
        "negative assertion corpus must exercise failed verdict composition"
    );
    assert_eq!(
        authoritative.assertion_fail_composed, concurrent.assertion_fail_composed,
        "deterministic run-verdict composition must match for failed assertions"
    );
    assert!(
        authoritative.assertion_fail_composed.is_failed(),
        "failed assertion verdict must fail final run-verdict composition"
    );
}

#[test]
fn gate_e2e_determinism_disk_completion_lands_at_independently_computed_icount() {
    // The disk completion lands at its independently-computed exact icount under
    // both the serial and concurrent drives ([IO-2], [DET-19]) — never the
    // consumer frontier, and never moved by host RUN dispatch.
    let (serial, _) = drive(DriveMode::Authoritative, Vec::new());
    let (concurrent, _) = drive(DriveMode::Concurrent, Vec::new());
    let expected = expected_disk_completion_icount(0, 8);
    assert_eq!(expected, 1008);
    let disk = serial
        .resolved
        .iter()
        .find(|event| matches!(event.payload, ScheduledEventPayload::IoCompletion(_)))
        .unwrap_or_else(|| panic!("a disk completion must be resolved"));
    assert_eq!(
        disk.key.virtual_time().ticks,
        expected,
        "the disk completion must land at its independently-computed exact icount"
    );
    assert_eq!(
        serial.deliveries, concurrent.deliveries,
        "host RUN dispatch must not move any delivery icount"
    );
}

#[test]
fn gate_e2e_determinism_concurrent_is_anchored_to_authoritative_path() {
    // T-SCHED-25 / SCHED-40: the REAL reference is the committed authoritative
    // `drive_quantum`, not another concurrent run. Driving the identical scenario
    // through the authoritative path and through the full-budget concurrent path
    // must yield the SAME fingerprint. A systematic defect in the concurrent
    // dispatch path (which would cancel out across two concurrent arms) is caught
    // here because the authoritative arm does not share that code.
    let (authoritative, _) = drive(DriveMode::Authoritative, Vec::new());
    let (concurrent, concurrent_stats) = drive(DriveMode::Concurrent, Vec::new());

    assert_eq!(
        authoritative, concurrent,
        "the full-budget concurrent path must match the authoritative reference"
    );
    assert!(
        !authoritative.resolved.is_empty(),
        "the corpus must resolve a cross-node event for this to be meaningful"
    );
    assert!(
        concurrent_stats.max_batch >= 2,
        "the concurrent arm must genuinely dispatch a round for the anchor to be non-vacuous"
    );
}

#[test]
fn gate_e2e_determinism_authoritative_anchor_holds_with_control_op() {
    // SCHED-33/40 regression at the gate level: a control op admitted at a boundary
    // must enter the scheduler's control-application record identically on the
    // authoritative and concurrent paths. If concurrent dispatch dropped or
    // reordered the control admission, this anchor would diverge.
    let control = vec![ControlOperation {
        sequence: 99,
        kind: ControlOperationKind::Snapshot,
    }];
    let (authoritative, _) = drive(DriveMode::Authoritative, control.clone());
    let (concurrent, _) = drive(DriveMode::Concurrent, control);

    assert_eq!(
        authoritative, concurrent,
        "concurrent drive must match authoritative with a control op admitted"
    );
    // The control op's sequence (99) entered the applied-control record on both
    // paths — proof it went through the boundary control fold, not silently
    // dropped.
    assert!(
        authoritative.control_sequences.contains(&99),
        "the control op must be applied at a boundary (sequence 99 recorded)"
    );
}

/// Independently computes a fault-free disk read's exact completion icount from
/// the request icount and the modeled block latency ([IO-2]).
///
/// At shift 0 the completion icount is
/// `request_icount + read_base_ns + per_byte_ns * count` with the default
/// [`BlockLatency`]. Pinned to the device arithmetic so the expectation is computed
/// from first principles, not recomputed from the delivery under test.
fn expected_disk_completion_icount(request_icount: u64, count: u64) -> u64 {
    let latency = BlockLatency::default();
    request_icount + latency.read_base_ns + latency.per_byte_ns * count
}
