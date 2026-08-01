//! Checks `gate:layer1-injection` (Contract B) on the scheduler RESOLVE path.
//!
//! RFC-0010 file 24 [HARN-8] / file 15 [IO-2], [IO-9]: the icount at which a
//! cross-node injection is observed by the receiving node MUST be a pure function
//! of `(virtual_time, node_id, sequence)`, independent of how the host interleaves
//! producers or how finely it slices RUN into quanta. This gate drives a real
//! scenario carrying **both** a peer-to-peer frame injection **and** a
//! deterministic disk I/O completion (a `crucible-device` sub-node wired into the
//! [`crucible::SingleScheduler`] horizon and RESOLVE path through the LIVE quantum
//! drivers) and asserts:
//!
//! 1. **Run-twice byte-identical.** The same scenario driven under deliberately
//!    different host conditions — serial (`drive_quantum`) vs full-budget
//!    concurrent (`drive_concurrent_quantum`) — produces an identical
//!    [`InjectionFingerprint`] (config hash + every resolved happening + every
//!    delivery icount + the decision stream).
//! 2. **Every injection is observed at exactly its `delivery_icount`** in the
//!    canonical `(delivery_icount, src_node, seq)` order — not at the consumer's
//!    later frontier.
//! 3. **A node found advanced past an inbound delivery_icount fails loud** — the
//!    scheduler's late-delivery guard, exercised by a negative control.
//!
//! # How the gate has teeth
//!
//! 1. **Independent expected icount.** Each injection's observed icount is asserted
//!    EQUAL to a value computed independently from the request + modeled latency
//!    ([`expected_disk_completion_icount`]) — pinned to the device arithmetic, not
//!    recomputed from the delivery under test — and asserted INVARIANT across host
//!    conditions / COMPUTE-submit order ([IO-2], [IO-4], [DET-19]).
//! 2. **Run-twice byte-identity.** If RESOLVE order leaked host interleaving the
//!    serial / concurrent arms would diverge.
//! 3. **Fail-loud late delivery.** The negative control proves a frame due in a
//!    node's past is rejected ([SCHED-31]), never delivered late.
//!
//! The full *production* falsifiability proof for the exactness property — driving
//! `SingleScheduler::resolve_device_completions` into the freeze-time bug and
//! asserting the resolved icounts diverge — is the in-crate
//! `broken_device_delivery_stamp_diverges_proving_gate_falsifiability` test. It
//! lives in-crate because a correct conservative scheduler fast-forwards an idle
//! requester to EXACTLY its completion, so frontier and exact icount are equal by
//! construction in a normally-driven run; the divergence is only observable when a
//! completion is resolved at a frontier above it, which the in-crate test
//! exercises through the injectable delivery-stamp hook.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BackendInput, ConcurrentQuantumLoop, ContentHash, Decision, DeviceId, DeviceSchedulingSubNode,
    NodeCounter, NodeId, QuantumLoop, QuantumRequest, ScheduledEvent, ScheduledEventKey,
    ScheduledEventPayload, SchedulerError, SchedulerLivenessScenario, SchedulerNodeActivity,
    SchedulerNodeId, SchedulerScenarioNode, SchedulingNodeKind, Seed, Shift, SimInstant,
    SingleScheduler, VirtualTime,
};
use crucible_device::{BaseImage, BlockDevice, BlockLatency, BlockRequest, IoCore, IoFaults};

/// The determinism-relevant fingerprint of one full run.
///
/// Equality is the Contract B invariant: the recorded decision stream `S`, every
/// resolved happening (frame or I/O completion) by content, and every observed
/// delivery icount `T`. The quantum count and the event-log content hash (a
/// bookkeeping value keyed by quantum index) are deliberately excluded.
#[derive(Clone, Debug, PartialEq, Eq)]
struct InjectionFingerprint {
    config_hash: ContentHash,
    decisions: Vec<Decision>,
    resolved: Vec<ScheduledEvent>,
    observed: Vec<ObservedInjection>,
}

/// One cross-node injection observed at the receiving node.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ObservedInjection {
    delivery_icount: u64,
    consumer: String,
    producer: String,
    sequence: u64,
    kind: InjectionKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum InjectionKind {
    Frame,
    IoCompletion,
}

/// How the run drives the scheduler, modeling a different host condition.
#[derive(Clone, Copy, Debug)]
enum HostCondition {
    /// Serial drive (one RUN at a time) through `drive_quantum`.
    Serial,
    /// Full-budget concurrent drive through `drive_concurrent_quantum`.
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
        network_lookahead: crucible::NetworkLookahead::Infinite,
        exact_local_event: crucible::ExactLocalEvent::NoArmedTimer,
    }
}

/// Builds the disk sub-node for VM `a` with a single in-flight read completion.
///
/// The read at request icount 0 completes (fault-free) at the block latency's
/// modeled icount — strictly below the node's run horizon — so its delivery icount
/// is exact and distinct from the consumer's frontier (the teeth of the gate).
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

/// Builds a fresh two-VM scenario with a peer frame injection and a disk
/// completion, under one host condition.
fn fresh_scheduler(seed: Seed) -> SingleScheduler {
    let consumer = scheduler_node("b");
    let producer = scheduler_node("a");
    // A peer frame a -> b delivered at vt 12.
    let pending = vec![ScheduledEvent {
        key: ScheduledEventKey::from_parts(VirtualTime { ticks: 12 }, consumer, producer, 0),
        payload: ScheduledEventPayload::BackendInput(BackendInput {
            node: node_id("b"),
            payload: b"a-to-b".to_vec(),
        }),
    }];
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "gate-layer1-injection-corpus",
        shift(),
        8192,
        SimInstant { nanos: 4096 },
        vec![runnable_node("a"), runnable_node("b")],
        pending,
    );
    match SingleScheduler::new(scenario) {
        Ok(scheduler) => scheduler.with_device_sub_node(disk_sub_node(seed)),
        Err(error) => panic!("scheduler should construct: {error}"),
    }
}

/// The full record of one run: the Contract-B fingerprint.
struct RunRecord {
    fingerprint: InjectionFingerprint,
}

/// Drives the scheduler to quiescence under a host condition, fingerprinting it.
fn run(seed: Seed, condition: HostCondition) -> RunRecord {
    let mut scheduler = fresh_scheduler(seed);
    let mut decisions = Vec::new();
    let mut resolved = Vec::new();
    let mut observed = Vec::new();
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
            control: Vec::new(),
        };
        // Collect every per-RUN outcome this host condition produced.
        let outcomes = match condition {
            HostCondition::Concurrent => {
                scheduler
                    .drive_concurrent_quantum(request, usize::MAX)
                    .unwrap_or_else(|error| {
                        panic!("quantum should drive under {condition:?}: {error}")
                    })
                    .outcomes
            }
            HostCondition::Serial => {
                vec![scheduler.drive_quantum(request).unwrap_or_else(|error| {
                    panic!("quantum should drive under {condition:?}: {error}")
                })]
            }
        };

        // A quantum that advances no node makes no progress: every runnable node
        // has reached the time limit. Terminate to model the scheduler's
        // `TimeLimitReached` terminal (the time-limit accessor is crate-private).
        let made_progress = outcomes
            .iter()
            .any(|outcome| outcome.advanced_node.is_some());
        for outcome in outcomes {
            decisions.extend(outcome.decisions);
            for event in &outcome.resolved_events {
                resolved.push(event.clone());
                if let Some(injection) = observed_at_exact_icount(event) {
                    observed.push(injection);
                }
            }
        }
        if !made_progress {
            break;
        }
    }

    resolved.sort_by(|left, right| left.key.cmp(&right.key));
    observed.sort();
    RunRecord {
        fingerprint: InjectionFingerprint {
            config_hash: scheduler.configuration().content_hash(),
            decisions,
            resolved,
            observed,
        },
    }
}

/// Reads a resolved injection's observed icount from its OWN delivery icount
/// (the correct, Contract B behavior).
fn observed_at_exact_icount(event: &ScheduledEvent) -> Option<ObservedInjection> {
    let kind = match &event.payload {
        ScheduledEventPayload::IoCompletion(_) => InjectionKind::IoCompletion,
        ScheduledEventPayload::BackendInput(_) => InjectionKind::Frame,
        ScheduledEventPayload::FaultActivation(_)
        | ScheduledEventPayload::ProbabilisticFault(_)
        | ScheduledEventPayload::Control(_) => {
            return None;
        }
    };
    Some(ObservedInjection {
        delivery_icount: event.key.virtual_time().ticks,
        consumer: event.key.consumer().node.name.clone(),
        producer: event.key.producer().node.name.clone(),
        sequence: event.key.sequence(),
        kind,
    })
}

#[test]
fn gate_layer1_injection_run_twice_is_byte_identical_across_host_conditions() {
    let seed = Seed::from_u64(0x1a1e_c742);
    let serial = run(seed, HostCondition::Serial);
    let concurrent = run(seed, HostCondition::Concurrent);

    assert_eq!(
        serial.fingerprint, concurrent.fingerprint,
        "serial and concurrent drives must be byte-identical (Contract B)"
    );

    // Non-vacuous: the scenario actually injects BOTH a peer frame and a disk
    // completion, so the observed vector carries both injection kinds.
    assert!(
        serial
            .fingerprint
            .observed
            .iter()
            .any(|injection| injection.kind == InjectionKind::IoCompletion),
        "the scenario must resolve a disk I/O completion to be meaningful"
    );
    assert!(
        serial
            .fingerprint
            .observed
            .iter()
            .any(|injection| injection.kind == InjectionKind::Frame),
        "the scenario must resolve a peer frame injection to be meaningful"
    );
}

#[test]
fn gate_layer1_injection_observes_each_injection_at_its_independently_computed_icount() {
    // The teeth ([IO-2], [DET-19]): each injection's observed icount must EQUAL an
    // icount computed INDEPENDENTLY from the request + modeled latency — pinned to
    // the device arithmetic, not recomputed from the delivery the gate is checking.
    // If production stamped the consumer frontier (the freeze-time bug) the disk
    // completion's observed icount would NOT equal `expected_disk_completion_icount`
    // and this assertion would go red. (The full production falsifiability proof —
    // driving the broken stamp and asserting the fingerprint diverges — is the
    // in-crate `broken_device_delivery_stamp_diverges_proving_gate_falsifiability`.)
    let seed = Seed::from_u64(0x1a1e_c742);
    let exact = run(seed, HostCondition::Serial).fingerprint.observed;

    let completion = exact
        .iter()
        .find(|injection| injection.kind == InjectionKind::IoCompletion)
        .unwrap_or_else(|| panic!("a disk completion must be observed"));
    assert_eq!(
        completion.delivery_icount,
        expected_disk_completion_icount(0, 8),
        "the disk completion must land at its independently-computed exact icount"
    );
    // The peer frame lands at exactly its scheduled delivery vt (12) — its
    // independent expected value is the scenario's scheduled delivery time.
    let frame = exact
        .iter()
        .find(|injection| injection.kind == InjectionKind::Frame)
        .unwrap_or_else(|| panic!("a peer frame must be observed"));
    assert_eq!(frame.delivery_icount, 12);
}

#[test]
fn gate_layer1_injection_exact_icount_is_invariant_under_host_condition() {
    // The anti-freeze-time guarantee ([IO-4], [DET-19]): the disk completion's
    // exact icount is a pure function of the request + modeled latency, so driving
    // under either host condition yields the SAME observed icount.
    let seed = Seed::from_u64(0x1a1e_c742);
    let serial = disk_completion_icounts(run(seed, HostCondition::Serial));
    let concurrent = disk_completion_icounts(run(seed, HostCondition::Concurrent));
    assert_eq!(serial, vec![expected_disk_completion_icount(0, 8)]);
    assert_eq!(serial, concurrent);
}

/// Independently computes a fault-free disk read's exact completion icount from
/// the request icount and the modeled block latency ([IO-2]).
///
/// At shift 0 (icount == virtual ns) the completion icount is
/// `request_icount + read_base_ns + per_byte_ns * count` with the default
/// [`BlockLatency`]. Pinned to the device arithmetic so the gate's expectation is
/// computed from first principles, not recomputed from the delivery under test.
fn expected_disk_completion_icount(request_icount: u64, count: u64) -> u64 {
    let latency = BlockLatency::default();
    request_icount + latency.read_base_ns + latency.per_byte_ns * count
}

/// Returns the observed disk-completion icounts of a run, in order.
fn disk_completion_icounts(record: RunRecord) -> Vec<u64> {
    record
        .fingerprint
        .observed
        .iter()
        .filter(|injection| injection.kind == InjectionKind::IoCompletion)
        .map(|injection| injection.delivery_icount)
        .collect()
}

#[test]
fn gate_layer1_injection_late_delivery_fails_loud() {
    // The fail-loud half of the gate: a peer frame whose delivery icount is in the
    // consumer's PAST when the consumer is advanced must be rejected by the
    // scheduler's lookahead guard ([SCHED-31]), never delivered late. We arm a
    // frame due at vt 1 for node `b`, then advance `b` far past it with NO horizon
    // term holding it back, and assert RESOLVE localizes a late delivery.
    let consumer = scheduler_node("b");
    let producer = scheduler_node("a");
    let late = vec![ScheduledEvent {
        key: ScheduledEventKey::from_parts(VirtualTime { ticks: 1 }, consumer, producer, 0),
        payload: ScheduledEventPayload::BackendInput(BackendInput {
            node: node_id("b"),
            payload: b"late".to_vec(),
        }),
    }];
    // `b` already advanced to counter 100 (vt 100), well past the due vt 1.
    let mut advanced_b = runnable_node("b");
    advanced_b.counter = NodeCounter { ticks: 100 };
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "gate-layer1-injection-late",
        shift(),
        16,
        SimInstant { nanos: 4096 },
        vec![runnable_node("a"), advanced_b],
        late,
    );
    let mut scheduler = match SingleScheduler::new(scenario) {
        Ok(scheduler) => scheduler,
        Err(error) => panic!("scheduler should construct: {error}"),
    };

    let error = drive_until_error(&mut scheduler);
    let message = error.to_string();
    // The TARGET fails loud at the conservative-PDES guard ("unresolved cross-node
    // dependency is due at ..") which rejects the advance BEFORE the RESOLVE late
    // guard ("late scheduled event") would fire; either is the past-due fail-loud
    // ([SCHED-31]).
    assert!(
        message.contains("late scheduled event")
            || message.contains("unresolved cross-node dependency"),
        "a frame due in the consumer's past must fail loud, got {error:?}"
    );
}

/// Drives quanta until one returns an error, returning it.
fn drive_until_error(scheduler: &mut SingleScheduler) -> SchedulerError {
    let mut guard = 0u64;
    loop {
        assert!(guard < 64, "the late-delivery guard must fire, not spin");
        guard += 1;
        let request = QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        };
        match scheduler.drive_quantum(request) {
            Ok(outcome) => {
                if outcome.advanced_node.is_none()
                    || scheduler
                        .quiescence()
                        .unwrap_or_else(|error| panic!("quiescence should compute: {error}"))
                        .is_quiescent()
                {
                    panic!("the scenario reached its terminal without the expected late delivery");
                }
            }
            Err(error) => return error,
        }
    }
}

/// Anchors the independent expected-icount helper to the device model, so it is
/// not a magic number divorced from the block latency.
#[test]
fn gate_layer1_injection_disk_completion_icount_matches_the_device_model() {
    // read_base_ns (1000) + per_byte_ns (1) * count (8) = 1008 at shift 0.
    assert_eq!(expected_disk_completion_icount(0, 8), 1008);
    // Fault-free table is the identity, so the modeled icount is the delivery icount.
    assert_eq!(IoFaults::none().added_latency_ns, 0);
}
