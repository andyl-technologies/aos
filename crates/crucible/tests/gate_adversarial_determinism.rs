//! Checks `gate:adversarial-determinism` (the Phase-3 exit gate) on the REAL
//! scheduler RESOLVE path.
//!
//! RFC-0010 file 24 [HARN-11] / §7: a fixed scenario run `N` times under
//! deliberately hostile host conditions MUST yield byte-identical canonical event
//! logs and final fingerprints (INV-1, INV-4, INV-9 — the determinism that
//! *survives* hostile conditions). This gate drives a **2-VM scenario with a disk
//! sub-node** through the host-adversary matrix ([`crucible_harness::adversarial`])
//! — hostile host thread scheduling, varied core counts, injected load,
//! producer/consumer skew — **and** rotates the modeled scheduler host condition
//! per task: serial drive ([`crucible::QuantumLoop::drive_quantum`]), full-budget
//! host-concurrent drive
//! ([`crucible::ConcurrentQuantumLoop::drive_concurrent_quantum`]), coarse
//! rendezvous frequency, and a COMPUTE-time skew that submits the two disk reads in
//! reversed host order. All runs must agree on the [`ScenarioFingerprint`] (config
//! hash + resolved-event log + delivery icounts + the decision stream).
//!
//! # How the gate has teeth
//!
//! The runs genuinely vary the modeled host condition: full-budget concurrent
//! dispatch, two rendezvous frequencies, and a COMPUTE-time skew that submits the
//! two disk reads in reversed host order. Three things would turn the fingerprints
//! red: host RUN dispatch leaking into RESOLVE/EMIT, the rendezvous frequency
//! moving a delivery icount, or the COMPUTE/submit order changing the result. Both
//! disk completions are additionally asserted to land at icounts computed
//! INDEPENDENTLY from the request + modeled latency ([IO-2], [IO-4]). The gate also
//! asserts the matrix is genuinely adversarial (more than one profile, the
//! concurrent condition actually dispatches two independent RUNs at once, and BOTH
//! sequential completions are delivered) so the proof is not vacuous.
//!
//! The production-level falsifiability proof for the exactness stamp is the in-crate
//! `broken_device_delivery_stamp_diverges_proving_gate_falsifiability` test (a
//! normally-driven run cannot observe frontier-vs-exact because an idle requester is
//! fast-forwarded to exactly its completion; the in-crate test resolves a completion
//! at a frontier above it through the injectable delivery-stamp hook).

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BackendInput, ConcurrentQuantumLoop, ContentHash, Decision, DeviceId, DeviceSchedulingSubNode,
    NetworkLookahead, NodeCounter, NodeId, QuantumLoop, QuantumRequest, ScheduledEvent,
    ScheduledEventKey, ScheduledEventPayload, SchedulerLivenessScenario, SchedulerLookaheadEdge,
    SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode, SchedulingNodeKind, Seed, Shift,
    SimDuration, SimInstant, SingleScheduler, VirtualTime,
};
use crucible_device::{BaseImage, BlockDevice, BlockLatency, BlockRequest, IoCore};
use crucible_harness::adversarial::{canonical_host_adversary_matrix, run_profiled_tasks};

/// The determinism-relevant fingerprint of one full run.
///
/// Equality is the [HARN-11] invariant: the recorded decision stream `S`, every
/// resolved happening (frame or I/O completion) by content, and every observed
/// delivery `(icount, consumer, sequence)`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ScenarioFingerprint {
    config_hash: ContentHash,
    decisions: Vec<Decision>,
    resolved: Vec<ScheduledEvent>,
    deliveries: Vec<(u64, String, u64)>,
}

/// One run's witness: its fingerprint and the widest concurrent dispatch it saw.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RunWitness {
    condition_index: usize,
    fingerprint: ScenarioFingerprint,
    max_batch: usize,
}

/// The modeled scheduler host condition rotated across adversarial tasks.
#[derive(Clone, Copy, Debug)]
enum HostCondition {
    /// Serial drive (one RUN at a time) through `drive_quantum`.
    Serial,
    /// Full-budget host-concurrent drive through `drive_concurrent_quantum`.
    Concurrent,
    /// Serial drive under a coarse fixed-interval rendezvous cap.
    CoarseRendezvous,
    /// Serial drive with the two disk reads submitted in reversed host order.
    ComputeSkew,
}

const HOST_CONDITIONS: [HostCondition; 4] = [
    HostCondition::Serial,
    HostCondition::Concurrent,
    HostCondition::CoarseRendezvous,
    HostCondition::ComputeSkew,
];

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

/// Builds the disk sub-node for VM `a`. Under [`HostCondition::ComputeSkew`] the
/// two reads are submitted in reversed host order — a different COMPUTE-time
/// interleaving that MUST NOT change the resulting delivery icounts.
fn disk_sub_node(seed: Seed, condition: HostCondition) -> DeviceSchedulingSubNode {
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
    // Two reads at distinct request icounts. COMPUTE/submit order is a host detail
    // ([IO-4]); under ComputeSkew the requests are submitted in reversed host
    // order. The device resolves the *sorted* modeled set, so the resulting
    // completions and their fault draws are a pure function of the request set and
    // the seed — identical under either submit order. This is the COMPUTE-time skew
    // dimension of the adversarial gate.
    let requests = [
        (0u64, BlockRequest::read(1, 0, 8)),
        (200u64, BlockRequest::read(2, 0, 8)),
    ];
    let order: Vec<usize> = match condition {
        HostCondition::ComputeSkew => vec![1, 0],
        _ => vec![0, 1],
    };
    for index in order {
        let (request_icount, request) = &requests[index];
        sub_node
            .submit(*request_icount, request)
            .unwrap_or_else(|error| panic!("disk submit should succeed: {error}"));
    }
    sub_node
}

/// Builds the fresh 2-VM-plus-disk scenario under one host condition.
fn fresh_scheduler(seed: Seed, condition: HostCondition) -> SingleScheduler {
    let a = scheduler_node("a");
    let b = scheduler_node("b");
    // Peer frames both directions so both VMs are independent within the lookahead
    // window (so the concurrent condition genuinely dispatches two RUNs at once).
    let pending = vec![
        ScheduledEvent {
            key: ScheduledEventKey::from_parts(VirtualTime { ticks: 12 }, b.clone(), a.clone(), 0),
            payload: ScheduledEventPayload::BackendInput(BackendInput {
                node: node_id("b"),
                payload: b"a-to-b".to_vec(),
            }),
        },
        ScheduledEvent {
            key: ScheduledEventKey::from_parts(VirtualTime { ticks: 16 }, a.clone(), b.clone(), 0),
            payload: ScheduledEventPayload::BackendInput(BackendInput {
                node: node_id("a"),
                payload: b"b-to-a".to_vec(),
            }),
        },
    ];
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "gate-adversarial-determinism-corpus",
        shift(),
        8192,
        SimInstant { nanos: 4096 },
        vec![runnable_node("a"), runnable_node("b")],
        pending,
    );
    // A wide lookahead (latency 8) so both VMs are independent within the same
    // window and the concurrent dispatch genuinely contains two members.
    let edges = vec![
        SchedulerLookaheadEdge::new(a.clone(), b.clone(), SimDuration { nanos: 8 }),
        SchedulerLookaheadEdge::new(b.clone(), a.clone(), SimDuration { nanos: 8 }),
    ];
    let scenario = scenario.with_effective_topology_edges(edges);
    // The CoarseRendezvous condition adds a fixed-interval rendezvous cap — a
    // different host condition that MUST NOT move any delivery icount.
    let scenario = match condition {
        HostCondition::CoarseRendezvous => {
            match scenario.with_rendezvous_interval(SimDuration { nanos: 64 }) {
                Ok(scenario) => scenario,
                Err(error) => panic!("valid rendezvous interval: {error}"),
            }
        }
        HostCondition::Serial | HostCondition::Concurrent | HostCondition::ComputeSkew => scenario,
    };
    match SingleScheduler::new(scenario) {
        Ok(scheduler) => scheduler.with_device_sub_node(disk_sub_node(seed, condition)),
        Err(error) => panic!("scheduler should construct: {error}"),
    }
}

/// Drives the scenario to quiescence under a host condition, fingerprinting it.
fn run(seed: Seed, condition_index: usize) -> RunWitness {
    let condition = HOST_CONDITIONS[condition_index % HOST_CONDITIONS.len()];
    let mut scheduler = fresh_scheduler(seed, condition);
    let mut decisions = Vec::new();
    let mut resolved = Vec::new();
    let mut deliveries = Vec::new();
    let mut max_batch = 0usize;
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
        // Each host condition produces a set of per-RUN outcomes; collect them all.
        let outcomes = match condition {
            HostCondition::Concurrent => {
                let round = scheduler
                    .drive_concurrent_quantum(request, usize::MAX)
                    .unwrap_or_else(|error| {
                        panic!("quantum should drive under {condition:?}: {error}")
                    });
                max_batch = max_batch.max(round.run_set.candidates.len());
                round.outcomes
            }
            HostCondition::Serial
            | HostCondition::CoarseRendezvous
            | HostCondition::ComputeSkew => {
                vec![scheduler.drive_quantum(request).unwrap_or_else(|error| {
                    panic!("quantum should drive under {condition:?}: {error}")
                })]
            }
        };

        // A round that advances no node makes no progress: every runnable node has
        // reached the time limit. Terminate to model the scheduler's
        // `TimeLimitReached` terminal (the time-limit accessor is crate-private).
        let made_progress = outcomes
            .iter()
            .any(|outcome| outcome.advanced_node.is_some());
        for outcome in outcomes {
            decisions.extend(outcome.decisions);
            for event in &outcome.resolved_events {
                resolved.push(event.clone());
                deliveries.push((
                    event.key.virtual_time().ticks,
                    event.key.consumer().node.name.clone(),
                    event.key.sequence(),
                ));
            }
        }
        if !made_progress {
            break;
        }
    }

    resolved.sort_by(|left, right| left.key.cmp(&right.key));
    deliveries.sort();
    RunWitness {
        condition_index,
        fingerprint: ScenarioFingerprint {
            config_hash: scheduler.configuration().content_hash(),
            decisions,
            resolved,
            deliveries,
        },
        max_batch,
    }
}

#[test]
fn gate_adversarial_determinism_two_vm_disk_scenario_is_byte_identical_across_hostile_runs() {
    let seed = Seed::from_u64(0x4ad_be57);
    let profiles = canonical_host_adversary_matrix();
    assert!(
        profiles.len() > 1,
        "the host-adversary matrix must contain more than one profile"
    );

    // Run every host condition under every hostile host profile, collecting the
    // per-condition witnesses. The hostile profile scrambles host thread
    // scheduling / load / skew; the condition index varies the modeled scheduler
    // host behavior (serial / concurrent dispatch / coarse rendezvous / COMPUTE
    // skew).
    let task_count = HOST_CONDITIONS.len();
    let mut witnesses = Vec::new();
    for profile in profiles {
        let results = run_profiled_tasks(*profile, task_count, |task| run(seed, task.index))
            .unwrap_or_else(|error| {
                panic!(
                    "adversarial profile {} should execute: {error}",
                    profile.name
                )
            });
        witnesses.extend(results);
    }

    let baseline = witnesses
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("at least one adversarial witness must exist"));
    for witness in &witnesses {
        assert_eq!(
            witness.fingerprint, baseline.fingerprint,
            "condition {} diverged from the baseline under a hostile host profile",
            witness.condition_index
        );
    }

    // Non-vacuous: the scenario resolves cross-node events (frames + disk
    // completions), and the concurrent condition genuinely dispatched two
    // independent RUNs at once — so the determinism proof spans real concurrency,
    // not a degenerate one-node run.
    assert!(
        !baseline.fingerprint.resolved.is_empty(),
        "the scenario must resolve at least one cross-node event"
    );
    assert!(
        baseline
            .fingerprint
            .deliveries
            .iter()
            .any(|(_, node, _)| node == "a"),
        "the disk completion must be delivered to VM a"
    );
    let concurrent_batch = witnesses
        .iter()
        .filter(|witness| {
            matches!(
                HOST_CONDITIONS[witness.condition_index % HOST_CONDITIONS.len()],
                HostCondition::Concurrent
            )
        })
        .map(|witness| witness.max_batch)
        .max()
        .unwrap_or(0);
    assert!(
        concurrent_batch >= 2,
        "the concurrent condition must dispatch >= 2 independent RUNs for the \
         concurrency teeth to be non-vacuous: saw {concurrent_batch}"
    );
}

#[test]
fn gate_adversarial_determinism_disk_completions_land_at_independently_computed_icounts() {
    // The COMPUTE-skew teeth ([IO-2], [IO-4], [DET-19]): submitting the two disk
    // reads in forward vs reversed host order yields a BYTE-IDENTICAL fingerprint,
    // and BOTH completions land at icounts computed INDEPENDENTLY from the request +
    // modeled latency — never the consumer frontier.
    let seed = Seed::from_u64(0x04ad_be57);
    let forward = run(seed, 0).fingerprint;
    let skewed = run(seed, 3).fingerprint;
    assert_eq!(
        forward, skewed,
        "COMPUTE-time submit order must not change the result ([IO-4])"
    );
    let disk_deliveries: Vec<u64> = forward
        .deliveries
        .iter()
        .filter(|(_, node, _)| node == "a")
        .map(|(icount, _, _)| *icount)
        .collect();
    // Independently-computed expected disk completion icounts: read at request
    // icount 0 -> 1008, read at request icount 200 -> 1208 (shift 0).
    let first = expected_disk_completion_icount(0, 8);
    let second = expected_disk_completion_icount(200, 8);
    assert_eq!((first, second), (1008, 1208));
    assert!(
        disk_deliveries.contains(&first) && disk_deliveries.contains(&second),
        "BOTH disk completions must land at their independently-computed exact \
         icounts (1008, 1208), not the consumer frontier: {disk_deliveries:?}"
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
