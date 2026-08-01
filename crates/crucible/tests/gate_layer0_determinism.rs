//! Checks `gate:layer0-determinism` for the engine test-double boundary.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    AdvanceOutcome, Backend, BackendInput, Configuration, Decision, ExecutionFingerprint,
    ExecutionHorizon, Icount, NodeId, RngDecision, RngStreamId, ScenarioDef, Schedule,
    ScheduledEventKey, SchedulerNodeId, SchedulingNodeKind, SimBackend, VirtualTime, step,
};

#[test]
fn gate_layer0_determinism_reduces_sim_backend_twice() {
    let input = BackendInput {
        node: node("node-a"),
        payload: b"recorded-input".to_vec(),
    };
    let fingerprint = assert_twice_reduce_canonical_digest(|| {
        let mut backend = SimBackend::new();

        drive_backend(&mut backend, input.clone(), 64);

        backend_fingerprint(&mut backend)
    });
    let mut first = SimBackend::new();
    let mut second = SimBackend::new();

    drive_backend(&mut first, input.clone(), 64);
    drive_backend(&mut second, input, 64);

    assert_eq!(first.state(), second.state());
    assert_eq!(backend_fingerprint(&mut first), fingerprint);
    assert_eq!(backend_fingerprint(&mut second), fingerprint);
}

#[test]
fn gate_layer0_determinism_keeps_schedule_decisions_explicitly_ordered() {
    let genesis = Configuration::genesis(ScenarioDef::from_canonical_material(
        "layer0-gate",
        "scenario",
    ));
    let first = rng_decision("node-a", 1);
    let second = rng_decision("node-b", 1);

    let left = step(&step(&genesis, first.clone()), second.clone());
    let right = step(&step(&genesis, second.clone()), first.clone());

    assert_eq!(left.schedule.decisions(), &[first.clone(), second.clone()]);
    assert_eq!(right.schedule.decisions(), &[second, first]);
    assert_ne!(left.schedule, right.schedule);
}

#[test]
fn gate_layer0_determinism_orders_scheduler_event_keys_canonically() {
    let vm_a = scheduler_node("a", SchedulingNodeKind::Vm);
    let vm_b = scheduler_node("b", SchedulingNodeKind::Vm);
    let disk_a = scheduler_node("a", SchedulingNodeKind::Disk);
    let mut keys = [
        event_key(2, &vm_b, &vm_a, 0),
        event_key(1, &vm_b, &disk_a, 1),
        event_key(1, &vm_a, &disk_a, 2),
        event_key(1, &vm_a, &disk_a, 1),
    ];

    keys.sort();

    assert_eq!(
        keys,
        [
            event_key(1, &vm_a, &disk_a, 1),
            event_key(1, &vm_a, &disk_a, 2),
            event_key(1, &vm_b, &disk_a, 1),
            event_key(2, &vm_b, &vm_a, 0),
        ]
    );
}

#[test]
fn gate_layer0_determinism_rejects_implicit_schedule_prefixes() {
    let schedule = Schedule::empty().appended(rng_decision("node-a", 1));

    assert_eq!(schedule.prefix(1).as_ref().map(Schedule::len), Ok(1));
    assert!(schedule.prefix(2).is_err());
}

fn assert_twice_reduce_canonical_digest<D, F>(mut reduce: F) -> D
where
    D: Clone + std::fmt::Debug + PartialEq,
    F: FnMut() -> D,
{
    let first = reduce();
    let second = reduce();

    assert_eq!(first, second);

    first
}

fn backend_fingerprint(backend: &mut SimBackend) -> ExecutionFingerprint {
    match backend.fingerprint() {
        Ok(fingerprint) => fingerprint,
        Err(error) => panic!("gate SimBackend fingerprint should be valid: {error:?}"),
    }
}

fn drive_backend(backend: &mut SimBackend, input: BackendInput, horizon: u64) {
    assert_eq!(backend.deliver_input(input), Ok(()));
    assert_eq!(
        backend.advance_to_horizon(ExecutionHorizon {
            icount: Icount { retired: horizon },
        }),
        Ok(AdvanceOutcome::ReachedHorizon)
    );
}

fn rng_decision(stream: &str, value: u64) -> Decision {
    Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name(stream),
        value,
    })
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn scheduler_node(name: &str, kind: SchedulingNodeKind) -> SchedulerNodeId {
    SchedulerNodeId {
        node: node(name),
        kind,
    }
}

fn event_key(
    virtual_time: u64,
    consumer: &SchedulerNodeId,
    producer: &SchedulerNodeId,
    sequence: u64,
) -> ScheduledEventKey {
    ScheduledEventKey::from_parts(
        VirtualTime {
            ticks: virtual_time,
        },
        consumer.clone(),
        producer.clone(),
        sequence,
    )
}
