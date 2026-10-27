//! Event-log continuation wire validation, restore, and streaming tests.

use super::*;

fn scheduler() -> SingleScheduler {
    let node = SchedulerScenarioNode {
        id: SchedulerNodeId {
            node: NodeId {
                name: String::from("a"),
            },
            kind: SchedulingNodeKind::Vm,
        },
        counter: NodeCounter { ticks: 11 },
        activity: SchedulerNodeActivity::Runnable,
        network_lookahead: NetworkLookahead::Infinite,
        exact_local_event: ExactLocalEvent::NoArmedTimer,
    };
    SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "event-log-continuation",
        16,
        SimInstant { ticks: 64 },
        vec![node],
        Vec::new(),
    ))
    .unwrap_or_else(|error| panic!("scheduler should build: {error}"))
}

fn console(bytes: &[u8]) -> ObservableEvent {
    ObservableEvent::console_output(
        VirtualTime { ticks: 11 },
        NodeId {
            name: String::from("a"),
        },
        bytes.to_vec(),
    )
}

/// Returns a scheduler with two appends and its continuation.
fn appended() -> (SingleScheduler, SingleSchedulerCheckpoint) {
    let mut scheduler = scheduler();
    for bytes in [b"first".as_slice(), b"second-append"] {
        QuantumLoop::append_backend_observable_events(&mut scheduler, vec![console(bytes)])
            .unwrap_or_else(|error| panic!("console output should append: {error}"));
    }
    let checkpoint = scheduler
        .checkpoint()
        .unwrap_or_else(|error| panic!("scheduler checkpoint should capture: {error}"));
    (scheduler, checkpoint)
}

#[test]
fn continuation_carries_the_tail_and_the_latest_append_length() {
    let (scheduler, checkpoint) = appended();
    let wire = &checkpoint.wire.event_log;

    assert!(wire.segments.is_empty());
    assert_eq!(wire.base_events, 0);
    assert_eq!(wire.tail, scheduler.event_log().retained_entries().to_vec());
    assert_eq!(wire.last_append_entries, 1);
    assert_eq!(wire.offset(), scheduler.event_log().offset());
}

#[test]
fn restore_refuses_a_tail_that_does_not_derive_the_appended_segment() {
    let (_, checkpoint) = appended();

    // A valid entry at the same sequence still changes the latest append.
    let mut forged = checkpoint.clone();
    let last = forged.wire.event_log.tail.len() - 1;
    let original = &forged.wire.event_log.tail[last];
    forged.wire.event_log.tail[last] = SchedulerEventLogEntry::observable(
        original.sequence(),
        original.at(),
        ObservableEventPayload::ConsoleOutput {
            node: NodeId {
                name: String::from("a"),
            },
            bytes: b"forged-append".to_vec(),
        },
    );
    assert_eq!(
        forged.restore_into(&mut scheduler()),
        Err(SingleSchedulerCheckpointError::EventLog)
    );
    assert!(checkpoint.restore_into(&mut scheduler()).is_ok());
}

#[test]
fn validation_refuses_inconsistent_positions() {
    let (_, checkpoint) = appended();
    let mutate = |change: &dyn Fn(&mut EventLogWire)| {
        let mut wire = checkpoint.wire.event_log.clone();
        change(&mut wire);
        wire.validate()
    };

    assert!(mutate(&|_| {}).is_ok());
    assert!(mutate(&|wire| wire.last_append_entries = 0).is_err());
    assert!(mutate(&|wire| wire.last_append_entries = 3).is_err());
    assert!(mutate(&|wire| wire.appended_segment = None).is_err());
    assert!(mutate(&|wire| wire.events += 1).is_err());
    assert!(mutate(&|wire| wire.base_events = 1).is_err());
    assert!(
        mutate(&|wire| {
            wire.tail.remove(0);
        })
        .is_err()
    );
    assert!(
        mutate(&|wire| {
            wire.segments.push(EventLogSegmentRef {
                object: ContentHash::from_bytes(b"segment"),
                first_sequence: 0,
                entry_count: 2,
                encoded_bytes: 64,
            });
        })
        .is_err()
    );
}

#[test]
fn entry_reader_stops_after_a_missing_segment() {
    let (_, checkpoint) = appended();
    let mut forged = checkpoint.clone();
    let tail = std::mem::take(&mut forged.wire.event_log.tail);
    forged.wire.event_log.segments.push(EventLogSegmentRef {
        object: ContentHash::from_bytes(b"absent"),
        first_sequence: 0,
        entry_count: 1,
        encoded_bytes: 64,
    });
    forged.wire.event_log.tail = tail[1..].to_vec();

    let store = MemoryDagStore::new();
    let mut entries = forged.event_log_entries(&store);
    assert_eq!(
        entries.next(),
        Some(Err(SingleSchedulerCheckpointError::EventLog))
    );
    assert_eq!(entries.next(), None);
}
