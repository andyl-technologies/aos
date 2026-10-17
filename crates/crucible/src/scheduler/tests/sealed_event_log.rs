//! Continuations that name sealed event-log segments instead of entries.

use super::*;

/// Raw console payload per append; four appends overflow one seal target.
///
/// A console entry encodes its bytes twice, as an event attribute and as the
/// observable payload, so each append encodes to about 5/16 of the target.
const CONSOLE_CHUNK_BYTES: usize = EVENT_LOG_SEAL_TARGET_BYTES * 5 / 32;

fn store_backed_scheduler(store: &Arc<MemoryDagStore>) -> SingleScheduler {
    let node = test_scenario_node(
        "a",
        11,
        SchedulerNodeActivity::Runnable,
        NetworkLookahead::Infinite,
        ExactLocalEvent::NoArmedTimer,
    );
    let shared: Arc<dyn DagStore> = store.clone();
    SingleScheduler::new_with_event_log_segment_store(
        SchedulerLivenessScenario::from_canonical_material(
            "sealed-event-log",
            16,
            SimInstant { ticks: 64 },
            vec![node],
            Vec::new(),
        ),
        shared,
    )
    .unwrap_or_else(|error| panic!("store-backed scheduler should build: {error}"))
}

fn append_console_chunks(scheduler: &mut SingleScheduler, chunks: usize, fill: u8) {
    for _ in 0..chunks {
        let output = ObservableEvent::console_output(
            VirtualTime { ticks: 11 },
            NodeId {
                name: String::from("a"),
            },
            vec![fill; CONSOLE_CHUNK_BYTES],
        );
        QuantumLoop::append_backend_observable_events(scheduler, vec![output])
            .unwrap_or_else(|error| panic!("console chunk should append: {error}"));
    }
}

fn checkpoint_bytes(scheduler: &SingleScheduler) -> Vec<u8> {
    scheduler
        .checkpoint()
        .and_then(|checkpoint| checkpoint.canonical_bytes())
        .unwrap_or_else(|error| panic!("scheduler checkpoint should encode: {error}"))
}

#[test]
fn long_log_continuation_names_sealed_segments_and_carries_only_the_tail() {
    let store = Arc::new(MemoryDagStore::new());
    let mut scheduler = store_backed_scheduler(&store);
    append_console_chunks(&mut scheduler, 4, 0);

    let log = scheduler.event_log();
    assert_eq!(log.sealed_segments().len(), 1);
    assert_eq!(log.sealed_segments()[0].first_sequence, 0);
    assert_eq!(log.sealed_segments()[0].entry_count, 3);
    assert_eq!(log.tail_entries().len(), 1);

    let checkpoint = scheduler
        .checkpoint()
        .unwrap_or_else(|error| panic!("scheduler checkpoint should capture: {error}"));
    assert_eq!(
        checkpoint.event_log_segments(),
        log.sealed_segments().to_vec()
    );
    assert_eq!(
        checkpoint.event_log_segment_dependencies(),
        vec![log.sealed_segments()[0].object]
    );
    let referenced = checkpoint
        .event_log_entries(store.as_ref())
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("referenced log should read back: {error}"));
    assert_eq!(referenced, log.retained_entries().to_vec());

    // The continuation embeds one console chunk, not the four appended.
    let bytes = checkpoint
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("scheduler checkpoint should encode: {error}"));
    assert!(bytes.len() < 4 * CONSOLE_CHUNK_BYTES, "{}", bytes.len());
    scheduler
        .verify_event_log_segments()
        .unwrap_or_else(|error| panic!("sealed segments should be present: {error}"));
}

#[test]
fn restore_rebuilds_the_condition_prefix_from_sealed_segments() {
    let store = Arc::new(MemoryDagStore::new());
    let mut scheduler = store_backed_scheduler(&store);
    append_console_chunks(&mut scheduler, 5, 0);
    let bytes = checkpoint_bytes(&scheduler);
    let decoded = SingleSchedulerCheckpoint::from_canonical_bytes(&bytes)
        .unwrap_or_else(|error| panic!("scheduler checkpoint should decode: {error}"));

    let mut restored = store_backed_scheduler(&store);
    decoded
        .restore_into(&mut restored)
        .unwrap_or_else(|error| panic!("scheduler checkpoint should restore: {error}"));

    assert_eq!(
        restored.event_log().retained_entries(),
        scheduler.event_log().retained_entries()
    );
    assert_eq!(
        restored.event_log().condition_prefix(),
        scheduler.event_log().condition_prefix()
    );
    assert_eq!(checkpoint_bytes(&restored), bytes);
}

#[test]
fn restore_refuses_a_store_without_the_sealed_segments() {
    let store = Arc::new(MemoryDagStore::new());
    let mut scheduler = store_backed_scheduler(&store);
    append_console_chunks(&mut scheduler, 4, 0);
    let checkpoint = scheduler
        .checkpoint()
        .unwrap_or_else(|error| panic!("scheduler checkpoint should capture: {error}"));

    let mut restored = store_backed_scheduler(&Arc::new(MemoryDagStore::new()));
    assert_eq!(
        checkpoint.restore_into(&mut restored),
        Err(SingleSchedulerCheckpointError::EventLog)
    );
}

#[test]
fn restored_log_seals_where_the_uninterrupted_log_would() {
    let store = Arc::new(MemoryDagStore::new());
    let mut uninterrupted = store_backed_scheduler(&store);
    append_console_chunks(&mut uninterrupted, 2, 0);
    let checkpoint = uninterrupted
        .checkpoint()
        .unwrap_or_else(|error| panic!("scheduler checkpoint should capture: {error}"));
    assert!(checkpoint.event_log_segments().is_empty());

    let mut restored = store_backed_scheduler(&store);
    checkpoint
        .restore_into(&mut restored)
        .unwrap_or_else(|error| panic!("scheduler checkpoint should restore: {error}"));
    append_console_chunks(&mut uninterrupted, 5, 1);
    append_console_chunks(&mut restored, 5, 1);

    assert_eq!(uninterrupted.event_log().sealed_segments().len(), 2);
    assert_eq!(
        restored.event_log().sealed_segments(),
        uninterrupted.event_log().sealed_segments()
    );
    assert_eq!(
        checkpoint_bytes(&restored),
        checkpoint_bytes(&uninterrupted)
    );
}
