//! Restored production scheduler event-log dependency tests.

use super::*;
use crucible::model::MemoryDagStore;

#[test]
fn resumed_capture_reads_authenticated_event_log_segments_from_new_run_store() {
    let scenario = ScenarioDef::from_canonical_material(
        "crucible.test.production-event-log-restore",
        "resumed-capture",
    );
    let runtime = SchedulerLivenessScenario::from_canonical_material(
        "resumed-capture-runtime",
        Shift::new(0).expect("zero shift is valid"),
        8,
        SimInstant { nanos: 8 },
        Vec::new(),
        Vec::new(),
    )
    .with_scenario_def(scenario);
    let source_store: Arc<dyn DagStore> = Arc::new(MemoryDagStore::new());
    let mut source = SingleScheduler::new_with_event_log_segment_store(
        runtime.clone(),
        Arc::clone(&source_store),
    )
    .expect("source scheduler is valid");

    QuantumLoop::append_backend_observable_events(
        &mut source,
        vec![ObservableEvent::console_output(
            VirtualTime { ticks: 0 },
            NodeId {
                name: String::from("resumed-node"),
            },
            b"retained-before-resume".to_vec(),
        )],
    )
    .expect("source observation is retained");
    let checkpoint = source.checkpoint().expect("source scheduler captures");
    let expected_segments = source
        .event_log_dependency_objects()
        .expect("source segments are readable");
    assert!(!expected_segments.is_empty());
    let authenticated_objects = expected_segments
        .iter()
        .cloned()
        .collect::<BTreeMap<_, _>>();

    let resumed_store: Arc<dyn DagStore> = Arc::new(MemoryDagStore::new());
    let mut resumed =
        SingleScheduler::new_with_event_log_segment_store(runtime, Arc::clone(&resumed_store))
            .expect("resumed scheduler is valid");
    checkpoint
        .restore_into(&mut resumed)
        .expect("scheduler continuation restores");
    assert!(resumed.event_log_dependency_objects().is_err());

    hydrate_checkpoint_event_log_dependencies(
        &checkpoint,
        &authenticated_objects,
        resumed_store.as_ref(),
    )
    .expect("authenticated segment bytes hydrate the new run store");
    let recaptured = resumed.checkpoint().expect("resumed scheduler captures");
    assert_eq!(
        recaptured.event_log_segment_dependencies(),
        checkpoint.event_log_segment_dependencies(),
    );
    assert_eq!(
        resumed
            .event_log_dependency_objects()
            .expect("resumed capture reads the complete event-log closure"),
        expected_segments,
    );
}

#[test]
fn event_log_hydration_rejects_changed_bytes_before_writing() {
    let runtime = SchedulerLivenessScenario::from_canonical_material(
        "changed-event-log-runtime",
        Shift::new(0).expect("zero shift is valid"),
        8,
        SimInstant { nanos: 8 },
        Vec::new(),
        Vec::new(),
    );
    let source_store: Arc<dyn DagStore> = Arc::new(MemoryDagStore::new());
    let mut source = SingleScheduler::new_with_event_log_segment_store(runtime, source_store)
        .expect("source scheduler is valid");
    QuantumLoop::append_backend_observable_events(
        &mut source,
        vec![ObservableEvent::console_output(
            VirtualTime { ticks: 0 },
            NodeId {
                name: String::from("resumed-node"),
            },
            b"retained-before-resume".to_vec(),
        )],
    )
    .expect("source observation is retained");
    let checkpoint = source.checkpoint().expect("source scheduler captures");
    let mut objects = source
        .event_log_dependency_objects()
        .expect("source segments are readable")
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let identity = *checkpoint
        .event_log_segment_dependencies()
        .first()
        .expect("source checkpoint retains a segment");
    objects.get_mut(&identity).expect("segment exists").push(0);

    let resumed_store = MemoryDagStore::new();
    assert!(
        hydrate_checkpoint_event_log_dependencies(&checkpoint, &objects, &resumed_store).is_err()
    );
    assert!(resumed_store.get(&identity).is_err());
}
