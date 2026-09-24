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
        Shift::new(0).unwrap_or_else(|error| panic!("zero shift is valid: {error}")),
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
    .unwrap_or_else(|error| panic!("source scheduler is valid: {error}"));

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
    .unwrap_or_else(|error| panic!("source observation is retained: {error}"));
    let checkpoint = source
        .checkpoint()
        .unwrap_or_else(|error| panic!("source scheduler captures: {error}"));
    let expected_segments = source
        .event_log_dependency_objects()
        .unwrap_or_else(|error| panic!("source segments are readable: {error}"));
    assert!(!expected_segments.is_empty());
    let authenticated_objects = expected_segments
        .iter()
        .cloned()
        .collect::<BTreeMap<_, _>>();

    let resumed_store: Arc<dyn DagStore> = Arc::new(MemoryDagStore::new());
    let mut resumed =
        SingleScheduler::new_with_event_log_segment_store(runtime, Arc::clone(&resumed_store))
            .unwrap_or_else(|error| panic!("resumed scheduler is valid: {error}"));
    checkpoint
        .restore_into(&mut resumed)
        .unwrap_or_else(|error| panic!("scheduler continuation restores: {error}"));
    assert!(resumed.event_log_dependency_objects().is_err());

    hydrate_checkpoint_event_log_dependencies(
        &checkpoint,
        &authenticated_objects,
        resumed_store.as_ref(),
    )
    .unwrap_or_else(|error| panic!("authenticated segments hydrate the new run store: {error}"));
    let recaptured = resumed
        .checkpoint()
        .unwrap_or_else(|error| panic!("resumed scheduler captures: {error}"));
    assert_eq!(
        recaptured.event_log_segment_dependencies(),
        checkpoint.event_log_segment_dependencies(),
    );
    assert_eq!(
        resumed
            .event_log_dependency_objects()
            .unwrap_or_else(|error| {
                panic!("resumed capture reads the complete event-log closure: {error}")
            }),
        expected_segments,
    );
}

#[test]
fn event_log_hydration_rejects_changed_bytes_before_writing() {
    let runtime = SchedulerLivenessScenario::from_canonical_material(
        "changed-event-log-runtime",
        Shift::new(0).unwrap_or_else(|error| panic!("zero shift is valid: {error}")),
        8,
        SimInstant { nanos: 8 },
        Vec::new(),
        Vec::new(),
    );
    let source_store: Arc<dyn DagStore> = Arc::new(MemoryDagStore::new());
    let mut source = SingleScheduler::new_with_event_log_segment_store(runtime, source_store)
        .unwrap_or_else(|error| panic!("source scheduler is valid: {error}"));
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
    .unwrap_or_else(|error| panic!("source observation is retained: {error}"));
    let checkpoint = source
        .checkpoint()
        .unwrap_or_else(|error| panic!("source scheduler captures: {error}"));
    let mut objects = source
        .event_log_dependency_objects()
        .unwrap_or_else(|error| panic!("source segments are readable: {error}"))
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let identity = *checkpoint
        .event_log_segment_dependencies()
        .first()
        .unwrap_or_else(|| panic!("source checkpoint retains a segment"));
    objects
        .get_mut(&identity)
        .unwrap_or_else(|| panic!("segment exists"))
        .push(0);

    let resumed_store = MemoryDagStore::new();
    assert!(
        hydrate_checkpoint_event_log_dependencies(&checkpoint, &objects, &resumed_store).is_err()
    );
    assert!(resumed_store.get(&identity).is_err());
}
