//! Actual installed linked-source recording and original source retirement.

// crucible-lint: allow panic-shortcut -- Actual source recording and native retirement failures invalidate the original attempt.
// crucible-lint: allow clippy-disallowed-method -- Absolute operational watchdogs bound source process cleanup without entering modeled time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::time::Instant;

use crucible::node_adapters::transcript::{TranscriptAction, TranscriptArchive};
use crucible_campaign::{
    CampaignRepository,
    observed_node_attempt::{ObservedAttemptState, ObservedAttemptWorker},
};
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend};

use super::*;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the current source-built native executable"]
fn actual_recording_refusal_keeps_complete_reserved_native_world_until_reclaimed() {
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let temporary = tempfile::tempdir().unwrap();
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        measure_executable(&executable).unwrap(),
        temporary.path().to_owned(),
        Duration::from_secs(5),
        1,
    )
    .unwrap();
    let selections = vec![
        InstalledNodeSelection {
            node: id("clock"),
            owner: id("clock-owner"),
            kind: InstalledNodeKind::HostClock,
        },
        InstalledNodeSelection {
            node: id("device"),
            owner: id("device-owner"),
            kind: InstalledNodeKind::ReferenceDevice {
                quantum_ps: U64::new(50),
                host_budget_ns: U64::new(20_000_000),
            },
        },
    ];
    let scenario = catalog.scenario(&selections).unwrap();
    let configuration = NodeRunConfiguration {
        format: "crucible.node-run-configuration".into(),
        version: 1,
        horizon_ps: U64::new(50),
        maximum_rounds: U64::new(8),
    };

    let result = catalog.prepare_recorded_world(
        &selections,
        scenario,
        &configuration,
        ExecutionId::from_bytes([92; 16]).unwrap(),
        TranscriptLimits {
            maximum_records: U64::new(8),
            maximum_record_bytes: U64::new(32),
            maximum_total_bytes: U64::new(32),
        },
    );
    let error = match result {
        Ok(_) => panic!("impossible source capture reservation was admitted"),
        Err(error) => error,
    };
    assert!(
        matches!(&error, NodeObservedError::Native(cause) if cause == "CaptureLimit"),
        "actual source refusal: {error}"
    );
    assert_eq!(catalog.custody().reserved_worlds(), 1);
    assert_eq!(catalog.custody().retained_worlds(), 1);

    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    let deadline = Instant::now() + Duration::from_secs(10);
    while catalog.custody().reserved_worlds() != 0 {
        if let std::task::Poll::Ready(Err(error)) = catalog.custody().poll_reclamation(&mut context)
        {
            panic!("retained native source reclamation failed: {error:?}");
        }
        assert!(
            Instant::now() < deadline,
            "refused native world remains alive"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(catalog.custody().retained_worlds(), 0);
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the current source-built native executable"]
fn actual_direct_native_source_records_complete_original_inputs_before_retirement() {
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let temporary = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "installed-recording",
        temporary.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(temporary.path().join("refs")));
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        measure_executable(&executable).unwrap(),
        temporary.path().to_owned(),
        Duration::from_secs(5),
        2,
    )
    .unwrap();
    let selections = vec![
        InstalledNodeSelection {
            node: id("consumer"),
            owner: id("consumer-owner"),
            kind: InstalledNodeKind::ReferenceNativeLinked {
                quantum_ps: U64::new(50),
                host_budget_ns: U64::new(20_000_000),
                closed_ingress: false,
            },
        },
        InstalledNodeSelection {
            node: id("producer"),
            owner: id("producer-owner"),
            kind: InstalledNodeKind::ReferenceNativeLinked {
                quantum_ps: U64::new(50),
                host_budget_ns: U64::new(20_000_000),
                closed_ingress: true,
            },
        },
    ];
    let scenario = catalog.scenario(&selections).unwrap();
    let run_configuration = NodeRunConfiguration {
        format: "crucible.node-run-configuration".into(),
        version: 1,
        horizon_ps: U64::new(150),
        maximum_rounds: U64::new(32),
    };
    let execution = ExecutionId::from_bytes([91; 16]).unwrap();
    let InstalledRecordedWorld {
        prepared,
        recording,
    } = catalog
        .prepare_recorded_world(
            &selections,
            scenario.clone(),
            &run_configuration,
            execution,
            TranscriptLimits {
                maximum_records: U64::new(128),
                maximum_record_bytes: U64::new(1024 * 1024),
                maximum_total_bytes: U64::new(16 * 1024 * 1024),
            },
        )
        .unwrap();
    let context =
        super::super::super::backend::input_context_bytes(&scenario, &run_configuration).unwrap();
    let inputs = ContentId::for_bytes(ObjectKind::Trace, 1, &context);
    assert!(
        blobs
            .put_if_absent(inputs, &BlobHandle::from_bytes(context))
            .unwrap()
            .is_durable()
    );
    let publisher = StoredWorldActivationPublisher::new(
        blobs.clone(),
        refs.clone(),
        RefName::new("node-world-activations/recording".to_owned()).unwrap(),
    )
    .unwrap();
    let backend = NodeObservedBackend::from_prepared(
        prepared,
        run_configuration.clone(),
        Box::new(publisher),
        blobs.clone(),
        inputs,
        execution,
    )
    .unwrap();
    let scenario = backend.scenario_artifact();
    repository
        .publish_scenario_artifact(
            scenario.scenario(),
            scenario.payload_schema(),
            scenario.payload().to_vec(),
        )
        .unwrap();
    let configuration = backend.configuration_artifact();
    repository
        .publish_configuration_artifact(
            configuration.scenario(),
            configuration.scenario_artifact(),
            configuration.configuration(),
            configuration.payload_schema(),
            configuration.payload().to_vec(),
        )
        .unwrap();
    let request = backend.request(execution).unwrap();
    let admission = backend.admission().clone();
    let mut worker = ObservedAttemptWorker::new(repository.clone(), backend, 1).unwrap();
    let _gc = repository.acquire_gc_exclusion_guard().unwrap();
    worker
        .submit("installed-recording", &request, &admission)
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match worker.poll(execution).unwrap() {
            ObservedAttemptState::Completed(_) => break,
            ObservedAttemptState::Quarantined { reason, .. } => {
                panic!("actual recorded native world quarantined: {reason}");
            }
            ObservedAttemptState::Reserved(_) => {}
        }
        assert!(Instant::now() < deadline, "native recording stalled");
        std::thread::sleep(Duration::from_millis(1));
    }

    let archive = TranscriptArchive::open(
        temporary.path().join("transcripts"),
        TranscriptLimits {
            maximum_records: U64::new(128),
            maximum_record_bytes: U64::new(1024 * 1024),
            maximum_total_bytes: U64::new(16 * 1024 * 1024),
        },
    )
    .unwrap();
    let recorded = recording.persist(&archive).unwrap();
    assert_eq!(recorded.len(), 2);
    let consumer = recorded.get(&id("consumer")).unwrap();
    assert_eq!(
        consumer.transcript().origin.repeatability,
        crucible_node_contract::Repeatability::Nondeterministic
    );
    assert!(
        consumer
            .transcript()
            .records
            .iter()
            .any(|record| record.request.action == TranscriptAction::StageInput)
    );
    assert!(
        consumer
            .transcript()
            .records
            .iter()
            .any(|record| !record.evidence.is_empty())
    );
    for source in recorded.values() {
        for record in &source.transcript().records {
            let response: serde_json::Value =
                serde_json::from_slice(&record.response_bytes).unwrap();
            let required = match response["kind"].as_str() {
                Some("observation") => {
                    let observation: crucible::node_scheduling::NativeSchedulingObservation =
                        serde_json::from_value(response["value"].clone()).unwrap();
                    let mut references = vec![observation.proof_ref];
                    references.extend(observation.bounds.into_iter().map(|bound| bound.proof_ref));
                    if let Some(progress) = observation.input_progress {
                        references.push(progress.proof_ref);
                    }
                    references
                }
                Some("input") => {
                    let acknowledgement: crucible::node_scheduling::NativeInputAcknowledgement =
                        serde_json::from_value(response["value"].clone()).unwrap();
                    vec![acknowledgement.proof_ref]
                }
                _ => Vec::new(),
            };
            for reference in required {
                let original = record
                    .evidence
                    .iter()
                    .find(|object| object.reference == reference)
                    .expect("native observe/stage proof body must survive source retirement");
                original.reference.verify(&original.bytes).unwrap();
            }
        }
    }

    for source in recorded.values() {
        let origin = &source.transcript().origin;
        let binding = origin
            .context
            .iter()
            .find(|object| object.reference == origin.source_binding)
            .unwrap();
        let binding: crucible_node_contract::NodeBinding =
            serde_json::from_slice(&binding.bytes).unwrap();
        let enrollment = origin
            .context
            .iter()
            .find(|object| object.reference == binding.authority.host_receipt)
            .expect("actual original enrolled receipt bytes must survive retirement");
        enrollment.reference.verify(&enrollment.bytes).unwrap();
        let manifest = origin
            .context
            .iter()
            .find(|object| object.reference.media_type == context_fragments::FRAGMENT_MEDIA_TYPE)
            .expect("the complete original source context exceeds one portable byte array");
        let original = context_fragments::reconstruct_source_object(
            manifest,
            &origin.context,
            64 * 1024 * 1024,
        )
        .unwrap();
        assert!(original.bytes.len() > 65_536);
        assert_eq!(
            original.reference.media_type,
            "application/vnd.crucible.installed-reference-recording-context+json"
        );
    }

    let mut changed_configuration = run_configuration.clone();
    changed_configuration.horizon_ps = U64::new(100);
    assert!(
        catalog
            .select_conditional_replay(recorded.clone(), &changed_configuration)
            .is_err()
    );
    // The fresh model has its own reserved supervision queue. Its inactive
    // custody must not be counted as an outstanding original physical owner.
    let production_catalog = InstalledNodeCatalog::new(
        executable.clone(),
        measure_executable(&executable).unwrap(),
        temporary.path().to_owned(),
        Duration::from_secs(5),
        1,
    )
    .unwrap();
    let production_execution = ExecutionId::from_bytes([99; 16]).unwrap();
    let production = production_catalog
        .select_conditional_replay(recorded.clone(), &run_configuration)
        .unwrap()
        .prepare(&production_catalog, production_execution)
        .unwrap();
    let second_catalog = InstalledNodeCatalog::new(
        executable.clone(),
        measure_executable(&executable).unwrap(),
        temporary.path().to_owned(),
        Duration::from_secs(5),
        1,
    )
    .unwrap();
    let second_execution = ExecutionId::from_bytes([100; 16]).unwrap();
    let production_second = second_catalog
        .select_conditional_replay(recorded.clone(), &run_configuration)
        .unwrap()
        .prepare(&second_catalog, second_execution)
        .unwrap();
    assert_eq!(
        production.world.scenario.artifact().unwrap(),
        production_second.world.scenario.artifact().unwrap()
    );
    assert_ne!(
        production.activation.owners,
        production_second.activation.owners
    );

    let verified =
        source_enrollment::verify_original_world(&catalog, recorded.clone(), &run_configuration)
            .unwrap();
    let mut original_plan = replay_execution::OriginalPlan::new(&verified).unwrap();
    let ordinary = cursor_allocation::CursorAllocation::allocate(
        &catalog,
        verified.clone(),
        ExecutionId::from_bytes([96; 16]).unwrap(),
    )
    .unwrap();
    let ordinary_graph = ordinary.admit_graph().unwrap();
    assert!(ordinary_graph.node_ids().all(|node| {
        ordinary_graph.guarantees(node).unwrap().capture_scope
            == crucible_node_contract::CaptureScope::None
    }));
    drop(ordinary_graph);
    drop(ordinary);
    let replay_allocation = std::rc::Rc::new(
        cursor_allocation::CursorAllocation::allocate_preserving(
            &catalog,
            verified,
            ExecutionId::from_bytes([93; 16]).unwrap(),
        )
        .unwrap(),
    );
    let replay = replay_allocation.prepare().unwrap();
    assert_eq!(replay.nodes.len(), 2);
    assert_eq!(replay.record.owners.len(), 2);
    assert_eq!(
        replay.graph.world_repeatability(),
        crucible_node_contract::Repeatability::Nondeterministic
    );
    assert_eq!(
        replay.configuration.horizon_ps,
        run_configuration.horizon_ps
    );
    assert_eq!(
        replay.scenario.world.identity().unwrap(),
        replay.record.world_binding_hash
    );

    drop(worker);
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    let deadline = Instant::now() + Duration::from_secs(10);
    while catalog.custody().reserved_worlds() != 0 {
        if let std::task::Poll::Ready(Err(error)) = catalog.custody().poll_reclamation(&mut context)
        {
            panic!("original native reclamation failed: {error:?}");
        }
        assert!(
            Instant::now() < deadline,
            "original native source remains alive"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    drop(catalog);
    drop(_gc);
    production_tests::drive_store_failures(
        recorded.clone(),
        executable.clone(),
        temporary.path().to_owned(),
        run_configuration.clone(),
    );
    production_tests::drive_service_original(production_tests::ServiceReplayFixture {
        archive,
        sources: recorded
            .iter()
            .map(|(node, source)| (node.clone(), source.reference().clone()))
            .collect(),
        executable: executable.clone(),
        private_root: temporary.path().to_owned(),
        configuration: run_configuration.clone(),
        repository: repository.clone(),
        blobs: blobs.clone(),
        refs: refs.clone(),
    });
    // Authenticate the source once, then remove its retrieval namespace before
    // any fresh replay response. The fresh node owns complete signed raw bytes.
    std::fs::remove_dir_all(temporary.path().join("transcripts")).unwrap();
    let first_plan = production_tests::drive_original_recipe(
        production,
        production_execution,
        blobs.clone(),
        refs.clone(),
        repository.clone(),
    );
    let second_plan = production_tests::drive_original_recipe(
        production_second,
        second_execution,
        blobs.clone(),
        refs.clone(),
        repository.clone(),
    );
    assert_eq!(
        first_plan, second_plan,
        "fresh operational nonce changed semantic replay identity"
    );
    // Even after native source death, the installed policy refuses a changed
    // raw context or its order before any fresh readiness or replay response.
    for node in &replay.nodes {
        let route = node.route();
        let source = replay_allocation.source_for(&route.node).unwrap();
        let original_context = &source.transcript().origin.context;
        let mut changed = original_context.clone();
        changed[0].bytes.push(b' ');
        changed[0].reference =
            canonical::content_ref(&changed[0].bytes, &changed[0].reference.media_type).unwrap();
        assert!(
            crucible::node_adapters::transcript::TranscriptReplayNode::prepare(
                source.clone(),
                &replay.graph,
                route.clone(),
                &changed,
                replay_allocation.as_ref(),
            )
            .is_err()
        );

        assert!(original_context.len() >= 2);
        let mut reordered = original_context.clone();
        reordered.swap(0, 1);
        assert!(
            crucible::node_adapters::transcript::TranscriptReplayNode::prepare(
                source.clone(),
                &replay.graph,
                route.clone(),
                &reordered,
                replay_allocation.as_ref(),
            )
            .is_err()
        );
    }
    let replay_queue = crucible::node_contract::RuntimeCustodyQueue::new(1).unwrap();
    let replay_limits = crucible::node_contract::RuntimeLimits::default();
    let replay_slot = replay_queue
        .reserve_world(&replay.record, replay_limits)
        .unwrap();
    let replay_record = replay.record.clone();
    let mut replay_runtime = crucible::node_contract::NodeRuntime::new(
        &replay.graph,
        replay.nodes,
        replay.record,
        replay_limits,
        replay_slot,
    )
    .unwrap_or_else(|failure| panic!("actual replay preparation failed: {}", failure.error));
    replay_runtime.arm_all().unwrap();
    let mut replay_publisher = StoredWorldActivationPublisher::new(
        blobs.clone(),
        refs.clone(),
        RefName::new("node-world-activations/original-replay".to_owned()).unwrap(),
    )
    .unwrap();
    let initial_coordinator = replay_runtime
        .initial_coordinator_snapshot(&replay.graph, 1024 * 1024)
        .unwrap();
    replay_publisher = replay_publisher
        .with_prepared_coordinator(
            replay_record,
            replay_runtime.prepared_node_records().unwrap().to_vec(),
            initial_coordinator,
        )
        .unwrap();
    let replay_activation = replay_runtime.activate(&mut replay_publisher).unwrap();
    let replay_outcomes = original_plan
        .execute_to_retained_cut(&mut replay_runtime, &replay.graph, &replay_activation)
        .unwrap();
    let archive_limits = crucible::node_state::NativeArchiveLimits {
        state: crucible::node_state::StateLimits {
            maximum_content_bytes: 512 * 1024 * 1024,
            maximum_total_content_bytes: 2 * 1024 * 1024 * 1024,
            ..crucible::node_state::StateLimits::default()
        },
        ..crucible::node_state::NativeArchiveLimits::default()
    };
    let replay_archive = crucible::node_state::NativeArchive::open(
        temporary.path().join("replay-native-archive"),
        archive_limits,
    )
    .unwrap();
    let replay_factory = continuation_factory::ReplayArchiveFactory {
        allocation: replay_allocation.clone(),
    };
    let requirements = crucible::node_state::StateRequirements {
        preservation_contract: id("transcript/complete-replay-continuation-v1"),
        exact_model_continuation: true,
        deterministic: false,
        restore_mode: crucible::node_state::StateRestoreMode::DurableRestart,
    };
    let cut = {
        let scheduler = replay_runtime
            .scheduler(&replay.graph, &replay_activation)
            .unwrap();
        replay
            .graph
            .node_ids()
            .map(|node| scheduler.position(node).unwrap())
            .min()
            .unwrap()
    };
    let replay_capture = replay_archive
        .capture_world_typed(
            &replay.graph,
            &mut replay_runtime,
            &replay_activation,
            cut,
            U64::new(1),
            id("original-held-replay"),
            requirements.clone(),
            &replay_factory,
            &replay_factory,
        )
        .unwrap();
    let original_snapshot = replay_capture.runtime_snapshot().unwrap();
    assert!(!original_snapshot.pending_acknowledgements().is_empty());
    assert!(
        original_snapshot
            .inputs
            .iter()
            .any(|input| !input.deliveries.is_empty() && input.acknowledgement.is_some())
    );
    let branch_queue = crucible::node_contract::RuntimeCustodyQueue::new(4).unwrap();
    let mut cold_branches = Vec::new();
    for branch in [94u8, 95u8] {
        let fresh = std::rc::Rc::new(
            replay_allocation
                .fresh_branch(
                    &replay_capture,
                    ExecutionId::from_bytes([branch; 16]).unwrap(),
                )
                .unwrap(),
        );
        let (driver, capture) = continuation_restore::ReplayColdDriver::prepare(
            fresh,
            &replay_capture,
            requirements.clone(),
            branch_queue.clone(),
        )
        .unwrap();
        let mut plan = replay_execution::OriginalPlan::new(replay_allocation.source()).unwrap();
        plan.restore_offsets(&driver.cursors().unwrap()).unwrap();
        cold_branches.push((driver, capture, plan));
    }
    let remaining_outcomes = original_plan
        .execute(&mut replay_runtime, &replay.graph, &replay_activation)
        .unwrap();
    assert!(!remaining_outcomes.is_empty());
    assert!(!replay_outcomes.is_empty());
    assert_eq!(
        replay_runtime
            .scheduler(&replay.graph, &replay_activation)
            .unwrap()
            .position(&id("consumer"))
            .unwrap()
            .time_ps,
        run_configuration.horizon_ps
    );
    assert_eq!(
        replay_runtime
            .scheduler(&replay.graph, &replay_activation)
            .unwrap()
            .position(&id("producer"))
            .unwrap()
            .time_ps,
        run_configuration.horizon_ps
    );
    drop(replay_runtime);
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    while replay_queue.reserved_worlds() != 0 {
        if let std::task::Poll::Ready(Err(error)) = replay_queue.poll_reclamation(&mut context) {
            panic!("fresh replay custody reclamation failed: {error:?}");
        }
    }
    drop(replay_capture);
    drop(replay_archive);
    std::fs::remove_dir_all(temporary.path().join("replay-native-archive")).unwrap();
    for (mut driver, capture, mut plan) in cold_branches {
        let graph = driver.graph.clone();
        let target = driver.target.clone();
        let prepared = crucible::node_state::stage_restore(
            &graph,
            capture,
            target,
            &mut driver,
            archive_limits.state,
        )
        .unwrap_or_else(|failure| {
            panic!(
                "actual eager replay restore preparation failed: {:?}",
                failure.error
            )
        });
        let publisher = StoredWorldActivationPublisher::new(
            blobs.clone(),
            refs.clone(),
            RefName::new(format!(
                "node-world-activations/{}",
                driver.target.activation_id
            ))
            .unwrap(),
        )
        .unwrap();
        let mut publisher = driver.publisher(publisher).unwrap();
        let mut restored = match prepared.publish(&mut publisher) {
            crucible::node_state::RestorePublication::Committed(restored) => restored,
            crucible::node_state::RestorePublication::Failed(failure) => panic!(
                "actual complete replay publication failed: {:?}",
                failure.error
            ),
            crucible::node_state::RestorePublication::Uncertain(_) => {
                panic!("actual complete replay publication is uncertain")
            }
        };
        let activation = restored.activation().clone();
        let before = restored
            .runtime_mut()
            .runtime_snapshot(activation.record().boundary, U64::new(1), 16 * 1024 * 1024)
            .unwrap();
        assert_eq!(before.operations.len(), original_snapshot.operations.len());
        assert_eq!(before.inputs.len(), original_snapshot.inputs.len());
        assert_eq!(
            before.pending_acknowledgements(),
            original_snapshot.pending_acknowledgements()
        );
        let outcomes = plan
            .execute(restored.runtime_mut(), &graph, &activation)
            .unwrap();
        assert_eq!(outcomes.len(), remaining_outcomes.len());
        for (actual, original) in outcomes.iter().zip(&remaining_outcomes) {
            assert_eq!(actual.operation, original.operation);
            assert_eq!(actual.retained_outputs, original.retained_outputs);
            assert_eq!(actual.progress, original.progress);
        }
        assert_eq!(
            restored.world_repeatability(),
            crucible_node_contract::Repeatability::Nondeterministic
        );
        for node in [id("consumer"), id("producer")] {
            assert_eq!(
                restored
                    .runtime_mut()
                    .scheduler(&graph, &activation)
                    .unwrap()
                    .position(&node)
                    .unwrap()
                    .time_ps,
                run_configuration.horizon_ps
            );
        }
        drop(restored);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        while branch_queue.retained_worlds() != 0 {
            if let std::task::Poll::Ready(Err(error)) = branch_queue.poll_reclamation(&mut context)
            {
                panic!("restored replay custody reclamation failed: {error:?}");
            }
        }
    }
    assert_eq!(branch_queue.reserved_worlds(), 0);
    for source in recorded.values() {
        assert_eq!(
            source.transcript().origin.attempt,
            id(&format!("observed/{}", execution_text(execution)))
        );
    }
}
