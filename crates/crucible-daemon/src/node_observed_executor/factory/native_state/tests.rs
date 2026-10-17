//! Actual installed mixed-world cold witnesses with no constructed native seals.

// Panics report failures of actual original custody and complete native reconstruction.
// crucible-lint: allow panic-shortcut -- These native state tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    os::unix::fs::PermissionsExt,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{
        ActivationRecord, BeginResult, NodeRuntime, OperationOutcome, OperationToken,
        SavedRuntimeResult,
    },
    node_dispatch::DispatchRound,
    node_state::{
        NativeArchive, NativeArchiveLimits, NativeArchiveRecord, NativeWorldRestoreDriver,
        PublicationKnowledge, RestorePublication, RestoredWorld, StateLimits, StateRequirements,
        StateRestoreMode, stage_restore,
    },
};
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, RefName,
};
use crucible_node_contract::{Id, U64};

use super::{factory::MixedNativeFactory, installed::InstalledMixedEngine};
use crate::node_observed_executor::StoredWorldActivationPublisher;

#[test]
#[ignore = "requires the compiled source-built complete gem5 closed profile"]
fn pending_native_budget_prefix_survives_source_death_in_two_complete_worlds() {
    cold_world_witness("x86_64", false, false);
}

#[test]
#[ignore = "requires the compiled source-built complete gem5 closed profile"]
fn held_native_publication_survives_source_death_in_two_complete_worlds() {
    cold_world_witness("aarch64", true, false);
}

#[test]
fn ordinary_closed_selection_requires_original_complete_owner_roster() {
    use super::super::{InstalledNodeKind, InstalledNodeSelection};

    let selected = vec![
        InstalledNodeSelection {
            node: id("clock"),
            owner: id("owner/clock"),
            kind: InstalledNodeKind::HostClock,
        },
        InstalledNodeSelection {
            node: id("cpu"),
            owner: id("owner/cpu"),
            kind: InstalledNodeKind::Gem5Closed {
                isa: super::control::InstalledGem5Isa::X86_64,
            },
        },
    ];
    assert!(super::public_catalog::selected_isa(&selected).is_ok());

    let mut foreign = selected.clone();
    foreign[1].owner = id("owner/foreign");
    assert!(super::public_catalog::selected_isa(&foreign).is_err());
    foreign = selected.clone();
    foreign.swap(0, 1);
    assert!(super::public_catalog::selected_isa(&foreign).is_err());
    assert!(super::public_catalog::selected_isa(&selected[1..]).is_err());
    foreign = selected;
    foreign[1].kind = InstalledNodeKind::HostClock;
    assert!(super::public_catalog::selected_isa(&foreign).is_err());
}

#[test]
#[ignore = "requires measured installed RF assets and explicit genuine companion; spawns no native peer"]
fn ordinary_public_profile_refuses_preservation_or_legacy_selection_before_allocation() {
    use super::super::{InstalledNodeCatalog, InstalledNodeKind, InstalledNodeSelection};

    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let companion = std::path::PathBuf::from(
        std::env::var_os("CRUCIBLE_REFERENCE_DEVICE")
            .expect("explicit genuine installed companion is required"),
    );
    let mut catalog = InstalledNodeCatalog::new(
        companion.clone(),
        super::super::measure_executable(&companion).unwrap(),
        directory.path().to_path_buf(),
        Duration::from_secs(30),
        8,
    )
    .unwrap();
    let selected = vec![
        InstalledNodeSelection {
            node: id("clock"),
            owner: id("owner/clock"),
            kind: InstalledNodeKind::HostClock,
        },
        InstalledNodeSelection {
            node: id("cpu"),
            owner: id("owner/cpu"),
            kind: InstalledNodeKind::Gem5Closed {
                isa: super::control::InstalledGem5Isa::X86_64,
            },
        },
    ];
    let expected = catalog.scenario(&selected).unwrap();
    let queue = super::custody::Gem5CustodyQueue::installed(8).unwrap();
    let original_reserved = queue.reserved_owners();
    assert_eq!(catalog.custody().reserved_worlds(), 0);

    let mut preserving = selected.clone();
    preserving[1].kind = InstalledNodeKind::Gem5ClosedPreserving {
        isa: super::control::InstalledGem5Isa::X86_64,
    };
    let preserving_world = catalog.scenario(&preserving).unwrap();
    assert_ne!(
        preserving_world.canonical_bytes().unwrap(),
        expected.canonical_bytes().unwrap()
    );
    for (selection, authored) in [
        (&preserving, expected.clone()),
        (&selected, preserving_world),
    ] {
        assert!(
            catalog
                .prepare_world(
                    selection,
                    authored,
                    crucible_campaign::ExecutionId::from_bytes([76; 16]).unwrap(),
                )
                .is_err()
        );
        assert_eq!(catalog.custody().reserved_worlds(), 0);
        assert_eq!(queue.reserved_owners(), original_reserved);
    }

    let mut capture = expected.clone();
    capture.requirements.exact_capture = true;
    let mut continuation = expected.clone();
    continuation.requirements.exact_continuation = true;
    let mut durable = expected;
    durable.requirements.durable_restart = true;
    let legacy = super::profile::MixedProfile::build(
        super::super::InstalledGem5ClosedProfile::built_in().unwrap(),
        &catalog.host_identity,
        "x86_64",
    )
    .unwrap()
    .scenario;

    for authored in [capture, continuation, durable, legacy] {
        assert!(
            catalog
                .prepare_world(
                    &selected,
                    authored,
                    crucible_campaign::ExecutionId::from_bytes([75; 16]).unwrap(),
                )
                .is_err()
        );
        assert_eq!(catalog.custody().reserved_worlds(), 0);
        assert_eq!(queue.reserved_owners(), original_reserved);
    }
}

#[test]
#[ignore = "requires genuine installed RF native preparation and current closure authority"]
fn original_native_and_clock_prepare_one_complete_public_world() {
    let directory = tempfile::tempdir().unwrap().keep();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let companion = std::path::PathBuf::from(
        std::env::var_os("CRUCIBLE_REFERENCE_DEVICE")
            .expect("explicit genuine installed companion is required"),
    );
    let mut catalog = super::super::InstalledNodeCatalog::new(
        companion.clone(),
        super::super::measure_executable(&companion).unwrap(),
        directory.clone(),
        Duration::from_secs(30),
        8,
    )
    .unwrap();
    let engine =
        InstalledMixedEngine::with_runtime(directory.clone(), catalog.custody().clone()).unwrap();
    let _supervision = FailedWitnessSupervision { engine: &engine };
    let selections = vec![
        super::super::InstalledNodeSelection {
            node: id("clock"),
            owner: id("owner/clock"),
            kind: super::super::InstalledNodeKind::HostClock,
        },
        super::super::InstalledNodeSelection {
            node: id("cpu"),
            owner: id("owner/cpu"),
            kind: super::super::InstalledNodeKind::Gem5Closed {
                isa: super::control::InstalledGem5Isa::X86_64,
            },
        },
    ];
    let scenario = catalog.scenario(&selections).unwrap();
    let execution = crucible_campaign::ExecutionId::from_bytes([73; 16]).unwrap();
    let live = catalog
        .prepare_world(&selections, scenario, execution)
        .unwrap();
    let graph = live.graph;
    for node in graph.node_ids() {
        let guarantee = graph.guarantees(node).unwrap();
        assert_eq!(
            guarantee.capture_scope,
            crucible_node_contract::CaptureScope::None
        );
        assert_eq!(
            guarantee.continuation,
            crucible_node_contract::Continuation::Unsupported
        );
        assert!(!guarantee.durable_restart && !guarantee.isolated_fork);
    }
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "public-native",
        directory.join("cas"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.join("refs")));
    let target = live.realization.activation_record().clone();
    let mut runtime = live
        .realization
        .admit(&graph)
        .unwrap_or_else(|failure| panic!("{}", failure.error));

    runtime.arm_all().unwrap();
    let preparations = runtime.prepared_node_records().unwrap().to_vec();
    assert_eq!(preparations.len(), 2);
    let coordinator = runtime
        .initial_coordinator_snapshot(&graph, 16 * 1024 * 1024)
        .unwrap();
    let stored = StoredWorldActivationPublisher::new(
        blobs.clone(),
        refs.clone(),
        RefName::new("node-world-activations/public-native").unwrap(),
    )
    .unwrap()
    .with_prepared_coordinator(target.clone(), preparations, coordinator.clone())
    .unwrap();
    let mut publisher = super::public_catalog::publisher(stored).unwrap();
    let activation = runtime.activate(publisher.as_mut()).unwrap();
    assert_eq!(activation.record(), &target);
    for node in graph.node_ids() {
        let observation = runtime.observe_scheduling(&activation, node).unwrap();
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .accept_boundary_observation(observation)
            .unwrap();
    }
    let admission = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .admit_exact(
            &id("cpu"),
            id("public/original-native-run"),
            U64::new(1_000_000_000),
        )
        .unwrap();
    let BeginResult::Accepted(token) = runtime.begin_admitted(admission).unwrap() else {
        panic!("genuine public native execution was refused");
    };
    let completed = finish_poll(&mut runtime, &token);
    assert_eq!(completed.retained_outputs.len(), 1);
    assert_eq!(
        completed.scheduling.as_ref().unwrap().publications[0]
            .payload_bytes
            .len(),
        8
    );
    assert!(
        runtime
            .initial_coordinator_snapshot(&graph, 16 * 1024 * 1024)
            .is_err()
    );

    drop(runtime);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..6000 {
        match engine.runtime.poll_reclamation(&mut context) {
            Poll::Ready(Ok(())) | Poll::Pending => {}
            Poll::Ready(Err(error)) => panic!("original public native cleanup failed: {error}"),
        }
        if engine.runtime.reserved_worlds() == 0 && engine.native.all_groups_reclaimed() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("actual public native group and whole-world custody did not retire");
}

#[test]
#[ignore = "requires current installed RF native profile and explicit genuine companion"]
fn ordinary_installed_gem5_scenario_executes_through_observed_attempt_worker() {
    use crucible_campaign::{
        CampaignRepository,
        observed_node_attempt::{
            ObservedAttemptOutcome, ObservedAttemptState, ObservedAttemptWorker,
        },
    };
    let directory = tempfile::tempdir().unwrap().keep();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let companion =
        std::path::PathBuf::from(std::env::var_os("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let mut catalog = super::super::InstalledNodeCatalog::new(
        companion.clone(),
        super::super::measure_executable(&companion).unwrap(),
        directory.clone(),
        Duration::from_secs(30),
        8,
    )
    .unwrap();
    let engine =
        InstalledMixedEngine::with_runtime(directory.clone(), catalog.custody().clone()).unwrap();
    let _supervision = FailedWitnessSupervision { engine: &engine };
    let selected = vec![
        super::super::InstalledNodeSelection {
            node: id("clock"),
            owner: id("owner/clock"),
            kind: super::super::InstalledNodeKind::HostClock,
        },
        super::super::InstalledNodeSelection {
            node: id("cpu"),
            owner: id("owner/cpu"),
            kind: super::super::InstalledNodeKind::Gem5Closed {
                isa: super::control::InstalledGem5Isa::X86_64,
            },
        },
    ];
    let scenario = catalog.scenario(&selected).unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "public-native-observed",
        directory.join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.join("refs")));
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
    let execution = crucible_campaign::ExecutionId::from_bytes([74; 16]).unwrap();
    let backend = catalog
        .prepare(
            &selected,
            scenario,
            crate::node_scenario::NodeRunConfiguration {
                format: "crucible.node-run-configuration".into(),
                version: 1,
                horizon_ps: 1_000_000_000.into(),
                maximum_rounds: 64.into(),
            },
            execution,
            blobs.clone(),
            refs.clone(),
        )
        .unwrap();
    let planned = backend.scenario_artifact();
    repository
        .publish_scenario_artifact(
            planned.scenario(),
            planned.payload_schema(),
            planned.payload().to_vec(),
        )
        .unwrap();
    let configured = backend.configuration_artifact();
    repository
        .publish_configuration_artifact(
            configured.scenario(),
            configured.scenario_artifact(),
            configured.configuration(),
            configured.payload_schema(),
            configured.payload().to_vec(),
        )
        .unwrap();
    let request = backend.request(execution).unwrap();
    let admission = backend.admission().clone();
    let mut worker = ObservedAttemptWorker::new(repository.clone(), backend, 1).unwrap();
    let _gc = repository.acquire_gc_exclusion_guard().unwrap();
    worker
        .submit("genuine-public-native", &request, &admission)
        .unwrap();
    let mut result = None;
    for _ in 0..60_000 {
        match worker.poll(execution).unwrap() {
            ObservedAttemptState::Completed(completed) => {
                result = Some(completed);
                break;
            }
            ObservedAttemptState::Quarantined { reason, .. } => {
                panic!("genuine public native observed world quarantined: {reason}")
            }
            ObservedAttemptState::Reserved(_) => {}
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let result = result.expect("original native observed operation exceeded finite watchdog");
    assert_eq!(result.outcome(), ObservedAttemptOutcome::Completed);
    let bytes = blobs
        .read(result.outgoing(), None)
        .unwrap()
        .read_all(16 * 1024 * 1024)
        .unwrap();
    let outgoing: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let mut publications = Vec::new();
    for event in outgoing["events"].as_array().unwrap() {
        let outcome: crucible::node_contract::OperationOutcome =
            serde_json::from_value(event.clone()).unwrap();
        if outcome.node.as_str() == "cpu" {
            publications.extend(outcome.scheduling.unwrap().publications);
        }
    }
    assert_eq!(publications.len(), 1);
    assert_eq!(publications[0].payload_bytes.len(), 8);
    publications[0]
        .payload
        .verify(&publications[0].payload_bytes)
        .unwrap();
    let ObservedAttemptState::Completed(repeated) = worker.poll(execution).unwrap() else {
        panic!("original completed nonce lost its immutable result");
    };
    assert_eq!(repeated, result);
    drop(worker);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..6000 {
        match engine.runtime.poll_reclamation(&mut context) {
            Poll::Ready(Ok(())) | Poll::Pending => {}
            Poll::Ready(Err(error)) => panic!("original observed cleanup failed: {error}"),
        }
        if engine.runtime.reserved_worlds() == 0 && engine.native.all_groups_reclaimed() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("original observed journals and all native groups did not retire");
}

#[test]
#[ignore = "requires genuine source-installed public preparation, images and fresh native authority"]
fn public_preparation_pending_native_survives_source_death_in_two_complete_worlds() {
    cold_world_witness("x86_64", false, true);
}

#[test]
#[ignore = "requires the genuine installed public catalog, planner and cold native images"]
fn ordinary_planner_clock_ack_and_pending_native_survive_two_fresh_worlds() {
    cold_world_witness_with_planner("x86_64", false, true, true);
}

fn cold_world_witness(isa: &str, held_publication: bool, public: bool) {
    cold_world_witness_with_planner(isa, held_publication, public, false);
}

fn cold_world_witness_with_planner(
    isa: &str,
    held_publication: bool,
    public: bool,
    ordinary_planner: bool,
) {
    // Failed native callbacks keep their original backing tree until the owning
    // supervisor proves reclamation. A temporary-directory Drop cannot decide
    // when live images and process-private files are safe to unlink.
    let directory = tempfile::tempdir().unwrap().keep();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut catalog = if public {
        let companion = std::path::PathBuf::from(
            std::env::var_os("CRUCIBLE_REFERENCE_DEVICE")
                .expect("explicit genuine installed companion is required"),
        );
        Some(
            super::super::InstalledNodeCatalog::new(
                companion.clone(),
                super::super::measure_executable(&companion).unwrap(),
                directory.clone(),
                Duration::from_secs(30),
                8,
            )
            .unwrap(),
        )
    } else {
        None
    };
    let engine = match &catalog {
        Some(catalog) => {
            InstalledMixedEngine::with_runtime(directory.clone(), catalog.custody().clone())
                .unwrap()
        }
        None => InstalledMixedEngine::new(directory.clone(), 8).unwrap(),
    };
    let _supervision = FailedWitnessSupervision { engine: &engine };
    let (graph, source_target, realization, factory, namespace) =
        if let Some(catalog) = &mut catalog {
            let selections = vec![
                super::super::InstalledNodeSelection {
                    node: id("clock"),
                    owner: id("owner/clock"),
                    kind: super::super::InstalledNodeKind::HostClock,
                },
                super::super::InstalledNodeSelection {
                    node: id("cpu"),
                    owner: id("owner/cpu"),
                    kind: if ordinary_planner {
                        super::super::InstalledNodeKind::Gem5ClosedEpochPreserving {
                            isa: super::control::InstalledGem5Isa::X86_64,
                        }
                    } else {
                        super::super::InstalledNodeKind::Gem5ClosedPreserving {
                            isa: super::control::InstalledGem5Isa::X86_64,
                        }
                    },
                },
            ];
            let scenario = catalog.scenario(&selections).unwrap();
            let prepared = catalog
                .prepare_native_world(
                    &selections,
                    scenario,
                    crucible_campaign::ExecutionId::from_bytes([78; 16]).unwrap(),
                )
                .unwrap();
            let target = prepared.world.realization.activation_record().clone();
            (
                Rc::new(prepared.world.graph),
                target,
                prepared.world.realization,
                prepared.preservation.factory,
                prepared.preservation.namespace,
            )
        } else {
            let live = engine.prepare_live(isa).unwrap();
            let factory = Rc::new(MixedNativeFactory::for_live(&live, engine.native.clone()));
            (
                live.graph,
                live.target,
                live.realization,
                factory,
                live.namespace,
            )
        };
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "mixed-native",
        directory.join("cas"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.join("refs")));
    let mut runtime = realization
        .admit(&graph)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    runtime.arm_all().unwrap();
    let mut original_publisher = publisher(&blobs, &refs, "original");
    if public {
        let nodes = runtime.prepared_node_records().unwrap().to_vec();
        assert_eq!(nodes.len(), 2);
        assert!(nodes.iter().all(|node| node.prepared_owners().is_some()));
        let coordinator = runtime
            .initial_coordinator_snapshot(&graph, 16 * 1024 * 1024)
            .unwrap();
        original_publisher = original_publisher
            .with_prepared_coordinator(source_target.clone(), nodes, coordinator)
            .unwrap();
    }
    let activation = runtime.activate(&mut original_publisher).unwrap();
    assert_eq!(activation.prepared_owners().is_some(), public);
    engine
        .native
        .record_publication(&source_target, PublicationKnowledge::Committed)
        .unwrap();
    for node in graph.node_ids() {
        let observation = runtime.observe_scheduling(&activation, node).unwrap();
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .accept_boundary_observation(observation)
            .unwrap();
    }
    let (admission, cut) = if ordinary_planner {
        let clock = plan_original_grant(
            &mut runtime,
            &graph,
            &activation,
            "clock",
            "original/clock-grant",
            10,
        );
        let mut round = DispatchRound::start(&mut runtime, vec![clock], 1).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            round.poll(&mut runtime, &mut context),
            Poll::Ready(Ok(()))
        ));
        let publication = round.publish(&mut runtime).unwrap();
        assert_eq!(publication.operations, vec![id("original/clock-grant")]);
        let cut = runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .position(&id("clock"))
            .unwrap();
        assert_eq!(cut.time_ps, U64::new(10));
        let cpu = plan_original_grant(
            &mut runtime,
            &graph,
            &activation,
            "cpu",
            "original/cpu-grant",
            1_000_000_000,
        );
        (cpu, cut)
    } else {
        let admission = runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .admit_exact(
                &id("cpu"),
                id("original/cpu-grant"),
                U64::new(1_000_000_000),
            )
            .unwrap();
        (admission, source_target.boundary)
    };
    let BeginResult::Accepted(original) = runtime.begin_admitted(admission).unwrap() else {
        panic!("actual native grant was refused");
    };
    let mut context = Context::from_waker(Waker::noop());
    assert!(runtime.poll(&original, &mut context).is_pending());
    let held = if held_publication {
        Some(finish_poll(&mut runtime, &original))
    } else {
        None
    };
    if let Some(outcome) = &held {
        assert_eq!(outcome.retained_outputs.len(), 1);
        assert_eq!(
            outcome.scheduling.as_ref().unwrap().publications[0]
                .payload_bytes
                .len(),
            8
        );
    }
    let ordinal = U64::new(17);
    let before = runtime
        .runtime_snapshot(cut, ordinal, 16 * 1024 * 1024)
        .unwrap();
    assert_eq!(
        before.operations.len(),
        if ordinary_planner { 2 } else { 1 }
    );
    assert!(before.inputs.is_empty());
    let original_cpu = before
        .operations
        .iter()
        .find(|operation| operation.route.node == id("cpu"))
        .unwrap();
    assert_eq!(original_cpu.operation, *original.operation());
    assert!(original_cpu.scheduling_commit.is_none());
    if ordinary_planner {
        let clock = before
            .operations
            .iter()
            .find(|operation| operation.route.node == id("clock"))
            .unwrap();
        assert_eq!(clock.operation, id("original/clock-grant"));
        assert!(matches!(clock.result, SavedRuntimeResult::Acknowledged(_)));
        assert!(clock.scheduling_commit.is_some());
    }
    if held_publication {
        assert!(matches!(
            original_cpu.result,
            SavedRuntimeResult::Complete(_)
        ));
    } else {
        assert_eq!(original_cpu.result, SavedRuntimeResult::Pending);
    }
    let limits = archive_limits();
    let archive_path = directory.join("native-archive");
    let archive = NativeArchive::open(&archive_path, limits).unwrap();
    let capture_world = if ordinary_planner {
        NativeArchive::capture_world_typed
    } else {
        NativeArchive::capture_world
    };
    let record = capture_world(
        &archive,
        &graph,
        &mut runtime,
        &activation,
        cut,
        ordinal,
        id("mixed/original-capture"),
        requirements(),
        &factory.immutable(),
        factory.as_ref(),
    )
    .unwrap();
    if public {
        let retry = capture_world(
            &archive,
            &graph,
            &mut runtime,
            &activation,
            cut,
            ordinal,
            id("mixed/original-capture-retry"),
            requirements(),
            &factory.immutable(),
            factory.as_ref(),
        )
        .unwrap();
        assert_eq!(retry.owners(), record.owners());
        // The signed owner state includes the original native capture identity,
        // image hashes and exact role/name roster. A second mechanical capture
        // would change that identity; identical state proves original seal reuse.
        assert_eq!(retry.runtime_snapshot().unwrap(), before);
    }
    assert_eq!(record.owners().len(), 2);
    assert_eq!(record.manifest().owners.len(), 2);
    assert_eq!(record.runtime_snapshot().unwrap(), before);
    if public {
        // These are the bytes actually acknowledged by the durable publisher,
        // not a fresh receipt inferred from a label or current native state.
        let published_id = refs
            .read_ref(&RefName::new("node-world-activations/original").unwrap())
            .unwrap()
            .unwrap();
        let published = blobs
            .read(published_id, None)
            .unwrap()
            .read_all(16 * 1024 * 1024)
            .unwrap();
        for owner in record.owners() {
            let envelope = record.object_bytes(&owner.state, 16 * 1024 * 1024).unwrap();
            let envelope: serde_json::Value = serde_json::from_slice(&envelope).unwrap();
            let world_ref: crucible_node_contract::ContentRef =
                serde_json::from_value(envelope["world_preparation"].clone()).unwrap();
            let world = record.object_bytes(&world_ref, 16 * 1024 * 1024).unwrap();
            let world: serde_json::Value = serde_json::from_slice(&world).unwrap();
            let publication_ref: crucible_node_contract::ContentRef =
                serde_json::from_value(world["publication"].clone()).unwrap();
            assert_eq!(
                record
                    .object_bytes(&publication_ref, 16 * 1024 * 1024)
                    .unwrap(),
                published
            );
            let coordinator_ref: crucible_node_contract::ContentRef =
                serde_json::from_value(world["coordinator"].clone()).unwrap();
            assert_eq!(
                record
                    .object_bytes(&coordinator_ref, 16 * 1024 * 1024)
                    .unwrap(),
                activation.coordinator_snapshot().unwrap().bytes
            );
        }
    }
    let original_scheduler = record.scheduling_snapshot().unwrap();
    assert_eq!(original_scheduler.reservations.len(), 1);
    assert_eq!(
        original_scheduler.reservations[0].operation,
        *original.operation()
    );
    let native_source = record
        .object_bytes(
            &record
                .owners()
                .iter()
                .find(|owner| owner.owner.as_str() == "owner/cpu")
                .unwrap()
                .state,
            16 * 1024 * 1024,
        )
        .unwrap();
    let configuration = record
        .object_bytes(
            &graph.descriptor(&id("cpu")).unwrap().configuration_ref,
            1024 * 1024,
        )
        .unwrap();
    let configuration: serde_json::Value = serde_json::from_slice(&configuration).unwrap();
    let expected_native_credit = match isa {
        "x86_64" => 65_536,
        "aarch64" => 262_144,
        _ => panic!("unknown native witness architecture"),
    };
    assert_eq!(
        configuration["native_poll"]["maximum_events_per_poll"],
        expected_native_credit.to_string()
    );
    let mut native_record: serde_json::Value = serde_json::from_slice(&native_source).unwrap();
    if public {
        let inner: crucible_node_contract::ContentRef =
            serde_json::from_value(native_record["native_state"].clone()).unwrap();
        let bytes = record.object_bytes(&inner, 16 * 1024 * 1024).unwrap();
        native_record = serde_json::from_slice(&bytes).unwrap();
    }
    let prefix_refs: Vec<crucible_node_contract::ContentRef> =
        serde_json::from_value(native_record["native_prefixes"].clone()).unwrap();
    assert!(!prefix_refs.is_empty());
    for reference in &prefix_refs {
        let bytes = record.object_bytes(reference, 16 * 1024 * 1024).unwrap();
        let prefix: crucible_node_provider::gem5::Gem5Completion =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            prefix.original.maximum_events,
            U64::new(expected_native_credit)
        );
    }
    if !held_publication {
        assert_eq!(prefix_refs.len(), 1);
    }
    let artifact = record.artifact().clone();
    let reserved_before = engine.native.reserved_owners();
    let other_isa = if isa == "x86_64" { "aarch64" } else { "x86_64" };
    assert!(engine.prepare_cold(record.clone(), other_isa).is_err());
    assert_eq!(engine.native.reserved_owners(), reserved_before);
    drop(original);
    drop(runtime);
    drop(activation);
    drop(factory);
    drop(graph);
    reclaim(&engine);
    std::fs::remove_dir_all(&namespace).unwrap();
    assert!(!namespace.exists());
    drop(record);
    drop(archive);

    let archive = NativeArchive::open(&archive_path, limits).unwrap();
    let record = archive.load(&artifact).unwrap();
    assert_eq!(
        record
            .object_bytes(
                &record
                    .owners()
                    .iter()
                    .find(|owner| owner.owner.as_str() == "owner/cpu")
                    .unwrap()
                    .state,
                16 * 1024 * 1024
            )
            .unwrap(),
        native_source
    );
    let (mut left_graph, mut left, mut left_factory, left_namespace) =
        restore(&engine, record.clone(), isa, &blobs, &refs, "left", limits);
    let (right_graph, mut right, right_factory, _right_namespace) =
        restore(&engine, record, isa, &blobs, &refs, "right", limits);
    assert_ne!(
        left.activation().record().owners,
        right.activation().record().owners
    );
    assert_eq!(left.activation().record().boundary, cut);
    assert_eq!(right.activation().record().boundary, cut);
    let left_snapshot = left
        .runtime_mut()
        .runtime_snapshot(cut, ordinal, 16 * 1024 * 1024)
        .unwrap();
    let right_snapshot = right
        .runtime_mut()
        .runtime_snapshot(cut, ordinal, 16 * 1024 * 1024)
        .unwrap();
    for saved in [&left_snapshot, &right_snapshot] {
        assert_eq!(saved.capture_cut, before.capture_cut);
        assert_eq!(saved.capture_ordinal, before.capture_ordinal);
        assert!(saved.inputs.is_empty());
        let cpu = saved
            .operations
            .iter()
            .find(|operation| operation.route.node == id("cpu"))
            .unwrap();
        assert_eq!(cpu.operation, original_cpu.operation);
        assert_eq!(cpu.request, original_cpu.request);
        assert_eq!(cpu.scheduling_commit, None);
        if ordinary_planner {
            let original = before
                .operations
                .iter()
                .find(|operation| operation.route.node == id("clock"))
                .unwrap();
            let fresh = saved
                .operations
                .iter()
                .find(|operation| operation.route.node == id("clock"))
                .unwrap();
            assert_eq!(fresh.operation, original.operation);
            assert_eq!(fresh.request, original.request);
            assert_eq!(fresh.scheduling_commit, original.scheduling_commit);
            let SavedRuntimeResult::Acknowledged(mut outcome) = fresh.result.clone() else {
                panic!("original Clock acknowledgement was lost");
            };
            assert_eq!(outcome.owners, fresh.route.owners);
            if let Some(observation) = &mut outcome.scheduling {
                assert_eq!(observation.owners, fresh.route.owners);
                observation.owners = original.route.owners.clone();
            }
            outcome.owners = original.route.owners.clone();
            assert_eq!(SavedRuntimeResult::Acknowledged(outcome), original.result);
        }
    }
    let mut left_activation = left.activation().clone();
    let right_activation = right.activation().clone();
    if public {
        // A current fresh preparation can become a later signed source while
        // retaining the prior original Ready and coordinator bodies unchanged.
        let recaptured = capture_world(
            &archive,
            &left_graph,
            left.runtime_mut(),
            &left_activation,
            cut,
            ordinal,
            id("mixed/restored-capture"),
            requirements(),
            &left_factory.immutable(),
            left_factory.as_ref(),
        )
        .unwrap();
        recaptured
            .admit(&left_graph, requirements(), left_factory.as_ref())
            .unwrap();
        assert_eq!(recaptured.runtime_snapshot().unwrap(), left_snapshot);
        if ordinary_planner {
            let scheduler = recaptured.scheduling_snapshot().unwrap();
            assert_eq!(scheduler.schema_version, 2);
            assert_eq!(
                scheduler.source_generation,
                left_activation.record().generation
            );
            assert_eq!(scheduler.source_boundary, left_activation.record().boundary);
            let epochs = scheduler.original_epochs.as_ref().unwrap();
            assert_eq!(epochs.len(), 1);
            assert_eq!(
                epochs[0].source_generation,
                before.source_activation.generation
            );
            assert_eq!(
                epochs[0].reservations[0].reservation.operation,
                id("original/cpu-grant")
            );
            assert_eq!(
                epochs[0].reservations[0].position.position.time_ps,
                U64::new(0)
            );
            assert_eq!(scheduler.source_boundary.time_ps, U64::new(10));
        }

        for owner in recaptured.owners() {
            let bytes = recaptured
                .object_bytes(&owner.state, 16 * 1024 * 1024)
                .unwrap();
            let wire: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let previous: crucible_node_contract::ContentRef =
                serde_json::from_value(wire["previous"].clone()).unwrap();
            let original = recaptured
                .object_bytes(&previous, 16 * 1024 * 1024)
                .unwrap();
            let original: serde_json::Value = serde_json::from_slice(&original).unwrap();
            assert!(original["previous"].is_null());
        }
        if ordinary_planner {
            let original_epochs = recaptured
                .scheduling_snapshot()
                .unwrap()
                .original_epochs
                .unwrap();
            let retired_activation = left_activation.record().clone();
            drop(left);
            drop(left_factory);
            drop(left_graph);
            reclaim_world(&engine, &retired_activation);
            std::fs::remove_dir_all(&left_namespace).unwrap();
            assert!(!left_namespace.exists());
            let (graph, restored, factory, _namespace) =
                restore(&engine, recaptured, isa, &blobs, &refs, "third", limits);
            left_graph = graph;
            left = restored;
            left_factory = factory;
            left_activation = left.activation().clone();
            assert_eq!(
                left_activation.record().generation,
                retired_activation
                    .generation
                    .checked_add(U64::new(1))
                    .unwrap()
            );
            let third_capture = capture_world(
                &archive,
                &left_graph,
                left.runtime_mut(),
                &left_activation,
                cut,
                ordinal,
                id("mixed/third-capture"),
                requirements(),
                &left_factory.immutable(),
                left_factory.as_ref(),
            )
            .unwrap();
            third_capture
                .admit(&left_graph, requirements(), left_factory.as_ref())
                .unwrap();
            let third_scheduler = third_capture.scheduling_snapshot().unwrap();
            assert_eq!(
                third_scheduler.original_epochs.as_ref(),
                Some(&original_epochs)
            );
            assert_eq!(
                third_scheduler.source_generation,
                left_activation.record().generation
            );
            assert_eq!(third_scheduler.source_boundary, cut);
            assert_eq!(
                third_scheduler.reservations[0].operation,
                id("original/cpu-grant")
            );
            assert_eq!(
                third_scheduler
                    .positions
                    .iter()
                    .find(|position| position.owner == id("owner/cpu"))
                    .unwrap()
                    .position
                    .time_ps,
                U64::new(0)
            );
        }
    }
    let left_original = left
        .runtime_mut()
        .recover(&id("original/cpu-grant"))
        .unwrap();
    let right_original = right
        .runtime_mut()
        .recover(&id("original/cpu-grant"))
        .unwrap();
    let left_outcome = finish_poll(left.runtime_mut(), &left_original);
    let right_outcome = finish_poll(right.runtime_mut(), &right_original);
    let left_publication = &left_outcome.scheduling.as_ref().unwrap().publications[0];
    let right_publication = &right_outcome.scheduling.as_ref().unwrap().publications[0];
    assert_eq!(left_publication, right_publication);
    assert_eq!(left_publication.payload_bytes, expected_checksum());
    if let Some(original) = held {
        assert_eq!(
            &original.scheduling.as_ref().unwrap().publications[0],
            left_publication
        );
    }
    for (runtime, token) in [
        (left.runtime_mut(), &left_original),
        (right.runtime_mut(), &right_original),
    ] {
        let receipt = runtime.scheduling_receipt(token).unwrap();
        let commit = runtime.commit_scheduling_receipt(receipt).unwrap();
        runtime.acknowledge_scheduled(token, &commit).unwrap();
        // The old restored-ready inventory cannot certify genuine later native
        // prefixes, publication custody retirement or changed ACK state.
        assert!(runtime.arm_all().is_err());
    }
    let left_position = left
        .runtime_mut()
        .scheduler(&left_graph, &left_activation)
        .unwrap()
        .position(&id("cpu"))
        .unwrap();
    let right_position = right
        .runtime_mut()
        .scheduler(&right_graph, &right_activation)
        .unwrap()
        .position(&id("cpu"))
        .unwrap();
    assert_eq!(left_position, right_position);
    drop(left_original);
    drop(right_original);
    drop(left);
    drop(right);
    drop(left_factory);
    drop(right_factory);
    reclaim(&engine);
    std::fs::remove_dir_all(directory).unwrap();
}

fn plan_original_grant(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &crucible::node_contract::WorldActivation,
    node: &str,
    operation: &str,
    horizon: u64,
) -> crucible::node_scheduling::ExecutionAdmission {
    let mut input_records = Vec::new();
    let planned: Result<_, crate::node_control::NodeControlError> =
        crate::node_execution::plan_exact_operation(
            runtime,
            crate::node_execution::ExactOperationRequest {
                graph,
                activation,
                node: &id(node),
                horizon: U64::new(horizon),
                names: crate::node_execution::ExactOperationNames {
                    operation: id(operation),
                    stage: id(&format!("{operation}/stage")),
                    batch: id(&format!("{operation}/batch")),
                },
            },
            |record| {
                input_records.push(record);
                Ok(())
            },
        );
    // These installed nodes have no ingress lanes. The actual ordinary planner
    // therefore creates no staging cut or invented zero-port input history.
    assert!(input_records.is_empty());
    planned.unwrap().unwrap()
}

fn restore(
    engine: &InstalledMixedEngine,
    record: NativeArchiveRecord,
    isa: &str,
    blobs: &Arc<dyn ImmutableBlobBackend>,
    refs: &Arc<dyn MutableRefBackend>,
    name: &str,
    limits: NativeArchiveLimits,
) -> (
    Rc<AdmittedGraph>,
    Box<RestoredWorld>,
    Rc<MixedNativeFactory>,
    std::path::PathBuf,
) {
    let plan = engine.prepare_cold(record.clone(), isa).unwrap();
    let public = plan.profile.public_continuation;
    let namespace = plan.namespace.clone();
    let graph = plan.graph.clone();
    let target = plan.target.clone();
    let factory = Rc::new(MixedNativeFactory::for_cold(plan, engine.native.clone()));
    let verified = record
        .admit(&graph, requirements(), factory.as_ref())
        .unwrap();
    let mut driver = NativeWorldRestoreDriver::new(
        graph.clone(),
        record.clone(),
        factory.clone(),
        engine.runtime.clone(),
    )
    .unwrap();
    let prepared = stage_restore(&graph, verified, target.clone(), &mut driver, limits.state)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    let mut stored = publisher(blobs, refs, name);
    let restored = if public {
        let mut source_publisher = super::publication::NativeCustodyPublisher::for_public_restore(
            stored,
            engine.native.clone(),
            &record,
            &target,
        )
        .unwrap();
        let RestorePublication::Committed(restored) = prepared.publish(&mut source_publisher)
        else {
            panic!("actual public restored native world did not commit");
        };
        assert_eq!(restored.activation().prepared_owners().unwrap().len(), 2);
        assert!(restored.activation().coordinator_snapshot().is_some());
        restored
    } else {
        let RestorePublication::Committed(restored) = prepared.publish(&mut stored) else {
            panic!("actual mixed native world did not commit");
        };
        restored
    };
    engine
        .native
        .record_publication(&target, PublicationKnowledge::Committed)
        .unwrap();
    (graph, restored, factory, namespace)
}

fn finish_poll(runtime: &mut NodeRuntime, token: &OperationToken) -> OperationOutcome {
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..4096 {
        match runtime.poll(token, &mut context) {
            Poll::Pending => {}
            Poll::Ready(Ok(outcome)) => return outcome,
            Poll::Ready(Err(error)) => panic!("{error}"),
        }
    }
    panic!("actual fixed guest exceeded bounded native prefix budget");
}

/// Computes the fixed installed ELF's integer/memory checksum independently of
/// either ISA's execution, native event journal or reconstructed child.
fn expected_checksum() -> [u8; 8] {
    let mut arena = vec![0_u64; 262_144 / 8];
    let mut state = 3_u32;
    let mut answer = 0_u64;

    for _ in 0..20_000 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let index = (state & 262_136) as usize / 8;
        arena[index] ^= u64::from(state);
        answer = answer.wrapping_add(arena[index]);
        if state & 1 != 0 {
            answer = answer.wrapping_add(19);
        }
    }

    answer.to_le_bytes()
}

fn reclaim_world(engine: &InstalledMixedEngine, activation: &ActivationRecord) {
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..6000 {
        if let Poll::Ready(Err(error)) = engine.runtime.poll_reclamation(&mut context) {
            panic!("{error}");
        }
        if engine.native.original_group_reclaimed(activation).unwrap() {
            let mut reclaimed = engine.native.take_reclaimed().unwrap();
            let original = reclaimed
                .iter_mut()
                .find(|original| &original.scope.activation == activation)
                .unwrap();
            assert!(original.custody.child.try_wait().unwrap().is_some());
            original.evidence.verify(&original.bytes).unwrap();
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("original source epoch namespace still owns native groups");
}

fn reclaim(engine: &InstalledMixedEngine) {
    let mut context = Context::from_waker(Waker::noop());
    let mut retired = Vec::new();
    for _ in 0..6000 {
        if let Poll::Ready(Err(error)) = engine.runtime.poll_reclamation(&mut context) {
            panic!("{error}");
        }
        if engine.runtime.reserved_worlds() == 0 {
            retired.extend(engine.native.take_reclaimed().unwrap());
        }
        if engine.runtime.reserved_worlds() == 0 && engine.native.reserved_owners() == 0 {
            assert!(!retired.is_empty());
            for original in &mut retired {
                assert!(original.custody.child.try_wait().unwrap().is_some());
                original.evidence.verify(&original.bytes).unwrap();
            }
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("original mixed native process and all helpers were not authentically reaped");
}

/// Keeps the installed cleanup actor and original source backing alive through
/// assertion unwind until actual common-world and native-group reclamation.
struct FailedWitnessSupervision<'a> {
    engine: &'a InstalledMixedEngine,
}

impl Drop for FailedWitnessSupervision<'_> {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        let mut context = Context::from_waker(Waker::noop());
        let mut retired = Vec::new();
        let mut reported_failure = false;
        for _ in 0..6000 {
            let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.engine.runtime.poll_reclamation(&mut context)
            }));
            if !matches!(cleanup, Ok(Poll::Ready(Ok(()))) | Ok(Poll::Pending)) && !reported_failure
            {
                eprintln!("failed mixed witness retains original cleanup obligations");
                reported_failure = true;
            }
            if self.engine.runtime.reserved_worlds() == 0 {
                match self.engine.native.take_reclaimed() {
                    Ok(capsules) => retired.extend(capsules),
                    Err(error) if !reported_failure => {
                        eprintln!("original native retirement remains owned: {error}");
                        reported_failure = true;
                    }
                    Err(_) => {}
                }
            }
            if self.engine.runtime.reserved_worlds() == 0
                && self.engine.native.reserved_owners() == 0
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // A cleanup timeout is never evidence of retirement. The global actor
        // keeps its actual native capsules, and the private tree remains.
        eprintln!("mixed witness original source remains quarantined after cleanup deadline");
    }
}

fn archive_limits() -> NativeArchiveLimits {
    // Native ledgers are small bounded records; checkpoint images use the
    // independently reserved streamed-artifact credits below.
    NativeArchiveLimits {
        state: StateLimits {
            maximum_content_bytes: 512 * 1024 * 1024,
            maximum_total_content_bytes: 2 * 1024 * 1024 * 1024,
            maximum_record_bytes: 16 * 1024 * 1024,
            maximum_native_processes: 8192,
            ..StateLimits::default()
        },
        native: crucible::node_contract::NativeCaptureLimits {
            maximum_objects: 20_000,
            maximum_record_bytes: 16 * 1024 * 1024,
            maximum_total_record_bytes: 64 * 1024 * 1024,
            maximum_artifact_bytes: 2 * 1024 * 1024 * 1024,
            maximum_total_artifact_bytes: 8 * 1024 * 1024 * 1024,
        },
    }
}

fn requirements() -> StateRequirements {
    StateRequirements {
        preservation_contract: id("mixed/native-preservation-v1"),
        exact_model_continuation: true,
        deterministic: true,
        restore_mode: StateRestoreMode::DurableRestart,
    }
}
fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}
fn publisher(
    blobs: &Arc<dyn ImmutableBlobBackend>,
    refs: &Arc<dyn MutableRefBackend>,
    name: &str,
) -> StoredWorldActivationPublisher {
    StoredWorldActivationPublisher::new(
        blobs.clone(),
        refs.clone(),
        RefName::new(format!("node-world-activations/{name}")).unwrap(),
    )
    .unwrap()
}

#[path = "tests/independent_group.rs"]
mod independent_group;
