//! Exercises actual four-owner native custody and the original pending Block suffix.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Genuine native preparations, signed source closure and original suffix assertions deliberately fail this fixture.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::super::super::{
    InstalledHostIoProfile, InstalledIoArtifact, InstalledNodeCatalog, InstalledNodeKind,
    InstalledNodeSelection, InstalledScriptedSourceProfile, measure_executable,
};
use super::*;
use crucible::node_adapters::{ScriptedRequest, ScriptedRequestKind, ScriptedSource};
use crucible::node_contract::WorldActivation;
use crucible::node_scheduling::NativePublication;
use crucible_device::{BlockRequest, BlockResponse, BlockStatus};
use crucible_node_contract::{ContentRef, canonical};

#[test]
#[ignore = "requires the compiled source-built SE profile and original installed catalog; creates no native child"]
fn preserving_transfer_cut_is_original_and_changed_dependency_refuses_before_birth() {
    let directory = tempfile::tempdir().unwrap();
    let companion =
        std::path::PathBuf::from(std::env::var_os("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let mut catalog = catalog(directory.path(), &companion);
    let (selections, script_ref, base_ref, script_path, base_path) = authored(directory.path());
    catalog
        .install_artifacts(vec![
            InstalledIoArtifact::path(script_path, script_ref),
            InstalledIoArtifact::path(base_path, base_ref),
        ])
        .unwrap();
    let scenario = catalog.independent_native_scenario(&selections).unwrap();
    let original = scenario
        .content
        .iter()
        .find(|body| body.reference == scenario.world.ownership_ref)
        .unwrap();
    let mut ownership: crucible::node_admission::OwnershipPolicy =
        serde_json::from_slice(&original.bytes).unwrap();
    let connection = &scenario.world.connections[0];
    let producer = scenario
        .compatibility
        .iter()
        .find(|binding| binding.node_id == connection.producer.node_id)
        .unwrap();
    let policy = ownership
        .capture_owners
        .iter_mut()
        .find(|owner| owner.owner_id == connection.capture_owner_id)
        .unwrap();

    assert_eq!(policy.dependencies, vec![producer.capture_owner.id.clone()]);
    assert_eq!(catalog.custody().reserved_worlds(), 0);

    policy.dependencies.clear();
    let bytes = canonical::canonical_json(&serde_json::to_value(&ownership).unwrap()).unwrap();
    let reference = canonical::content_ref(&bytes, &original.reference.media_type).unwrap();
    let mut changed = scenario;
    changed.world.ownership_ref = reference.clone();
    changed
        .content
        .push(crate::node_scenario::ScenarioContent { reference, bytes });
    assert!(
        catalog
            .prepare_independent_native_world(
                &selections,
                changed,
                crucible_campaign::ExecutionId::from_bytes([110; 16]).unwrap(),
            )
            .is_err()
    );
    assert_eq!(catalog.custody().reserved_worlds(), 0);
}

#[test]
#[ignore = "requires genuine compiled SE profile, actual original four-owner preparation and complete source-gone native restoration"]
fn original_pending_storage_input_and_cpu_survive_two_fresh_complete_worlds() {
    let directory = tempfile::Builder::new()
        .prefix("gem5-independent-cold-")
        .tempdir()
        .unwrap()
        .keep();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    eprintln!("original independent preservation: {}", directory.display());
    let companion =
        std::path::PathBuf::from(std::env::var_os("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let mut source_catalog = catalog(&directory, &companion);
    let source_engine =
        InstalledMixedEngine::with_runtime(directory.clone(), source_catalog.custody().clone())
            .unwrap();
    let _source_supervision = FailedWitnessSupervision {
        engine: &source_engine,
    };
    let (selections, script_ref, base_ref, script_path, base_path) = authored(&directory);
    source_catalog
        .install_artifacts(vec![
            InstalledIoArtifact::path(script_path.clone(), script_ref.clone()),
            InstalledIoArtifact::path(base_path.clone(), base_ref.clone()),
        ])
        .unwrap();
    let scenario = source_catalog
        .independent_native_scenario(&selections)
        .unwrap();
    let mut changed = scenario.clone();
    changed.requirements.exact_capture = false;
    assert!(
        source_catalog
            .prepare_independent_native_world(
                &selections,
                changed,
                crucible_campaign::ExecutionId::from_bytes([111; 16]).unwrap(),
            )
            .is_err()
    );
    assert_eq!(source_catalog.custody().reserved_worlds(), 0);
    let prepared = source_catalog
        .prepare_independent_native_world(
            &selections,
            scenario,
            crucible_campaign::ExecutionId::from_bytes([112; 16]).unwrap(),
        )
        .unwrap();
    let graph = Rc::new(prepared.world.graph);
    let original_target = prepared.world.realization.activation_record().clone();
    let preservation = prepared.preservation;
    let factory = preservation.factory();
    let source_namespace = preservation.namespace.clone();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "independent-native",
        directory.join("cas"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.join("refs")));
    let mut runtime = prepared
        .world
        .realization
        .admit(&graph)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    runtime.arm_all().unwrap();
    let nodes = runtime.prepared_node_records().unwrap().to_vec();
    assert_eq!(nodes.len(), 4);
    assert!(nodes.iter().all(|node| node.prepared_owners().is_some()));
    let coordinator = runtime
        .initial_coordinator_snapshot(&graph, 16 * 1024 * 1024)
        .unwrap();
    let mut stored = publisher(&blobs, &refs, "independent-original")
        .with_prepared_coordinator(original_target.clone(), nodes, coordinator)
        .unwrap();
    let activation = runtime.activate(&mut stored).unwrap();
    assert_eq!(activation.prepared_owners().unwrap().len(), 4);
    source_engine
        .native
        .record_publication(&original_target, PublicationKnowledge::Committed)
        .unwrap();

    let prefix = planner_to(&mut runtime, &graph, &activation, "prefix", 11);
    assert!(prefix.iter().all(|(node, _)| node != &id("disk-a")));
    let cut = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .position(&id("clock"))
        .unwrap();
    assert_eq!(cut.time_ps, U64::new(11));
    let ordinal = U64::new(41);
    let before = runtime
        .runtime_snapshot(cut, ordinal, 16 * 1024 * 1024)
        .unwrap();
    assert!(
        before
            .inputs
            .iter()
            .any(|input| input.node == id("disk-a") && !input.deliveries.is_empty())
    );
    save(&directory, "original-runtime-before-capture", &before);
    let limits = archive_limits();
    let archive_path = directory.join("archive");
    let archive = NativeArchive::open(&archive_path, limits).unwrap();
    let record = NativeArchive::capture_world_typed(
        &archive,
        &graph,
        &mut runtime,
        &activation,
        cut,
        ordinal,
        id("independent/original-capture"),
        group_requirements(),
        preservation.immutable().as_ref(),
        factory.as_ref(),
    )
    .unwrap();
    assert_eq!(record.owners().len(), 4);
    assert_eq!(record.runtime_snapshot().unwrap(), before);
    for owner in record.owners().iter().filter(|owner| {
        owner.owner.as_str() == "owner/disk-a" || owner.owner.as_str() == "owner/source-a"
    }) {
        let body = record.object_bytes(&owner.state, 16 * 1024 * 1024).unwrap();
        let wire: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(wire["schema_version"], 9);
    }
    save(&directory, "original-runtime", &before);
    save(
        &directory,
        "original-scheduler",
        &record.scheduling_snapshot().unwrap(),
    );
    // These future operation names are unused at the saved cut. Each fresh
    // activation grants them independently; original prefix identities remain
    // retained, while native publication IDs use the same actual operation/FIFO.
    let original_suffix = planner_to(
        &mut runtime,
        &graph,
        &activation,
        "original-suffix",
        2_000_000_000,
    );
    verify_suffix(&original_suffix);
    save(&directory, "original-suffix", &original_suffix);
    let artifact = record.artifact().clone();
    drop(runtime);
    drop(activation);
    drop(factory);
    drop(preservation);
    drop(graph);
    drop(record);
    drop(archive);
    reclaim(&source_engine);
    std::fs::remove_dir_all(&source_namespace).unwrap();
    std::fs::remove_file(&script_path).unwrap();
    std::fs::remove_file(&base_path).unwrap();
    assert!(!source_namespace.exists() && !script_path.exists() && !base_path.exists());
    drop(source_catalog);

    let archive = NativeArchive::open(&archive_path, limits).unwrap();
    let record = archive.load(&artifact).unwrap();
    let mut left_catalog = catalog(&directory, &companion);
    let mut right_catalog = catalog(&directory, &companion);
    for fresh in [&mut left_catalog, &mut right_catalog] {
        fresh
            .install_artifacts(vec![
                InstalledIoArtifact::archive_only(script_ref.clone()),
                InstalledIoArtifact::archive_only(base_ref.clone()),
            ])
            .unwrap();
    }
    let left_engine =
        InstalledMixedEngine::with_runtime(directory.clone(), left_catalog.custody().clone())
            .unwrap();
    let right_engine =
        InstalledMixedEngine::with_runtime(directory.clone(), right_catalog.custody().clone())
            .unwrap();
    let _left_supervision = FailedWitnessSupervision {
        engine: &left_engine,
    };
    let _right_supervision = FailedWitnessSupervision {
        engine: &right_engine,
    };
    let (left_graph, mut left, left_preservation, left_namespace) = restore_group(
        &left_catalog,
        &selections,
        record.clone(),
        &blobs,
        &refs,
        "left",
        limits,
    );
    let (right_graph, mut right, right_preservation, right_namespace) = restore_group(
        &right_catalog,
        &selections,
        record,
        &blobs,
        &refs,
        "right",
        limits,
    );
    assert_ne!(
        left.activation().record().owners,
        right.activation().record().owners
    );
    let left_activation = left.activation().clone();
    let right_activation = right.activation().clone();
    assert_eq!(left_activation.record().boundary, cut);
    assert_eq!(right_activation.record().boundary, cut);
    for (restored, name) in [(&mut left, "left"), (&mut right, "right")] {
        let saved = restored
            .runtime_mut()
            .runtime_snapshot(cut, ordinal, 16 * 1024 * 1024)
            .unwrap();
        assert_original_history(&before, &saved);
        save(&directory, &format!("{name}-restored-runtime"), &saved);
    }
    let left_suffix = planner_to(
        left.runtime_mut(),
        &left_graph,
        &left_activation,
        "original-suffix",
        2_000_000_000,
    );
    let right_suffix = planner_to(
        right.runtime_mut(),
        &right_graph,
        &right_activation,
        "original-suffix",
        2_000_000_000,
    );
    verify_suffix(&left_suffix);
    verify_suffix(&right_suffix);
    save(&directory, "left-suffix", &left_suffix);
    save(&directory, "right-suffix", &right_suffix);

    assert_eq!(original_suffix, left_suffix);
    assert_eq!(original_suffix, right_suffix);
    drop(left);
    drop(right);
    drop(left_preservation);
    drop(right_preservation);
    drop(left_graph);
    drop(right_graph);
    reclaim_twins(&left_engine, &right_engine);
    assert_eq!(left_catalog.custody().reserved_worlds(), 0);
    assert_eq!(right_catalog.custody().reserved_worlds(), 0);
    assert_eq!(left_engine.native.reserved_owners(), 0);
    save(
        &directory,
        "retirement",
        &serde_json::json!({"reserved_worlds":0,"reserved_native_owners":0,"source_namespace_gone":true,"source_script_gone":true,"source_base_gone":true,"left_namespace":left_namespace,"right_namespace":right_namespace}),
    );
}

fn catalog(directory: &std::path::Path, companion: &std::path::Path) -> InstalledNodeCatalog {
    InstalledNodeCatalog::new(
        companion.to_owned(),
        measure_executable(companion).unwrap(),
        directory.to_owned(),
        Duration::from_secs(30),
        8,
    )
    .unwrap()
}

fn authored(
    directory: &std::path::Path,
) -> (
    Vec<InstalledNodeSelection>,
    ContentRef,
    ContentRef,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let script = ScriptedSource::new(
        ScriptedRequestKind::Block,
        vec![
            ScriptedRequest {
                time_ps: 10,
                payload: BlockRequest::write(9, 0, vec![0x33; 512]).encode().unwrap(),
            },
            ScriptedRequest {
                time_ps: 1_000_000_000,
                payload: BlockRequest::read(10, 0, 512).encode().unwrap(),
            },
        ],
    )
    .unwrap()
    .script_bytes()
    .unwrap();
    let base = vec![0x11; 4096];
    let script_ref = canonical::content_ref(&script, "application/octet-stream").unwrap();
    let base_ref = canonical::content_ref(&base, "application/octet-stream").unwrap();
    let script_path = directory.join("original-script");
    let base_path = directory.join("original-base");
    std::fs::write(&script_path, &script).unwrap();
    std::fs::write(&base_path, &base).unwrap();
    let selections = vec![
        InstalledNodeSelection {
            node: id("clock"),
            owner: id("owner/clock"),
            kind: InstalledNodeKind::HostClock,
        },
        InstalledNodeSelection {
            node: id("cpu"),
            owner: id("owner/cpu"),
            kind: InstalledNodeKind::Gem5ClosedPreserving {
                isa: super::super::control::InstalledGem5Isa::X86_64,
            },
        },
        InstalledNodeSelection {
            node: id("disk-a"),
            owner: id("owner/disk-a"),
            kind: InstalledNodeKind::HostIo {
                profile: InstalledHostIoProfile::Block {
                    base_image: base_ref.clone(),
                    source_node: 17,
                    read_ns: 1.into(),
                    write_ns: 1.into(),
                    flush_ns: 1.into(),
                    get_length_ns: 1.into(),
                    per_byte_ns: 1.into(),
                },
            },
        },
        InstalledNodeSelection {
            node: id("source-a"),
            owner: id("owner/source-a"),
            kind: InstalledNodeKind::HostScripted {
                profile: InstalledScriptedSourceProfile {
                    script: script_ref.clone(),
                    consumer: id("disk-a"),
                },
            },
        },
    ];
    (selections, script_ref, base_ref, script_path, base_path)
}

fn planner_to(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    name: &str,
    horizon: u64,
) -> Vec<(Id, NativePublication)> {
    let mut publications = Vec::new();
    publications.try_reserve_exact(8).unwrap();
    for round in 0..64 {
        for node in graph.node_ids() {
            let observation = runtime.observe_scheduling(activation, node).unwrap();
            runtime
                .scheduler(graph, activation)
                .unwrap()
                .accept_boundary_observation(observation)
                .unwrap();
        }
        let mut progress = false;
        for node in graph.node_ids() {
            if runtime
                .scheduler(graph, activation)
                .unwrap()
                .position(node)
                .unwrap()
                .time_ps
                .get()
                >= horizon
            {
                continue;
            }
            let operation = format!("{name}/{round}/{node}");
            let grant = crate::node_execution::plan_exact_operation::<
                crate::node_observed_executor::NodeObservedError,
                _,
            >(
                runtime,
                crate::node_execution::ExactOperationRequest {
                    graph,
                    activation,
                    node,
                    horizon: horizon.into(),
                    names: crate::node_execution::ExactOperationNames {
                        operation: id(&operation),
                        stage: id(&format!("{operation}/stage")),
                        batch: id(&format!("{operation}/batch")),
                    },
                },
                |_| Ok(()),
            )
            .unwrap();
            if let Some(grant) = grant {
                let mut dispatched = DispatchRound::start(runtime, vec![grant], 1).unwrap();
                let mut context = Context::from_waker(Waker::noop());
                let mut complete = false;
                for _ in 0..4096 {
                    if let Poll::Ready(result) = dispatched.poll(runtime, &mut context) {
                        result.unwrap();
                        complete = true;
                        break;
                    }
                }
                assert!(
                    complete,
                    "original native grant exceeded finite poll credit"
                );
                let outcome = dispatched.publish(runtime).unwrap();
                for original in &outcome.outcomes {
                    if let Some(observation) = &original.scheduling {
                        publications.extend(
                            observation
                                .publications
                                .iter()
                                .cloned()
                                .map(|publication| (node.clone(), publication)),
                        );
                    }
                }
                assert!(
                    publications.len() <= 8,
                    "authored output roster exceeds its original finite credit"
                );
                progress = true;
            }
        }
        if graph.node_ids().all(|node| {
            runtime
                .scheduler(graph, activation)
                .unwrap()
                .position(node)
                .unwrap()
                .time_ps
                .get()
                >= horizon
        }) {
            return publications;
        }
        assert!(progress, "original common planner is causally blocked");
    }
    panic!("original common planner exhausted authored round credit");
}

fn restore_group(
    catalog: &InstalledNodeCatalog,
    selections: &[InstalledNodeSelection],
    record: NativeArchiveRecord,
    blobs: &Arc<dyn ImmutableBlobBackend>,
    refs: &Arc<dyn MutableRefBackend>,
    name: &str,
    limits: NativeArchiveLimits,
) -> (
    Rc<AdmittedGraph>,
    Box<RestoredWorld>,
    super::super::public_group::InstalledIndependentNativePreservation,
    std::path::PathBuf,
) {
    let plan = catalog
        .prepare_independent_native_restore(selections, record.clone())
        .unwrap();
    let graph = plan.graph;
    let target = plan.target;
    let preservation = plan.preservation;
    let namespace = preservation.namespace.clone();
    let factory = preservation.factory();
    let verified = record
        .admit(&graph, group_requirements(), factory.as_ref())
        .unwrap();
    let mut driver = NativeWorldRestoreDriver::new(
        graph.clone(),
        record.clone(),
        factory,
        catalog.custody().clone(),
    )
    .unwrap();
    let prepared = stage_restore(&graph, verified, target.clone(), &mut driver, limits.state)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    let mut stored = preservation
        .restored_publisher(publisher(blobs, refs, name), &record, &target)
        .unwrap();
    let RestorePublication::Committed(restored) = prepared.publish(&mut stored) else {
        panic!("actual complete fresh four-owner activation did not commit");
    };
    assert_eq!(restored.activation().prepared_owners().unwrap().len(), 4);
    assert!(restored.activation().coordinator_snapshot().is_some());
    drop(stored);
    (graph, restored, preservation, namespace)
}

fn assert_original_history(
    original: &crucible::node_contract::RuntimeSnapshot,
    fresh: &crucible::node_contract::RuntimeSnapshot,
) {
    assert_eq!(original.operations.len(), fresh.operations.len());
    assert_eq!(original.inputs.len(), fresh.inputs.len());
    for (original, fresh) in original.operations.iter().zip(&fresh.operations) {
        assert_eq!(original.operation, fresh.operation);
        assert_eq!(original.request, fresh.request);
        assert_eq!(original.scheduling_commit, fresh.scheduling_commit);
    }
    for (original, fresh) in original.inputs.iter().zip(&fresh.inputs) {
        assert_eq!(original.batch, fresh.batch);
        assert_eq!(original.inventory, fresh.inventory);
        assert_eq!(original.deliveries, fresh.deliveries);
        assert_eq!(original.payloads, fresh.payloads);
    }
}

fn verify_suffix(publications: &[(Id, NativePublication)]) {
    let disk: Vec<_> = publications
        .iter()
        .filter(|(node, _)| node == &id("disk-a"))
        .map(|(_, publication)| publication)
        .collect();
    assert_eq!(disk.len(), 2);
    assert_eq!(disk[0].native_sequence, U64::new(0));
    assert_eq!(disk[1].native_sequence, U64::new(1));
    let write = BlockResponse::decode(&disk[0].payload_bytes).unwrap();
    let read = BlockResponse::decode(&disk[1].payload_bytes).unwrap();
    assert_eq!(write.status, BlockStatus::Ok);
    assert_eq!(write.request_id, 9);
    assert_eq!(read.status, BlockStatus::Ok);
    assert_eq!(read.request_id, 10);
    assert_eq!(read.data, vec![0x33; 512]);
    let cpu: Vec<_> = publications
        .iter()
        .filter(|(node, _)| node == &id("cpu"))
        .collect();
    assert_eq!(cpu.len(), 1);
    assert_eq!(cpu[0].1.payload_bytes, expected_checksum());
}

fn group_requirements() -> StateRequirements {
    StateRequirements {
        preservation_contract: id("independent-group/native-preservation-v1"),
        ..requirements()
    }
}

fn save<T: serde::Serialize>(directory: &std::path::Path, name: &str, value: &T) {
    let bytes = canonical::canonical_json(&serde_json::to_value(value).unwrap()).unwrap();
    assert!(bytes.len() <= 16 * 1024 * 1024);
    std::fs::write(directory.join(format!("{name}.json")), bytes).unwrap();
}

fn reclaim_twins(left: &InstalledMixedEngine, right: &InstalledMixedEngine) {
    let mut context = Context::from_waker(Waker::noop());
    let mut retired = Vec::new();
    let deadline = crate::supervision::ProcessDeadline::after(Duration::from_secs(60)).unwrap();
    while !deadline.expired() {
        for engine in [left, right] {
            if let Poll::Ready(Err(error)) = engine.runtime.poll_reclamation(&mut context) {
                panic!("{error}");
            }
        }
        if left.runtime.reserved_worlds() == 0 && right.runtime.reserved_worlds() == 0 {
            retired.extend(left.native.take_reclaimed().unwrap());
        }
        if left.runtime.reserved_worlds() == 0
            && right.runtime.reserved_worlds() == 0
            && left.native.reserved_owners() == 0
        {
            assert_eq!(retired.len(), 2);
            for original in &mut retired {
                assert!(original.custody.child.try_wait().unwrap().is_some());
                original.evidence.verify(&original.bytes).unwrap();
            }
            return;
        }
        deadline.pause(Duration::from_millis(10));
    }
    panic!("original twin worlds still retain native custody");
}
