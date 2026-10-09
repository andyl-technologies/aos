//! Installed terminal execution and signed source-gone independent cold branches.

// Native custody and exact bytes are asserted directly rather than synthesized.
// crucible-lint: allow panic-shortcut -- Original native terminal bytes and cold owner histories are independent assertions.
// crucible-lint: allow rust-allow -- Unexpected native terminal outcomes invalidate the original test attempt.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
    task::{Context, Poll, Waker},
};

use crucible::{
    AssertionDef, AssertionId, Predicate, Properties, Property, VirtualTime,
    model::PropertyNamespace,
    node_adapters::HostSemanticDefinition,
    node_contract::{
        BeginResult, NodeRuntime, PublicationStatus, TerminalPublicationState, WorldActivation,
    },
    node_state::{
        HostArchive, HostWorldRestoreDriver, RestorePublication, StateLimits, StateRequirements,
        StateRestoreMode, stage_restore,
    },
};
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend};
use crucible_node_contract::Bytes;

use super::*;
use crate::node_observed_executor::StoredTerminalResultPublisher;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn requirements() -> StateRequirements {
    StateRequirements {
        preservation_contract: id("host/preservation-v1"),
        exact_model_continuation: true,
        deterministic: true,
        restore_mode: StateRestoreMode::DurableRestart,
    }
}

fn activation_publisher(
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

fn exact(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    node: &Id,
) {
    let observation = runtime.observe_scheduling(activation, node).unwrap();
    runtime
        .scheduler(graph, activation)
        .unwrap()
        .accept_boundary_observation(observation)
        .unwrap();
    let grant = runtime
        .scheduler(graph, activation)
        .unwrap()
        .admit_exact(node, id(&format!("original-run/{node}")), 11.into())
        .unwrap();
    let BeginResult::Accepted(token) = runtime.begin_admitted(grant).unwrap() else {
        panic!("installed exact operation was refused");
    };
    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(Ok(outcome)) = runtime.poll(&token, &mut context) else {
        panic!("installed exact operation did not complete");
    };
    if node.as_str() == "semantics" {
        assert_eq!(outcome.retained_outputs.len(), 1);
        let publication = &outcome.scheduling.as_ref().unwrap().publications[0];
        assert_eq!(publication.evaluation.unwrap().time_ps.get(), 2);
        assert_eq!(publication.native_sequence.get(), 0);
    }
    let receipt = runtime.scheduling_receipt(&token).unwrap();
    let commit = runtime.commit_scheduling_receipt(receipt).unwrap();
    runtime.acknowledge_scheduled(&token, &commit).unwrap();
}

fn reclaim(catalog: &InstalledNodeCatalog) {
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..32 {
        if catalog.custody().reserved_worlds() == 0 {
            return;
        }
        let _ = catalog.custody().clone().poll_reclamation(&mut context);
    }
    assert_eq!(catalog.custody().reserved_worlds(), 0);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CaptureStage {
    Completed,
    Published,
    Acknowledged,
}

#[test]
#[ignore = "requires actual source-built companion and installed terminal archive candidate"]
fn installed_terminal_report_and_ack_survive_source_gone_two_fresh_worlds() {
    installed_terminal_cold_branches(CaptureStage::Acknowledged);
}

#[test]
#[ignore = "requires actual source-built companion and installed terminal archive candidate"]
fn installed_terminal_unpublished_report_survives_source_gone_two_fresh_worlds() {
    installed_terminal_cold_branches(CaptureStage::Completed);
}

#[test]
#[ignore = "requires actual source-built companion and installed terminal archive candidate"]
fn installed_terminal_pending_native_ack_survives_source_gone_two_fresh_worlds() {
    installed_terminal_cold_branches(CaptureStage::Published);
}

fn installed_terminal_cold_branches(stage: CaptureStage) {
    let directory = tempfile::tempdir().unwrap();
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let expected = measure_executable(&executable).unwrap();
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        expected.clone(),
        directory.path().to_owned(),
        Duration::from_secs(5),
        8,
    )
    .unwrap();
    let namespace = PropertyNamespace::new(BTreeMap::new(), false, true, BTreeSet::new()).unwrap();
    let properties = Properties::from_assertions_for_namespace(
        &namespace,
        vec![
            AssertionDef {
                id: AssertionId::from_name("original-emitted"),
                message: "emitted once".into(),
                property: Property::Sometimes {
                    predicate: Predicate::at(VirtualTime { ticks: 2 }),
                },
            },
            AssertionDef {
                id: AssertionId::from_name("terminal-only"),
                message: "actual full closure".into(),
                property: Property::AfterQuiescence {
                    predicate: Predicate::quiescent(),
                },
            },
        ],
    )
    .unwrap();
    let definition = HostSemanticDefinition {
        version: 2,
        properties: Bytes::new(properties.to_compact_binary()),
        inputs: Vec::new(),
    };
    let program = canonical::canonical_json(&serde_json::to_value(&definition).unwrap()).unwrap();
    let program_ref = canonical::content_ref(&program, "application/json").unwrap();
    let program_path = directory.path().join("original-program.json");
    std::fs::write(&program_path, &program).unwrap();
    catalog
        .install_artifacts(vec![InstalledIoArtifact::path(
            program_path.clone(),
            program_ref.clone(),
        )])
        .unwrap();
    let selections = vec![
        InstalledNodeSelection {
            node: id("clock"),
            owner: id("clock-owner"),
            kind: InstalledNodeKind::HostClock,
        },
        InstalledNodeSelection {
            node: id("semantics"),
            owner: id("semantics-owner"),
            kind: InstalledNodeKind::HostSemantics {
                profile: InstalledHostSemanticProfile {
                    program: program_ref.clone(),
                },
            },
        },
    ];
    let scenario = catalog.scenario(&selections).unwrap();
    let factory = catalog.host_state_factory(&selections, &scenario).unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "terminal",
        directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let prepared = catalog
        .prepare_world(
            &selections,
            scenario.clone(),
            ExecutionId::from_bytes([71; 16]).unwrap(),
        )
        .unwrap();
    let graph = prepared.graph;
    let mut runtime = prepared
        .realization
        .admit(&graph)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    runtime.arm_all().unwrap();
    let activation = runtime
        .activate(&mut activation_publisher(&blobs, &refs, "terminal-source"))
        .unwrap();
    exact(&mut runtime, &graph, &activation, &id("clock"));
    exact(&mut runtime, &graph, &activation, &id("semantics"));
    let barrier = runtime
        .terminal_barrier(
            &graph,
            &activation,
            &id("semantics"),
            id("original-terminal"),
            1 << 20,
        )
        .unwrap();
    let original_record = barrier.record().clone();
    let cut = original_record.cut;
    let BeginResult::Accepted(token) = runtime.begin_terminal_assertions(barrier).unwrap() else {
        panic!("installed original finalization refused");
    };
    let Poll::Ready(Ok(original_outcome)) =
        runtime.poll(&token, &mut Context::from_waker(Waker::noop()))
    else {
        panic!("actual terminal report did not complete");
    };
    let mut publisher = StoredTerminalResultPublisher::new(
        blobs.clone(),
        refs.clone(),
        RefName::new("node-world-coordinators/terminal/original").unwrap(),
        1 << 20,
    )
    .unwrap();
    let crucible::node_contract::ProgressEvidence::AssertionsFinalized { report, .. } =
        &original_outcome.progress
    else {
        panic!("actual original finalization has no report commitment");
    };
    let original_report = runtime
        .operation_evidence(&token, std::slice::from_ref(report), (1u64 << 20).into())
        .unwrap()
        .pop()
        .unwrap();
    if stage != CaptureStage::Completed {
        let (status, commit) = runtime
            .publish_terminal_result(&token, &mut publisher, 1 << 20)
            .unwrap();
        assert_eq!(status, PublicationStatus::Committed);
        if stage == CaptureStage::Acknowledged {
            runtime
                .acknowledge_terminal_result(&token, &commit.unwrap())
                .unwrap();
        }
    }
    let original = runtime.terminal_checkpoint().unwrap().clone();
    let mut completed = original.clone();
    completed.report = Some(original_report.clone());
    completed.publication = Some(TerminalPublicationState::Committed);
    completed.acknowledged = true;
    let report: serde_json::Value = serde_json::from_slice(&original_report.bytes).unwrap();
    assert_eq!(
        report["newly_terminal"],
        serde_json::json!(["terminal-only"])
    );
    assert_eq!(report["outcomes"].as_array().unwrap().len(), 2);
    assert!(!report["failed"].as_bool().unwrap());
    let limits = StateLimits {
        maximum_content_bytes: 512 * 1024 * 1024,
        maximum_total_content_bytes: 1024 * 1024 * 1024,
        ..StateLimits::default()
    };
    let archive_path = directory.path().join("archive");
    let archive = HostArchive::open(&archive_path, limits).unwrap();
    let record = archive
        .capture_terminal_world(
            &graph,
            &mut runtime,
            &activation,
            cut,
            11.into(),
            id("original-capture"),
            requirements(),
            factory.as_ref(),
            factory.as_ref(),
        )
        .unwrap();
    let artifact = record.artifact().clone();
    drop(record);
    drop(runtime);
    reclaim(&catalog);
    drop(graph);
    drop(factory);
    drop(catalog);
    drop(archive);
    std::fs::remove_file(&program_path).unwrap();

    let archive = HostArchive::open(&archive_path, limits).unwrap();
    let record = archive.load(&artifact).unwrap();
    let mut catalog = InstalledNodeCatalog::new(
        executable,
        expected,
        directory.path().to_owned(),
        Duration::from_secs(5),
        8,
    )
    .unwrap();
    catalog
        .install_artifacts(vec![InstalledIoArtifact::archive_only(program_ref)])
        .unwrap();
    assert!(catalog.scenario(&selections).is_err());
    for nonce in [81, 82] {
        let factory = catalog
            .host_state_factory_from_archive(&selections, &scenario, &record)
            .unwrap();
        let (graph, target) = catalog
            .prepare_host_restore_graph(
                &selections,
                &scenario,
                &record,
                ExecutionId::from_bytes([nonce; 16]).unwrap(),
            )
            .unwrap();
        reclaim(&catalog);
        let graph = Rc::new(graph);
        let verified = record
            .admit(&graph, requirements(), factory.as_ref(), limits)
            .unwrap();
        let mut driver = HostWorldRestoreDriver::new(
            graph.clone(),
            record.clone(),
            factory,
            catalog.custody().clone(),
        )
        .unwrap();
        let prepared = stage_restore(&graph, verified, target, &mut driver, limits)
            .unwrap_or_else(|failure| panic!("{}", failure.error));
        let RestorePublication::Committed(mut restored) = prepared.publish(
            &mut activation_publisher(&blobs, &refs, &format!("terminal-restored-{nonce}")),
        ) else {
            panic!("actual fresh world publication failed");
        };
        let activation = restored.activation().clone();
        let runtime = restored.runtime_mut();
        assert_eq!(runtime.terminal_checkpoint(), Some(&original));
        assert_ne!(
            activation.record().activation_id,
            original.record.source.activation_id
        );
        let token = runtime.recover(&original.record.operation).unwrap();
        if stage != CaptureStage::Completed {
            let empty_blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
                "empty-terminal-store",
                directory.path().join(format!("empty-blobs-{nonce}")),
            ));
            let empty_refs: Arc<dyn MutableRefBackend> = Arc::new(DirectoryRefBackend::new(
                directory.path().join(format!("empty-refs-{nonce}")),
            ));
            let mut empty_publisher = StoredTerminalResultPublisher::new(
                empty_blobs.clone(),
                empty_refs.clone(),
                RefName::new("node-world-coordinators/terminal/original").unwrap(),
                1 << 20,
            )
            .unwrap();
            let (status, permit) = runtime
                .publish_terminal_result(&token, &mut empty_publisher, 1 << 20)
                .unwrap();
            assert_eq!(status, PublicationStatus::NotCommitted);
            assert!(
                permit.is_none(),
                "historical source publication cannot mint fresh ACK authority"
            );
            assert_eq!(runtime.terminal_checkpoint(), Some(&original));
            assert_eq!(
                runtime.terminal_checkpoint().unwrap().record,
                original.record
            );
            assert_eq!(
                runtime.terminal_checkpoint().unwrap().report,
                original.report
            );
            let Poll::Ready(Ok(retained)) =
                runtime.poll(&token, &mut Context::from_waker(Waker::noop()))
            else {
                panic!("original report disappeared after a refused fresh-store reconciliation");
            };
            assert_eq!(retained.operation, original_outcome.operation);
            assert_eq!(retained.progress, original_outcome.progress);
            assert_eq!(retained.retained_outputs, original_outcome.retained_outputs);
            assert!(runtime.scheduler(&graph, &activation).is_err());
            let changed = crucible_cas::content_store::ContentId::for_bytes(
                crucible_cas::content_store::ObjectKind::Trace,
                1,
                b"different report root",
            );
            empty_blobs
                .put_if_absent(
                    changed,
                    &crucible_cas::content_store::BlobHandle::from_bytes(
                        b"different report root".to_vec(),
                    ),
                )
                .unwrap();
            empty_refs
                .compare_exchange(
                    &RefName::new("node-world-coordinators/terminal/original").unwrap(),
                    None,
                    changed,
                )
                .unwrap();
            let (status, permit) = runtime
                .publish_terminal_result(&token, &mut empty_publisher, 1 << 20)
                .unwrap();
            assert_eq!(status, PublicationStatus::NotCommitted);
            assert!(
                permit.is_none(),
                "a changed result root cannot authorize the original native ACK"
            );
            assert_eq!(runtime.terminal_checkpoint(), Some(&original));
            assert_eq!(
                runtime.terminal_checkpoint().unwrap().record,
                original.record
            );
            assert_eq!(
                runtime.terminal_checkpoint().unwrap().report,
                original.report
            );
        }
        let (status, commit) = runtime
            .publish_terminal_result(&token, &mut publisher, 1 << 20)
            .unwrap();
        assert_eq!(status, PublicationStatus::Committed);
        runtime
            .acknowledge_terminal_result(&token, &commit.unwrap())
            .unwrap();
        assert_eq!(runtime.terminal_checkpoint(), Some(&completed));
        let Poll::Ready(Ok(retained)) =
            runtime.poll(&token, &mut Context::from_waker(Waker::noop()))
        else {
            panic!("original restored terminal outcome disappeared");
        };
        assert_eq!(retained.operation, original_outcome.operation);
        assert_eq!(retained.progress, original_outcome.progress);
        assert!(runtime.scheduler(&graph, &activation).is_err());
        drop(restored);
        drop(driver);
        reclaim(&catalog);
    }
}
