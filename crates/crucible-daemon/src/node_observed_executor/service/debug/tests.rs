//! Actual owning-service condition control and unchanged durable nonce history.

// crucible-lint: allow panic-shortcut -- Actual native fixtures deliberately panic on violated custody and byte assertions.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::node_observed_executor::{
    InstalledHostIoProfile, InstalledIoArtifact, InstalledNodeKind, InstalledScriptedSourceProfile,
    NodeObservationServiceConfig,
    factory::{InstalledConditionDebugProfile, measure_executable},
};
use crucible::{
    AssertionDef, AssertionId, IoEventKind, NodeId, Predicate, Properties, Property,
    node_adapters::{
        ConditionDebugDefinition, HostSemanticDefinition, HostSemanticInput, HostSemanticInputKind,
        ScriptedRequest, ScriptedRequestKind, ScriptedSource,
    },
};
use crucible_campaign::CampaignRepository;
use crucible_cas::content_store::{
    BlobHandle, ContentId, DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend,
    MutableRefBackend, ObjectKind, RefCasOutcome, RefName,
};
use crucible_device::{BlockRequest, BlockResponse};
use crucible_node_contract::{Bytes, Endpoint, Phase};
use std::{path::Path, sync::Arc, time::Duration};

fn id(name: &str) -> Id {
    Id::new(name).unwrap()
}

fn condition_program() -> Vec<u8> {
    let disk = NodeId {
        name: "disk".to_owned(),
    };
    let namespace = crucible::model::PropertyNamespace::new(
        std::collections::BTreeMap::from([(
            disk.clone(),
            std::collections::BTreeSet::from([crucible::model::PropertyObservation::Io(
                IoEventKind::Any,
            )]),
        )]),
        false,
        false,
        std::collections::BTreeSet::new(),
    )
    .unwrap();
    let properties = Properties::from_assertions_for_namespace(
        &namespace,
        vec![AssertionDef {
            id: AssertionId::from_name("first-native-reply"),
            message: "first actual Block completion".to_owned(),
            property: Property::Sometimes {
                predicate: Predicate::IoPattern {
                    node: disk,
                    kind: IoEventKind::Any,
                },
            },
        }],
    )
    .unwrap();
    let definition = ConditionDebugDefinition {
        version: 1,
        condition: id("first-native-reply"),
        evaluation: HostSemanticDefinition {
            version: 1,
            properties: Bytes::new(properties.to_compact_binary()),
            inputs: vec![HostSemanticInput {
                source: Endpoint {
                    node_id: id("disk"),
                    port_id: id("data"),
                    lane_id: id("output"),
                },
                kind: HostSemanticInputKind::BlockCompletion,
            }],
        },
    };
    canonical::canonical_json(&serde_json::to_value(definition).unwrap()).unwrap()
}

fn installed_fixture(directory: &Path) -> (NodeDebugStartRequest, Vec<InstalledIoArtifact>) {
    let script = ScriptedSource::new(
        ScriptedRequestKind::Block,
        vec![
            ScriptedRequest {
                time_ps: 10,
                payload: BlockRequest::write(7, 0, vec![0x5c; 512]).encode().unwrap(),
            },
            ScriptedRequest {
                time_ps: 1_000_000,
                payload: BlockRequest::read(9, 0, 512).encode().unwrap(),
            },
        ],
    )
    .unwrap()
    .script_bytes()
    .unwrap();
    let mut artifacts = Vec::new();
    let mut references = Vec::new();
    for (name, bytes, media) in [
        ("base", vec![0xab; 4096], "application/octet-stream"),
        ("script", script, "application/octet-stream"),
        ("condition", condition_program(), "application/json"),
    ] {
        let expected = canonical::content_ref(&bytes, media).unwrap();
        let path = directory.join(name);
        std::fs::write(&path, bytes).unwrap();
        artifacts.push(InstalledIoArtifact::path(path, expected.clone()));
        references.push(expected);
    }
    let mut selections = vec![
        InstalledNodeSelection {
            node: id("source"),
            owner: id("source-owner"),
            kind: InstalledNodeKind::HostScripted {
                profile: InstalledScriptedSourceProfile {
                    script: references[1].clone(),
                    consumer: id("disk"),
                },
            },
        },
        InstalledNodeSelection {
            node: id("disk"),
            owner: id("disk-owner"),
            kind: InstalledNodeKind::HostIo {
                profile: InstalledHostIoProfile::Block {
                    base_image: references[0].clone(),
                    source_node: 7,
                    read_ns: 1.into(),
                    write_ns: 1.into(),
                    flush_ns: 1.into(),
                    get_length_ns: 1.into(),
                    per_byte_ns: 1.into(),
                },
            },
        },
        InstalledNodeSelection {
            node: id("observer"),
            owner: id("observer-owner"),
            kind: InstalledNodeKind::HostConditionDebug {
                profile: InstalledConditionDebugProfile {
                    program: references[2].clone(),
                },
            },
        },
    ];
    selections.sort_by(|left, right| left.node.cmp(&right.node));
    (
        NodeDebugStartRequest {
            format: "crucible.live-debug-start".into(),
            version: 1,
            execution: "a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7".into(),
            selections,
            observer: id("observer"),
            maximum_physical_cut: 2_000_000.into(),
        },
        artifacts,
    )
}

fn wait_for(service: &NodeObservationService, execution: &str, resumed: bool) -> NodeDebugRecord {
    let deadline = crate::supervision::ProcessDeadline::after(Duration::from_secs(20)).unwrap();
    loop {
        let original = service.debug_state(execution).unwrap();
        match &original.outcome {
            NodeDebugState::Stopped { .. } if !resumed => return original,
            NodeDebugState::Resumed { .. } if resumed => return original,
            NodeDebugState::Unknown { reason } => {
                panic!("actual Debug native custody failed: {reason}")
            }
            _ => {}
        }
        assert!(
            !deadline.expired(),
            "actual original Debug deadline expired"
        );
        std::thread::yield_now();
    }
}

type InstalledService = (
    NodeDebugStartRequest,
    NodeObservationService,
    Arc<dyn ImmutableBlobBackend>,
    Arc<dyn MutableRefBackend>,
);

fn start_service(directory: &Path) -> InstalledService {
    start_service_with(directory, |blobs| blobs, 2)
}

fn start_service_with(
    directory: &Path,
    decorate: impl FnOnce(Arc<dyn ImmutableBlobBackend>) -> Arc<dyn ImmutableBlobBackend>,
    maximum_worlds: usize,
) -> InstalledService {
    let executable = std::path::PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let expected_device = measure_executable(&executable).unwrap();
    let (request, artifacts) = installed_fixture(directory);
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "actual-debug",
        directory.join("blobs"),
    ));
    let blobs = decorate(blobs);
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.join("refs")));
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
    let service = NodeObservationService::start(
        NodeObservationServiceConfig {
            installed_artifacts: artifacts,
            device_executable: executable,
            expected_device,
            socket_parent: directory.join("sockets"),
            control_timeout: Duration::from_secs(5),
            maximum_worlds,
            maximum_pending_requests: 4,
        },
        repository,
        blobs.clone(),
        refs.clone(),
    )
    .unwrap();
    (request, service, blobs, refs)
}

fn retire(service: NodeObservationService) {
    let retention = service.retention_owner();
    drop(service);
    let deadline = crate::supervision::ProcessDeadline::after(Duration::from_secs(20)).unwrap();
    while !retention.is_retired() {
        assert!(
            !deadline.expired(),
            "actual original Debug custody failed retirement"
        );
        std::thread::yield_now();
    }
}

#[test]
#[ignore = "requires actual source-built installed companion"]
fn actual_actor_stop_report_ack_and_resume_preserve_original_nonce_and_native_cut() {
    let directory = tempfile::tempdir().unwrap();
    let (request, service, blobs, refs) = start_service(directory.path());
    let retention = service.retention_owner();
    let original = service.start_debug(request.clone()).unwrap();
    assert!(matches!(
        original.outcome,
        NodeDebugState::AwaitingAdmission { .. }
    ));
    let stopped = wait_for(&service, &request.execution, false);
    let NodeDebugState::Stopped {
        cut,
        barrier,
        report,
    } = &stopped.outcome
    else {
        panic!("actual stop absent")
    };
    assert_eq!(
        *cut,
        Position::new(513_010.into(), 3.into(), Phase::BoundaryControl)
    );
    assert!(cut.time_ps < 1_000_000.into());
    assert_eq!(stopped.request, original.request);
    let result_name = RefName::new(format!(
        "node-world-coordinators/condition/debug-{}-stop-report",
        request.execution
    ))
    .unwrap();
    let report_id = refs.read_ref(&result_name).unwrap().unwrap();
    let report_body = blobs
        .read(report_id, None)
        .unwrap()
        .read_all(32 << 20)
        .unwrap();
    report.verify(&report_body).unwrap();
    let barrier_name = RefName::new(format!(
        "node-world-coordinators/condition/debug-{}-stop-barrier",
        request.execution
    ))
    .unwrap();
    let barrier_body = blobs
        .read(refs.read_ref(&barrier_name).unwrap().unwrap(), None)
        .unwrap()
        .read_all(32 << 20)
        .unwrap();
    barrier.verify(&barrier_body).unwrap();
    let saved: crucible::node_contract::ConditionStopRecord =
        serde_json::from_slice(&barrier_body).unwrap();
    assert_eq!(
        saved.hit.evaluation,
        Position::new(513_010.into(), 2.into(), Phase::Reaction)
    );
    assert_eq!(saved.hit.input.producer, id("disk"));
    assert_eq!(
        encode(&service.start_debug(request.clone()).unwrap()).unwrap(),
        encode(&stopped).unwrap()
    );
    let mut changed = request.clone();
    changed.maximum_physical_cut = 3_000_000.into();
    assert!(service.start_debug(changed).is_err());

    let resume = NodeDebugResumeRequest {
        format: "crucible.live-debug-resume".into(),
        version: 1,
        execution: request.execution.clone(),
        operation: id("operator/original-resume"),
        horizon_ps: 2_000_000.into(),
    };
    let pending = service.resume_debug(resume.clone()).unwrap();
    assert!(matches!(
        pending.outcome,
        NodeDebugState::AwaitingResume { .. }
    ));
    let resumed = wait_for(&service, &request.execution, true);
    assert_eq!(resumed.request, original.request);
    assert_eq!(resumed.resume_request, pending.resume_request);
    assert_eq!(
        encode(&resumed.stop).unwrap(),
        encode(&stopped.stop).unwrap()
    );
    let NodeDebugState::Resumed { publications, .. } = &resumed.outcome else {
        panic!("original resumed result absent")
    };
    let output_name =
        RefName::new(format!("node-debug-publications/{}", request.execution)).unwrap();
    let output_bytes = blobs
        .read(refs.read_ref(&output_name).unwrap().unwrap(), None)
        .unwrap()
        .read_all(32 << 20)
        .unwrap();
    publications.verify(&output_bytes).unwrap();
    let output: serde_json::Value = serde_json::from_slice(&output_bytes).unwrap();
    let outputs: Vec<crucible::node_scheduling::NativePublication> =
        serde_json::from_value(output["publications"].clone()).unwrap();
    let disk: Vec<_> = outputs
        .iter()
        .filter(|publication| publication.endpoint.node_id == id("disk"))
        .collect();
    assert_eq!(
        disk.len(),
        2,
        "write and future read each complete exactly once"
    );
    assert_eq!(disk[0].native_sequence.get(), 0);
    assert_eq!(disk[1].native_sequence.get(), 1);
    let write = BlockResponse::decode(&disk[0].payload_bytes).unwrap();
    let read = BlockResponse::decode(&disk[1].payload_bytes).unwrap();
    assert_eq!(write.request_id, 7);
    assert!(write.data.is_empty());
    assert_eq!(read.request_id, 9);
    assert_eq!(read.data, vec![0x5c; 512]);
    assert!(disk[1].publication.time_ps >= 1_000_000.into());
    assert!(!disk[1].causal_parents.is_empty());
    assert_eq!(
        std::fs::read(directory.path().join("base")).unwrap(),
        vec![0xab; 4096]
    );
    assert_eq!(
        encode(&service.resume_debug(resume.clone()).unwrap()).unwrap(),
        encode(&resumed).unwrap()
    );
    let mut changed = resume;
    changed.operation = id("operator/replacement-resume");
    assert!(service.resume_debug(changed).is_err());
    assert_eq!(
        encode(&service.debug_state(&request.execution).unwrap()).unwrap(),
        encode(&resumed).unwrap()
    );
    drop(service);
    let deadline = crate::supervision::ProcessDeadline::after(Duration::from_secs(20)).unwrap();
    while !retention.is_retired() {
        assert!(
            !deadline.expired(),
            "actual Debug owner failed authentic retirement"
        );
        std::thread::yield_now();
    }
}

#[test]
fn retained_common_claims_never_dispatch_again_and_exclude_other_routes() {
    use super::super::original_claim::{OriginalClaims, Route};

    let directory = tempfile::tempdir().unwrap();
    let (request, _) = installed_fixture(directory.path());
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "debug-original-claim",
        directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let ledger = DebugLedger::new(blobs.clone(), refs.clone()).unwrap();
    let original = ledger.reserve_start(&request).unwrap();
    assert!(original.original_dispatch);

    let restarted = DebugLedger::new(blobs.clone(), refs.clone()).unwrap();
    let retained = restarted.reserve_start(&request).unwrap();
    assert!(!retained.original_dispatch);
    assert_eq!(
        encode(&retained.record).unwrap(),
        encode(&original.record).unwrap()
    );
    let claims = OriginalClaims::new(blobs, refs).unwrap();
    for route in [
        Route::Ordinary,
        Route::Conditional,
        Route::Capability,
        Route::Root,
    ] {
        assert!(
            claims
                .reserve(&request.execution, route, &encode(&request).unwrap())
                .is_err()
        );
    }
    let mut changed = request;
    changed.maximum_physical_cut = 3_000_000.into();
    assert!(restarted.reserve_start(&changed).is_err());
}

#[test]
fn claimed_original_without_its_record_refuses_replacement_dispatch() {
    use super::super::original_claim::{OriginalClaims, Reservation, Route};

    let directory = tempfile::tempdir().unwrap();
    let (request, _) = installed_fixture(directory.path());
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "debug-ambiguous-claim",
        directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let claims = OriginalClaims::new(blobs.clone(), refs.clone()).unwrap();
    assert_eq!(
        claims
            .reserve(&request.execution, Route::Debug, &encode(&request).unwrap())
            .unwrap(),
        Reservation::Original
    );
    let ledger = DebugLedger::new(blobs, refs).unwrap();
    assert!(ledger.reserve_start(&request).is_err());
}

#[test]
#[ignore = "requires actual source-built installed companion"]
fn changed_current_report_root_refuses_native_resume_and_preserves_original_stop() {
    let directory = tempfile::tempdir().unwrap();
    let (request, service, blobs, refs) = start_service(directory.path());
    service.start_debug(request.clone()).unwrap();
    let stopped = wait_for(&service, &request.execution, false);
    let name = RefName::new(format!(
        "node-world-coordinators/condition/debug-{}-stop-report",
        request.execution
    ))
    .unwrap();
    let original = refs.read_ref(&name).unwrap().unwrap();
    let wrong_bytes = b"changed current-store report";
    let wrong = ContentId::for_bytes(ObjectKind::Trace, 1, wrong_bytes);
    blobs
        .put_if_absent(wrong, &BlobHandle::from_bytes(wrong_bytes.to_vec()))
        .unwrap();
    assert!(matches!(
        refs.compare_exchange(&name, Some(original), wrong).unwrap(),
        RefCasOutcome::Advanced { .. }
    ));

    let resume = NodeDebugResumeRequest {
        format: "crucible.live-debug-resume".into(),
        version: 1,
        execution: request.execution.clone(),
        operation: id("original/rejected-resume"),
        horizon_ps: 2_000_000.into(),
    };
    let pending = service.resume_debug(resume.clone()).unwrap();
    let deadline = crate::supervision::ProcessDeadline::after(Duration::from_secs(20)).unwrap();
    let retained = loop {
        let state = service.debug_state(&request.execution).unwrap();
        if matches!(state.outcome, NodeDebugState::Unknown { .. }) {
            break state;
        }
        assert!(
            !deadline.expired(),
            "corrupt original result failed to refuse resume"
        );
        std::thread::yield_now();
    };
    assert_eq!(
        encode(&retained.stop).unwrap(),
        encode(&stopped.stop).unwrap()
    );
    assert_eq!(retained.resume_request, pending.resume_request);
    assert!(
        refs.read_ref(
            &RefName::new(format!(
                "node-world-coordinators/condition/debug-{}-resume",
                request.execution
            ))
            .unwrap()
        )
        .unwrap()
        .is_none()
    );
    assert!(
        refs.read_ref(
            &RefName::new(format!("node-debug-publications/{}", request.execution)).unwrap()
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(
        encode(&service.resume_debug(resume).unwrap()).unwrap(),
        encode(&retained).unwrap()
    );
    assert_eq!(
        std::fs::read(directory.path().join("base")).unwrap(),
        vec![0xab; 4096]
    );
    retire(service);
}

#[test]
fn direct_profile_serialization_is_charged_before_canonical_allocation() {
    let directory = tempfile::tempdir().unwrap();
    let (mut request, _) = installed_fixture(directory.path());
    let observer = request
        .selections
        .iter_mut()
        .find(|selected| selected.node == request.observer)
        .unwrap();
    let InstalledNodeKind::HostConditionDebug { profile } = &mut observer.kind else {
        panic!("authored observer profile absent")
    };
    profile.program.media_type = "a".repeat(1024 * 1024);
    let error = request.validate().unwrap_err();
    assert!(error.to_string().contains("JSON byte credit exhausted"));

    // Only the encoding boundary is exercised here: exact admitted byte credit
    // succeeds, and a single extra authored byte cannot reach canonical encode.
    let exact = "a".repeat(1024 * 1024 - 2);
    assert!(super::budget::bounded_json(&exact, 1024 * 1024).is_ok());
    let excessive = "a".repeat(1024 * 1024 - 1);
    assert!(super::budget::bounded_json(&excessive, 1024 * 1024).is_err());
}

#[test]
#[ignore = "requires actual source-built installed companion"]
fn historical_stopped_owner_never_redispatches_or_resumes_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let (request, original_service, _, refs) = start_service(directory.path());
    original_service.start_debug(request.clone()).unwrap();
    let stopped = wait_for(&original_service, &request.execution, false);
    let activation_name = RefName::new(format!(
        "node-world-activations/debug-{}",
        request.execution
    ))
    .unwrap();
    let activation = refs.read_ref(&activation_name).unwrap();
    retire(original_service);

    let (_, restarted, _, _) = start_service(directory.path());
    assert_eq!(
        encode(&restarted.start_debug(request.clone()).unwrap()).unwrap(),
        encode(&stopped).unwrap()
    );
    let resume = NodeDebugResumeRequest {
        format: "crucible.live-debug-resume".into(),
        version: 1,
        execution: request.execution.clone(),
        operation: id("original/historical-resume"),
        horizon_ps: 2_000_000.into(),
    };
    restarted.resume_debug(resume.clone()).unwrap();
    let deadline = crate::supervision::ProcessDeadline::after(Duration::from_secs(20)).unwrap();
    let retained = loop {
        let state = restarted.debug_state(&request.execution).unwrap();
        if matches!(state.outcome, NodeDebugState::Unknown { .. }) {
            break state;
        }
        assert!(!deadline.expired(), "historical original was not refused");
        std::thread::yield_now();
    };
    assert_eq!(
        encode(&retained.stop).unwrap(),
        encode(&stopped.stop).unwrap()
    );
    assert_eq!(refs.read_ref(&activation_name).unwrap(), activation);
    assert!(
        refs.read_ref(
            &RefName::new(format!(
                "node-world-coordinators/condition/debug-{}-resume",
                request.execution
            ))
            .unwrap()
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(
        encode(&restarted.resume_debug(resume).unwrap()).unwrap(),
        encode(&retained).unwrap()
    );
    retire(restarted);
}

#[test]
#[ignore = "requires actual source-built installed companion"]
fn paused_original_consumes_aggregate_capacity_before_another_world_allocation() {
    let directory = tempfile::tempdir().unwrap();
    let (request, service, _, refs) = start_service_with(directory.path(), |blobs| blobs, 1);
    service.start_debug(request.clone()).unwrap();
    let stopped = wait_for(&service, &request.execution, false);
    let mut second = request.clone();
    second.execution = "b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8".into();
    service.start_debug(second.clone()).unwrap();
    let deadline = crate::supervision::ProcessDeadline::after(Duration::from_secs(20)).unwrap();
    loop {
        if matches!(
            service.debug_state(&second.execution).unwrap().outcome,
            NodeDebugState::Unknown { .. }
        ) {
            break;
        }
        assert!(
            !deadline.expired(),
            "aggregate capacity original remains unresolved"
        );
        std::thread::yield_now();
    }
    assert!(
        refs.read_ref(
            &RefName::new(format!("node-world-activations/debug-{}", second.execution)).unwrap()
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(
        encode(&service.debug_state(&request.execution).unwrap()).unwrap(),
        encode(&stopped).unwrap()
    );
    retire(service);
}

#[path = "completion_fault.rs"]
mod completion_fault;
