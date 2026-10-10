//! Exercises original preserving claims through the actual private control socket.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Actual original custody and native byte assertions deliberately panic on failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod adverse;
mod capabilities;

use super::*;
use crate::node_control::{
    NodeArchiveArtifactMode, NodeControlCommand, NodeControlDaemon, NodeControlRequest,
    NodeControlResult, NodeDaemonPolicy, NodeImmutableArtifactPolicy,
    decode_preserving_debug_record, request_node_control,
};
use crate::node_observed_executor::{
    InstalledConditionDebugProfile, InstalledScriptedSourceProfile, factory::measure_executable,
};
use crucible::{
    AssertionDef, AssertionId, IoEventKind, NodeId, Predicate, Properties, Property,
    node_adapters::{
        ConditionDebugDefinition, HostSemanticDefinition, HostSemanticInput, HostSemanticInputKind,
        ScriptedRequest, ScriptedRequestKind, ScriptedSource,
    },
    node_scheduling::NativePublication,
};
use crucible_cas::content_store::{
    ContentId, DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend,
    RefName,
};
use crucible_device::{BlockRequest, BlockResponse};
use crucible_node_contract::Endpoint;
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

fn id(name: &str) -> Id {
    Id::new(name).unwrap()
}

struct Server {
    socket: PathBuf,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    retention: super::super::NodeObservationRetention,
}

impl Server {
    fn start(policy: NodeDaemonPolicy) -> Self {
        let socket = policy.socket.clone();
        let mut daemon = NodeControlDaemon::start(policy).unwrap();
        let retention = daemon.retention_owner();
        let stopping = Arc::new(AtomicBool::new(false));
        let actor_stopping = stopping.clone();
        let thread = std::thread::spawn(move || daemon.serve(&actor_stopping).unwrap());
        Self {
            socket,
            stopping,
            thread: Some(thread),
            retention,
        }
    }

    fn request(&self, request: NodeControlRequest) -> NodePreservingDebugRecord {
        decode_preserving_debug_record(&request_node_control(&self.socket, &request).unwrap())
            .unwrap()
    }

    fn status(&self, execution: &str, resumed: bool) -> NodePreservingDebugRecord {
        let deadline = crate::supervision::ProcessDeadline::after(Duration::from_secs(40)).unwrap();
        loop {
            let record = self.request(
                NodeControlRequest::preserving_debug_status("test/status", execution.into())
                    .unwrap(),
            );
            match &record.outcome {
                NodePreservingDebugState::Stopped {} if !resumed => return record,
                NodePreservingDebugState::Resumed { .. } if resumed => return record,
                NodePreservingDebugState::Unknown { reason } => {
                    panic!("original preserving custody refused: {reason}")
                }
                _ => {}
            }
            assert!(
                !deadline.expired(),
                "original preserving actor deadline expired"
            );
            std::thread::yield_now();
        }
    }

    fn prepare(&self, request: NodePreservingDebugRequest) -> NodePreservingDebugRecord {
        let execution = request.execution.clone();
        self.request(
            NodeControlRequest::preserving_debug_prepare("test/prepare", request).unwrap(),
        );
        self.status(&execution, false)
    }

    fn resume(&self, execution: &str) -> NodePreservingDebugRecord {
        self.request(
            NodeControlRequest::preserving_debug_resume(
                "test/resume",
                NodePreservingDebugResumeRequest {
                    format: "crucible.preserving-debug-resume".into(),
                    version: 1,
                    execution: execution.into(),
                    horizon_ps: 2_100_000.into(),
                },
            )
            .unwrap(),
        );
        self.status(execution, true)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        assert!(
            self.retention.is_retired(),
            "original complete daemon native custody remains"
        );
    }
}

pub(super) fn fixture(
    directory: &Path,
) -> (
    Vec<InstalledNodeSelection>,
    Vec<NodeImmutableArtifactPolicy>,
) {
    let script = ScriptedSource::new(
        ScriptedRequestKind::Block,
        vec![
            ScriptedRequest {
                time_ps: 10,
                payload: BlockRequest::write(7, 0, vec![0x5c; 64]).encode().unwrap(),
            },
            ScriptedRequest {
                time_ps: 10,
                payload: BlockRequest::write(8, 0, vec![0x6d; 128]).encode().unwrap(),
            },
            ScriptedRequest {
                time_ps: 1_000_000,
                payload: BlockRequest::read(9, 0, 64).encode().unwrap(),
            },
        ],
    )
    .unwrap()
    .script_bytes()
    .unwrap();
    let mut references = Vec::new();
    let mut artifacts = Vec::new();
    for (name, bytes, media) in [
        ("base", vec![0xab; 4096], "application/octet-stream"),
        ("script", script, "application/octet-stream"),
        ("condition", condition_program(), "application/json"),
    ] {
        let expected = canonical::content_ref(&bytes, media).unwrap();
        let path = directory.join(name);
        std::fs::write(&path, bytes).unwrap();
        artifacts.push(NodeImmutableArtifactPolicy::Path {
            path,
            expected: expected.clone(),
        });
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
            kind: InstalledNodeKind::HostConditionDebugPreserving {
                profile: InstalledConditionDebugProfile {
                    program: references[2].clone(),
                },
            },
        },
    ];
    selections.sort_by(|left, right| left.node.cmp(&right.node));
    (selections, artifacts)
}

fn policy(
    directory: &Path,
    immutable_artifacts: Vec<NodeImmutableArtifactPolicy>,
) -> NodeDaemonPolicy {
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    NodeDaemonPolicy {
        format: "crucible.node-daemon-policy".into(),
        version: 2,
        state_directory: directory.into(),
        socket: directory.join("control.sock"),
        expected_device: measure_executable(&executable).unwrap(),
        device_executable: executable,
        control_timeout_ms: 5000,
        maximum_worlds: 8,
        maximum_pending_requests: 8,
        maximum_host_state_worlds: Some(4),
        maximum_native_state_requests: None,
        immutable_artifacts,
    }
}

fn publications(directory: &Path, record: &NodePreservingDebugRecord) -> Vec<NativePublication> {
    let NodePreservingDebugState::Resumed { publications, .. } = &record.outcome else {
        panic!("original suffix is not retired")
    };
    let refs = DirectoryRefBackend::new(directory.join("refs"));
    let stored = refs
        .read_ref(
            &RefName::new(format!(
                "node-preserving-debug-publications/{}",
                record.execution
            ))
            .unwrap(),
        )
        .unwrap()
        .unwrap();
    let blobs = DirectoryBlobBackend::new("operator-proof", directory.join("blobs"));
    let bytes = blobs
        .read(stored, None)
        .unwrap()
        .read_all(32 << 20)
        .unwrap();
    assert_eq!(
        ContentId::for_bytes(crucible_cas::content_store::ObjectKind::Trace, 1, &bytes),
        stored
    );
    publications.verify(&bytes).unwrap();
    let value = canonical::parse_json(&bytes, 32 << 20).unwrap();
    serde_json::from_value(value["publications"].clone()).unwrap()
}

fn native_suffix(
    publications: &[NativePublication],
    cut: Position,
) -> Vec<(U64, Position, Vec<Position>, Vec<u8>)> {
    publications
        .iter()
        .filter(|publication| {
            publication.endpoint.node_id == id("disk") && publication.publication > cut
        })
        .map(|publication| {
            (
                publication.native_sequence,
                publication.publication,
                publication.causal_parents.clone(),
                publication.payload_bytes.clone(),
            )
        })
        .collect()
}

#[test]
#[ignore = "requires actual source-built installed host catalog companion measurement"]
fn original_capture_claim_survives_source_gone_twins_and_native_suffix_once() {
    let directory = tempfile::tempdir().unwrap().keep();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    eprintln!(
        "operator preserving original custody: {}",
        directory.display()
    );
    let (selections, artifacts) = fixture(&directory);
    let original_policy = policy(&directory, artifacts.clone());
    let server = Server::start(original_policy.clone());
    let scenario_reply = request_node_control(
        &server.socket,
        &NodeControlRequest::new(
            "test/compile",
            NodeControlCommand::Compile {
                selections: selections.clone(),
            },
        )
        .unwrap(),
    )
    .unwrap();
    let NodeControlResult::Compiled { scenario } = scenario_reply.result else {
        panic!("installed scenario was not compiled")
    };
    let request = NodePreservingDebugRequest {
        format: "crucible.preserving-debug-request".into(),
        version: 1,
        requirements: None,
        execution: "10101010101010101010101010101010".into(),
        selections,
        scenario,
        observer: id("observer"),
        maximum_physical_cut: 2_000_000.into(),
        maximum_record_bytes: (32 << 20).into(),
        action: NodePreservingDebugAction::Capture {},
    };
    let stopped = adverse::prepare_cli(&server, &directory, request.clone());
    let original_capture = stopped.capture.clone().unwrap();
    let original_record_bytes = encode(&stopped).unwrap();
    std::fs::write(
        directory.join("source-stopped.json"),
        &original_record_bytes,
    )
    .unwrap();
    adverse::refuse_original_nonce_change(&server, &directory, &request);
    let original = adverse::resume_cli(&server, &directory, &request.execution);
    let original_publications = publications(&directory, &original);
    let suffix = native_suffix(&original_publications, original_capture.cut);
    assert_eq!(suffix.len(), 2);
    let read = BlockResponse::decode(&suffix[1].3).unwrap();
    assert_eq!(read.request_id, 9);
    assert_eq!(read.data, vec![0x6d; 64]);
    assert_eq!(
        std::fs::read(directory.join("base")).unwrap(),
        vec![0xab; 4096]
    );
    drop(server);

    // Independently enrolled identities survive source removal; the remote
    // archive supplies original bytes only after source MAC/native admission.
    let archive_only = artifacts
        .into_iter()
        .map(|artifact| {
            let NodeImmutableArtifactPolicy::Path { path, expected } = artifact else {
                unreachable!()
            };
            std::fs::remove_file(path).unwrap();
            NodeImmutableArtifactPolicy::ArchiveOnly {
                mode: NodeArchiveArtifactMode::ArchiveOnly,
                expected,
            }
        })
        .collect();
    let mut restored_policy = original_policy;
    restored_policy.immutable_artifacts = archive_only;
    let server = Server::start(restored_policy.clone());
    assert_eq!(
        encode(&server.status(&request.execution, true)).unwrap(),
        encode(&original).unwrap()
    );
    adverse::refuse_foreign_relations(&server, &directory, &request, &original_capture);
    adverse::refuse_unavailable_signed_archive(&server, &directory, &request, &original_capture);
    let mut restored_requests = Vec::new();
    for execution in [
        "20202020202020202020202020202020",
        "30303030303030303030303030303030",
    ] {
        let mut target = request.clone();
        target.execution = execution.into();
        target.action = NodePreservingDebugAction::Restore {
            source_execution: request.execution.clone(),
            capture: original_capture.artifact.clone(),
        };
        let stopped = server.prepare(target.clone());
        assert_eq!(stopped.capture.as_ref(), Some(&original_capture));
        restored_requests.push(target);
    }
    // Both independently activated native worlds retain the original Stop at
    // the same current cut before either actual Resume is authorized.
    for target in &restored_requests {
        let restored = server.resume(&target.execution);
        let actual = publications(&directory, &restored);
        assert_eq!(native_suffix(&actual, original_capture.cut), suffix);
        assert_eq!(
            server.resume(&target.execution).resume_request,
            restored.resume_request
        );
        assert_eq!(
            encode(&server.status(&target.execution, true)).unwrap(),
            encode(&restored).unwrap()
        );
        std::fs::write(
            directory.join(format!("target-{}.json", target.execution)),
            encode(&restored).unwrap(),
        )
        .unwrap();
    }
    assert!(!directory.join("base").exists());
    assert!(!directory.join("script").exists());
    assert!(!directory.join("condition").exists());
    adverse::refuse_changed_current_report(&server, &directory, &request, &original_capture);
    let mut orphan = request.clone();
    orphan.execution = "60606060606060606060606060606060".into();
    orphan.action = NodePreservingDebugAction::Restore {
        source_execution: request.execution.clone(),
        capture: original_capture.artifact.clone(),
    };
    server.prepare(orphan.clone());
    drop(server);
    let server = Server::start(restored_policy);
    adverse::refuse_stored_stop_without_owner(&server, &directory, &orphan.execution);
    for target in &restored_requests {
        server.status(&target.execution, true);
    }
    drop(server);
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

#[test]
fn direct_profile_preflight_refuses_oversized_metadata_before_canonical_encoding() {
    let directory = tempfile::tempdir().unwrap();
    let (mut selections, _) = fixture(directory.path());
    let observer = selections
        .iter_mut()
        .find(|selection| selection.node == id("observer"))
        .unwrap();
    let InstalledNodeKind::HostConditionDebugPreserving { profile } = &mut observer.kind else {
        panic!("authored observer absent")
    };
    profile.program.media_type = "a".repeat(2 << 20);
    let request = NodePreservingDebugRequest {
        format: "crucible.preserving-debug-request".into(),
        version: 1,
        requirements: None,
        execution: "40404040404040404040404040404040".into(),
        selections,
        scenario: Bytes::new(Vec::new()),
        observer: id("observer"),
        maximum_physical_cut: 1.into(),
        maximum_record_bytes: (32 << 20).into(),
        action: NodePreservingDebugAction::Capture {},
    };
    let error = request.validate().unwrap_err().to_string();
    assert!(error.contains("JSON byte credit exhausted"), "{error}");
}

#[test]
fn nonretaining_serializer_accepts_exact_credit_and_refuses_next_byte() {
    let exact = serde_json::Value::String("a".repeat((2 << 20) - 2));
    assert!(budget::bounded_json(&exact, 2 << 20).is_ok());
    let excessive = serde_json::Value::String("a".repeat((2 << 20) - 1));
    assert!(budget::bounded_json(&excessive, 2 << 20).is_err());
}
