//! Original terminal requests over the real authenticated local actor transport.

// crucible-lint: allow panic-shortcut -- Original terminal publication, failure and cold ACK assertions fail immediately.
// crucible-lint: allow rust-allow -- Unexpected actor states must fail rather than replace the original attempt.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use crucible::{
    AssertionDef, AssertionId, Predicate, Properties, Property, VirtualTime,
    model::PropertyNamespace,
    node_adapters::HostSemanticDefinition,
    node_state::{HostArchive, StateLimits},
};
use crucible_node_contract::{Bytes, U64, canonical};

use super::{
    NodeControlCommand, NodeControlDaemon, NodeControlRequest, NodeControlResult, NodeDaemonPolicy,
    NodeHostStateOutcome, NodeHostStateRequest, NodeTerminalStage, NodeTerminalStateRequest,
    request_node_control,
};

#[test]
fn terminal_wire_requires_its_explicit_edition_and_preserves_legacy_status_bytes() {
    let original = NodeTerminalStateRequest::Status {
        execution: "29292929292929292929292929292929".into(),
    };
    let mut request =
        NodeControlRequest::terminal_state("probe/terminal", original.clone()).unwrap();
    assert_eq!(request.version, 4);
    for version in [1, 2, 3, 5] {
        request.version = version;
        assert!(request.validate().is_err());
    }
    assert!(
        NodeControlRequest::host_state(
            "probe/forged",
            NodeHostStateRequest::Terminal {
                request: Box::new(original),
            }
        )
        .is_err()
    );

    let legacy = NodeControlRequest::new(
        "probe/old",
        NodeControlCommand::Status {
            execution: "29292929292929292929292929292929".into(),
        },
    )
    .unwrap();
    assert_eq!(canonical::canonical_json(&serde_json::to_value(&legacy).unwrap()).unwrap(),
        br#"{"command":{"execution":"29292929292929292929292929292929","operation":"status"},"format":"crucible.node-control","request_id":"probe/old","version":1}"#);
    let legacy_state = NodeControlRequest::host_state(
        "probe/state",
        NodeHostStateRequest::Status {
            execution: "29292929292929292929292929292929".into(),
        },
    )
    .unwrap();
    assert_eq!(canonical::canonical_json(&serde_json::to_value(&legacy_state).unwrap()).unwrap(),
        br#"{"command":{"operation":"host_state","request":{"execution":"29292929292929292929292929292929","operation":"status"}},"format":"crucible.node-control","request_id":"probe/state","version":2}"#);
    // This schema-only record does not claim a real retained request body.
    let legacy_record_bytes = br#"{"execution":"29292929292929292929292929292929","format":"crucible.node-state-operation","request":"trace.1.0000000000000000000000000000000000000000000000000000000000000000","state":{"status":"reserved"},"version":1}"#;
    let legacy_record = super::NodeHostStateRecord::from_json(legacy_record_bytes).unwrap();
    assert_eq!(
        canonical::canonical_json(&serde_json::to_value(legacy_record).unwrap()).unwrap(),
        legacy_record_bytes
    );
    let native_status = NodeControlRequest::native_state(
        "probe/native",
        crate::node_observed_executor::NativeWorldRequest::Status {
            execution: "29292929292929292929292929292929".into(),
        },
    )
    .unwrap();
    assert_eq!(canonical::canonical_json(&serde_json::to_value(&native_status).unwrap()).unwrap(),
        br#"{"command":{"operation":"native_state","request":{"execution":"29292929292929292929292929292929","operation":"status"}},"format":"crucible.node-control","request_id":"probe/native","version":3}"#);
    let unknown = serde_json::json!({"operation":"status","execution":"29292929292929292929292929292929","eof":true});
    assert!(serde_json::from_value::<NodeTerminalStateRequest>(unknown).is_err());
}

#[test]
#[ignore = "requires the actual source-built companion and terminal archive overlay"]
fn terminal_actor_preserves_original_publication_after_restart_and_two_fresh_restores() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let expected =
        canonical::content_ref(&fs::read(&executable).unwrap(), "application/octet-stream")
            .unwrap();
    let namespace = PropertyNamespace::new(BTreeMap::new(), false, true, BTreeSet::new()).unwrap();
    let properties = Properties::from_assertions_for_namespace(
        &namespace,
        vec![
            AssertionDef {
                id: AssertionId::from_name("original-emitted"),
                message: "original deadline".into(),
                property: Property::Sometimes {
                    predicate: Predicate::at(VirtualTime { ticks: 2 }),
                },
            },
            AssertionDef {
                id: AssertionId::from_name("original-terminal"),
                message: "actual native and coordinator closure".into(),
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
    let program = canonical::canonical_json(&serde_json::to_value(definition).unwrap()).unwrap();
    let program_ref = canonical::content_ref(&program, "application/json").unwrap();
    let program_path = directory.path().join("program.json");
    fs::write(&program_path, &program).unwrap();
    let mut policy = serde_json::json!({
        "format":"crucible.node-daemon-policy", "version":2,
        "state_directory":directory.path(), "socket":directory.path().join("control.sock"),
        "device_executable":executable, "expected_device":expected,
        "control_timeout_ms":3000, "maximum_worlds":2, "maximum_pending_requests":2,
        "maximum_host_state_worlds":4,
        "immutable_artifacts":[{"path":program_path,"expected":program_ref}]
    });
    let selections: Vec<crate::node_observed_executor::InstalledNodeSelection> = serde_json::from_value(serde_json::json!([
        {"node":"clock","owner":"clock-owner","kind":{"implementation":"host_clock"}},
        {"node":"semantics","owner":"semantics-owner","kind":{"implementation":"host_semantics","profile":{"program":program_ref}}}
    ])).unwrap();
    let socket = directory.path().join("control.sock");
    let (stopping, server) = start(&policy);
    let compiled = request_node_control(
        &socket,
        &NodeControlRequest::new(
            "compile",
            NodeControlCommand::Compile {
                selections: selections.clone(),
            },
        )
        .unwrap(),
    )
    .unwrap();
    let NodeControlResult::Compiled { scenario } = compiled.result else {
        panic!("actual owning actor did not compile");
    };
    let unfinished = NodeTerminalStateRequest::Capture {
        execution: "31313131313131313131313131313131".into(),
        selections: selections.clone(),
        scenario: scenario.clone(),
        ceiling_ps: U64::new(1),
        stage: NodeTerminalStage::Acknowledged,
    };
    let refused = complete(&socket, &unfinished);
    assert!(
        matches!(refused.state, NodeHostStateOutcome::Unknown { .. }),
        "a reached ceiling before original pending evaluation must not authorize EOF or an artifact"
    );
    assert_eq!(
        serde_json::to_value(complete(&socket, &unfinished)).unwrap(),
        serde_json::to_value(refused).unwrap(),
        "the original refusal remains committed rather than retrying finalization"
    );
    let capture = NodeTerminalStateRequest::Capture {
        execution: "41414141414141414141414141414141".into(),
        selections: selections.clone(),
        scenario: scenario.clone(),
        ceiling_ps: U64::new(11),
        stage: NodeTerminalStage::Published,
    };
    let original = complete(&socket, &capture);
    assert_eq!(original.version, 2);
    let NodeHostStateOutcome::Completed { artifact, .. } = &original.state else {
        panic!("actual terminal capture did not complete");
    };
    let artifact = artifact.clone();
    let legacy_status = request_node_control(
        &socket,
        &NodeControlRequest::host_state(
            "legacy/status",
            NodeHostStateRequest::Status {
                execution: capture.execution().into(),
            },
        )
        .unwrap(),
    );
    let legacy_status = legacy_status.unwrap();
    assert!(
        matches!(legacy_status.result, NodeControlResult::Refused { .. }),
        "control2 cannot expose a terminal2 operation record"
    );
    let clock_selections = vec![selections[0].clone()];
    let compiled_clock = request_node_control(
        &socket,
        &NodeControlRequest::new(
            "legacy/compile",
            NodeControlCommand::Compile {
                selections: clock_selections.clone(),
            },
        )
        .unwrap(),
    )
    .unwrap();
    let NodeControlResult::Compiled {
        scenario: clock_scenario,
    } = compiled_clock.result
    else {
        panic!("actual clock compile refused");
    };
    let legacy_capture = NodeHostStateRequest::Capture {
        execution: "39393939393939393939393939393939".into(),
        selections: clock_selections,
        scenario: clock_scenario,
        horizon_ps: U64::new(1),
    };
    request_node_control(
        &socket,
        &NodeControlRequest::host_state("legacy/capture", legacy_capture).unwrap(),
    )
    .unwrap();
    let mut legacy_completed = false;
    for _ in 0..2000 {
        let reply = request_node_control(
            &socket,
            &NodeControlRequest::host_state(
                "legacy/read",
                NodeHostStateRequest::Status {
                    execution: "39393939393939393939393939393939".into(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        let NodeControlResult::HostState { record } = reply.result else {
            panic!("legacy state status refused");
        };
        if matches!(record.state, NodeHostStateOutcome::Completed { .. }) {
            legacy_completed = true;
            break;
        }
        assert!(matches!(record.state, NodeHostStateOutcome::Reserved {}));
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        legacy_completed,
        "actual legacy capture must settle without changing edition"
    );
    let wrong_terminal = request_node_control(
        &socket,
        &NodeControlRequest::terminal_state(
            "terminal/legacy",
            NodeTerminalStateRequest::Status {
                execution: "39393939393939393939393939393939".into(),
            },
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        matches!(wrong_terminal.result, NodeControlResult::Refused { .. }),
        "control4 cannot expose a legacy1 operation record"
    );
    stop(stopping, server);
    fs::remove_file(&program_path).unwrap();
    policy["immutable_artifacts"] =
        serde_json::json!([{"mode":"archive_only","expected":program_ref}]);

    let (stopping, server) = start(&policy);
    assert_eq!(
        serde_json::to_value(complete(&socket, &capture)).unwrap(),
        serde_json::to_value(&original).unwrap(),
        "the source-gone retry reads the original reservation without native redispatch"
    );
    let limits = StateLimits {
        maximum_content_bytes: 512 * 1024 * 1024,
        maximum_total_content_bytes: 1024 * 1024 * 1024,
        ..StateLimits::default()
    };
    let archive = HostArchive::open(directory.path().join("host-state-archives"), limits).unwrap();
    let source = archive.load(&artifact).unwrap();
    let original_coordinator: serde_json::Value = serde_json::from_slice(
        &source
            .content_bytes(&source.manifest().coordinator_state_ref, 16 * 1024 * 1024)
            .unwrap(),
    )
    .unwrap();
    let original_terminal = &original_coordinator["runtime"]["terminal"];
    assert_eq!(original_terminal["acknowledged"], false);
    assert_eq!(original_terminal["publication"], "committed");
    for nonce in [
        "51515151515151515151515151515151",
        "61616161616161616161616161616161",
    ] {
        let request = NodeTerminalStateRequest::Restore {
            execution: nonce.into(),
            selections: selections.clone(),
            scenario: scenario.clone(),
            source: artifact.clone(),
            stage: NodeTerminalStage::Acknowledged,
        };
        let result = complete(&socket, &request);
        let NodeHostStateOutcome::Completed {
            artifact: fresh, ..
        } = result.state
        else {
            panic!("original cold terminal continuation did not complete");
        };
        let restored = archive.load(&fresh).unwrap();
        let coordinator: serde_json::Value = serde_json::from_slice(
            &restored
                .content_bytes(&restored.manifest().coordinator_state_ref, 16 * 1024 * 1024)
                .unwrap(),
        )
        .unwrap();
        let terminal = &coordinator["runtime"]["terminal"];
        assert_eq!(terminal["record"], original_terminal["record"]);
        assert_eq!(terminal["report"], original_terminal["report"]);
        assert_eq!(terminal["publication"], "committed");
        assert_eq!(terminal["acknowledged"], true);
    }
    stop(stopping, server);
}

fn start(policy: &serde_json::Value) -> (Arc<AtomicBool>, thread::JoinHandle<()>) {
    let policy = NodeDaemonPolicy::from_json(&serde_json::to_vec(policy).unwrap()).unwrap();
    let mut daemon = NodeControlDaemon::start(policy).unwrap();
    assert!(daemon.host_state_retention_owner().is_some());
    let stopping = Arc::new(AtomicBool::new(false));
    let control = Arc::clone(&stopping);
    let server = thread::spawn(move || {
        daemon.serve(&control).unwrap();
    });
    (stopping, server)
}

fn stop(stopping: Arc<AtomicBool>, server: thread::JoinHandle<()>) {
    stopping.store(true, Ordering::Release);
    server.join().unwrap();
}

fn complete(
    socket: &std::path::Path,
    request: &NodeTerminalStateRequest,
) -> super::NodeHostStateRecord {
    let reply = request_node_control(
        socket,
        &NodeControlRequest::terminal_state("original/submit", request.clone()).unwrap(),
    )
    .unwrap();
    let NodeControlResult::HostState { mut record } = reply.result else {
        panic!("actual original terminal admission was refused");
    };
    for _ in 0..2000 {
        if !matches!(record.state, NodeHostStateOutcome::Reserved {}) {
            return *record;
        }
        thread::sleep(Duration::from_millis(10));
        let status = NodeTerminalStateRequest::Status {
            execution: request.execution().into(),
        };
        let reply = request_node_control(
            socket,
            &NodeControlRequest::terminal_state("original/status", status).unwrap(),
        )
        .unwrap();
        let NodeControlResult::HostState { record: next } = reply.result else {
            panic!("original terminal status disappeared");
        };
        record = next;
    }
    panic!("original terminal operation exceeded the test's operational wait");
}

use crucible_cas::content_store::{
    ContentId, DirectoryBlobBackend, DirectoryRefBackend, MutableRefBackend,
    RefBackendCapabilities, RefCasOutcome, RefName, RefPublicationGuard, RefScanPage, StoreError,
};

struct PanicCompletionRefs {
    returns_error: bool,
    inner: DirectoryRefBackend,
    panicked: AtomicBool,
}

impl MutableRefBackend for PanicCompletionRefs {
    fn capabilities(&self) -> RefBackendCapabilities {
        self.inner.capabilities()
    }
    fn acquire_publication_guard(&self) -> Result<Box<dyn RefPublicationGuard + '_>, StoreError> {
        self.inner.acquire_publication_guard()
    }
    fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
        self.inner.read_ref(name)
    }
    fn scan_refs(
        &self,
        namespace: &RefName,
        after: Option<&RefName>,
        limit: usize,
    ) -> Result<RefScanPage, StoreError> {
        self.inner.scan_refs(namespace, after, limit)
    }
    fn compare_exchange(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
        next: ContentId,
    ) -> Result<RefCasOutcome, StoreError> {
        if name.as_str().starts_with("node-state-operations/")
            && expected.is_some()
            && !self.panicked.swap(true, Ordering::AcqRel)
        {
            if self.returns_error {
                return Err(StoreError::Unavailable);
            }
            panic!("completion backend fails after original terminal native effects");
        }
        self.inner.compare_exchange(name, expected, next)
    }
}

#[test]
#[ignore = "requires actual source-built companion and terminal archive overlay"]
fn original_terminal_completion_panic_keeps_result_until_reconciliation_and_reclamation() {
    original_terminal_completion_failure(false);
}

#[test]
#[ignore = "requires actual source-built companion and terminal archive overlay"]
fn original_terminal_completion_error_keeps_result_until_reconciliation_and_reclamation() {
    original_terminal_completion_failure(true);
}

fn original_terminal_completion_failure(returns_error: bool) {
    use super::host_state_service::NodeHostStateService;
    use crate::node_observed_executor::{
        InstalledIoArtifact, InstalledNodeCatalog, NodeObservationServiceConfig,
    };
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let expected =
        canonical::content_ref(&fs::read(&executable).unwrap(), "application/octet-stream")
            .unwrap();
    let namespace = PropertyNamespace::new(BTreeMap::new(), false, true, BTreeSet::new()).unwrap();
    let properties = Properties::from_assertions_for_namespace(
        &namespace,
        vec![AssertionDef {
            id: AssertionId::from_name("retained-terminal"),
            message: "original report must survive storage panic".into(),
            property: Property::AfterQuiescence {
                predicate: Predicate::quiescent(),
            },
        }],
    )
    .unwrap();
    let definition = HostSemanticDefinition {
        version: 2,
        properties: Bytes::new(properties.to_compact_binary()),
        inputs: Vec::new(),
    };
    let program = canonical::canonical_json(&serde_json::to_value(definition).unwrap()).unwrap();
    let program_ref = canonical::content_ref(&program, "application/json").unwrap();
    let path = directory.path().join("program.json");
    fs::write(&path, program).unwrap();
    let selections: Vec<crate::node_observed_executor::InstalledNodeSelection> = serde_json::from_value(serde_json::json!([
        {"node":"clock","owner":"clock-owner","kind":{"implementation":"host_clock"}},
        {"node":"semantics","owner":"semantics-owner","kind":{"implementation":"host_semantics","profile":{"program":program_ref}}}
    ])).unwrap();
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        expected.clone(),
        directory.path().to_path_buf(),
        Duration::from_secs(3),
        4,
    )
    .unwrap();
    catalog
        .install_artifacts(vec![InstalledIoArtifact::path(
            path.clone(),
            program_ref.clone(),
        )])
        .unwrap();
    let scenario = catalog
        .scenario(&selections)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    drop(catalog);
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "terminal-panic",
        directory.path().join("blobs"),
    ));
    let refs = Arc::new(PanicCompletionRefs {
        returns_error,
        inner: DirectoryRefBackend::new(directory.path().join("refs")),
        panicked: AtomicBool::new(false),
    });
    let service = NodeHostStateService::start(
        NodeObservationServiceConfig {
            installed_artifacts: vec![InstalledIoArtifact::path(path, program_ref)],
            device_executable: executable,
            expected_device: expected,
            socket_parent: directory.path().to_path_buf(),
            control_timeout: Duration::from_secs(3),
            maximum_worlds: 4,
            maximum_pending_requests: 2,
        },
        directory.path().join("archives"),
        blobs,
        refs.clone(),
    )
    .unwrap();
    let request = NodeHostStateRequest::Terminal {
        request: Box::new(NodeTerminalStateRequest::Capture {
            execution: "81818181818181818181818181818181".into(),
            selections,
            scenario: Bytes::new(scenario),
            ceiling_ps: U64::new(11),
            stage: NodeTerminalStage::Published,
        }),
    };
    assert!(matches!(
        service.submit(request.clone()).unwrap().state,
        NodeHostStateOutcome::Reserved {}
    ));
    let retention = service.retention_owner();
    for _ in 0..18000 {
        if retention.is_retired() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(refs.panicked.load(Ordering::Acquire));
    assert!(
        retention.is_retired(),
        "original result must reconcile before metadata retirement"
    );
    let record = service
        .submit(NodeHostStateRequest::Status {
            execution: request.execution().into(),
        })
        .unwrap();
    assert!(
        matches!(record.state, NodeHostStateOutcome::Completed { .. }),
        "same original successful artifact must survive callback unwind"
    );
    assert!(
        retention
            .retention_roots()
            .unwrap()
            .contains(&record.request)
    );
    drop(service);
}
