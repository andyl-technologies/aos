//! Exercises original live condition stop/report/resume through the actual CLI.

#![cfg(target_os = "linux")]
// crucible-lint: allow panic-shortcut -- Real native/process fixtures deliberately panic on incorrect original bytes or custody.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// crucible-lint: allow clippy-disallowed-method -- Absolute process deadlines bound cleanup and never enter modeled state.
#![allow(clippy::disallowed_methods)]

use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, RefName,
};
use crucible_core::{
    AssertionDef, AssertionId, IoEventKind, NodeId, Predicate, Properties, Property,
    node_adapters::{
        ConditionDebugDefinition, HostSemanticDefinition, HostSemanticInput, HostSemanticInputKind,
        ScriptedRequest, ScriptedRequestKind, ScriptedSource,
    },
};
use crucible_daemon::node_observed_executor::{
    InstalledConditionDebugProfile, InstalledHostIoProfile, InstalledIoArtifact,
    InstalledIoArtifactSource, InstalledNodeKind, InstalledNodeSelection,
    InstalledScriptedSourceProfile, NodeDebugStartRequest,
};
use crucible_device::{BlockRequest, BlockResponse};
use crucible_node_contract::{Bytes, Endpoint, Id, canonical};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

fn cli(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args(arguments)
        .output()
        .unwrap()
}

fn successful(arguments: &[&str]) -> Value {
    let output = cli(arguments);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

struct Daemon(Child);

impl Daemon {
    fn start(policy: &Path, socket: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_crucible"))
            .args(["node", "serve", "--policy", policy.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut daemon = Self(child);
        let deadline = Instant::now() + Duration::from_secs(20);
        while !socket.exists() {
            assert!(
                daemon.0.try_wait().unwrap().is_none(),
                "actual daemon exited during installation"
            );
            assert!(
                Instant::now() < deadline,
                "private endpoint installation expired"
            );
            std::thread::yield_now();
        }
        daemon
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(pid) = rustix::process::Pid::from_raw(self.0.id() as i32) {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::INT);
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.0.try_wait().ok().flatten().is_none() {
            if Instant::now() >= deadline {
                let _ = self.0.kill();
                let _ = self.0.wait();
                panic!("actual Debug owner failed graceful native reclamation");
            }
            std::thread::yield_now();
        }
    }
}

fn await_state(socket: &Path, execution: &str, expected: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let state = successful(&[
            "node",
            "debug-status",
            "--socket",
            socket.to_str().unwrap(),
            "--execution",
            execution,
        ]);
        if state["outcome"]["state"] == expected {
            return state;
        }
        assert_ne!(state["outcome"]["state"], "unknown", "{state}");
        assert!(
            Instant::now() < deadline,
            "original Debug operation deadline expired"
        );
        std::thread::yield_now();
    }
}

fn id(name: &str) -> Id {
    Id::new(name).unwrap()
}

fn condition_program() -> Vec<u8> {
    let disk = NodeId {
        name: "disk".to_owned(),
    };
    let namespace = crucible_core::model::PropertyNamespace::new(
        std::collections::BTreeMap::from([(
            disk.clone(),
            std::collections::BTreeSet::from([crucible_core::model::PropertyObservation::Io(
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

#[test]
#[ignore = "requires actual source-built installed native companion"]
fn actual_cli_stops_reports_resumes_once_and_restart_reads_original_result() {
    let device = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path();
    fs::set_permissions(state, fs::Permissions::from_mode(0o700)).unwrap();
    let (request, artifacts) = installed_fixture(state);
    let expected_device =
        canonical::content_ref(&fs::read(&device).unwrap(), "application/octet-stream").unwrap();
    let socket = state.join("control.sock");
    let policy = state.join("policy.json");
    let start = state.join("start.json");
    let resume = state.join("resume.json");
    let installed: Vec<_> = artifacts
        .into_iter()
        .map(|artifact| {
            let InstalledIoArtifactSource::Path(path) = artifact.source else {
                panic!("actual fixture path absent")
            };
            json!({"path":path,"expected":artifact.expected})
        })
        .collect();
    fs::write(
        &policy,
        serde_json::to_vec(&json!({
            "format":"crucible.node-daemon-policy", "version":1, "state_directory":state,
            "socket":socket, "device_executable":device, "expected_device":expected_device,
            "control_timeout_ms":3000,"maximum_worlds":2,"maximum_pending_requests":4,
            "immutable_artifacts":installed
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(&start, serde_json::to_vec(&request).unwrap()).unwrap();
    fs::write(
        &resume,
        serde_json::to_vec(&json!({
            "format":"crucible.live-debug-resume", "version":1, "execution":request.execution,
            "operation":"operator/original-resume", "horizon_ps":"2000000"
        }))
        .unwrap(),
    )
    .unwrap();
    let daemon = Daemon::start(&policy, &socket);
    let start_args = [
        "node",
        "debug-start",
        "--socket",
        socket.to_str().unwrap(),
        "--request",
        start.to_str().unwrap(),
    ];
    let original = successful(&start_args);
    assert_eq!(original["outcome"]["state"], "awaiting_admission");
    let stopped = await_state(&socket, &request.execution, "stopped");
    assert_eq!(
        stopped["outcome"]["cut"],
        json!({"time_ps":"513010","microstep":"3","phase":0})
    );
    assert_eq!(successful(&start_args), stopped);
    let resume_args = [
        "node",
        "debug-resume",
        "--socket",
        socket.to_str().unwrap(),
        "--request",
        resume.to_str().unwrap(),
    ];
    let pending = successful(&resume_args);
    assert_eq!(pending["outcome"]["state"], "awaiting_resume");
    let resumed = await_state(&socket, &request.execution, "resumed");
    assert_eq!(resumed["request"], original["request"]);
    assert_eq!(resumed["stop"], stopped["stop"]);
    assert_eq!(successful(&resume_args), resumed);

    let blobs = DirectoryBlobBackend::new("actual-cli-debug", state.join("blobs"));
    let refs = DirectoryRefBackend::new(state.join("refs"));
    let outputs_name =
        RefName::new(format!("node-debug-publications/{}", request.execution)).unwrap();
    let body = blobs
        .read(refs.read_ref(&outputs_name).unwrap().unwrap(), None)
        .unwrap()
        .read_all(32 << 20)
        .unwrap();
    let reference: crucible_node_contract::ContentRef =
        serde_json::from_value(resumed["outcome"]["publications"].clone()).unwrap();
    reference.verify(&body).unwrap();
    let outputs: Value = serde_json::from_slice(&body).unwrap();
    let publications: Vec<crucible_core::node_scheduling::NativePublication> =
        serde_json::from_value(outputs["publications"].clone()).unwrap();
    let disk: Vec<_> = publications
        .iter()
        .filter(|output| output.endpoint.node_id == id("disk"))
        .collect();
    assert_eq!(disk.len(), 2);
    assert_eq!(disk[0].native_sequence.get(), 0);
    assert_eq!(disk[1].native_sequence.get(), 1);
    assert_eq!(
        BlockResponse::decode(&disk[0].payload_bytes)
            .unwrap()
            .request_id,
        7
    );
    let read = BlockResponse::decode(&disk[1].payload_bytes).unwrap();
    assert_eq!(read.request_id, 9);
    assert_eq!(read.data, vec![0x5c; 512]);
    assert!(!disk[1].causal_parents.is_empty());
    assert_eq!(fs::read(state.join("base")).unwrap(), vec![0xab; 4096]);
    let activation_name = RefName::new(format!(
        "node-world-activations/debug-{}",
        request.execution
    ))
    .unwrap();
    let activation = refs.read_ref(&activation_name).unwrap();
    drop(daemon);

    let daemon = Daemon::start(&policy, &socket);
    assert_eq!(
        successful(&start_args),
        resumed,
        "restart returns original result, never a fresh attempt"
    );
    assert_eq!(
        successful(&resume_args),
        resumed,
        "restart cannot dispatch the original resume again"
    );
    assert_eq!(refs.read_ref(&activation_name).unwrap(), activation);
    drop(daemon);
}
