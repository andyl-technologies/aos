//! Actual operator-enrolled immutable sources through local CLI storage execution.
//!
//! The test uses real public block frames and native scripted-source/storage
//! adapters. Independently selected fixture content is installed only through
//! private policy; remote selection JSON cannot enroll paths or qualifications.

#![cfg(target_os = "linux")]
// crucible-lint: allow rust-allow -- real process fixtures and independent byte/provenance oracles panic on failure.
// crucible-lint: allow panic-shortcut -- These node storage process tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// crucible-lint: allow rust-allow -- physical deadlines bound process cleanup and never enter modeled state.
// crucible-lint: allow clippy-disallowed-method -- Operational deadlines in these node storage process tests bound native supervision and never enter modeled state.
#![allow(clippy::disallowed_methods)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use crucible_campaign::{
    CampaignRepository, ExecutionId, observed_node_attempt::ObservedAttemptState,
};
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, RefName,
};
use crucible_core::{
    node_adapters::{ScriptedRequest, ScriptedRequestKind, ScriptedSource},
    node_contract::OperationOutcome,
};
use crucible_device::{BlockRequest, BlockResponse};
use crucible_node_contract::canonical;
use serde_json::{Value, json};

#[path = "node_storage_process/host_state.rs"]
mod host_state;

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
                "installed daemon exited"
            );
            assert!(
                Instant::now() < deadline,
                "daemon did not publish private endpoint"
            );
            std::thread::sleep(Duration::from_millis(10));
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
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the current source-built native companion"]
fn actual_cli_enrolls_immutable_storage_sources_without_remote_path_authority() {
    let device = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let temporary = tempfile::tempdir().unwrap();
    let state = temporary.path();
    fs::set_permissions(state, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = state.join("node.sock");
    let policy = state.join("policy.json");
    let selections = state.join("selections.json");
    let scenario = state.join("scenario.json");
    let configuration = state.join("configuration.json");
    let base_path = state.join("base.img");
    let script_path = state.join("requests.bin");
    let base = vec![0xab; 4096];
    let script = ScriptedSource::new(
        ScriptedRequestKind::Block,
        vec![
            ScriptedRequest {
                time_ps: 10,
                payload: BlockRequest::write(101, 0, vec![7, 8, 9]).encode().unwrap(),
            },
            ScriptedRequest {
                time_ps: 50_000,
                payload: BlockRequest::read(102, 0, 3).encode().unwrap(),
            },
        ],
    )
    .unwrap()
    .script_bytes()
    .unwrap();
    fs::write(&base_path, &base).unwrap();
    fs::write(&script_path, &script).unwrap();
    let reference =
        |bytes: &[u8]| canonical::content_ref(bytes, "application/octet-stream").unwrap();
    let installed_policy = json!({
        "format":"crucible.node-daemon-policy", "version":1, "state_directory":state,
        "socket":socket, "device_executable":device, "expected_device":reference(&fs::read(&device).unwrap()),
        "control_timeout_ms":3000,"maximum_worlds":2,"maximum_pending_requests":4,
        "immutable_artifacts":[{"path":base_path,"expected":reference(&base)}, {"path":script_path,"expected":reference(&script)}]
    });
    fs::write(&policy, serde_json::to_vec(&installed_policy).unwrap()).unwrap();
    let selected = json!([
        {"node":"disk","owner":"disk-owner","kind":{"implementation":"host_io","profile":{
            "kind":"block","base_image":reference(&base),"source_node":7,
            "read_ns":"1","write_ns":"1","flush_ns":"1","get_length_ns":"1","per_byte_ns":"1"}}},
        {"node":"source","owner":"source-owner","kind":{"implementation":"host_scripted","profile":{
            "script":reference(&script),"consumer":"disk"}}}
    ]);
    fs::write(&selections, serde_json::to_vec(&selected).unwrap()).unwrap();
    fs::write(&configuration, br#"{"format":"crucible.node-run-configuration","version":1,"horizon_ps":"200000","maximum_rounds":"32"}"#).unwrap();
    let daemon = Daemon::start(&policy, &socket);
    let compile = [
        "node",
        "compile",
        "--socket",
        socket.to_str().unwrap(),
        "--selections",
        selections.to_str().unwrap(),
        "--output",
        scenario.to_str().unwrap(),
    ];
    let compiled = cli(&compile);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let parsed: Value = serde_json::from_slice(&fs::read(&scenario).unwrap()).unwrap();
    assert_eq!(parsed["world"]["connections"].as_array().unwrap().len(), 1);
    let execution = "48484848484848484848484848484848";
    let observe = [
        "node",
        "observe",
        "--socket",
        socket.to_str().unwrap(),
        "--ledger",
        "installed-storage",
        "--execution",
        execution,
        "--selections",
        selections.to_str().unwrap(),
        "--scenario",
        scenario.to_str().unwrap(),
        "--configuration",
        configuration.to_str().unwrap(),
    ];
    successful(&observe);
    let status = [
        "node",
        "status",
        "--socket",
        socket.to_str().unwrap(),
        "--execution",
        execution,
    ];
    let deadline = Instant::now() + Duration::from_secs(20);
    let completed = loop {
        let record = successful(&status);
        if record["status"] == "completed" {
            break record;
        }
        assert_eq!(record["status"], "reserved", "{record}");
        assert!(
            Instant::now() < deadline,
            "native storage requests stayed blocked"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(completed["repeatable"], true);
    assert_eq!(completed["outcome"], "completed");

    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "node-observations",
        state.join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> = Arc::new(DirectoryRefBackend::new(state.join("refs")));
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let original = repository
        .observed_execution_state(ExecutionId::from_bytes([72; 16]).unwrap())
        .unwrap()
        .unwrap();
    let ObservedAttemptState::Completed(result) = original else {
        panic!("original result absent");
    };
    let outgoing: Value = serde_json::from_slice(
        &blobs
            .read(result.outgoing(), None)
            .unwrap()
            .read_all(16 * 1024 * 1024)
            .unwrap(),
    )
    .unwrap();
    let mut responses = vec![];
    for event in outgoing["events"].as_array().unwrap() {
        let outcome: OperationOutcome = serde_json::from_value(event.clone()).unwrap();
        if outcome.node.as_str() != "disk" {
            continue;
        }
        for publication in outcome.scheduling.unwrap().publications {
            assert!(publication.evaluation.is_some());
            assert_eq!(publication.causal_parents.len(), 1);
            publication
                .payload
                .verify(&publication.payload_bytes)
                .unwrap();
            responses.push(BlockResponse::decode(&publication.payload_bytes).unwrap());
        }
    }
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0].request_id, 101);
    assert_eq!(responses[1].request_id, 102);
    assert_eq!(responses[1].data, vec![7, 8, 9]);
    assert_eq!(
        fs::read(&base_path).unwrap(),
        base,
        "native writes remain in owned COW state"
    );
    let activation_name = RefName::new(format!("node-world-activations/{execution}")).unwrap();
    let activation = refs.read_ref(&activation_name).unwrap().unwrap();

    // A remote path is rejected by the closed selection before any new native allocation.
    let mut invented = selected;
    invented[0]["kind"]["profile"]["path"] = json!(base_path);
    let remote = state.join("remote-path.json");
    fs::write(&remote, serde_json::to_vec(&invented).unwrap()).unwrap();
    let rejected = cli(&[
        "node",
        "compile",
        "--socket",
        socket.to_str().unwrap(),
        "--selections",
        remote.to_str().unwrap(),
        "--output",
        state.join("invented.json").to_str().unwrap(),
    ]);
    assert!(!rejected.status.success());
    assert!(!state.join("invented.json").exists());
    drop(daemon);

    fs::write(&base_path, vec![0xcd; 4096]).unwrap();
    let changed = cli(&["node", "serve", "--policy", policy.to_str().unwrap()]);
    assert!(
        !changed.status.success(),
        "changed source bytes cannot replace installed expectation"
    );
    assert!(
        !socket.exists(),
        "changed source exposed admission before enrollment"
    );
    assert_eq!(refs.read_ref(&activation_name).unwrap(), Some(activation));
    fs::write(&base_path, &base).unwrap();
    let daemon = Daemon::start(&policy, &socket);
    assert_eq!(successful(&status), completed);
    assert_eq!(
        successful(&observe),
        completed,
        "restart reads original state rather than dispatching"
    );
    assert_eq!(refs.read_ref(&activation_name).unwrap(), Some(activation));
    drop(daemon);
}
