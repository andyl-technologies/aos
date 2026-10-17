//! Exercises exact installed deterministic cache reuse through owning CLI processes.

#![cfg(target_os = "linux")]
// crucible-lint: allow rust-allow -- actual process setup and independent state oracles deliberately panic on failure.
// crucible-lint: allow panic-shortcut -- The real daemon and CLI must preserve the exact original result after source exit.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// crucible-lint: allow rust-allow -- physical deadlines bound process cleanup and never enter modeled state.
// crucible-lint: allow clippy-disallowed-method -- Absolute process watchdogs never influence the modeled workload or result identity.
#![allow(clippy::disallowed_methods)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

use crucible_node_contract::canonical;
use serde_json::{Value, json};

fn cli(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args(arguments)
        .output()
        .unwrap()
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
                "source-built daemon exited during installation"
            );
            assert!(
                Instant::now() < deadline,
                "private daemon endpoint was not created"
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

fn successful(arguments: &[&str]) -> Value {
    let output = cli(arguments);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
#[ignore = "requires the source-built companion and actual owning CLI executable"]
fn actual_cli_cache_reuse_preserves_original_storage_result_after_daemon_and_source_exit() {
    use crucible_campaign::observed_node_attempt::ObservedAttemptResult;
    use crucible_core::node_adapters::{ScriptedRequest, ScriptedRequestKind, ScriptedSource};
    use crucible_daemon::node_observed_executor::NodeCacheReuseReceipt;
    use crucible_device::BlockRequest;

    let device = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path();
    fs::set_permissions(state, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = state.join("control.sock");
    let policy_path = state.join("policy.json");
    let selections = state.join("selections.json");
    let scenario = state.join("scenario.json");
    let configuration = state.join("configuration.json");
    let request = state.join("cache-request.json");
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
    let base_ref = canonical::content_ref(&base, "application/octet-stream").unwrap();
    let script_ref = canonical::content_ref(&script, "application/octet-stream").unwrap();
    let base_path = state.join("base");
    let script_path = state.join("script");
    fs::write(&base_path, base).unwrap();
    fs::write(&script_path, script).unwrap();
    let selected = json!([
        {"node":"disk","owner":"disk-owner","kind":{"implementation":"host_io","profile":{
            "kind":"block","base_image":base_ref,"source_node":7,"read_ns":"1","write_ns":"1",
            "flush_ns":"1","get_length_ns":"1","per_byte_ns":"1"}}},
        {"node":"source","owner":"source-owner","kind":{"implementation":"host_scripted","profile":{
            "script":script_ref,"consumer":"disk"}}}
    ]);
    fs::write(&selections, serde_json::to_vec(&selected).unwrap()).unwrap();
    let config = json!({"format":"crucible.node-run-configuration","version":1,
        "horizon_ps":"200000","maximum_rounds":"32"});
    fs::write(&configuration, serde_json::to_vec(&config).unwrap()).unwrap();
    let expected =
        canonical::content_ref(&fs::read(&device).unwrap(), "application/octet-stream").unwrap();
    let mut policy = json!({"format":"crucible.node-daemon-policy","version":2,
        "state_directory":state,"socket":socket,"device_executable":device,"expected_device":expected,
        "control_timeout_ms":3000,"maximum_worlds":2,"maximum_host_state_worlds":2,"maximum_pending_requests":2,
        "immutable_artifacts":[{"path":base_path,"expected":base_ref},{"path":script_path,"expected":script_ref}]});
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let daemon = Daemon::start(&policy_path, &socket);
    let compiled = cli(&[
        "node",
        "compile",
        "--socket",
        socket.to_str().unwrap(),
        "--selections",
        selections.to_str().unwrap(),
        "--output",
        scenario.to_str().unwrap(),
    ]);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let execution = "61616161616161616161616161616161";
    successful(&[
        "node",
        "observe",
        "--socket",
        socket.to_str().unwrap(),
        "--ledger",
        "cli-cache-storage",
        "--execution",
        execution,
        "--selections",
        selections.to_str().unwrap(),
        "--scenario",
        scenario.to_str().unwrap(),
        "--configuration",
        configuration.to_str().unwrap(),
    ]);
    let deadline = Instant::now() + Duration::from_secs(30);
    let original = loop {
        let status = successful(&[
            "node",
            "status",
            "--socket",
            socket.to_str().unwrap(),
            "--execution",
            execution,
        ]);
        if status["status"] == "completed" {
            break status;
        }
        assert_eq!(status["status"], "reserved");
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(original["repeatable"], true);
    assert_eq!(original["outcome"], "completed");
    drop(daemon);
    fs::remove_file(&base_path).unwrap();
    fs::remove_file(&script_path).unwrap();
    policy["immutable_artifacts"] = json!([
        {"mode":"archive_only","expected":base_ref},{"mode":"archive_only","expected":script_ref}]);
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let daemon = Daemon::start(&policy_path, &socket);
    let scenario_bytes = crucible_node_contract::Bytes::new(fs::read(&scenario).unwrap());
    let configuration_bytes = crucible_node_contract::Bytes::new(fs::read(&configuration).unwrap());
    let mut cache_request = json!({"format":"crucible.node-cache-reuse","version":1,
        "source_execution":execution,"selections":selected,"scenario":scenario_bytes,
        "configuration":configuration_bytes});
    fs::write(&request, serde_json::to_vec(&cache_request).unwrap()).unwrap();
    let first = successful(&[
        "node",
        "cache-reuse",
        "--socket",
        socket.to_str().unwrap(),
        "--request",
        request.to_str().unwrap(),
    ]);
    let receipt: NodeCacheReuseReceipt = serde_json::from_value(first.clone()).unwrap();
    assert_eq!(receipt.source_execution, execution);
    assert_eq!(receipt.original_result, original["result"]);
    let result = ObservedAttemptResult::from_canonical_bytes(receipt.result.as_slice()).unwrap();
    assert_eq!(
        result.id().unwrap().content_id().encode(),
        receipt.original_result
    );
    assert_eq!(result.request().execution().as_bytes(), [0x61; 16]);
    assert_eq!(result.outgoing().encode(), original["outgoing"]);
    assert_eq!(result.evidence().encode(), original["evidence"]);
    cache_request["expected_cache_key"] = json!(receipt.cache_key);
    fs::write(&request, serde_json::to_vec(&cache_request).unwrap()).unwrap();
    assert_eq!(
        successful(&[
            "node",
            "cache-reuse",
            "--socket",
            socket.to_str().unwrap(),
            "--request",
            request.to_str().unwrap()
        ]),
        first
    );
    assert_eq!(
        successful(&[
            "node",
            "status",
            "--socket",
            socket.to_str().unwrap(),
            "--execution",
            execution
        ]),
        original
    );
    cache_request["expected_cache_key"] = json!("00".repeat(32));
    fs::write(&request, serde_json::to_vec(&cache_request).unwrap()).unwrap();
    assert!(
        !cli(&[
            "node",
            "cache-reuse",
            "--socket",
            socket.to_str().unwrap(),
            "--request",
            request.to_str().unwrap()
        ])
        .status
        .success()
    );
    drop(daemon);
}
