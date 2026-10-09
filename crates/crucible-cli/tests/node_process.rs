//! Actual installed-node CLI/daemon execution, retained provenance, and restart.
//!
//! Native tests use the current source-built companion explicitly; no synthetic
//! qualification, measured-self installation shortcut, or deterministic replay
//! evidence is claimed.

#![cfg(target_os = "linux")]
// crucible-lint: allow rust-allow -- test fixture setup and exact regression assertions deliberately panic on failure.
// crucible-lint: allow panic-shortcut -- These node process tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// crucible-lint: allow rust-allow -- physical deadlines bound process cleanup and never enter modeled state.
// crucible-lint: allow clippy-disallowed-method -- Operational deadlines in these node process tests bound native supervision and never enter modeled state.
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
    CampaignRepository, ExecutionId,
    observed_node_attempt::{ObservedAttemptOutcome, ObservedAttemptState},
};
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, RefName,
};
use crucible_node_contract::canonical;
use serde_json::{Value, json};

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            if let Some(pid) = rustix::process::Pid::from_raw(self.0.id() as i32) {
                let _ = rustix::process::kill_process(pid, rustix::process::Signal::INT);
            }
            let deadline = Instant::now() + Duration::from_secs(20);
            while self.0.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
            }
        }
        let _ = self.0.wait();
    }
}

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
        "CLI refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn launch(policy: &Path, socket: &Path) -> Daemon {
    let mut daemon = Daemon(
        Command::new(env!("CARGO_BIN_EXE_crucible"))
            .args(["node", "serve", "--policy"])
            .arg(policy)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(
            daemon.0.try_wait().unwrap().is_none(),
            "node daemon stopped during startup"
        );
        assert!(
            Instant::now() < deadline,
            "node daemon did not expose its private endpoint"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    daemon
}

#[test]
fn installed_node_help_preserves_explicit_policy_and_original_nonce_controls() {
    for (command, fields) in [
        ("serve", vec!["--policy"]),
        ("compile", vec!["--socket", "--selections", "--output"]),
        (
            "observe",
            vec!["--execution", "--ledger", "--scenario", "--configuration"],
        ),
        ("status", vec!["--execution", "--socket"]),
    ] {
        let output = cli(&["node", command, "--help"]);
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).unwrap();
        for field in fields {
            assert!(help.contains(field), "{command} missing {field}");
        }
    }
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the current source-built native companion"]
fn actual_cli_daemon_retains_mixed_node_provenance_without_redispatch_after_restart() {
    let device = PathBuf::from(
        std::env::var("CRUCIBLE_REFERENCE_DEVICE").expect("source-built device executable"),
    );
    let temporary = tempfile::tempdir().unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let state = temporary.path();
    let socket = state.join("node.sock");
    let policy = state.join("policy.json");
    // This independent test oracle measures a selected source-built fixture. The
    // production CLI only reads a preinstalled operator policy and never derives
    // its own expected artifact identity to authorize an installation.
    let expected =
        canonical::content_ref(&fs::read(&device).unwrap(), "application/octet-stream").unwrap();
    fs::write(
        &policy,
        serde_json::to_vec(&json!({
            "format":"crucible.node-daemon-policy", "version":1,
            "state_directory":state, "socket":socket, "device_executable":device,
            "expected_device":expected, "control_timeout_ms":3000,
            "maximum_worlds":2, "maximum_pending_requests":4
        }))
        .unwrap(),
    )
    .unwrap();
    let mut foreign_policy: Value = serde_json::from_slice(&fs::read(&policy).unwrap()).unwrap();
    foreign_policy["expected_device"]["hash"]["digest"] = json!("0".repeat(64));
    let foreign_policy_path = state.join("foreign-policy.json");
    fs::write(
        &foreign_policy_path,
        serde_json::to_vec(&foreign_policy).unwrap(),
    )
    .unwrap();
    let refused_installation = cli(&[
        "node",
        "serve",
        "--policy",
        foreign_policy_path.to_str().unwrap(),
    ]);
    assert!(
        !refused_installation.status.success(),
        "daemon replaced independent expected identity with its own measurement"
    );
    assert!(!socket.exists(), "foreign installation exposed an endpoint");
    let selected = state.join("selections.json");
    fs::write(
        &selected,
        serde_json::to_vec(&json!([
            {"node":"clock","owner":"clock-owner","kind":{"implementation":"host_clock"}},
            {"node":"device","owner":"device-owner","kind":{"implementation":"reference_device",
                "quantum_ps":"50","host_budget_ns":"20000000"}}
        ]))
        .unwrap(),
    )
    .unwrap();
    let scenario = state.join("scenario.json");
    let configuration = state.join("configuration.json");
    fs::write(&configuration, br#"{"format":"crucible.node-run-configuration","version":1,"horizon_ps":"100","maximum_rounds":"8"}"#).unwrap();
    let daemon = launch(&policy, &socket);
    let socket_text = socket.to_str().unwrap();
    let selected_text = selected.to_str().unwrap();
    let scenario_text = scenario.to_str().unwrap();
    let configuration_text = configuration.to_str().unwrap();
    let compiled = cli(&[
        "node",
        "compile",
        "--socket",
        socket_text,
        "--selections",
        selected_text,
        "--output",
        scenario_text,
    ]);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let original_scenario = fs::read(&scenario).unwrap();
    crucible_daemon::node_scenario::NodeScenario::from_json(&original_scenario).unwrap();
    let execution = "29292929292929292929292929292929";
    let observation_arguments = [
        "node",
        "observe",
        "--socket",
        socket_text,
        "--ledger",
        "operator-observations",
        "--execution",
        execution,
        "--selections",
        selected_text,
        "--scenario",
        scenario_text,
        "--configuration",
        configuration_text,
    ];
    let _reserved = successful(&observation_arguments);
    let status_arguments = [
        "node",
        "status",
        "--socket",
        socket_text,
        "--execution",
        execution,
    ];
    let deadline = Instant::now() + Duration::from_secs(20);
    let completed = loop {
        let status = successful(&status_arguments);
        if status["status"] == "completed" {
            break status;
        }
        assert_eq!(status["status"], "reserved", "{status}");
        assert!(
            Instant::now() < deadline,
            "original native world did not complete"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(completed["repeatable"], false);
    assert_eq!(completed["outcome"], "completed");
    assert_eq!(successful(&observation_arguments), completed);

    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "node-observations",
        state.join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> = Arc::new(DirectoryRefBackend::new(state.join("refs")));
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let retained = repository
        .observed_execution_state(ExecutionId::from_bytes([41; 16]).unwrap())
        .unwrap()
        .unwrap();
    let ObservedAttemptState::Completed(result) = &retained else {
        panic!("retained execution is incomplete");
    };
    assert_eq!(result.outcome(), ObservedAttemptOutcome::Completed);
    assert_eq!(result.request().capabilities().roster().owners().len(), 2);
    let outgoing = blobs
        .read(result.outgoing(), None)
        .unwrap()
        .read_all(16 * 1024 * 1024)
        .unwrap();
    let provenance: Value = serde_json::from_slice(&outgoing).unwrap();
    assert_eq!(provenance["format"], "crucible.node-observed-boundary");
    assert_eq!(provenance["events"].as_array().unwrap().len(), 3);
    assert_eq!(
        repository
            .load_observed_result(result.id().unwrap())
            .unwrap(),
        *result
    );

    let activation_name = RefName::new(format!("node-world-activations/{execution}")).unwrap();
    let activation = refs.read_ref(&activation_name).unwrap().unwrap();

    drop(daemon);
    assert!(!socket.exists(), "graceful cleanup did not retire endpoint");
    let _restarted = launch(&policy, &socket);
    assert_eq!(successful(&status_arguments), completed);
    assert_eq!(successful(&observation_arguments), completed);
    assert_eq!(refs.read_ref(&activation_name).unwrap(), Some(activation));
    fs::write(&configuration, br#"{"format":"crucible.node-run-configuration","version":1,"horizon_ps":"200","maximum_rounds":"8"}"#).unwrap();
    assert!(
        !cli(&observation_arguments).status.success(),
        "recovered nonce accepted changed original inputs"
    );
    assert_eq!(successful(&status_arguments), completed);
    assert_eq!(fs::read(&scenario).unwrap(), original_scenario);
    assert_eq!(
        repository
            .observed_execution_state(ExecutionId::from_bytes([41; 16]).unwrap())
            .unwrap()
            .unwrap(),
        retained
    );
}
