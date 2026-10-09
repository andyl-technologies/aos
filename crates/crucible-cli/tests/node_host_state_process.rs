//! Exercises actual daemon archive custody through the source-built CLI.

#![cfg(target_os = "linux")]
// crucible-lint: allow rust-allow -- actual process setup and independent state oracles deliberately panic on failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// crucible-lint: allow rust-allow -- physical deadlines bound process cleanup and never enter modeled state.
#![allow(clippy::disallowed_methods)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, RefName,
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

fn terminal(socket: &Path, execution: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let record = successful(&[
            "node",
            "state-status",
            "--socket",
            socket.to_str().unwrap(),
            "--execution",
            execution,
        ]);
        if record["state"]["status"] != "reserved" {
            return record;
        }
        assert!(
            Instant::now() < deadline,
            "actual complete archive was not issued"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn activation(state: &Path, execution: &str) -> Option<Value> {
    let refs = DirectoryRefBackend::new(state.join("refs"));
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "node-observations",
        state.join("blobs"),
    ));
    let reference = RefName::new(format!("node-world-activations/state-{execution}")).unwrap();
    refs.read_ref(&reference).unwrap().map(|identity| {
        serde_json::from_slice(
            &blobs
                .read(identity, None)
                .unwrap()
                .read_all(1024 * 1024)
                .unwrap(),
        )
        .unwrap()
    })
}

#[test]
fn exact_state_help_exposes_complete_original_state_inputs() {
    for (command, fields) in [
        (
            "capture",
            vec![
                "--socket",
                "--execution",
                "--selections",
                "--scenario",
                "--horizon-ps",
            ],
        ),
        (
            "restore",
            vec![
                "--socket",
                "--execution",
                "--selections",
                "--scenario",
                "--source",
                "--horizon-ps",
            ],
        ),
        ("state-status", vec!["--socket", "--execution"]),
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
fn actual_cli_restores_exact_host_clock_world_after_original_process_exit() {
    let device =
        PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").expect("source-built companion"));
    let temporary = tempfile::tempdir().unwrap();
    let state = temporary.path();
    fs::set_permissions(state, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = state.join("node.sock");
    let policy = state.join("policy.json");
    let selections = state.join("clocks.json");
    let scenario = state.join("scenario.json");
    let source = state.join("captured.json");
    let expected =
        canonical::content_ref(&fs::read(&device).unwrap(), "application/octet-stream").unwrap();
    fs::write(
        &policy,
        serde_json::to_vec(&json!({
            "format":"crucible.node-daemon-policy","version":2,"state_directory":state,
            "socket":socket,"device_executable":device,"expected_device":expected,
            "control_timeout_ms":3000,"maximum_worlds":2,"maximum_host_state_worlds":2,
            "maximum_pending_requests":4
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &selections,
        serde_json::to_vec(&json!([
            {"node":"clock-a","owner":"owner-a","kind":{"implementation":"host_clock"}},
            {"node":"clock-z","owner":"owner-z","kind":{"implementation":"host_clock"}}
        ]))
        .unwrap(),
    )
    .unwrap();
    let daemon = Daemon::start(&policy, &socket);
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
    let capture_arguments = [
        "node",
        "capture",
        "--socket",
        socket.to_str().unwrap(),
        "--execution",
        "33333333333333333333333333333333",
        "--selections",
        selections.to_str().unwrap(),
        "--scenario",
        scenario.to_str().unwrap(),
        "--horizon-ps",
        "100",
    ];

    let reserved = successful(&capture_arguments);
    assert_eq!(reserved["state"]["status"], "reserved");
    let captured = terminal(&socket, "33333333333333333333333333333333");
    assert_eq!(captured["state"]["status"], "completed");
    assert_eq!(captured["state"]["manifest"]["cut"]["time_ps"], "100");
    assert_eq!(
        captured["state"]["manifest"]["cut"]["phase"], 0,
        "capture cannot fabricate a publication-phase stop"
    );
    assert_eq!(captured["state"]["manifest"]["event_ordinal"], "2");
    let original_activation = activation(state, "33333333333333333333333333333333").unwrap();
    fs::write(&source, serde_json::to_vec(&captured).unwrap()).unwrap();
    drop(daemon);
    assert!(
        !socket.exists(),
        "original daemon must close and reap its endpoint"
    );

    let daemon = Daemon::start(&policy, &socket);
    assert_eq!(
        successful(&capture_arguments),
        captured,
        "retry after process exit must be a read"
    );
    assert_eq!(
        activation(state, "33333333333333333333333333333333").unwrap(),
        original_activation
    );
    let restore_arguments = [
        "node",
        "restore",
        "--socket",
        socket.to_str().unwrap(),
        "--execution",
        "44444444444444444444444444444444",
        "--selections",
        selections.to_str().unwrap(),
        "--scenario",
        scenario.to_str().unwrap(),
        "--source",
        source.to_str().unwrap(),
        "--horizon-ps",
        "100",
    ];
    successful(&restore_arguments);
    let restored = terminal(&socket, "44444444444444444444444444444444");
    assert_eq!(restored["state"]["status"], "completed");
    assert_eq!(
        restored["state"]["manifest"]["cut"],
        captured["state"]["manifest"]["cut"]
    );
    assert_eq!(
        restored["state"]["manifest"]["event_ordinal"],
        captured["state"]["manifest"]["event_ordinal"]
    );
    assert_eq!(
        restored["state"]["manifest"]["world_binding_hash"],
        captured["state"]["manifest"]["world_binding_hash"]
    );
    let fresh = activation(state, "44444444444444444444444444444444").unwrap();
    assert_eq!(fresh["activation"]["generation"], "2");
    assert_ne!(
        fresh["activation"]["owners"],
        original_activation["activation"]["owners"]
    );

    // A self-consistent public manifest digest still lacks the original private
    // archive authentication. It cannot authorize native reconstruction.
    let mut forged = captured.clone();
    forged["state"]["manifest"]["cut"]["time_ps"] = json!("101");
    let bytes = canonical::canonical_json(&forged["state"]["manifest"]).unwrap();
    forged["state"]["artifact"] =
        serde_json::to_value(canonical::content_ref(&bytes, "application/json").unwrap()).unwrap();
    let forged_path = state.join("forged.json");
    fs::write(&forged_path, serde_json::to_vec(&forged).unwrap()).unwrap();
    successful(&[
        "node",
        "restore",
        "--socket",
        socket.to_str().unwrap(),
        "--execution",
        "55555555555555555555555555555555",
        "--selections",
        selections.to_str().unwrap(),
        "--scenario",
        scenario.to_str().unwrap(),
        "--source",
        forged_path.to_str().unwrap(),
        "--horizon-ps",
        "200",
    ]);
    assert_eq!(
        terminal(&socket, "55555555555555555555555555555555")["state"]["status"],
        "refused"
    );
    assert!(activation(state, "55555555555555555555555555555555").is_none());

    fs::write(&source, serde_json::to_vec(&restored).unwrap()).unwrap();
    successful(&[
        "node",
        "restore",
        "--socket",
        socket.to_str().unwrap(),
        "--execution",
        "66666666666666666666666666666666",
        "--selections",
        selections.to_str().unwrap(),
        "--scenario",
        scenario.to_str().unwrap(),
        "--source",
        source.to_str().unwrap(),
        "--horizon-ps",
        "200",
    ]);
    let continued = terminal(&socket, "66666666666666666666666666666666");
    assert_eq!(continued["state"]["status"], "completed");
    assert_eq!(continued["state"]["manifest"]["cut"]["time_ps"], "200");
    assert_eq!(continued["state"]["manifest"]["event_ordinal"], "4");
    assert_eq!(
        activation(state, "66666666666666666666666666666666").unwrap()["activation"]["generation"],
        "3"
    );
    drop(daemon);
    assert!(!socket.exists());
}
