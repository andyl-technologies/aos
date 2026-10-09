//! Exercises installed native preservation through the actual daemon and CLI.

#![cfg(target_os = "linux")]
// crucible-lint: allow rust-allow -- actual process setup and independent native preservation oracles deliberately panic on failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// crucible-lint: allow rust-allow -- physical deadlines bound child supervision and never enter modeled state.
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
        let deadline = Instant::now() + Duration::from_secs(30);
        while !socket.exists() {
            assert!(
                daemon.0.try_wait().unwrap().is_none(),
                "source-built daemon exited during installed native startup"
            );
            assert!(Instant::now() < deadline, "native endpoint did not open");
            std::thread::sleep(Duration::from_millis(10));
        }
        daemon
    }

    fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if self.0.try_wait().unwrap().is_some() {
            return;
        }
        let pid = rustix::process::Pid::from_raw(self.0.id() as i32).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::INT).unwrap();
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(status.success(), "original daemon cleanup failed: {status}");
                return;
            }
            assert!(
                Instant::now() < deadline,
                "daemon failed to retire original native groups"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Preserve all native directories for diagnosis. The actual actor
            // keeps supervising its children after this admission channel closes.
            if let Some(pid) = rustix::process::Pid::from_raw(self.0.id() as i32) {
                let _ = rustix::process::kill_process(pid, rustix::process::Signal::INT);
            }
            return;
        }
        self.shutdown();
    }
}

fn completed(socket: &Path, execution: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let record = successful(&[
            "node",
            "native-status",
            "--socket",
            socket.to_str().unwrap(),
            "--execution",
            execution,
        ]);
        if record["state"]["status"] != "reserved" {
            assert_eq!(record["state"]["status"], "completed", "{record}");
            return record;
        }
        assert!(
            Instant::now() < deadline,
            "original native work did not settle"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn operational_namespaces(realm: &Path) -> Vec<PathBuf> {
    fs::read_dir(realm)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            let name = path.file_name().unwrap().to_string_lossy();
            name.len() == 32 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .collect()
}

#[test]
fn native_preservation_help_exposes_only_installed_choices_and_original_source() {
    for (command, fields) in [
        (
            "native-capture",
            vec!["--socket", "--execution", "--isa", "--point"],
        ),
        (
            "native-restore",
            vec![
                "--socket",
                "--execution",
                "--isa",
                "--source",
                "--complete-original",
            ],
        ),
        ("native-status", vec!["--socket", "--execution"]),
    ] {
        let output = cli(&["node", command, "--help"]);
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).unwrap();
        for field in fields {
            assert!(help.contains(field), "{command} missing {field}");
        }
        for untrusted in ["--executable", "--certificate", "--horizon-ps"] {
            assert!(!help.contains(untrusted), "{command} exposes {untrusted}");
        }
    }
}

#[test]
#[ignore = "requires the source-installed closed gem5 profile and CRUCIBLE_REFERENCE_DEVICE native companion"]
fn actual_cli_preserves_pending_native_world_after_source_daemon_exit() {
    let device = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let state = tempfile::tempdir().unwrap().keep();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = state.join("node.sock");
    let policy = state.join("policy.json");
    let source = state.join("captured.json");
    let realm = state.join("native-state");
    let expected =
        canonical::content_ref(&fs::read(&device).unwrap(), "application/octet-stream").unwrap();
    fs::write(
        &policy,
        serde_json::to_vec(&json!({
            "format":"crucible.node-daemon-policy", "version":3,
            "state_directory":state, "socket":socket,
            "device_executable":device, "expected_device":expected,
            "control_timeout_ms":3000, "maximum_worlds":2,
            "maximum_pending_requests":4, "maximum_native_state_requests":4,
        }))
        .unwrap(),
    )
    .unwrap();
    let capture_arguments = [
        "node",
        "native-capture",
        "--socket",
        socket.to_str().unwrap(),
        "--execution",
        "4162738495a6b7c8d9eafb0c1d2e3f50",
        "--isa",
        "x86-64",
        "--point",
        "pending",
    ];

    let daemon = Daemon::start(&policy, &socket);
    let reserved = successful(&capture_arguments);
    assert_eq!(reserved["state"]["status"], "reserved");
    let captured = completed(&socket, "4162738495a6b7c8d9eafb0c1d2e3f50");
    assert_eq!(captured["state"]["original"]["result"]["kind"], "pending");
    fs::write(&source, serde_json::to_vec(&captured).unwrap()).unwrap();
    daemon.stop();
    assert!(!socket.exists(), "original endpoint remains live");
    assert!(
        operational_namespaces(&realm).is_empty(),
        "original native namespaces remain"
    );

    let daemon = Daemon::start(&policy, &socket);
    assert_eq!(
        successful(&capture_arguments),
        captured,
        "retry must read original state"
    );
    let mut results = Vec::new();
    for execution in [
        "52738495a6b7c8d9eafb0c1d2e3f5061",
        "638495a6b7c8d9eafb0c1d2e3f506172",
    ] {
        successful(&[
            "node",
            "native-restore",
            "--socket",
            socket.to_str().unwrap(),
            "--execution",
            execution,
            "--isa",
            "x86-64",
            "--source",
            source.to_str().unwrap(),
            "--complete-original",
        ]);
        results.push(completed(&socket, execution));
    }

    // Logical operation/grant identities remain original; only newly measured
    // native owner routes and their authentic acknowledgements are fresh.
    let original = &captured["state"]["original"];
    let mut publications = Vec::new();
    for result in &results {
        let operation = &result["state"]["original"];
        assert_eq!(operation["operation"], original["operation"]);
        assert_eq!(result["state"]["artifact"], captured["state"]["artifact"]);
        assert_eq!(result["state"]["manifest"], captured["state"]["manifest"]);
        assert_eq!(operation["request"], original["request"]);
        assert!(!operation["scheduling_commit"].is_null());
        assert!(!result["state"]["completion_evidence"].is_null());
        assert_ne!(
            result["state"]["activation"]["owners"],
            captured["state"]["activation"]["owners"]
        );
        assert_eq!(operation["result"]["kind"], "acknowledged");
        publications.push(operation["result"]["value"]["scheduling"]["publications"][0].clone());
    }
    assert_eq!(publications[0], publications[1]);
    assert_eq!(
        publications[0]["payload_bytes"],
        json!(known_guest_checksum())
    );
    assert_ne!(
        results[0]["state"]["activation"]["owners"],
        results[1]["state"]["activation"]["owners"]
    );
    daemon.stop();
    assert!(!socket.exists());
    assert!(operational_namespaces(&realm).is_empty());
    fs::remove_dir_all(state).unwrap();
}

fn known_guest_checksum() -> [u8; 8] {
    let mut arena = vec![0_u64; 262_144 / 8];
    let mut state = 3_u32;
    let mut answer = 0_u64;
    for _ in 0..20_000 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let index = (state & 262_136) as usize / 8;
        arena[index] ^= u64::from(state);
        answer = answer.wrapping_add(arena[index]);
        if state & 1 != 0 {
            answer = answer.wrapping_add(19);
        }
    }
    answer.to_le_bytes()
}
