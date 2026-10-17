//! Exercises original terminal publication and cold ACK through the actual CLI.

#![cfg(target_os = "linux")]
// crucible-lint: allow rust-allow -- actual process setup and independent state oracles deliberately panic on failure.
// crucible-lint: allow panic-shortcut -- Real CLI terminal state and both fresh ACK branches must preserve original bytes.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// crucible-lint: allow rust-allow -- physical deadlines bound process cleanup and never enter modeled state.
// crucible-lint: allow clippy-disallowed-method -- Absolute process watchdogs bound cleanup without influencing simulated time.
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

fn terminal(socket: &Path, execution: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let record = successful(&[
            "node",
            "terminal-status",
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

#[test]
#[ignore = "requires the source-built companion and terminal archive overlay"]
fn actual_cli_preserves_terminal_report_after_source_exit_and_two_fresh_ack_branches() {
    use crucible_core::{
        AssertionDef, AssertionId, Predicate, Properties, Property, VirtualTime,
        model::PropertyNamespace,
        node_adapters::HostSemanticDefinition,
        node_state::{HostArchive, StateLimits},
    };
    use crucible_node_contract::Bytes;
    use std::collections::{BTreeMap, BTreeSet};

    let device = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path();
    fs::set_permissions(state, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = state.join("control.sock");
    let policy_path = state.join("policy.json");
    let selections = state.join("selections.json");
    let scenario = state.join("scenario.json");
    let source_path = state.join("original.json");
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
                message: "actual whole-world closure".into(),
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
    let program_path = state.join("program.json");
    fs::write(&program_path, &program).unwrap();
    let expected =
        canonical::content_ref(&fs::read(&device).unwrap(), "application/octet-stream").unwrap();
    let mut policy = json!({"format":"crucible.node-daemon-policy","version":2,
        "state_directory":state,"socket":socket,"device_executable":device,"expected_device":expected,
        "control_timeout_ms":3000,"maximum_worlds":2,"maximum_host_state_worlds":4,"maximum_pending_requests":2,
        "immutable_artifacts":[{"path":program_path,"expected":program_ref}]});
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    fs::write(&selections,serde_json::to_vec(&json!([
        {"node":"clock","owner":"clock-owner","kind":{"implementation":"host_clock"}},
        {"node":"semantics","owner":"semantics-owner","kind":{"implementation":"host_semantics","profile":{"program":program_ref}}}
    ])).unwrap()).unwrap();
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
    let capture_args = [
        "node",
        "terminal-capture",
        "--socket",
        socket.to_str().unwrap(),
        "--execution",
        "41414141414141414141414141414141",
        "--selections",
        selections.to_str().unwrap(),
        "--scenario",
        scenario.to_str().unwrap(),
        "--ceiling-ps",
        "11",
        "--stage",
        "published",
    ];
    successful(&capture_args);
    let original = terminal(&socket, "41414141414141414141414141414141");
    assert_eq!(original["version"], 2);
    assert_eq!(original["state"]["status"], "completed", "{original}");
    fs::write(&source_path, serde_json::to_vec(&original).unwrap()).unwrap();
    let limits = StateLimits {
        maximum_content_bytes: 512 * 1024 * 1024,
        maximum_total_content_bytes: 1024 * 1024 * 1024,
        ..StateLimits::default()
    };
    let archive = HostArchive::open(state.join("host-state-archives"), limits).unwrap();
    let original_artifact = serde_json::from_value(original["state"]["artifact"].clone()).unwrap();
    let original_archive = archive.load(&original_artifact).unwrap();
    let original_coordinator: Value = serde_json::from_slice(
        &original_archive
            .content_bytes(
                &original_archive.manifest().coordinator_state_ref,
                16 * 1024 * 1024,
            )
            .unwrap(),
    )
    .unwrap();
    let original_terminal = &original_coordinator["runtime"]["terminal"];
    assert_eq!(original_terminal["publication"], "committed");
    assert_eq!(original_terminal["acknowledged"], false);
    drop(daemon);
    fs::remove_file(&program_path).unwrap();
    policy["immutable_artifacts"] = json!([{"mode":"archive_only","expected":program_ref}]);
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();

    let daemon = Daemon::start(&policy_path, &socket);
    assert_eq!(
        successful(&capture_args),
        original,
        "unchanged original nonce cannot redispatch after source exit"
    );
    let legacy = cli(&[
        "node",
        "state-status",
        "--socket",
        socket.to_str().unwrap(),
        "--execution",
        "41414141414141414141414141414141",
    ]);
    assert!(
        !legacy.status.success(),
        "legacy control2 cannot expose terminal2"
    );
    let mut branches = Vec::new();
    for execution in [
        "51515151515151515151515151515151",
        "61616161616161616161616161616161",
    ] {
        successful(&[
            "node",
            "terminal-restore",
            "--socket",
            socket.to_str().unwrap(),
            "--execution",
            execution,
            "--selections",
            selections.to_str().unwrap(),
            "--scenario",
            scenario.to_str().unwrap(),
            "--source",
            source_path.to_str().unwrap(),
            "--stage",
            "acknowledged",
        ]);
        let restored = terminal(&socket, execution);
        assert_eq!(restored["state"]["status"], "completed", "{restored}");
        let artifact = serde_json::from_value(restored["state"]["artifact"].clone()).unwrap();
        let record = archive.load(&artifact).unwrap();
        let coordinator: Value = serde_json::from_slice(
            &record
                .content_bytes(&record.manifest().coordinator_state_ref, 16 * 1024 * 1024)
                .unwrap(),
        )
        .unwrap();
        let terminal = &coordinator["runtime"]["terminal"];
        assert_eq!(terminal["record"], original_terminal["record"]);
        assert_eq!(terminal["report"], original_terminal["report"]);
        assert_eq!(terminal["acknowledged"], true);
        assert!(coordinator["runtime"]["source_activation"].is_object());
        branches.push(coordinator["runtime"]["source_activation"].clone());
    }
    assert_ne!(
        branches[0], branches[1],
        "both restored worlds require fresh native authority"
    );
    drop(daemon);
}
