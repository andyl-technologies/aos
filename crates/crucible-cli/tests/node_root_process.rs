//! Exercises queued fixed Root preparation through the actual local CLI and daemon.

#![cfg(target_os = "linux")]
// crucible-lint: allow panic-shortcut -- Single-shot native process fixtures stop and report their original failed invariant.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// crucible-lint: allow clippy-disallowed-method -- One absolute deadline bounds polling each original process and receipt; failed fixtures are never rerun.
#![allow(clippy::disallowed_methods)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

use crucible_daemon::node_observed_executor::{
    RootPreparationDiagnostic, RootPreparationRecord, RootPreparationState,
};
use crucible_node_contract::{Bytes, canonical};
use serde_json::{Value, json};

#[path = "node_root_process/mod.rs"]
mod original_oracle;

fn cli(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args(arguments)
        .output()
        .unwrap()
}

fn positive(arguments: &[&str]) -> Value {
    let output = cli(arguments);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

// A failed fixture preserves its own directory and actual spawned daemon inside
// the still-running cohort supervisor. Ending that tool namespace terminates its
// processes, so failure inspection and cleanup must precede supervisor exit.
struct EvidenceDirectory(Option<tempfile::TempDir>);

impl EvidenceDirectory {
    fn new() -> Self {
        Self(Some(tempfile::tempdir().unwrap()))
    }

    fn path(&self) -> &Path {
        self.0.as_ref().unwrap().path()
    }
}

impl Drop for EvidenceDirectory {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let path = self.0.take().unwrap().keep();
            eprintln!(
                "original failed Root fixture evidence retained: {}",
                path.display()
            );
        }
    }
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
        retain_daemon_identity(&child, policy, socket);
        let mut owner = Self(child);
        let deadline = Instant::now() + Duration::from_secs(20);
        while !socket.exists() {
            assert!(owner.0.try_wait().unwrap().is_none());
            assert!(
                Instant::now() < deadline,
                "original daemon installation timed out"
            );
            std::thread::yield_now();
        }
        owner
    }
}

// This metadata names only the fixture's actual Child, not a native peer. The
// supervisor checks the original namespace and kernel start tick before opening
// its process handle; a later numeric PID lookup alone grants no cleanup scope.
fn retain_daemon_identity(child: &Child, policy: &Path, socket: &Path) {
    let pid = child.id();
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let (_, fields) = stat.rsplit_once(')').unwrap();
    let start_ticks = fields.split_whitespace().nth(19).unwrap();
    let namespace = fs::read_link("/proc/self/ns/pid").unwrap();
    let executable = fs::read_link(format!("/proc/{pid}/exe")).unwrap();
    let identity = json!({
        "format": "crucible.root-fixture-daemon-owner",
        "version": 1,
        "pid": pid,
        "start_ticks": start_ticks,
        "pid_namespace": namespace,
        "executable": executable,
        "socket": socket,
    });
    let retained = policy
        .parent()
        .unwrap()
        .join(format!("daemon-owner-{pid}-{start_ticks}.json"));
    fs::write(&retained, serde_json::to_vec(&identity).unwrap()).unwrap();
    eprintln!(
        "original Root fixture daemon owner retained: {}",
        retained.display()
    );
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "original fixture daemon retained inside the running cohort supervisor: pid={}",
                self.0.id(),
            );
            return;
        }
        if let Some(pid) = rustix::process::Pid::from_raw(self.0.id() as i32) {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::INT);
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.0.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::yield_now();
        }
        if self.0.try_wait().unwrap().is_none() {
            self.0.kill().unwrap();
        }
        self.0.wait().unwrap();
    }
}

fn installation(directory: &Path, companion: &Path) -> (PathBuf, PathBuf) {
    fs::create_dir_all(directory).unwrap();
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    let policy = directory.join("policy.json");
    let socket = directory.join("control.sock");
    let expected =
        canonical::content_ref(&fs::read(companion).unwrap(), "application/octet-stream").unwrap();
    fs::write(
        &policy,
        serde_json::to_vec(&json!({
            "format": "crucible.node-daemon-policy", "version": 1,
            "state_directory": directory, "socket": socket,
            "device_executable": companion, "expected_device": expected,
            "control_timeout_ms": 3000, "maximum_worlds": 4, "maximum_pending_requests": 4,
        }))
        .unwrap(),
    )
    .unwrap();
    (policy, socket)
}

fn complete(socket: &Path, execution: &str) -> RootPreparationRecord {
    let deadline = Instant::now() + Duration::from_secs(1200);
    let mut last_diagnostic_revision = 0;
    loop {
        assert!(Instant::now() < deadline, "original Root recipe timed out");
        let value = positive(&[
            "node",
            "root-status",
            "--socket",
            socket.to_str().unwrap(),
            "--execution",
            execution,
        ]);
        assert!(
            Instant::now() < deadline,
            "original status exchange exceeded its deadline"
        );
        let record: RootPreparationRecord = serde_json::from_value(value).unwrap();
        let diagnostic = cli(&[
            "node",
            "root-diagnostic",
            "--socket",
            socket.to_str().unwrap(),
            "--execution",
            execution,
        ]);
        assert!(
            Instant::now() < deadline,
            "original diagnostic exchange exceeded its deadline"
        );
        if diagnostic.status.success() {
            let diagnostic: RootPreparationDiagnostic =
                serde_json::from_slice(&diagnostic.stdout).unwrap();
            assert_eq!(diagnostic.request, record.request);
            if diagnostic.revision != last_diagnostic_revision {
                eprintln!(
                    "original Root diagnostic: {}",
                    serde_json::to_string(&diagnostic).unwrap()
                );
                last_diagnostic_revision = diagnostic.revision;
            }
            if let Some(first) = diagnostic.first_refusal {
                panic!(
                    "original Root recipe retained refusal at {}: {}",
                    first.phase, first.reason
                );
            }
        }
        match record.outcome {
            RootPreparationState::AwaitingAdmission {} => std::thread::yield_now(),
            RootPreparationState::Completed { .. } | RootPreparationState::Described { .. } => {
                return record;
            }
            RootPreparationState::Unavailable { ref reason } => {
                panic!("original Root recipe refused: {reason}")
            }
        }
    }
}

fn copy_tree(source: &Path, target: &Path) {
    fs::create_dir_all(target).unwrap();
    fs::set_permissions(target, fs::metadata(source).unwrap().permissions()).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let destination = target.join(entry.file_name());
        assert!(!entry.file_type().unwrap().is_symlink());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).unwrap();
        }
    }
}

fn assert_native_namespaces_released(directory: &Path) {
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name = name.to_str().unwrap();
        assert!(
            !name.starts_with("root-") || name == "root-operator-archive",
            "original native namespace still present: {name}",
        );
    }
}

#[test]
#[ignore = "requires the source-built Root manifest, actual opaque closure auditor and three genuinely supervised worlds"]
fn queued_root_cli_preserves_original_held_publication_after_namespace_death_and_two_fresh_retirements()
 {
    let companion = PathBuf::from(std::env::var_os("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let temporary = EvidenceDirectory::new();
    let original = temporary.path().join("original");
    let (policy, socket) = installation(&original, &companion);
    let daemon = Daemon::start(&policy, &socket);
    let selections = json!([
        {"node":"clock", "owner":"owner/clock", "kind":{"implementation":"host_clock"}},
        {"node":"root", "owner":"owner/root", "kind":{"implementation":"gem5_arm_root"}},
    ]);
    // Source-only description has the same durable asynchronous reservation as
    // native preparation; hashing the full installed closure never extends an exchange.
    let description_path = original.join("description.json");
    fs::write(
        &description_path,
        serde_json::to_vec(&json!({
            "format":"crucible.root-preparation-request", "version":1,
            "execution":"95959595959595959595959595959595", "selections":selections,
            "scenario":Bytes::new(Vec::new()), "action":{"operation":"describe_held_uart"},
        }))
        .unwrap(),
    )
    .unwrap();
    let pending_description = positive(&[
        "node",
        "root",
        "--socket",
        socket.to_str().unwrap(),
        "--request",
        description_path.to_str().unwrap(),
    ]);
    assert_eq!(
        pending_description["outcome"]["state"],
        "awaiting_admission"
    );
    let description = complete(&socket, "95959595959595959595959595959595");
    let RootPreparationState::Described { scenario } = description.outcome else {
        panic!("original source-only description missing");
    };
    let execution = "96969696969696969696969696969696";
    let request = json!({
        "format":"crucible.root-preparation-request", "version":1,
        "execution":execution, "selections":selections, "scenario":scenario,
        "action":{"operation":"capture_held_uart"},
    });
    let request_path = original.join("request.json");
    fs::write(&request_path, serde_json::to_vec(&request).unwrap()).unwrap();
    let pending = positive(&[
        "node",
        "root",
        "--socket",
        socket.to_str().unwrap(),
        "--request",
        request_path.to_str().unwrap(),
    ]);
    assert_eq!(pending["outcome"]["state"], "awaiting_admission");
    let completed = complete(&socket, execution);
    let RootPreparationState::Completed {
        artifact,
        progress,
        continued,
        ..
    } = &completed.outcome
    else {
        panic!("original capture result missing");
    };
    assert!(!continued);
    assert_native_namespaces_released(&original);
    let original_publication =
        original_oracle::PublishedSource::read(&original, execution, artifact);
    let exact_original = serde_json::to_value(&completed).unwrap();
    drop(daemon);

    let restarted = Daemon::start(&policy, &socket);
    assert_eq!(
        positive(&[
            "node",
            "root-status",
            "--socket",
            socket.to_str().unwrap(),
            "--execution",
            execution,
        ]),
        exact_original
    );
    // A retained original claim cannot launch the same recipe after restart.
    assert_eq!(
        positive(&[
            "node",
            "root",
            "--socket",
            socket.to_str().unwrap(),
            "--request",
            request_path.to_str().unwrap(),
        ]),
        exact_original
    );
    drop(restarted);

    let retained_archive = temporary.path().join("retained-archive");
    copy_tree(&original.join("root-operator-archive"), &retained_archive);
    fs::remove_dir_all(&original).unwrap();
    assert!(!original.exists());
    let mut previous_target: Option<crucible_core::node_contract::SavedRuntimeActivation> = None;
    for (name, nonce) in [
        ("left", "97979797979797979797979797979797"),
        ("right", "98989898989898989898989898989898"),
    ] {
        let fresh = temporary.path().join(name);
        let (policy, socket) = installation(&fresh, &companion);
        copy_tree(&retained_archive, &fresh.join("root-operator-archive"));
        let daemon = Daemon::start(&policy, &socket);
        let request_path = fresh.join("request.json");
        fs::write(
            &request_path,
            serde_json::to_vec(&json!({
                "format":"crucible.root-preparation-request", "version":1,
                "execution":nonce, "selections":selections, "scenario":scenario,
                "action":{"operation":"continue_held_uart", "source":artifact},
            }))
            .unwrap(),
        )
        .unwrap();
        positive(&[
            "node",
            "root",
            "--socket",
            socket.to_str().unwrap(),
            "--request",
            request_path.to_str().unwrap(),
        ]);
        let record = complete(&socket, nonce);
        let RootPreparationState::Completed {
            progress: restored,
            artifact: restored_artifact,
            scenario: restored_scenario,
            continued,
        } = record.outcome
        else {
            panic!("fresh original held continuation missing");
        };
        assert!(continued);
        assert_eq!(restored_artifact, *artifact);
        assert_eq!(restored_scenario, scenario);
        let target = original_oracle::assert_restored_original(
            &fresh,
            nonce,
            artifact,
            progress,
            &restored,
            &original_publication,
        );
        if let Some(previous) = &previous_target {
            assert_ne!(previous.activation_id, target.activation_id);
            for (old, fresh) in previous.owners.iter().zip(&target.owners) {
                assert_eq!(old.owner, fresh.owner);
                assert_eq!(old.generation, fresh.generation);
                assert_ne!(old.incarnation, fresh.incarnation);
            }
        }
        previous_target = Some(target);
        original_oracle::assert_archive_bytes_unchanged(
            &retained_archive,
            &fresh.join("root-operator-archive"),
        );
        assert_native_namespaces_released(&fresh);
        drop(daemon);
        assert!(!original.exists());
    }
}
