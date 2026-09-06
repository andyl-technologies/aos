//! Hermetic process flight for the public campaign-store porcelain.
//!
//! The flight uses only the shipped `crucible` process for fixture generation,
//! import validation, daemon ownership, campaign creation, inspection, and GC.
//! Test setup injects one authenticated orphan placement to model crash debris;
//! the public plan/apply commands must reclaim it without breaking restart.

#![cfg(target_os = "linux")]
// crucible-lint: allow clippy-disallowed-method -- this process boundary test intentionally exercises host process methods.
// crucible-lint: allow panic-shortcut -- assertions localize failures in a single hermetic operator flight.
#![allow(clippy::disallowed_methods, clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc as std_mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crucible_cas::content_store::{
    BlobHandle, ContentId, DirectoryBlobBackend, ImmutableBlobBackend, ObjectKind,
};
use serde_json::Value;
use tempfile::TempDir;

const CAMPAIGN: &str = "worked-network";
const PRINCIPAL: &str = "operator";
const START_COMMAND: &str = "4242424242424242424242424242424242424242424242424242424242424242";

#[path = "support/campaign_packaged_process.rs"]
mod packaged;

#[test]
fn public_campaign_store_flight_survives_gc_and_service_restart() -> Result<(), Box<dyn Error>> {
    let fixture = FlightFixture::new()?;

    let generated = run_json(
        command(&[
            "--format",
            "jsonl",
            "campaign",
            "fixture",
            "worked-network",
            "--output",
        ])
        .arg(&fixture.fixture),
        "generate worked-network fixture",
    )?;
    let manifest = json_path(&generated, "manifest")?;
    let lineage = json_path(&generated, "lineage")?;
    let policy = json_path(&generated, "policy")?;
    let scenario_artifact = json_string(&generated, "scenario")?;
    let scenario = typed_content_id(&scenario_artifact)?;

    let validated = run_json(
        command(&["--format", "jsonl", "campaign", "validate-import"]).arg(&manifest),
        "validate generated import manifest",
    )?;
    assert_eq!(
        validated["schema"],
        "crucible.cli.campaign-import-validation.v1"
    );

    let mut service = fixture.start_service(Some(&manifest))?;
    let created = run_json(
        connected_campaign(&fixture)
            .args(["create", CAMPAIGN, "--lineage"])
            .arg(&lineage)
            .arg("--policy")
            .arg(&policy)
            .args(["--start-command", START_COMMAND]),
        "create and start imported campaign",
    )?;
    assert_eq!(created["schema"], "crucible.cli.campaign-acceptance.v2");
    assert_eq!(created["campaign"], CAMPAIGN);
    assert_eq!(created["replayed"], false);
    assert_eq!(created["start"]["command"], START_COMMAND);

    let live_head = campaign_status(&fixture)?;
    assert_eq!(live_head["state"], "running");
    let live_snapshot = json_string(&live_head, "snapshot")?;

    let store_status = run_json(
        command(&["--format", "jsonl", "store", "status"]).arg(&fixture.store),
        "inspect live composed store",
    )?;
    assert_eq!(store_status["schema"], "crucible.cli.store-status.v1");
    assert_eq!(store_status["root"], "primary");
    assert_eq!(store_status["nodes"][0]["kind"], "directory");

    let ensured = run_json(
        command(&["--format", "jsonl", "store", "ensure", &scenario, "--in"]).arg(&fixture.store),
        "authenticate imported scenario through live store",
    )?;
    assert_eq!(ensured["content"], scenario);
    assert_eq!(ensured["authenticated"], true);

    let before_orphan = fixture.verify_store()?;
    let retained_placements = json_u64(&before_orphan, "placements")?;
    assert!(retained_placements > 0);

    service.stop()?;

    let orphan_bytes = b"authenticated campaign-store process-flight orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    DirectoryBlobBackend::new("process-flight-primary", &fixture.objects)
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes.to_vec()))?;
    let orphan_id = orphan.encode();
    let orphan_ensured = run_json(
        command(&["--format", "jsonl", "store", "ensure", &orphan_id, "--in"]).arg(&fixture.store),
        "authenticate injected orphan",
    )?;
    assert_eq!(orphan_ensured["logical_bytes"], orphan_bytes.len());

    let with_orphan = fixture.verify_store()?;
    assert_eq!(
        json_u64(&with_orphan, "placements")?,
        retained_placements + 1
    );

    let planned = run_json(&mut fixture.gc_command("plan"), "plan stopped-owner GC")?;
    assert_eq!(planned["schema"], "crucible.cli.campaign-store-gc.v1");
    assert_eq!(planned["operation"], "plan");
    assert_eq!(planned["phase"], "planned");
    let candidates = json_u64(&planned, "candidates")?;
    assert!(candidates >= 1);
    assert!(json_u64(&planned, "candidate_logical_bytes")? >= orphan_bytes.len() as u64);

    let applied = run_json(&mut fixture.gc_command("apply"), "apply stopped-owner GC")?;
    assert_eq!(applied["plan"], planned["plan"]);
    assert_eq!(applied["phase"], "complete");
    assert_eq!(applied["apply_status"], "applied");

    let after_gc = fixture.verify_store()?;
    let expected_placements = retained_placements
        .checked_add(1)
        .and_then(|placements| placements.checked_sub(candidates))
        .ok_or("GC candidate count exceeds the authenticated physical inventory")?;
    assert_eq!(json_u64(&after_gc, "placements")?, expected_placements);
    let missing_orphan = command(&["--format", "jsonl", "store", "ensure", &orphan_id, "--in"])
        .arg(&fixture.store)
        .output()?;
    assert!(!missing_orphan.status.success());
    assert!(String::from_utf8_lossy(&missing_orphan.stderr).contains("store ensure read failed"));
    let retained_scenario = run_json(
        command(&["--format", "jsonl", "store", "ensure", &scenario, "--in"]).arg(&fixture.store),
        "reauthenticate retained scenario after GC",
    )?;
    assert_eq!(retained_scenario["authenticated"], true);

    let mut restarted = fixture.start_service(None)?;
    let reopened_head = campaign_status(&fixture)?;
    assert_eq!(reopened_head["snapshot"], live_snapshot);
    assert_eq!(reopened_head["state"], "running");
    restarted.stop()?;

    Ok(())
}

struct FlightFixture {
    _temporary: TempDir,
    fixture: PathBuf,
    state: PathBuf,
    objects: PathBuf,
    socket: PathBuf,
    peer_policy: PathBuf,
    store: PathBuf,
    journal: PathBuf,
}

impl FlightFixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().to_path_buf();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let state = secure_directory(&root, "state")?;
        let objects = secure_directory(&root, "objects")?;
        let refs = secure_directory(&root, "refs")?;
        let fixture = root.join("fixture");
        let socket = root.join("campaign.sock");
        let peer_policy = root.join("peer-policy.toml");
        let store = root.join("store.toml");
        let journal = root.join("gc-journal");

        let metadata = fs::metadata(&root)?;
        fs::write(
            &peer_policy,
            format!(
                r#"schema = "crucible.campaign-local-policy"
version = 1

[[bindings]]
user_id = {}
group_id = {}
principal = "{PRINCIPAL}"

[[grants]]
principal = "{PRINCIPAL}"
operation = "create-campaign"
campaign = "*"

[[grants]]
principal = "{PRINCIPAL}"
operation = "apply-campaign-command"
campaign = "*"

[[grants]]
principal = "{PRINCIPAL}"
operation = "get-campaign"
campaign = "*"

[[grants]]
principal = "{PRINCIPAL}"
operation = "get-campaign-status"
campaign = "*"

[[grants]]
principal = "{PRINCIPAL}"
operation = "get-campaign-snapshot"
campaign = "*"

[[grants]]
principal = "{PRINCIPAL}"
operation = "explain-campaign-attempt"
campaign = "*"
"#,
                metadata.uid(),
                metadata.gid(),
            ),
        )?;
        fs::set_permissions(&peer_policy, fs::Permissions::from_mode(0o600))?;

        fs::write(
            &store,
            format!(
                r#"schema = "crucible.campaign-repository-store"
version = 1
root = "primary"
admitted_kinds = ["campaign-fact", "campaign-snapshot", "merkle-node", "scenario", "configuration", "policy", "exact-manifest", "ram-extent", "disk-extent", "device-state", "observation", "finding", "projection", "trace"]
ref_directory = {refs:?}

[[nodes]]
id = "primary"
[nodes.spec]
kind = "directory"
root = {objects:?}
"#,
            ),
        )?;
        fs::set_permissions(&store, fs::Permissions::from_mode(0o600))?;

        Ok(Self {
            _temporary: temporary,
            fixture,
            state,
            objects,
            socket,
            peer_policy,
            store,
            journal,
        })
    }

    fn start_service(&self, import: Option<&Path>) -> Result<CampaignServiceChild, Box<dyn Error>> {
        self.start_service_command(self.service_command(import), Duration::from_secs(15))
    }

    fn service_command(&self, import: Option<&Path>) -> Command {
        let mut command = command(&[
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--trusted-unauthenticated-bind",
            "--campaign-socket",
        ]);
        command
            .arg(&self.socket)
            .arg("--campaign-state")
            .arg(&self.state)
            .arg("--campaign-policy")
            .arg(&self.peer_policy)
            .arg("--campaign-store")
            .arg(&self.store);
        if let Some(import) = import {
            command.arg("--campaign-import-manifest").arg(import);
        }
        command
    }

    fn start_service_command(
        &self,
        mut command: Command,
        timeout: Duration,
    ) -> Result<CampaignServiceChild, Box<dyn Error>> {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let child = command.spawn()?;
        let mut child = CampaignServiceChild {
            child,
            kill_on_drop: true,
        };
        let stdout = child
            .child
            .stdout
            .take()
            .ok_or("campaign service stdout was not piped")?;
        let announcement = match read_first_line(stdout, timeout) {
            Ok(line) => line,
            Err(error) => {
                let _ = child.child.kill();
                let _ = child.child.wait();
                let mut stderr = String::new();
                if let Some(mut stream) = child.child.stderr.take() {
                    stream.read_to_string(&mut stderr)?;
                }
                return Err(format!("{error}; stderr={stderr}").into());
            }
        };
        if !announcement.contains("http://") {
            return Err(format!("invalid service announcement: {announcement}").into());
        }
        let metadata = fs::metadata(&self.socket)?;
        if !metadata.file_type().is_socket() {
            return Err("campaign endpoint is not a Unix socket".into());
        }
        Ok(child)
    }

    fn verify_store(&self) -> Result<Value, Box<dyn Error>> {
        run_json(
            command(&["--format", "jsonl", "store", "verify"]).arg(&self.store),
            "verify complete physical inventory",
        )
    }

    fn gc_command(&self, operation: &str) -> Command {
        let mut command = command(&["--format", "jsonl", "store", "gc", "--state"]);
        command
            .arg(&self.state)
            .arg("--policy")
            .arg(&self.peer_policy)
            .arg("--store")
            .arg(&self.store)
            .arg("--journal")
            .arg(&self.journal)
            .arg(operation);
        command
    }
}

struct CampaignServiceChild {
    child: Child,
    kill_on_drop: bool,
}

impl CampaignServiceChild {
    fn stop(&mut self) -> Result<(), Box<dyn Error>> {
        send_sigterm(&self.child)?;
        // The packaged pool has a thirty-second bounded cleanup window.
        let status = wait_for_exit(&mut self.child, Duration::from_secs(45));
        let mut stderr = String::new();
        if let Some(mut stream) = self.child.stderr.take() {
            stream.read_to_string(&mut stderr)?;
        }
        if !stderr.is_empty() {
            eprintln!("campaign service stderr: {stderr}");
        }
        let status = status.map_err(|error| format!("{error}; stderr={stderr}"))?;
        if !status.success() {
            return Err(format!("campaign service failed: {status}; stderr={stderr}").into());
        }
        self.kill_on_drop = false;
        Ok(())
    }
}

impl Drop for CampaignServiceChild {
    fn drop(&mut self) {
        if self.kill_on_drop {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn connected_campaign(fixture: &FlightFixture) -> Command {
    let mut command = command(&["--format", "jsonl", "campaign", "--socket"]);
    command
        .arg(&fixture.socket)
        .args(["--principal", PRINCIPAL]);
    command
}

fn campaign_status(fixture: &FlightFixture) -> Result<Value, Box<dyn Error>> {
    run_json(
        connected_campaign(fixture).args(["status", CAMPAIGN]),
        "read campaign head",
    )
}

fn command(arguments: &[&str]) -> Command {
    // The hermetic VM copies both built executables into its store closure;
    // the build-time Cargo target path itself is not available in the guest.
    let binary = std::env::var_os("CRUCIBLE_PROCESS_FLIGHT_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_crucible").into());
    let mut command = Command::new(binary);
    command.args(arguments);
    command
}

fn run_json(command: &mut Command, operation: &str) -> Result<Value, Box<dyn Error>> {
    let output = command.output()?;
    parse_json_output(output, operation)
}

fn parse_json_output(output: Output, operation: &str) -> Result<Value, Box<dyn Error>> {
    require_success(&output, operation)?;
    let stdout = String::from_utf8(output.stdout)?;
    let mut lines = stdout.lines();
    let line = lines
        .next()
        .ok_or_else(|| format!("{operation} returned empty stdout"))?;
    if lines.next().is_some() {
        return Err(format!("{operation} returned more than one JSONL record").into());
    }
    Ok(serde_json::from_str(line)?)
}

fn require_success(output: &Output, operation: &str) -> Result<(), Box<dyn Error>> {
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "{operation} failed with {}; stdout=`{}` stderr=`{}`",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
    .into())
}

fn json_string(value: &Value, field: &str) -> Result<String, Box<dyn Error>> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("JSON field `{field}` is not a string").into())
}

fn json_path(value: &Value, field: &str) -> Result<PathBuf, Box<dyn Error>> {
    json_string(value, field).map(PathBuf::from)
}

fn typed_content_id(value: &str) -> Result<String, Box<dyn Error>> {
    value
        .split_once('@')
        .map(|(_, content)| content.to_owned())
        .ok_or_else(|| format!("typed campaign ID `{value}` does not contain a content ID").into())
}

fn json_u64(value: &Value, field: &str) -> Result<u64, Box<dyn Error>> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("JSON field `{field}` is not an unsigned integer").into())
}

fn secure_directory(root: &Path, name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = root.join(name);
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

fn read_first_line(
    stdout: impl Read + Send + 'static,
    timeout: Duration,
) -> Result<String, Box<dyn Error>> {
    let (sender, receiver) = std_mpsc::channel();
    thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        let mut line = String::new();
        let result = stdout.read_line(&mut line).map(|_| line);
        let _ = sender.send(result);
        // Keep the pipe open for subsequent listener announcements and logs.
        // A first-line-only reader can otherwise make a healthy daemon fail
        // its next stdout write with EPIPE.
        let _ = std::io::copy(&mut stdout, &mut std::io::sink());
    });
    match receiver.recv_timeout(timeout) {
        Ok(Ok(line)) if !line.is_empty() => Ok(line),
        Ok(Ok(_)) => Err("campaign service exited before announcing its listener".into()),
        Ok(Err(error)) => Err(Box::new(error)),
        Err(std_mpsc::RecvTimeoutError::Timeout) => {
            Err("campaign service did not announce its listener before timeout".into())
        }
        Err(std_mpsc::RecvTimeoutError::Disconnected) => {
            Err("campaign service stdout reader exited without a result".into())
        }
    }
}

fn send_sigterm(child: &Child) -> Result<(), Box<dyn Error>> {
    let pid = i32::try_from(child.id())?;
    // SAFETY: `pid` is the live child process ID returned by `Child`. Sending
    // SIGTERM does not dereference memory and reports failure through errno.
    let result = unsafe { libc::kill(pid, libc::SIGTERM) };
    if result == 0 {
        Ok(())
    } else {
        Err(Box::new(std::io::Error::last_os_error()))
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Result<ExitStatus, Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("campaign service did not exit before timeout".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}
