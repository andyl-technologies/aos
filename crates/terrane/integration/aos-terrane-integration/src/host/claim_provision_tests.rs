//! Exercises complete provisioning, process death and broker observations in the VM.
//!
//! These ignored tests run only from the dedicated bounded-capability VM artifact.
//! The worker executes the same provisioning and serving entry points as the host
//! executable; test-only durable checkpoints let the supervisor kill it precisely.

use super::{ANCHOR_PATH, REGISTRY_PATH};
use crate::host::{provision, serve};
use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;
use terrane_linux::host_quota::{HostQuotaClient, NativeProject, NativeQuota, ROOT_LABELS};
use terrane_sdk::store::{Clock, TokioClock};

const WORKER: &str = "host::claims::provision_tests::host_global_provision_worker_vm";

struct Worker(Child);

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Fixture {
    config: PathBuf,
    ledger: PathBuf,
    socket: PathBuf,
    layouts: Vec<PathBuf>,
    owners: Vec<String>,
    projects: Vec<u32>,
}

impl Fixture {
    fn create(mount: &Path, name: &str, projects: &[u32]) -> Self {
        let admin = mount.join(format!("{name}-admin"));
        fs::create_dir(&admin).expect("administrative directory");
        fs::set_permissions(&admin, fs::Permissions::from_mode(0o700)).expect("private custody");
        let mut fixture = Self {
            config: admin.join("host.toml"),
            ledger: admin.join("ledger.toml"),
            socket: admin.join("quota.sock"),
            layouts: Vec::new(),
            owners: Vec::new(),
            projects: projects.to_vec(),
        };
        for index in 0..projects.len() {
            let layout = mount.join(format!("{name}-layout-{index}"));
            fs::create_dir(&layout).expect("layout root");
            fs::set_permissions(&layout, fs::Permissions::from_mode(0o755))
                .expect("layout custody");
            for label in ROOT_LABELS {
                if label != "layout-root" {
                    fs::create_dir(layout.join(label)).expect("allocation root");
                    let (uid, gid, mode) = match label {
                        "state" => (0, 0, 0o755),
                        "sealed" | "staging" | "pending-delete" => (841, 841, 0o700),
                        _ => (840, 845, 0o2770),
                    };
                    set_metadata(&layout.join(label), uid, gid, mode);
                }
            }
            for (child, uid, gid, mode) in [
                ("cache", 840, 844, 0o2770),
                ("publication", 841, 841, 0o700),
            ] {
                let path = layout.join("state").join(child);
                fs::create_dir(&path).expect("state scaffold");
                set_metadata(&path, uid, gid, mode);
            }
            fixture.layouts.push(layout);
            fixture.owners.push(format!("{name}-owner-{index}"));
        }
        fixture.write_config("00000000000000000000000000000001", 2097152);
        fixture
    }

    fn write_config(&self, epoch: &str, limit: u64) {
        let mut text = format!(
            "socket = {:?}\nepoch = {epoch:?}\ntier_charge_budget_bytes = 8388608\n",
            self.socket.to_str().expect("UTF-8 socket")
        );
        for (index, ((layout, owner), project)) in self
            .layouts
            .iter()
            .zip(&self.owners)
            .zip(&self.projects)
            .enumerate()
        {
            let domain = self.domain(index);
            text.push_str(&format!("[[owners]]\nowner_id = {owner:?}\ndomain = {domain:?}\nproject_id = {project}\nhard_limit_bytes = {limit}\nallowed_client_uids = [0]\n"));
            for label in ROOT_LABELS {
                let path = if label == "layout-root" {
                    layout.clone()
                } else {
                    layout.join(label)
                };
                text.push_str(&format!(
                    "[[owners.roots]]\nrole_directory = {label:?}\npath = {:?}\n",
                    path.to_str().expect("UTF-8 root")
                ));
            }
        }
        fs::write(&self.config, text).expect("configuration publication");
        fs::set_permissions(&self.config, fs::Permissions::from_mode(0o600))
            .expect("protected configuration");
    }

    fn domain(&self, index: usize) -> String {
        if index == 0 {
            "public".to_owned()
        } else {
            format!("tenant:{}", self.owners[index])
        }
    }

    fn worker(&self, operation: &str, stage: Option<&str>) -> Worker {
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command
            .args(["--exact", WORKER, "--ignored", "--nocapture"])
            .env("TERRANE_QUOTA_TEST_OPERATION", operation)
            .env("TERRANE_QUOTA_TEST_CONFIG", &self.config)
            .env("TERRANE_QUOTA_TEST_LEDGER", &self.ledger)
            .env_remove("TERRANE_QUOTA_TEST_STOP");
        if let Some(stage) = stage {
            command.env("TERRANE_QUOTA_TEST_STOP", stage).env(
                "TERRANE_QUOTA_TEST_MARKER",
                self.config.with_extension("marker"),
            );
        }
        Worker(command.spawn().expect("real host worker"))
    }

    fn kill_provision_at(&self, stage: &str) {
        let marker = self.config.with_extension("marker");
        let mut worker = self.worker("provision", Some(stage));
        wait_for(&mut worker, || {
            fs::read_to_string(&marker).is_ok_and(|actual| actual == stage)
        });
        assert_eq!(
            fs::read_to_string(&marker).expect("durable checkpoint"),
            stage
        );
        worker.0.kill().expect("kill provisioning process");
        assert!(!worker.0.wait().expect("terminated worker").success());
        fs::remove_file(marker).expect("checkpoint cleanup");
    }

    fn broker(&self) -> Worker {
        let mut worker = self.worker("serve", None);
        // A socket pathname is visible before listen/accept readiness. Require
        // a real correlated observation from the retained native partition.
        wait_for(&mut worker, || self.query(0).is_ok());
        worker
    }

    fn query(
        &self,
        index: usize,
    ) -> std::io::Result<terrane_linux::host_quota::VerifiedQuotaObservation> {
        let mut client = HostQuotaClient::connect(
            &self.socket,
            0,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        )?;
        client.query(&self.owners[index], &self.domain(index))
    }
}

fn set_metadata(path: &Path, uid: u32, gid: u32, mode: u32) {
    std::os::unix::fs::chown(path, Some(uid), Some(gid)).expect("role ownership");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("role permissions");
}

fn wait_for(worker: &mut Worker, ready: impl Fn() -> bool) {
    let deadline = TokioClock
        .monotonic()
        .checked_add(Duration::from_secs(15))
        .expect("bounded native checkpoint deadline");
    while !ready() {
        assert!(
            worker.0.try_wait().expect("worker state").is_none(),
            "worker exited before checkpoint"
        );
        assert!(
            TokioClock.monotonic() < deadline,
            "worker checkpoint timed out"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn require_bounded_vm() {
    assert_eq!(std::env::var("TERRANE_HOST_QUOTA_VM").as_deref(), Ok("1"));
    let status = fs::read_to_string("/proc/self/status").expect("actual worker privileges");
    for field in ["CapEff", "CapPrm", "CapBnd"] {
        assert!(
            status
                .lines()
                .any(|line| line == format!("{field}:\t000000000020001d")),
            "actual provision capability set: {field}"
        );
    }
    let groups = status
        .lines()
        .find(|line| line.starts_with("Groups:"))
        .expect("actual groups");
    assert!(
        !groups
            .split_whitespace()
            .skip(1)
            .any(|group| group == "844" || group == "845")
    );
}

#[test]
#[ignore = "requires the explicit host-quota-proof administrative VM worker"]
fn host_global_provision_worker_vm() {
    require_bounded_vm();
    let config =
        PathBuf::from(std::env::var_os("TERRANE_QUOTA_TEST_CONFIG").expect("worker config"));
    let ledger =
        PathBuf::from(std::env::var_os("TERRANE_QUOTA_TEST_LEDGER").expect("worker ledger"));
    match std::env::var("TERRANE_QUOTA_TEST_OPERATION")
        .expect("worker operation")
        .as_str()
    {
        "provision" => provision(&config, &ledger).expect("actual provisioning"),
        "serve" => serve(&config, &ledger).expect("actual serving"),
        _ => panic!("unknown worker operation"),
    }
}

#[test]
#[ignore = "requires the explicit host-quota-proof administrative VM"]
fn host_global_provision_kill_restart_and_broker_vm() {
    require_bounded_vm();
    let mount =
        PathBuf::from(std::env::var_os("TERRANE_HOST_QUOTA_ADMIN_ROOT").expect("guest mount"));
    for (index, stage) in [
        "claim-durable",
        "ledger-durable",
        "custody-taken",
        "project-mutated",
    ]
    .into_iter()
    .enumerate()
    {
        let project = 49101 + index as u32;
        let a = Fixture::create(&mount, &format!("crash-A-{index}"), &[project]);
        let b = Fixture::create(&mount, &format!("crash-B-{index}"), &[project]);
        a.kill_provision_at(stage);
        assert_eq!(a.ledger.exists(), stage != "claim-durable");
        let interrupted_root = File::open(&a.layouts[0]).expect("interrupted actual root");
        assert_eq!(
            NativeProject::inspect(&interrupted_root)
                .expect("actual interrupted project")
                .project_id,
            if stage == "project-mutated" {
                project
            } else {
                0
            }
        );
        if stage == "project-mutated" {
            assert_eq!(
                NativeQuota::query(&interrupted_root, project)
                    .expect("actual interrupted quota limit")
                    .hard_limit_bytes,
                2097152
            );
        }
        assert!(serve(&a.config, &a.ledger).is_err());
        assert!(provision(&b.config, &b.ledger).is_err());
        assert!(!b.ledger.exists());
        assert_eq!(
            NativeProject::inspect(&File::open(&b.layouts[0]).expect("B root"))
                .expect("B project")
                .project_id,
            0
        );

        provision(&a.config, &a.ledger).expect("original owner crash recovery");
        provision(&a.config, &a.ledger).expect("matching Ready restart");
        let cache = File::open(a.layouts[0].join("state/cache")).expect("restored cache scaffold");
        let metadata = cache.metadata().expect("actual restored metadata");
        assert_eq!(
            (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777),
            (840, 844, 0o2770)
        );
        assert_eq!(
            NativeProject::inspect(&cache)
                .expect("assigned scaffold")
                .project_id,
            project
        );
        let broker = a.broker();
        let observation = a.query(0).expect("genuine helper observation");
        assert_eq!(observation.observation().project_id, project);
        assert_eq!(observation.observation().roots.len(), 8);

        a.write_config("00000000000000000000000000000002", 2097152);
        assert!(provision(&a.config, &a.ledger).is_err());
        a.write_config("00000000000000000000000000000001", 3145728);
        assert!(provision(&a.config, &a.ledger).is_err());
        assert_eq!(
            NativeQuota::query(&cache, project)
                .expect("unchanged hard limit")
                .hard_limit_bytes,
            2097152
        );
        a.write_config("00000000000000000000000000000001", 2097152);
        drop(broker);
        assert!(a.query(0).is_err());
    }

    let multi = Fixture::create(&mount, "partial-multi", &[49110, 49111]);
    multi.kill_provision_at("claim-durable");
    assert!(!multi.ledger.exists());
    let foreign = Fixture::create(&mount, "partial-foreign", &[49110]);
    assert!(provision(&foreign.config, &foreign.ledger).is_err());
    provision(&multi.config, &multi.ledger).expect("complete original multi-owner claim set");
    let broker = multi.broker();
    multi.query(0).expect("first owner actual quota");
    multi.query(1).expect("second owner actual quota");

    let anchor_bytes = fs::read(ANCHOR_PATH).expect("actual anchor bytes");
    let absent_anchor =
        Path::new(ANCHOR_PATH).with_file_name("project-claims.identity.live-vm-missing");
    fs::rename(ANCHOR_PATH, &absent_anchor).expect("live broker anchor loss");
    assert!(multi.query(0).is_err());
    fs::rename(absent_anchor, ANCHOR_PATH).expect("restore original anchor");
    multi
        .query(0)
        .expect("actual quota after anchor restoration");
    fs::write(ANCHOR_PATH, b"malformed live anchor").expect("VM anchor corruption");
    assert!(multi.query(1).is_err());
    assert!(provision(&multi.config, &multi.ledger).is_err());
    fs::write(ANCHOR_PATH, anchor_bytes).expect("VM administrator anchor restoration");
    multi.query(1).expect("actual quota after anchor repair");

    let root = File::open(&multi.layouts[0]).expect("actual owner root");
    let uuid = terrane_linux::host_quota::filesystem_uuid(&root).expect("actual owner UUID");
    let claim_name = terrane_linux::host_quota::project_claim_name(&uuid, multi.projects[0])
        .expect("exact native claim key");
    let claim = Path::new(REGISTRY_PATH).join(claim_name);
    let claim_bytes = fs::read(&claim).expect("actual protected claim bytes");
    let absent_claim = claim.with_extension("live-vm-missing");
    fs::rename(&claim, &absent_claim).expect("live broker owner claim loss");
    assert!(multi.query(0).is_err());
    // Every observation checks the entire native partition, including owners
    // other than the requested one. Missing A also makes B unavailable.
    assert!(multi.query(1).is_err());
    fs::rename(absent_claim, &claim).expect("restore actual owner claim");
    multi
        .query(1)
        .expect("actual partition after claim restoration");
    fs::write(&claim, b"foreign project claim bytes").expect("VM individual claim corruption");
    assert!(multi.query(0).is_err());
    assert!(multi.query(1).is_err());
    assert!(provision(&multi.config, &multi.ledger).is_err());
    fs::write(&claim, claim_bytes).expect("VM administrator claim restoration");
    multi
        .query(0)
        .expect("actual quota after individual claim repair");

    let displaced = Path::new(REGISTRY_PATH).with_file_name("project-claims.full-vm-displaced");
    fs::rename(REGISTRY_PATH, &displaced).expect("registry loss");
    assert!(multi.query(0).is_err());
    fs::create_dir(REGISTRY_PATH).expect("empty replacement registry");
    fs::set_permissions(REGISTRY_PATH, fs::Permissions::from_mode(0o700))
        .expect("replacement custody");
    let fresh = Fixture::create(&mount, "fresh-after-replacement", &[49112]);
    assert!(provision(&fresh.config, &fresh.ledger).is_err());
    assert!(!fresh.ledger.exists());
    assert!(multi.query(1).is_err());
    assert!(provision(&multi.config, &multi.ledger).is_err());
    assert!(Path::new(ANCHOR_PATH).exists());
    fs::remove_dir(REGISTRY_PATH).expect("empty VM replacement cleanup");
    fs::rename(displaced, REGISTRY_PATH).expect("restore original registry");
    multi.query(0).expect("original claim after restoration");
    drop(broker);

    concurrent_full_enrollment(&mount);
}

fn concurrent_full_enrollment(mount: &Path) {
    let a = Fixture::create(mount, "concurrent-A", &[49120]);
    let b = Fixture::create(mount, "concurrent-B", &[49120]);
    let barrier = std::sync::Barrier::new(3);
    let (a_result, b_result) = std::thread::scope(|scope| {
        let a_worker = scope.spawn(|| {
            barrier.wait();
            provision(&a.config, &a.ledger)
        });
        let b_worker = scope.spawn(|| {
            barrier.wait();
            provision(&b.config, &b.ledger)
        });
        barrier.wait();
        (
            a_worker.join().expect("A enrollment worker"),
            b_worker.join().expect("B enrollment worker"),
        )
    });

    assert_ne!(
        a_result.is_ok(),
        b_result.is_ok(),
        "exactly one common-project enrollment may succeed"
    );
    let (winner, refused) = if a_result.is_ok() { (&a, &b) } else { (&b, &a) };
    assert!(winner.ledger.exists());
    assert!(!refused.ledger.exists());
    assert_eq!(
        NativeProject::inspect(&File::open(&refused.layouts[0]).expect("refused root"))
            .expect("refused actual project")
            .project_id,
        0
    );
    assert!(
        provision(&refused.config, &refused.ledger).is_err(),
        "a transient lock refusal must become permanent foreign-owner refusal"
    );
    provision(&winner.config, &winner.ledger).expect("winning owner Ready verification");
    let broker = winner.broker();
    let observation = winner.query(0).expect("actual winning native partition");
    assert_eq!(observation.observation().project_id, 49120);
    assert_eq!(observation.observation().hard_limit_bytes, 2097152);
    drop(broker);
}
