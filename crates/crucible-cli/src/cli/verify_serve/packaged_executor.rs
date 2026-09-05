//! Strict deployment-file adapter for the packaged campaign QEMU executor.

use std::fs::{self, File};
use std::io::{Read, Take};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::fs::{Mode, OFlags};
use serde::Deserialize;

use super::*;

const PACKAGED_EXECUTOR_SCHEMA: &str = "crucible.campaign-packaged-executor";
const PACKAGED_EXECUTOR_VERSION: u32 = 1;
const MAX_PACKAGED_EXECUTOR_CONFIG_BYTES: usize = 64 * 1024;
const OS_ENTROPY_DEVICE: &str = "/dev/urandom";
const DEFAULT_PACKAGED_RUN_INTERVAL_ICOUNT: u64 = 1_000_000;

/// Keeps packaged campaign RUNs bounded without reducing the terminal ceiling.
pub(super) fn production_rendezvous_interval(
    requested: Option<u64>,
    packaged: bool,
) -> Option<u64> {
    // Conditions, checkpoint requests, and resource checks run at modeled
    // boundaries. Without rendezvous, an isolated VM can consume the complete
    // forty-billion-instruction CLI run allowance before returning to them.
    requested.or_else(|| packaged.then_some(DEFAULT_PACKAGED_RUN_INTERVAL_ICOUNT))
}

/// Authored deployment contract; unknown fields fail closed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackagedExecutorDeployment {
    schema: String,
    version: u32,
    cgroup_root: PathBuf,
    run_root: PathBuf,
    attempt_namespace: String,
    first_project_id: u32,
    project_id_count: u32,
    child_user_id: u32,
    child_group_id: u32,
    maximum_tasks: u32,
    maximum_inodes: u64,
    finish_timeout_ms: u64,
    maximum_slots: u32,
    maximum_vcpus: u32,
    maximum_resident_bytes: u64,
    maximum_disk_bytes: u64,
    maximum_execution_quanta: u64,
    maximum_checkpoint_bytes: u64,
    worker_count: usize,
    host_architecture: String,
    qemu_profile: String,
}

pub(super) fn prepare_cli_packaged_executor(
    prepared: &crucible_daemon::PreparedCampaignLocalService,
    args: &ServeArgs,
    campaigns: std::collections::BTreeSet<crucible_campaign::CampaignName>,
    executor_socket: &Path,
    deployment_path: &Path,
    lifecycle: &crucible_api::ProductionVmLifecycleConfig,
) -> Result<crucible_daemon::AttachedPackagedQemuExecutor, CliError> {
    let deployment = load_deployment(deployment_path)?;
    if deployment.schema != PACKAGED_EXECUTOR_SCHEMA
        || deployment.version != PACKAGED_EXECUTOR_VERSION
    {
        return Err(serve_error(
            "campaign packaged-executor deployment has an unsupported schema or version",
        ));
    }
    if deployment.project_id_count < deployment.maximum_slots {
        return Err(serve_error(
            "campaign packaged-executor project-ID count is below its slot ceiling",
        ));
    }
    if deployment.maximum_checkpoint_bytes > deployment.maximum_disk_bytes {
        return Err(serve_error(
            "campaign packaged-executor checkpoint ceiling exceeds writable-disk capacity",
        ));
    }
    let finish_timeout = Duration::from_millis(deployment.finish_timeout_ms);
    if finish_timeout.is_zero() || finish_timeout > Duration::from_secs(60 * 60) {
        return Err(serve_error(
            "campaign packaged-executor finish timeout is outside 1ms..=1h",
        ));
    }

    let user_id = rustix::process::geteuid().as_raw();
    let group_id = rustix::process::getegid().as_raw();
    let endpoint = crucible_daemon::ExecutorLoopbackEndpointConfig::new(
        executor_socket,
        user_id,
        group_id,
        0o600,
    )
    .map_err(|error| serve_error(format!("campaign executor endpoint error: {error}")))?;
    let host = crucible_daemon::LinuxQemuAttemptHostConfig::new(
        deployment.cgroup_root,
        deployment.run_root,
        deployment.attempt_namespace,
        deployment.first_project_id,
        deployment.project_id_count,
        deployment.child_user_id,
        deployment.child_group_id,
        deployment.maximum_tasks,
        deployment.maximum_inodes,
        finish_timeout,
    )
    .map_err(|error| serve_error(format!("campaign executor host policy error: {error}")))?;
    let capacity = crucible_daemon::ExecutorCapacity::new(
        deployment.maximum_slots,
        deployment.maximum_vcpus,
        deployment.maximum_resident_bytes,
        deployment.maximum_disk_bytes,
        deployment.maximum_execution_quanta,
    )
    .map_err(|error| serve_error(format!("campaign executor capacity error: {error}")))?;
    let state = args
        .campaign_state
        .as_ref()
        .ok_or_else(|| serve_error("campaign packaged executor has no state directory"))?;
    let store_namespace = packaged_store_namespace(state);
    let daemon_epoch = fresh_daemon_epoch()?;
    let config = crucible_daemon::PackagedQemuExecutorConfig::new(
        campaigns,
        endpoint,
        crucible_daemon::ExecutorLoopbackServerConfig::default(),
        state.join("executor-ledger"),
        deployment.maximum_checkpoint_bytes,
        daemon_epoch,
        capacity,
        deployment.worker_count,
        deployment.host_architecture,
        deployment.qemu_profile,
        store_namespace,
        lifecycle.clone(),
        host,
    )
    .map_err(|error| serve_error(format!("campaign executor configuration error: {error}")))?;
    let executor = prepared
        .prepare_packaged_executor(config)
        .map_err(|error| {
            serve_error(format!(
                "campaign executor preparation error: {}",
                preparation_error_chain(&error)
            ))
        })?;
    crucible_daemon::AttachedPackagedQemuExecutor::start(executor)
        .map_err(|error| serve_error(format!("campaign executor startup error: {error}")))
}

/// Keeps nested startup causes visible without unbounded diagnostic traversal.
fn preparation_error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut message = String::new();
    let mut current = Some(error);
    for _ in 0..12 {
        let Some(error) = current else { break };
        if !message.is_empty() {
            message.push_str("; caused by: ");
        }
        message.extend(error.to_string().chars().take(1024));
        current = error.source();
    }
    if current.is_some() {
        message.push_str("; further causes omitted");
    }
    message
}

fn packaged_store_namespace(state: &Path) -> crucible_campaign::CampaignHash {
    crucible_campaign::CampaignHash::derive(
        "crucible.campaign.packaged-executor-store.v2",
        state.as_os_str().as_encoded_bytes(),
    )
}

fn load_deployment(path: &Path) -> Result<PackagedExecutorDeployment, CliError> {
    let before = fs::symlink_metadata(path).map_err(|error| {
        serve_error(format!(
            "campaign packaged-executor metadata error for {}: {error}",
            path.display()
        ))
    })?;
    let user_id = rustix::process::geteuid().as_raw();
    let group_id = rustix::process::getegid().as_raw();
    if !before.is_file()
        || before.uid() != user_id
        || before.gid() != group_id
        || before.mode() & 0o777 != 0o600
        || before.len() > MAX_PACKAGED_EXECUTOR_CONFIG_BYTES as u64
    {
        return Err(serve_error(
            "campaign packaged-executor deployment is not an exact-owner mode-0600 bounded file",
        ));
    }
    let mut file: File = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        serve_error(format!(
            "campaign packaged-executor open error for {}: {error}",
            path.display()
        ))
    })?
    .into();
    let after = file.metadata().map_err(|error| {
        serve_error(format!(
            "campaign packaged-executor opened metadata error for {}: {error}",
            path.display()
        ))
    })?;
    if after.dev() != before.dev()
        || after.ino() != before.ino()
        || !after.is_file()
        || after.uid() != user_id
        || after.gid() != group_id
        || after.mode() & 0o777 != 0o600
        || after.len() > MAX_PACKAGED_EXECUTOR_CONFIG_BYTES as u64
    {
        return Err(serve_error(
            "campaign packaged-executor deployment changed while opening",
        ));
    }

    let mut bytes = Vec::with_capacity(after.len() as usize);
    let mut bounded: Take<&mut File> =
        std::io::Read::by_ref(&mut file).take((MAX_PACKAGED_EXECUTOR_CONFIG_BYTES + 1) as u64);
    bounded.read_to_end(&mut bytes).map_err(|error| {
        serve_error(format!(
            "campaign packaged-executor read error for {}: {error}",
            path.display()
        ))
    })?;
    if bytes.len() > MAX_PACKAGED_EXECUTOR_CONFIG_BYTES {
        return Err(serve_error(
            "campaign packaged-executor deployment exceeds 64 KiB",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| serve_error("campaign packaged-executor deployment is not UTF-8"))?;
    toml::from_str(text).map_err(|error| {
        serve_error(format!(
            "campaign packaged-executor TOML is invalid: {error}"
        ))
    })
}

fn fresh_daemon_epoch() -> Result<crucible_campaign::DaemonEpoch, CliError> {
    let mut bytes = [0_u8; 16];
    File::open(OS_ENTROPY_DEVICE)
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|error| serve_error(format!("campaign executor entropy error: {error}")))?;
    crucible_campaign::DaemonEpoch::from_bytes(bytes)
        .map_err(|error| serve_error(format!("campaign executor epoch error: {error}")))
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[derive(Debug)]
    struct CyclicCause;

    impl std::fmt::Display for CyclicCause {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("bounded cause")
        }
    }

    impl std::error::Error for CyclicCause {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self)
        }
    }

    #[test]
    fn preparation_diagnostics_bound_cyclic_and_long_causes() {
        let cycle = preparation_error_chain(&CyclicCause);
        assert_eq!(cycle.matches("bounded cause").count(), 12);
        assert!(cycle.ends_with("further causes omitted"));
        let long = std::io::Error::other("x".repeat(4096));
        assert_eq!(preparation_error_chain(&long).len(), 1024);
    }

    fn authored() -> String {
        String::from(
            r#"schema = "crucible.campaign-packaged-executor"
version = 1
cgroup_root = "/sys/fs/cgroup/crucible"
run_root = "/var/lib/crucible/attempts"
attempt_namespace = "campaign-local"
first_project_id = 10000
project_id_count = 4
child_user_id = 2000
child_group_id = 2000
maximum_tasks = 64
maximum_inodes = 4096
finish_timeout_ms = 30000
maximum_slots = 2
maximum_vcpus = 4
maximum_resident_bytes = 1073741824
maximum_disk_bytes = 2147483648
maximum_execution_quanta = 100000
maximum_checkpoint_bytes = 1073741824
worker_count = 2
host_architecture = "x86_64"
qemu_profile = "deterministic-tcg-v1"
"#,
        )
    }

    #[test]
    fn packaged_executor_deployment_is_strict_and_owner_only() {
        let directory = tempfile::tempdir().expect("deployment directory");
        let path = directory.path().join("executor.toml");
        fs::write(&path, authored()).expect("write deployment");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure deployment");

        let deployment = load_deployment(&path).expect("load deployment");
        assert_eq!(deployment.schema, PACKAGED_EXECUTOR_SCHEMA);
        assert_eq!(deployment.worker_count, 2);

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("weaken deployment mode");
        assert!(load_deployment(&path).is_err());
    }

    #[test]
    fn packaged_runs_default_to_bounded_rendezvous_without_overriding_explicit_policy() {
        assert_eq!(production_rendezvous_interval(None, false), None);
        assert_eq!(production_rendezvous_interval(None, true), Some(1_000_000));
        for packaged in [false, true] {
            assert_eq!(
                production_rendezvous_interval(Some(100), packaged),
                Some(100)
            );
            assert_eq!(
                production_rendezvous_interval(Some(2_000_000), packaged),
                Some(2_000_000)
            );
        }
    }

    #[test]
    fn packaged_executor_deployment_rejects_unknown_fields() {
        let directory = tempfile::tempdir().expect("deployment directory");
        let path = directory.path().join("executor.toml");
        fs::write(&path, format!("{}unknown = true\n", authored())).expect("write deployment");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure deployment");
        assert!(load_deployment(&path).is_err());
    }

    #[test]
    fn packaged_executor_store_namespace_is_stable_for_one_state_root() {
        let state = Path::new("/var/lib/crucible/campaign-state");
        assert_eq!(
            packaged_store_namespace(state),
            packaged_store_namespace(state)
        );
        assert_ne!(
            packaged_store_namespace(state),
            packaged_store_namespace(Path::new("/var/lib/crucible/other-state"))
        );
    }
}
