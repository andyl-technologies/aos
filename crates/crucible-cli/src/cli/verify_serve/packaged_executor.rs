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
const GUARDED_RUN_QEMU_PROFILE: &str = "deterministic-tcg-v1";
const CAMPAIGN_DEPLOYMENT_ENV: &str = "CRUCIBLE_CAMPAIGN_DEPLOYMENT";
const DEFAULT_CAMPAIGN_DEPLOYMENT_PATH: &str = "/etc/crucible/packaged-executor.toml";

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
    hot_fork: Option<PackagedHotForkDeployment>,
}

/// Optional retained-source policy; absence keeps hot-fork execution disabled.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackagedHotForkDeployment {
    maximum_templates: usize,
    maximum_template_bytes: u64,
    maximum_expected_private_dirty_bytes: u64,
    maximum_processes: u32,
    maximum_virtual_cpus: u32,
    maximum_descriptors: u32,
    maximum_overlays: u32,
    maximum_forks_per_window: u32,
    fork_rate_window_ms: u64,
    shutdown_step_timeout_ms: u64,
    host_io_timeout_ms: u64,
}

/// Guarded host capability loaded for one campaign-backed legacy command.
pub(crate) struct GuardedCampaignRunDeployment {
    pub(crate) host: crucible_daemon::LinuxQemuAttemptHostConfig,
    pub(crate) resources: crucible_campaign::AttemptResourceLimits,
}

/// Resolves the operator-provisioned capability for local campaign execution.
///
/// Explicit CLI configuration takes precedence over the environment. When
/// neither is present, an installed system deployment is discovered at the
/// documented default path. The strict loader authenticates the selected file
/// before any host resource is acquired.
///
/// # Errors
///
/// Returns [`CliError`] when no deployment capability is configured or the
/// environment value is empty.
// crucible-lint: allow host-nondeterminism-state -- deployment discovery selects operational host authority and never enters modeled campaign identity.
pub(crate) fn resolve_guarded_campaign_deployment_path(
    explicit: Option<&Path>,
) -> Result<PathBuf, CliError> {
    let environment = std::env::var_os(CAMPAIGN_DEPLOYMENT_ENV);
    resolve_campaign_deployment_path(explicit, environment.as_deref(), |path| path.is_file())
}

fn resolve_campaign_deployment_path(
    explicit: Option<&Path>,
    environment: Option<&std::ffi::OsStr>,
    default_exists: impl FnOnce(&Path) -> bool,
) -> Result<PathBuf, CliError> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if let Some(value) = environment {
        if value.is_empty() {
            return Err(serve_error(format!(
                "{CAMPAIGN_DEPLOYMENT_ENV} is empty; set it to an owner-only packaged-executor deployment file",
            )));
        }
        return Ok(PathBuf::from(value));
    }

    let default = Path::new(DEFAULT_CAMPAIGN_DEPLOYMENT_PATH);
    if default_exists(default) {
        return Ok(default.to_path_buf());
    }
    Err(serve_error(format!(
        "local QEMU execution requires guarded campaign host authority; pass --campaign-deployment PATH, set {CAMPAIGN_DEPLOYMENT_ENV}, or provision {DEFAULT_CAMPAIGN_DEPLOYMENT_PATH}",
    )))
}

/// Loads the exact process and storage ceilings for a guarded legacy run.
///
/// The deployment uses the same strict schema, ownership, cgroup, and project
/// quota policy as the packaged executor. The returned host config still opens
/// and authenticates both kernel resource namespaces before guest launch.
///
/// # Errors
///
/// Returns [`CliError`] when the deployment file or its resource policy is
/// malformed, mutable by another user, or outside the supported bounds.
pub(crate) fn load_guarded_campaign_run_deployment(
    path: &Path,
) -> Result<GuardedCampaignRunDeployment, CliError> {
    let deployment = load_validated_deployment(path)?;
    if deployment.host_architecture != std::env::consts::ARCH {
        return Err(serve_error(format!(
            "campaign deployment host architecture `{}` does not match this `{}` host",
            deployment.host_architecture,
            std::env::consts::ARCH,
        )));
    }
    if deployment.qemu_profile != GUARDED_RUN_QEMU_PROFILE {
        return Err(serve_error(format!(
            "campaign deployment QEMU profile `{}` is unsupported; guarded run requires `{GUARDED_RUN_QEMU_PROFILE}`",
            deployment.qemu_profile,
        )));
    }
    // Worker and checkpoint fields remain part of the shared, strictly
    // validated schema, although this ephemeral path owns one synchronous slot
    // and does not publish checkpoints.
    let host = deployment_host(&deployment)?;
    let capacity = deployment_capacity(&deployment)?;
    let resources = crucible_campaign::AttemptResourceLimits::new(
        capacity.maximum_vcpus(),
        capacity.maximum_resident_bytes(),
        capacity.maximum_disk_bytes(),
        capacity.maximum_execution_quanta(),
    )
    .map_err(|error| serve_error(format!("campaign executor resource limits error: {error}")))?;

    Ok(GuardedCampaignRunDeployment { host, resources })
}

pub(super) fn prepare_cli_packaged_executor(
    prepared: &crucible_daemon::PreparedCampaignLocalService,
    args: &ServeArgs,
    campaigns: std::collections::BTreeSet<crucible_campaign::CampaignName>,
    executor_socket: &Path,
    deployment_path: &Path,
    lifecycle: &crucible_api::ProductionVmLifecycleConfig,
) -> Result<crucible_daemon::AttachedPackagedQemuExecutor, CliError> {
    let deployment = load_validated_deployment(deployment_path)?;
    let host = deployment_host(&deployment)?;
    let capacity = deployment_capacity(&deployment)?;
    let user_id = rustix::process::geteuid().as_raw();
    let group_id = rustix::process::getegid().as_raw();
    let endpoint = crucible_daemon::ExecutorLoopbackEndpointConfig::new(
        executor_socket,
        user_id,
        group_id,
        0o600,
    )
    .map_err(|error| serve_error(format!("campaign executor endpoint error: {error}")))?;
    let state = args
        .campaign_state
        .as_ref()
        .ok_or_else(|| serve_error("campaign packaged executor has no state directory"))?;
    let store_namespace = packaged_store_namespace(state);
    let daemon_epoch = fresh_daemon_epoch()?;
    let hot_fork = deployment_hot_fork_policy(&deployment, lifecycle)?;
    let mut config = crucible_daemon::PackagedQemuExecutorConfig::new(
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
    if let Some(hot_fork) = hot_fork {
        config = config.with_hot_fork_sources(hot_fork);
    }
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

fn deployment_hot_fork_policy(
    deployment: &PackagedExecutorDeployment,
    lifecycle: &crucible_api::ProductionVmLifecycleConfig,
) -> Result<Option<crucible_daemon::PackagedQemuHotForkConfig>, CliError> {
    let Some(policy) = deployment.hot_fork.as_ref() else {
        return Ok(None);
    };
    let maximum_resources = crucible_daemon::HotCheckpointResourceProfile::new(
        policy.maximum_template_bytes,
        policy.maximum_expected_private_dirty_bytes,
        policy.maximum_processes,
        policy.maximum_virtual_cpus,
        policy.maximum_descriptors,
        policy.maximum_overlays,
    )
    .map_err(|error| serve_error(format!("campaign hot-fork resource policy error: {error}")))?;
    let fork_rate_window_nanos = policy
        .fork_rate_window_ms
        .checked_mul(1_000_000)
        .ok_or_else(|| serve_error("campaign hot-fork rate window overflows nanoseconds"))?;
    let limits = crucible_daemon::HotCheckpointLimits::new(
        policy.maximum_templates,
        maximum_resources,
        policy.maximum_forks_per_window,
        fork_rate_window_nanos,
    )
    .map_err(|error| serve_error(format!("campaign hot-fork limit policy error: {error}")))?;
    let shutdown_wait =
        deployment_timeout("hot-fork shutdown step", policy.shutdown_step_timeout_ms)?;
    let host_io_timeout = deployment_timeout("hot-fork host I/O", policy.host_io_timeout_ms)?;
    let hot_fork = crucible_daemon::PackagedQemuHotForkConfig::authenticate(
        lifecycle,
        limits,
        crucible_daemon::HotCheckpointHotnessSignals::new(),
        shutdown_wait,
        host_io_timeout,
    )
    .map_err(|error| serve_error(format!("campaign hot-fork policy error: {error}")))?;

    Ok(Some(hot_fork))
}

fn deployment_timeout(role: &str, milliseconds: u64) -> Result<Duration, CliError> {
    let timeout = Duration::from_millis(milliseconds);
    if timeout.is_zero() || timeout > Duration::from_secs(60 * 60) {
        return Err(serve_error(format!(
            "campaign {role} timeout is outside 1ms..=1h"
        )));
    }
    Ok(timeout)
}

fn load_validated_deployment(path: &Path) -> Result<PackagedExecutorDeployment, CliError> {
    let deployment = load_deployment(path)?;
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
    if deployment.maximum_checkpoint_bytes == 0 {
        return Err(serve_error(
            "campaign packaged-executor checkpoint byte ceiling is zero",
        ));
    }
    if deployment.worker_count == 0
        || deployment.worker_count > usize::try_from(deployment.maximum_slots).unwrap_or(usize::MAX)
    {
        return Err(serve_error(
            "campaign packaged-executor worker count is outside its slot ceiling",
        ));
    }
    let finish_timeout = Duration::from_millis(deployment.finish_timeout_ms);
    if finish_timeout.is_zero() || finish_timeout > Duration::from_secs(60 * 60) {
        return Err(serve_error(
            "campaign packaged-executor finish timeout is outside 1ms..=1h",
        ));
    }

    Ok(deployment)
}

fn deployment_host(
    deployment: &PackagedExecutorDeployment,
) -> Result<crucible_daemon::LinuxQemuAttemptHostConfig, CliError> {
    let finish_timeout = Duration::from_millis(deployment.finish_timeout_ms);
    crucible_daemon::LinuxQemuAttemptHostConfig::new(
        deployment.cgroup_root.clone(),
        deployment.run_root.clone(),
        deployment.attempt_namespace.clone(),
        deployment.first_project_id,
        deployment.project_id_count,
        deployment.child_user_id,
        deployment.child_group_id,
        deployment.maximum_tasks,
        deployment.maximum_inodes,
        finish_timeout,
    )
    .map_err(|error| serve_error(format!("campaign executor host policy error: {error}")))
}

fn deployment_capacity(
    deployment: &PackagedExecutorDeployment,
) -> Result<crucible_daemon::ExecutorCapacity, CliError> {
    crucible_daemon::ExecutorCapacity::new(
        deployment.maximum_slots,
        deployment.maximum_vcpus,
        deployment.maximum_resident_bytes,
        deployment.maximum_disk_bytes,
        deployment.maximum_execution_quanta,
    )
    .map_err(|error| serve_error(format!("campaign executor capacity error: {error}")))
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
        .replace(
            "host_architecture = \"x86_64\"",
            &format!("host_architecture = \"{}\"", std::env::consts::ARCH),
        )
    }

    fn authored_hot_fork() -> String {
        format!(
            "{}\n[hot_fork]\n\
             maximum_templates = 2\n\
             maximum_template_bytes = 1073741824\n\
             maximum_expected_private_dirty_bytes = 536870912\n\
             maximum_processes = 8\n\
             maximum_virtual_cpus = 8\n\
             maximum_descriptors = 4096\n\
             maximum_overlays = 16\n\
             maximum_forks_per_window = 8\n\
             fork_rate_window_ms = 1000\n\
             shutdown_step_timeout_ms = 1000\n\
             host_io_timeout_ms = 30000\n",
            authored()
        )
    }

    fn hot_fork_artifacts(directory: &Path) -> crucible_api::ProductionVmLifecycleConfig {
        let qemu = directory.join("bin/qemu-system-x86_64");
        let plugin = directory.join("lib/libcrucible-qemu-plugin.so");
        let qemu_marker = directory.join("share/aos/crucible/qemu-build-identity.env");
        let plugin_marker = directory.join("nix-support/crucible-qemu-plugin-build-info");
        for path in [&qemu, &plugin, &qemu_marker, &plugin_marker] {
            fs::create_dir_all(path.parent().expect("artifact parent"))
                .expect("create artifact parent");
        }
        fs::write(&qemu, b"qemu").expect("write QEMU artifact");
        fs::write(&plugin, b"plugin").expect("write plugin artifact");
        let abi_version = crucible::SHMEM_ABI_VERSION;
        let abi = format!("crucible-shmem-abi-v{abi_version}");
        fs::write(
            qemu_marker,
            format!(
                "qemu_sim_capability=qemu-crucible\n\
                 qemu_crucible_patches_applied=true\n\
                 qemu_plugins_enabled=true\n\
                 qemu_build_id=qemu-build-v1\n\
                 qemu_patch_series_hash=sha256:patch\n\
                 qemu_shmem_abi_version={abi_version}\n\
                 qemu_shmem_abi={abi}\n\
                 qemu_shmem_header=include/aos/crucible/crucible_shmem_abi.h\n\
                 qemu_shmem_header_hash=sha256:header\n"
            ),
        )
        .expect("write QEMU marker");
        fs::write(
            plugin_marker,
            format!(
                "plugin_abi={abi}\n\
                 qemu_build_id=qemu-build-v1\n\
                 shmem_abi_version={abi_version}\n\
                 shmem_abi={abi}\n\
                 shmem_generated_header_hash=sha256:header\n"
            ),
        )
        .expect("write plugin marker");
        crucible_api::ProductionVmLifecycleConfig::new(
            &qemu,
            &plugin,
            directory.join("kernel"),
            directory.join("root"),
            directory.join("run-state"),
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
        let guarded =
            load_guarded_campaign_run_deployment(&path).expect("load guarded run deployment");
        assert_eq!(guarded.resources.maximum_vcpus(), 4);
        assert_eq!(guarded.resources.maximum_disk_bytes(), 2_147_483_648);

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("weaken deployment mode");
        assert!(load_deployment(&path).is_err());
    }

    #[test]
    fn packaged_hot_fork_policy_authenticates_artifacts_and_explicit_limits() {
        let directory = tempfile::tempdir().expect("hot-fork deployment directory");
        let path = directory.path().join("executor.toml");
        fs::write(&path, authored_hot_fork()).expect("write hot-fork deployment");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("secure hot-fork deployment");
        let deployment = load_validated_deployment(&path).expect("load hot-fork deployment");
        let lifecycle = hot_fork_artifacts(directory.path());

        let policy = deployment_hot_fork_policy(&deployment, &lifecycle)
            .expect("authenticate hot-fork policy")
            .expect("hot-fork policy present");

        assert_eq!(policy.limits().maximum_templates(), 2);
        assert_eq!(policy.limits().maximum_forks_per_window(), 8);
        assert_eq!(policy.limits().fork_rate_window_nanos(), 1_000_000_000);
    }

    #[test]
    fn guarded_campaign_run_rejects_an_unsupported_qemu_profile() {
        let directory = tempfile::tempdir().expect("deployment directory");
        let path = directory.path().join("executor.toml");
        let deployment = authored().replace(
            "qemu_profile = \"deterministic-tcg-v1\"",
            "qemu_profile = \"nondeterministic-host-v1\"",
        );
        fs::write(&path, deployment).expect("write deployment");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure deployment");

        let error = load_guarded_campaign_run_deployment(&path)
            .err()
            .expect("unsupported guarded QEMU profile");
        assert!(
            error
                .to_string()
                .contains("QEMU profile `nondeterministic-host-v1` is unsupported")
        );
    }

    #[test]
    fn guarded_campaign_run_rejects_a_mismatched_host_architecture() {
        let directory = tempfile::tempdir().expect("deployment directory");
        let path = directory.path().join("executor.toml");
        let deployment = authored().replace(
            &format!("host_architecture = \"{}\"", std::env::consts::ARCH),
            "host_architecture = \"incompatible-test-host\"",
        );
        fs::write(&path, deployment).expect("write deployment");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure deployment");

        let error = load_guarded_campaign_run_deployment(&path)
            .err()
            .expect("mismatched guarded host architecture");
        assert!(
            error
                .to_string()
                .contains("host architecture `incompatible-test-host` does not match")
        );
    }

    #[test]
    fn campaign_deployment_resolution_has_explicit_environment_and_system_precedence() {
        let explicit = Path::new("/explicit/campaign.toml");
        let environment = std::ffi::OsStr::new("/environment/campaign.toml");
        assert_eq!(
            resolve_campaign_deployment_path(Some(explicit), Some(environment), |_| true)
                .expect("explicit deployment"),
            explicit
        );
        assert_eq!(
            resolve_campaign_deployment_path(None, Some(environment), |_| true)
                .expect("environment deployment"),
            Path::new("/environment/campaign.toml")
        );
        assert_eq!(
            resolve_campaign_deployment_path(None, None, |_| true).expect("system deployment"),
            Path::new(DEFAULT_CAMPAIGN_DEPLOYMENT_PATH)
        );

        let missing = resolve_campaign_deployment_path(None, None, |_| false)
            .expect_err("missing host authority");
        assert!(missing.to_string().contains("--campaign-deployment PATH"));
        assert!(missing.to_string().contains(CAMPAIGN_DEPLOYMENT_ENV));
        assert!(
            missing
                .to_string()
                .contains(DEFAULT_CAMPAIGN_DEPLOYMENT_PATH)
        );
        assert!(
            resolve_campaign_deployment_path(None, Some(std::ffi::OsStr::new("")), |_| true,)
                .is_err()
        );
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
