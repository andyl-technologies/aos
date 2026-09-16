//! Runs the authenticated, systemd-activated Storage broker.
//!
//! The daemon claims its exact listener before opening protected Storage state.
//! Each connection completes one authenticated, durable, bounded request cycle.

use std::env;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use aos_sandbox_broker_session_security::{
    ProductionBrokerSessionActivationErrorV1, ProductionBrokerSessionActivationV1,
    production_deadline_after,
};
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_storage::{
    DormantStorageApplyCompositionV1, StorageIdentityPoolV1, StoragePrepareReadiness,
    StorageRuntimeError, StorageServiceError, SystemdZfsExecutor,
};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const STATE_ROOT: &str = "/var/lib/aos/sandbox-storage";
const ZFS_WORKER_SOCKET: &str = "/run/aos/sandbox-zfs-worker/control.sock";
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(45);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-storaged: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), StorageServiceError> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(StorageServiceError::Activation(
            "broker must start with real and effective UID zero".to_owned(),
        ));
    }
    let arguments = arguments()?;

    // SAFETY: this is the single-threaded entrypoint before any other
    // descriptor operation. PID 1 exclusively transfers the fixed FD 3.
    let mut activation = unsafe { ProductionBrokerSessionActivationV1::adopt_storage() }
        .map_err(production_error)?;
    let identity_pool =
        StorageIdentityPoolV1::new(arguments.identity_pool_start, arguments.identity_pool_size)
            .map_err(StorageRuntimeError::WorkspaceCatalog)?;
    let executor = SystemdZfsExecutor::new(PathBuf::from(ZFS_WORKER_SOCKET), open_cgroup_root()?)
        .map_err(StorageRuntimeError::Worker)?;
    let mut storage = DormantStorageApplyCompositionV1::open_root_owned(
        &arguments.authority_directory,
        &arguments.bootstrap_directory,
        Path::new(STATE_ROOT),
        arguments.resolver_policy_directory.as_deref(),
        identity_pool,
        arguments.zfs_executable,
        executor,
    )?;
    if let Some(diagnostic) = prepare_readiness_diagnostic(storage.runtime().prepare_readiness()) {
        eprintln!("aos-storaged: {diagnostic}");
    }

    loop {
        let accept_deadline = production_deadline_after(ACCEPT_TIMEOUT)
            .map_err(|error| StorageServiceError::Activation(error.to_string()))?;
        let session = match activation.accept_authenticated(accept_deadline) {
            Ok(session) => session,
            Err(ProductionBrokerSessionActivationErrorV1::Deadline) => continue,
            Err(error) => return Err(production_error(error)),
        };
        let request_deadline = production_deadline_after(REQUEST_TIMEOUT)
            .map_err(|error| StorageServiceError::Activation(error.to_string()))?;
        if let Err(error) = session.serve_production_storage_request(&mut storage, request_deadline)
        {
            // The session was consumed. The next accepted connection reopens
            // and validates its fixed protected broker-session journal.
            eprintln!("aos-storaged: authenticated request failed: {error}");
        }
    }
}

fn production_error(error: ProductionBrokerSessionActivationErrorV1) -> StorageServiceError {
    StorageServiceError::Activation(error.to_string())
}

fn prepare_readiness_diagnostic(readiness: StoragePrepareReadiness) -> Option<&'static str> {
    match readiness {
        StoragePrepareReadiness::Unconfigured => {
            Some("Storage Prepare disabled: resolver policy is unconfigured")
        }
        StoragePrepareReadiness::PolicyInvalid => {
            Some("Storage Prepare disabled: resolver policy is invalid")
        }
        StoragePrepareReadiness::Ready => None,
    }
}

struct Arguments {
    #[allow(dead_code, reason = "retained for stable daemon CLI compatibility")]
    controller_identity: (u32, u32),
    identity_pool_start: u32,
    identity_pool_size: u32,
    zfs_executable: PathBuf,
    authority_directory: PathBuf,
    bootstrap_directory: PathBuf,
    resolver_policy_directory: Option<PathBuf>,
}

fn arguments() -> Result<Arguments, StorageServiceError> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let controller_uid = parse_controller_identity(arguments.next(), "controller UID")?;
    let controller_gid = parse_controller_identity(arguments.next(), "controller GID")?;
    let identity_pool_start = parse_u32(arguments.next(), "identity-pool start")?;
    let identity_pool_size = parse_u32(arguments.next(), "identity-pool size")?;
    let zfs_executable = required_path(arguments.next(), "ZFS executable")?;
    let authority_directory = required_path(arguments.next(), "authority directory")?;
    let bootstrap_directory = required_path(arguments.next(), "bootstrap directory")?;
    let resolver_policy_directory = optional_path(arguments.next(), "resolver policy directory")?;
    if arguments.next().is_some() {
        return Err(usage_error());
    }

    Ok(Arguments {
        controller_identity: (controller_uid, controller_gid),
        identity_pool_start,
        identity_pool_size,
        zfs_executable,
        authority_directory,
        bootstrap_directory,
        resolver_policy_directory,
    })
}

fn parse_controller_identity(
    value: Option<std::ffi::OsString>,
    label: &str,
) -> Result<u32, StorageServiceError> {
    let identity = parse_u32(value, label)?;
    if !(1..65_536).contains(&identity) {
        return Err(StorageServiceError::Activation(format!(
            "{label} must be in 1..65535"
        )));
    }

    Ok(identity)
}

fn parse_u32(value: Option<std::ffi::OsString>, label: &str) -> Result<u32, StorageServiceError> {
    value
        .and_then(|value| value.into_string().ok())
        .ok_or_else(usage_error)?
        .parse()
        .map_err(|_| StorageServiceError::Activation(format!("{label} is not a decimal u32")))
}

fn required_path(
    value: Option<std::ffi::OsString>,
    label: &str,
) -> Result<PathBuf, StorageServiceError> {
    let path = value.map(PathBuf::from).ok_or_else(usage_error)?;
    if !path.is_absolute() {
        return Err(StorageServiceError::Activation(format!(
            "{label} is not absolute"
        )));
    }

    Ok(path)
}

fn optional_path(
    value: Option<std::ffi::OsString>,
    label: &str,
) -> Result<Option<PathBuf>, StorageServiceError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value == "-" {
        return Ok(None);
    }
    required_path(Some(value), label).map(Some)
}

fn usage_error() -> StorageServiceError {
    StorageServiceError::Activation(
        "usage: aos-storaged CONTROLLER_UID CONTROLLER_GID IDENTITY_START IDENTITY_SIZE ZFS_PATH AUTHORITY_DIRECTORY BOOTSTRAP_DIRECTORY [RESOLVER_POLICY_DIRECTORY|-]"
            .to_owned(),
    )
}

fn open_cgroup_root() -> Result<CgroupV2Root, StorageServiceError> {
    let descriptor: OwnedFd = rustix::fs::open(
        CGROUP_ROOT,
        rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    CgroupV2Root::from_owned(descriptor).map_err(Into::into)
}
