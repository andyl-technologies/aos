//! Runs the root-only, systemd-activated Storage repair and inventory broker.
//!
//! Deployment supplies an existing protected authority directory, immutable
//! bootstrap publication, durable state root, finite subordinate-identity
//! pool, and exact AOS OpenZFS executable. This process never manufactures
//! trust keys, genesis state, or dataset ownership.

use std::env;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_storage::activation::take_systemd_listener;
use aos_sandbox_storage::peer::ControllerPeerVerifier;
use aos_sandbox_storage::{
    StorageBrokerRuntime, StorageIdentityPoolV1, StorageRuntimeError, StorageService,
    StorageServiceError, SystemdZfsExecutor,
};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const STATE_ROOT: &str = "/var/lib/aos/sandbox-storage";
const ZFS_WORKER_SOCKET: &str = "/run/aos/sandbox-zfs-worker/control.sock";
const CONTROLLER_CGROUP: &str = "aos.slice/aos-control.slice/aos-sandboxd.service";

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

    // Descriptor 3 must be duplicated before another operation can reuse it.
    let mut listener = take_systemd_listener()?;
    let controller_cgroup = open_controller_cgroup()?;
    let verifier = ControllerPeerVerifier::new(controller_cgroup, arguments.controller_identity)?;
    let identity_pool =
        StorageIdentityPoolV1::new(arguments.identity_pool_start, arguments.identity_pool_size)
            .map_err(StorageRuntimeError::WorkspaceCatalog)?;
    let executor = SystemdZfsExecutor::new(PathBuf::from(ZFS_WORKER_SOCKET), open_cgroup_root()?)
        .map_err(StorageRuntimeError::Worker)?;
    let runtime = StorageBrokerRuntime::open_root_owned(
        &arguments.authority_directory,
        &arguments.bootstrap_directory,
        Path::new(STATE_ROOT),
        identity_pool,
        arguments.zfs_executable,
        executor,
    )?;
    let mut service = StorageService::new(runtime, verifier);

    loop {
        service.serve_once(&mut listener)?;
    }
}

struct Arguments {
    controller_identity: (u32, u32),
    identity_pool_start: u32,
    identity_pool_size: u32,
    zfs_executable: PathBuf,
    authority_directory: PathBuf,
    bootstrap_directory: PathBuf,
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

fn usage_error() -> StorageServiceError {
    StorageServiceError::Activation(
        "usage: aos-storaged CONTROLLER_UID CONTROLLER_GID IDENTITY_START IDENTITY_SIZE ZFS_PATH AUTHORITY_DIRECTORY BOOTSTRAP_DIRECTORY"
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

fn open_controller_cgroup() -> Result<RetainedCgroupAnchor, StorageServiceError> {
    open_cgroup_root()?
        .resolve(production_controller_cgroup())
        .map_err(Into::into)
}

fn production_controller_cgroup() -> &'static Path {
    Path::new(CONTROLLER_CGROUP)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_profile_selects_only_the_nested_controller_service() {
        let selected = production_controller_cgroup();

        assert_eq!(
            selected,
            Path::new("aos.slice/aos-control.slice/aos-sandboxd.service")
        );
        assert_ne!(
            selected,
            Path::new("aos-control.slice/aos-sandboxd.service")
        );
        assert_ne!(selected, Path::new("aos.slice/aos-sandboxd.service"));
    }

    #[test]
    fn controller_identity_is_strictly_unprivileged_and_bounded() {
        for value in ["1", "65535"] {
            assert_eq!(
                parse_controller_identity(Some(value.into()), "controller UID").unwrap(),
                value.parse::<u32>().unwrap()
            );
        }
        for value in ["0", "65536", "4294967295"] {
            assert!(
                parse_controller_identity(Some(value.into()), "controller UID").is_err(),
                "accepted {value}"
            );
        }
    }
}
