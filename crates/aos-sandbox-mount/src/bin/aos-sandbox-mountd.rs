//! Runs the root-only, systemd-activated sandbox mount broker.

use std::collections::BTreeSet;
use std::env;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;
use std::process::ExitCode;

use aos_sandbox::journal::{Journal, JournalLimits};
use aos_sandbox_linux::path::BeneathRoot;
use aos_sandbox_mount::broker::MountBroker;
use aos_sandbox_mount::catalog::FileMountCatalog;
use aos_sandbox_mount::helper::PosixSpawnNamespaceHelper;
use aos_sandbox_mount::keeper::SystemdFdStore;
use aos_sandbox_mount::peer::ControllerPeerVerifier;
use aos_sandbox_mount::service::MountService;
use aos_sandbox_mount::transport::ActivatedSeqpacketListener;
use aos_sandbox_mount::worker::DescriptorMountWorker;
use aos_sandbox_mount::{MountError, Result};

const EXPECTED_FD_NAME: &str = "aos-sandbox-mount";
const MAXIMUM_RETAINED_MOUNTS: usize = 1_024;
const CATALOG_ROOT: &str = "/run/aos/sandbox-mount-catalog";
const STATE_ROOT: &str = "/var/lib/aos/sandbox-mount";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-mountd: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(MountError::State(
            "mount broker must start with real and effective UID zero".to_owned(),
        ));
    }
    let activation =
        SystemdFdStore::adopt_service_activation(EXPECTED_FD_NAME, MAXIMUM_RETAINED_MOUNTS)?;
    let retained_names: BTreeSet<_> = activation.mounts.keys().cloned().collect();
    let listener = ActivatedSeqpacketListener::from_owned(activation.listener)?;
    let keeper =
        SystemdFdStore::from_environment_with_inventory(retained_names, MAXIMUM_RETAINED_MOUNTS)?;
    let (controller_identity, helper_executable) = arguments()?;
    validate_private_root(Path::new(STATE_ROOT))?;
    let (journal, _) = Journal::open(
        Path::new(STATE_ROOT).join("mount.journal"),
        JournalLimits::default(),
    )?;
    let catalog = FileMountCatalog::open_root_owned(CATALOG_ROOT)?;
    let helper = PosixSpawnNamespaceHelper::new(helper_executable)?;
    let worker = DescriptorMountWorker::new(catalog, helper, keeper, activation.mounts)?;
    let broker = MountBroker::new(journal, worker)?;
    let verifier = ControllerPeerVerifier::new(open_cgroup_root()?);
    let mut service = MountService::new(broker, verifier, controller_identity);
    loop {
        service.serve_once(&listener)?;
    }
}

fn arguments() -> Result<((u32, u32), String)> {
    let mut arguments = env::args();
    let _program = arguments.next();
    let uid = parse_identity(arguments.next(), "controller UID")?;
    let gid = parse_identity(arguments.next(), "controller GID")?;
    let helper = arguments
        .next()
        .ok_or_else(|| MountError::State("mount helper path is absent".to_owned()))?;
    if arguments.next().is_some() {
        return Err(MountError::State(
            "usage: aos-sandbox-mountd CONTROLLER_UID CONTROLLER_GID HELPER_PATH".to_owned(),
        ));
    }
    Ok(((uid, gid), helper))
}

fn parse_identity(value: Option<String>, label: &str) -> Result<u32> {
    value
        .ok_or_else(|| MountError::State(format!("{label} is absent")))?
        .parse()
        .map_err(|_| MountError::State(format!("{label} is not a decimal u32")))
}

fn validate_private_root(path: &Path) -> Result<()> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| MountError::State(error.to_string()))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(MountError::State(
            "mount state root must be a private root-owned real directory".to_owned(),
        ));
    }
    Ok(())
}

fn open_cgroup_root() -> Result<BeneathRoot> {
    let descriptor: OwnedFd = rustix::fs::open(
        CGROUP_ROOT,
        rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| MountError::State(error.to_string()))?;
    BeneathRoot::from_owned(descriptor).map_err(|error| MountError::State(error.to_string()))
}
