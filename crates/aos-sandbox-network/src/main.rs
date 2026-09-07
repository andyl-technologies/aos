//! Runs the root-only, systemd-activated AOS Network inventory broker.
//!
//! The executable opens the protected namespace journal and fixed namespace-pin
//! root before serving Network 1.2 inventory. Apply is not advertised and this
//! process holds no network-administration capability in the current deployment.

use std::env;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::process::ExitCode;

use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_network::activation::take_systemd_listener;
use aos_sandbox_network::{
    NetworkInventoryService, NetworkNamespaceCatalogV1, NetworkServiceError,
};

const STATE_ROOT: &str = "/var/lib/aos/sandbox-network";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CONTROLLER_CGROUP: &str = "aos-control.slice/aos-sandboxd.service";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-netd: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), NetworkServiceError> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(NetworkServiceError::Activation(
            "broker must start with real and effective UID zero".to_owned(),
        ));
    }
    let controller_identity = arguments()?;

    // Descriptor 3 must be adopted before another operation can allocate it.
    let mut listener = take_systemd_listener()?;
    let controller_cgroup = open_controller_cgroup()?;
    let catalog = NetworkNamespaceCatalogV1::open_root_owned(Path::new(STATE_ROOT))?;
    let mut service =
        NetworkInventoryService::new(catalog, controller_cgroup, controller_identity)?;

    loop {
        service.serve_once(&mut listener)?;
    }
}

fn arguments() -> Result<(u32, u32), NetworkServiceError> {
    let mut arguments = env::args();
    let _program = arguments.next();
    let uid = parse_identity(arguments.next(), "controller UID")?;
    let gid = parse_identity(arguments.next(), "controller GID")?;
    if arguments.next().is_some() {
        return Err(NetworkServiceError::Activation(
            "usage: aos-netd CONTROLLER_UID CONTROLLER_GID".to_owned(),
        ));
    }

    Ok((uid, gid))
}

fn parse_identity(value: Option<String>, label: &str) -> Result<u32, NetworkServiceError> {
    value
        .ok_or_else(|| NetworkServiceError::Activation(format!("{label} is absent")))?
        .parse()
        .map_err(|_| NetworkServiceError::Activation(format!("{label} is not a decimal u32")))
}

fn open_controller_cgroup() -> Result<RetainedCgroupAnchor, NetworkServiceError> {
    let descriptor: OwnedFd = rustix::fs::open(
        CGROUP_ROOT,
        rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let root = CgroupV2Root::from_owned(descriptor)?;

    root.resolve(Path::new(CONTROLLER_CGROUP))
        .map_err(Into::into)
}
