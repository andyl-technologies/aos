//! Runs the root-only, systemd-activated sandbox host broker.
//!
//! PID 1 supplies the sole sequence-packet socket and private state/catalog
//! directories. The executable accepts only the node-controller numeric
//! identity and the immutable AOS `systemd-nspawn` store path selected by its
//! system unit.

use std::env;
use std::os::fd::OwnedFd;
use std::process::ExitCode;

use aos_sandbox_host::activation::take_systemd_listener;
use aos_sandbox_host::broker::HostBroker;
use aos_sandbox_host::catalog::FileHostCatalog;
use aos_sandbox_host::peer::ControllerPeerVerifier;
use aos_sandbox_host::service::HostService;
use aos_sandbox_host::state::FileHostStateStore;
use aos_sandbox_host::worker::SystemdOneShotWorker;
use aos_sandbox_host::{HostError, Result};
use aos_sandbox_linux::path::BeneathRoot;

const CATALOG_ROOT: &str = "/run/aos/sandbox-host";
const STATE_ROOT: &str = "/var/lib/aos/sandbox-host";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-hostd: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(HostError::State(
            "host broker must start with real and effective UID zero".to_owned(),
        ));
    }
    let (controller_identity, discarded_nspawn_executable) = arguments()?;
    drop(discarded_nspawn_executable);

    // Adopt FD 3 before Tokio or another dependency can create a thread.
    let listener = take_systemd_listener()?;
    let catalog = FileHostCatalog::open_root_owned(CATALOG_ROOT)?;
    let state = FileHostStateStore::open(STATE_ROOT)?;
    let worker = SystemdOneShotWorker::new(open_cgroup_root()?);
    let verifier = ControllerPeerVerifier::new(open_cgroup_root()?);
    // Launch remains unavailable until the phase-0 evidence publisher can
    // construct an opaque BackendReadiness token bound to the configured
    // executable. The argv value above is intentionally discarded rather than
    // being treated as evidence that an arbitrary path is safe to launch.
    let broker = HostBroker::open(catalog, state, worker, None)?;
    let mut service = HostService::new(broker, verifier, controller_identity);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| HostError::State(error.to_string()))?;
    runtime.block_on(async move {
        loop {
            service.serve_once(&listener).await?;
        }
    })
}

fn arguments() -> Result<((u32, u32), String)> {
    let mut arguments = env::args();
    let _program = arguments.next();
    let uid = parse_identity(arguments.next(), "controller UID")?;
    let gid = parse_identity(arguments.next(), "controller GID")?;
    let nspawn = arguments
        .next()
        .ok_or_else(|| HostError::State("systemd-nspawn path is absent".to_owned()))?;
    if arguments.next().is_some() {
        return Err(HostError::State(
            "usage: aos-sandbox-hostd CONTROLLER_UID CONTROLLER_GID NSPAWN_PATH".to_owned(),
        ));
    }
    Ok(((uid, gid), nspawn))
}

fn parse_identity(value: Option<String>, label: &str) -> Result<u32> {
    let value = value.ok_or_else(|| HostError::State(format!("{label} is absent")))?;
    value
        .parse()
        .map_err(|_| HostError::State(format!("{label} is not a decimal u32")))
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
    .map_err(|error| HostError::State(error.to_string()))?;
    BeneathRoot::from_owned(descriptor).map_err(|error| HostError::State(error.to_string()))
}
