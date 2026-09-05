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
use aos_sandbox_host::authorization::HostAuthorityV1;
use aos_sandbox_host::broker::HostBroker;
use aos_sandbox_host::catalog::FileHostCatalog;
use aos_sandbox_host::peer::ControllerPeerVerifier;
use aos_sandbox_host::plan::{BackendReadinessBlocker, ProtectedBackendReadinessEvidence};
use aos_sandbox_host::service::HostService;
use aos_sandbox_host::state::FileHostStateStore;
use aos_sandbox_host::worker::{PidfdNamespaceAccessProbe, SystemdOneShotWorker};
use aos_sandbox_host::{HostError, Result};
use aos_sandbox_linux::cgroup::CgroupV2Root;
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
    let (controller_identity, nspawn_executable) = arguments()?;

    // Adopt FD 3 before another dependency can allocate descriptors or create
    // a thread.
    let listener = take_systemd_listener()?;
    // This is intentionally non-authorizing. It exercises pidfs from inside
    // the deployed service sandbox, while shifted-payload ptrace access remains
    // an explicit readiness blocker. Observation stays available on failure.
    let _pidfd_namespace_probe = match PidfdNamespaceAccessProbe::current_service() {
        Ok(probe) => Some(probe),
        Err(error) => {
            eprintln!("aos-sandbox-hostd: pidfd namespace self-probe unavailable: {error}");
            None
        }
    };

    let catalog = FileHostCatalog::open_root_owned(CATALOG_ROOT)?;
    let state = FileHostStateStore::open(STATE_ROOT)?;
    let credential_directory = env::var_os("CREDENTIALS_DIRECTORY").ok_or_else(|| {
        HostError::State("systemd authority credential directory is absent".to_owned())
    })?;
    let authority = HostAuthorityV1::from_protected_directory(&credential_directory)
        .map_err(|error| HostError::State(error.to_string()))?;
    let readiness = ProtectedBackendReadinessEvidence::load_protected_optional(
        &credential_directory,
        STATE_ROOT,
        &nspawn_executable,
    )?;
    if let Some(readiness) = readiness {
        let blockers = readiness.runtime_blockers();
        if blockers
            != [
                BackendReadinessBlocker::Phase0ClaimVerification,
                BackendReadinessBlocker::ShiftedPayloadPidfdNamespaceInspection,
                BackendReadinessBlocker::PayloadRootPolicyDeploymentVerification,
            ]
        {
            return Err(HostError::State(
                "host backend readiness boundary changed without launch wiring".to_owned(),
            ));
        }
        drop(readiness);
    }
    let worker = SystemdOneShotWorker::new(open_cgroup_root()?);
    let verifier = ControllerPeerVerifier::new(
        CgroupV2Root::try_from(open_cgroup_root()?)
            .map_err(|error| HostError::State(error.to_string()))?,
    );
    // Any present phase-0 artifact is protected, boot-bound, and
    // rollback-protected above. Its declared digests are not yet independently
    // verified, and the self-probe above does not prove ptrace access to a
    // shifted payload, so it cannot be promoted into BackendReadiness and
    // Apply remains unadvertised.
    let broker = HostBroker::open(catalog, state, worker, None, authority)?;
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
