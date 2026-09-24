//! Runs the root-only, systemd-activated sandbox host broker.
//!
//! PID 1 supplies the sole sequence-packet socket and private state/catalog
//! directories. The executable accepts only the node-controller numeric
//! identity plus the immutable AOS `systemd-nspawn`, Guardian, and SELinux
//! production-policy store paths selected by its system unit.

use std::env;
use std::os::fd::OwnedFd;
use std::process::ExitCode;

use aos_sandbox_host::activation::take_systemd_listeners;
use aos_sandbox_host::authorization::HostAuthorityV1;
use aos_sandbox_host::broker::HostBroker;
use aos_sandbox_host::catalog::{FileHostCatalog, FileHostCatalogPublisher};
use aos_sandbox_host::peer::ControllerPeerVerifier;
use aos_sandbox_host::plan::{GuardianConfig, verify_optional_backend_deployment_v1};
use aos_sandbox_host::service::{HostListenerRole, HostService};
use aos_sandbox_host::state::FileHostStateStore;
use aos_sandbox_host::worker::{PidfdNamespaceAccessProbe, SystemdOneShotWorker};
use aos_sandbox_host::{HostError, Result};
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::path::BeneathRoot;
use rustix::event::{PollFd, PollFlags, poll};

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
    let (controller_identity, nspawn_executable, guardian_executable, selinux_policy) =
        arguments()?;

    // SAFETY: PID 1 transfers the two stable activation entries to this
    // single-threaded entrypoint. No Rust owner has been constructed for FDs
    // 3 or 4, and no preceding operation opens, closes, or duplicates them.
    let (controller_listener, root_mount_listener) = unsafe { take_systemd_listeners()? };
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

    let root_export_cgroup = CgroupV2Root::try_from(open_cgroup_root()?)
        .map_err(|error| HostError::State(error.to_string()))?;
    let catalog =
        FileHostCatalog::open_root_owned(CATALOG_ROOT)?.with_root_export_cgroup(root_export_cgroup);
    let catalog_publisher = FileHostCatalogPublisher::open_root_owned(CATALOG_ROOT)?;
    let state = FileHostStateStore::open(STATE_ROOT)?;
    let credential_directory = env::var_os("CREDENTIALS_DIRECTORY").ok_or_else(|| {
        HostError::State("systemd authority credential directory is absent".to_owned())
    })?;
    let authority = HostAuthorityV1::from_protected_directory(&credential_directory)
        .map_err(|error| HostError::State(error.to_string()))?;
    let guardian = GuardianConfig::new(&guardian_executable, std::time::Duration::from_secs(30))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| HostError::State(error.to_string()))?;
    runtime.block_on(verify_optional_backend_deployment_v1(
        std::path::Path::new(&credential_directory),
        std::path::Path::new(STATE_ROOT),
        &nspawn_executable,
        &selinux_policy,
    ))?;
    let worker = SystemdOneShotWorker::new(open_cgroup_root()?);
    let verifier = ControllerPeerVerifier::new(
        CgroupV2Root::try_from(open_cgroup_root()?)
            .map_err(|error| HostError::State(error.to_string()))?,
    );
    // Any present phase-0 artifact is protected, boot-bound, and
    // rollback-protected above. The live MAC policy is independently checked,
    // but the declared probe and payload-filter digests are not, and the
    // self-probe above does not prove ptrace access to a
    // shifted payload, so it cannot be promoted into BackendReadiness and
    // Host Launch remains disabled. A Guardian profile alone is
    // not sufficient to compile a payload; Apply is never advertised until a
    // production NspawnConfig can be built from complete readiness evidence.
    let broker = HostBroker::open(catalog, state, worker, None, authority)?.with_guardian(guardian);
    let mut service = HostService::new(broker, verifier, controller_identity)
        .with_catalog_publisher(catalog_publisher);

    runtime.block_on(async move {
        let mut next_role = HostListenerRole::Controller;
        loop {
            let ready = {
                let mut descriptors = [
                    PollFd::from_borrowed_fd(controller_listener.as_fd(), PollFlags::IN),
                    PollFd::from_borrowed_fd(root_mount_listener.as_fd(), PollFlags::IN),
                ];
                match poll(&mut descriptors, None) {
                    Ok(_) => [
                        !descriptors[0].revents().is_empty(),
                        !descriptors[1].revents().is_empty(),
                    ],
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(error) => {
                        return Err(HostError::State(format!(
                            "cannot poll activated Host listeners: {error}"
                        )));
                    }
                }
            };
            let selected = if ready == [true, true] {
                next_role
            } else if ready[0] {
                HostListenerRole::Controller
            } else if ready[1] {
                HostListenerRole::RootMount
            } else {
                continue;
            };
            match selected {
                HostListenerRole::Controller => {
                    service
                        .serve_once(&controller_listener, HostListenerRole::Controller)
                        .await?;
                    next_role = HostListenerRole::RootMount;
                }
                HostListenerRole::RootMount => {
                    service
                        .serve_once(&root_mount_listener, HostListenerRole::RootMount)
                        .await?;
                    next_role = HostListenerRole::Controller;
                }
            }
        }
    })
}

fn arguments() -> Result<((u32, u32), String, String, String)> {
    let mut arguments = env::args();
    let _program = arguments.next();
    let uid = parse_identity(arguments.next(), "controller UID")?;
    let gid = parse_identity(arguments.next(), "controller GID")?;
    let nspawn = arguments
        .next()
        .ok_or_else(|| HostError::State("systemd-nspawn path is absent".to_owned()))?;
    let guardian = arguments
        .next()
        .ok_or_else(|| HostError::State("Guardian path is absent".to_owned()))?;
    let selinux_policy = arguments
        .next()
        .ok_or_else(|| HostError::State("production SELinux policy path is absent".to_owned()))?;
    if arguments.next().is_some() {
        return Err(HostError::State(
            "usage: aos-sandbox-hostd CONTROLLER_UID CONTROLLER_GID NSPAWN_PATH GUARDIAN_PATH SELINUX_POLICY_PATH"
                .to_owned(),
        ));
    }
    Ok(((uid, gid), nspawn, guardian, selinux_policy))
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
