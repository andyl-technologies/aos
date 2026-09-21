//! Runs the authenticated, systemd-activated sandbox Host broker.
//!
//! The daemon adopts both fixed Host listeners before opening any other file
//! descriptor. Each accepted connection completes the protected broker-session
//! handshake and retains its protected sequence owner across bounded request
//! cycles. Ready controller and RootMount roles alternate without dropping idle
//! sessions. A failed request drops only its session, preserving durable recovery.

use std::env;
use std::os::fd::OwnedFd;
use std::process::ExitCode;
use std::time::Duration;

use aos_sandbox_broker_session_security::{
    ProductionBrokerSessionActivationErrorV1, ProductionBrokerSessionActivationV1,
    ProductionHostBrokerServiceErrorV1, production_deadline_after,
};
use aos_sandbox_host::DormantHostBrokerCompositionV1;
use aos_sandbox_host::authorization::HostAuthorityV1;
use aos_sandbox_host::broker::HostBroker;
use aos_sandbox_host::catalog::{FileHostCatalog, FileHostCatalogPublisher};
use aos_sandbox_host::plan::{
    BackendReadinessBlocker, GuardianConfig, ProtectedBackendReadinessEvidence,
};
use aos_sandbox_host::state::FileHostStateStore;
use aos_sandbox_host::worker::{PidfdNamespaceAccessProbe, SystemdOneShotWorker};
use aos_sandbox_host::{HostError, Result};
use aos_sandbox_linux::path::BeneathRoot;

const CATALOG_ROOT: &str = "/run/aos/sandbox-host";
const STATE_ROOT: &str = "/var/lib/aos/sandbox-host";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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
    let (_legacy_controller_identity, nspawn_executable, guardian_executable) = arguments()?;

    // SAFETY: this is the single-threaded entrypoint before any operation can
    // allocate or mutate a descriptor. PID 1 owns and transfers exactly FDs 3
    // and 4 under the fixed controller and RootMount descriptor names.
    let activation =
        unsafe { ProductionBrokerSessionActivationV1::adopt_host() }.map_err(production_error)?;
    let mut service = activation.into_host_service().map_err(production_error)?;

    // This probe is diagnostic only. Protected backend readiness remains the
    // sole authority for enabling Host Launch.
    let _pidfd_namespace_probe = match PidfdNamespaceAccessProbe::current_service() {
        Ok(probe) => Some(probe),
        Err(error) => {
            eprintln!("aos-sandbox-hostd: pidfd namespace self-probe unavailable: {error}");
            None
        }
    };

    let catalog = FileHostCatalog::open_root_owned(CATALOG_ROOT)?;
    let catalog_publisher = FileHostCatalogPublisher::open_root_owned(CATALOG_ROOT)?;
    let state = FileHostStateStore::open(STATE_ROOT)?;
    let credential_directory = env::var_os("CREDENTIALS_DIRECTORY").ok_or_else(|| {
        HostError::State("systemd authority credential directory is absent".to_owned())
    })?;
    let authority = HostAuthorityV1::from_protected_directory(&credential_directory)
        .map_err(|error| HostError::State(error.to_string()))?;
    let guardian = GuardianConfig::new(&guardian_executable, Duration::from_secs(30))?;
    validate_backend_readiness(
        std::path::Path::new(&credential_directory),
        &nspawn_executable,
    )?;

    let worker = SystemdOneShotWorker::new(open_cgroup_root()?);
    let mut broker =
        HostBroker::open(catalog, state, worker, None, authority)?.with_guardian(guardian);
    let mut host = DormantHostBrokerCompositionV1::new(&mut broker);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| HostError::State(error.to_string()))?;

    runtime.block_on(async move {
        loop {
            let request_deadline = production_deadline_after(REQUEST_TIMEOUT)
                .map_err(|error| HostError::State(error.to_string()))?;
            match service
                .serve_next(&mut host, &catalog_publisher, request_deadline)
                .await
            {
                Ok(()) => {}
                Err(ProductionHostBrokerServiceErrorV1::Activation(
                    ProductionBrokerSessionActivationErrorV1::Deadline,
                )) => continue,
                Err(ProductionHostBrokerServiceErrorV1::Activation(error)) => {
                    return Err(production_error(error));
                }
                Err(ProductionHostBrokerServiceErrorV1::Request(error)) => {
                    eprintln!("aos-sandbox-hostd: authenticated request failed: {error}");
                }
            }
        }
    })
}

fn validate_backend_readiness(
    credential_directory: &std::path::Path,
    nspawn_executable: &str,
) -> Result<()> {
    let readiness = ProtectedBackendReadinessEvidence::load_protected_optional(
        credential_directory,
        STATE_ROOT,
        nspawn_executable,
    )?;
    let Some(readiness) = readiness else {
        return Ok(());
    };
    if readiness.runtime_blockers()
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

    Ok(())
}

fn production_error(error: ProductionBrokerSessionActivationErrorV1) -> HostError {
    HostError::State(error.to_string())
}

fn arguments() -> Result<((u32, u32), String, String)> {
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
    if arguments.next().is_some() {
        return Err(HostError::State(
            "usage: aos-sandbox-hostd CONTROLLER_UID CONTROLLER_GID NSPAWN_PATH GUARDIAN_PATH"
                .to_owned(),
        ));
    }

    Ok(((uid, gid), nspawn, guardian))
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
