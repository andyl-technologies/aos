//! Runs the authenticated, systemd-activated descriptor Mount broker.
//!
//! Mount FD-store adoption claims the complete inherited table first. The
//! listener is then transferred into broker-session activation while retained
//! mount and source descriptors remain under their dedicated custody owners.

use std::collections::BTreeSet;
use std::env;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use aos_sandbox::journal::{Journal, JournalError, JournalLimits};
use aos_sandbox_broker_session_security::{
    ProductionBrokerDeadlineErrorV1, ProductionBrokerServiceErrorV1,
    ProductionBrokerSessionActivationErrorV1, ProductionBrokerSessionActivationV1,
    ProductionMountBrokerOwnersV1, production_deadline_after,
};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_mount::authorization::MountAuthorityV1;
use aos_sandbox_mount::broker::{MountBroker, preflight_recovery_state};
use aos_sandbox_mount::catalog::{FileMountCatalog, PreparedMountCatalog};
use aos_sandbox_mount::helper::PosixSpawnNamespaceHelper;
use aos_sandbox_mount::keeper::SystemdFdStore;
use aos_sandbox_mount::source_pin::recover_source_custody;
use aos_sandbox_mount::worker::{DescriptorMountWorker, RetainedMountObservation};
use aos_sandbox_mount::{DormantMountBrokerCompositionV1, MountError};

const EXPECTED_FD_NAME: &str = "aos-sandbox-mount";
const MAXIMUM_RETAINED_MOUNTS: usize = 1_024;
const CATALOG_ROOT: &str = "/run/aos/sandbox-mount-catalog";
const STATE_ROOT: &str = "/var/lib/aos/sandbox-mount";
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Debug, thiserror::Error)]
enum MountDaemonErrorV1 {
    #[error("Mount broker must start with real and effective UID zero")]
    Identity,
    #[error("systemd authority credential directory is absent")]
    CredentialDirectory,
    #[error("usage: aos-sandbox-mountd HELPER_PATH")]
    Arguments,
    #[error("Mount domain failed: {0}")]
    Mount(#[from] MountError),
    #[error("Mount journal failed: {0}")]
    Journal(#[from] JournalError),
    #[error("Mount activation failed: {0}")]
    Activation(#[from] ProductionBrokerSessionActivationErrorV1),
    #[error("Mount deadline failed: {0}")]
    Deadline(#[from] ProductionBrokerDeadlineErrorV1),
    #[error("Mount request failed: {0}")]
    Request(#[from] ProductionBrokerServiceErrorV1),
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-mountd: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), MountDaemonErrorV1> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(MountDaemonErrorV1::Identity);
    }

    // SAFETY: this is the single-threaded process entrypoint before any Rust
    // owner represents systemd's complete activation descriptor range.
    let retained = unsafe {
        SystemdFdStore::adopt_service_activation(EXPECTED_FD_NAME, MAXIMUM_RETAINED_MOUNTS)?
    };
    let retained_names = retained.mounts.keys().cloned().collect::<BTreeSet<_>>();
    let retained_sources = retained
        .source_pins
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut activation =
        ProductionBrokerSessionActivationV1::adopt_mount_listener(retained.listener)?;
    let keeper = Arc::new(SystemdFdStore::from_environment_with_inventories(
        retained_names,
        retained_sources,
        MAXIMUM_RETAINED_MOUNTS,
    )?);

    let helper_executable = helper_argument()?;
    validate_private_root(Path::new(STATE_ROOT))?;
    let (mut journal, _) = Journal::open(
        Path::new(STATE_ROOT).join("mount.journal"),
        JournalLimits::default(),
    )?;
    let kernel_boot_id = KernelBootId::current()
        .map_err(|error| MountError::State(error.to_string()))?
        .into_bytes();
    let retained_mounts = retained
        .mounts
        .iter()
        .map(|(name, mount)| RetainedMountObservation {
            handle: name.digest(),
            mount_id: mount.mount_id(),
        })
        .collect::<Vec<_>>();
    preflight_recovery_state(&journal, kernel_boot_id, &retained_mounts)?;
    let reopened_sources =
        recover_source_custody(&mut journal, retained.source_pins, &keeper, kernel_boot_id)?;
    let catalog = PreparedMountCatalog::with_reopened_sources(
        FileMountCatalog::open_root_owned(CATALOG_ROOT)?,
        reopened_sources,
    );
    let helper = PosixSpawnNamespaceHelper::new(helper_executable)?;
    let worker = DescriptorMountWorker::new(catalog, helper, keeper, retained.mounts)?;
    let credential_directory =
        env::var_os("CREDENTIALS_DIRECTORY").ok_or(MountDaemonErrorV1::CredentialDirectory)?;
    let authority = MountAuthorityV1::from_protected_directory(credential_directory)
        .map_err(|error| MountError::State(error.to_string()))?;
    let mut broker =
        MountBroker::new_with_destination_slots(journal, worker, authority, CATALOG_ROOT, 0)?;
    let mut mount = DormantMountBrokerCompositionV1::new(&mut broker);

    loop {
        let accept_deadline = production_deadline_after(ACCEPT_TIMEOUT)?;
        let mut session = match activation.accept_authenticated(accept_deadline) {
            Ok(session) => session,
            Err(ProductionBrokerSessionActivationErrorV1::Deadline) => continue,
            Err(error) => return Err(error.into()),
        };
        loop {
            let request_deadline = production_deadline_after(REQUEST_TIMEOUT)?;
            let owners = ProductionMountBrokerOwnersV1 {
                mount: &mut mount,
                catalog_scope: None,
                source: None,
            };
            match session.serve_production_mount_request(owners, request_deadline) {
                Ok(retained) => session = retained,
                Err(error) => {
                    // Preserve the protected sequence owner between successful
                    // resource and destination-slot queries on one session.
                    eprintln!("aos-sandbox-mountd: authenticated request failed: {error}");
                    break;
                }
            }
        }
    }
}

fn helper_argument() -> Result<String, MountDaemonErrorV1> {
    let mut arguments = env::args();
    let _program = arguments.next();
    let helper = arguments.next().ok_or(MountDaemonErrorV1::Arguments)?;
    if arguments.next().is_some() {
        return Err(MountDaemonErrorV1::Arguments);
    }

    Ok(helper)
}

fn validate_private_root(path: &Path) -> Result<(), MountDaemonErrorV1> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| MountError::State(error.to_string()))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(MountError::State(
            "mount state root must be a private root-owned real directory".to_owned(),
        )
        .into());
    }

    Ok(())
}
