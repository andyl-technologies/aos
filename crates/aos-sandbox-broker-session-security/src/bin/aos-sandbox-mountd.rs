//! Runs the authenticated, systemd-activated descriptor Mount broker.
//!
//! Mount FD-store adoption claims the complete inherited table first. The
//! listener is then transferred into broker-session activation while retained
//! mount and source descriptors remain under their dedicated custody owners.

use std::collections::BTreeSet;
use std::env;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use aos_sandbox::journal::{Journal, JournalError, JournalLimits, RecordNamespace};
use aos_sandbox::mount_manager_startup::{
    MountManagerSourceInventoryError, MountManagerStartupJournalBorrowV1,
    MountManagerStartupProtectedOwnerV1,
};
use aos_sandbox_broker_session_security::{
    ProductionBrokerDeadlineErrorV1, ProductionBrokerServiceErrorV1,
    ProductionBrokerSessionActivationErrorV1, ProductionBrokerSessionActivationV1,
    ProductionMountBrokerOwnersV1, ProductionRootMountSourceProviderErrorV1,
    connect_authenticated_fixed_source_provider, observe_original_pending_acquires,
    production_deadline_after, recover_reserved_remote_inventories,
};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::protected_file::{open_nofollow_child, read_exact_positioned};
use aos_sandbox_linux::startup_fd_table::{
    StartupExecutableObservationV1, observe_provisioned_startup_executable,
};
use aos_sandbox_mount::authorization::MountAuthorityV1;
use aos_sandbox_mount::broker::{MountBroker, preflight_recovery_state};
use aos_sandbox_mount::catalog::{FileMountCatalog, PreparedMountCatalog};
use aos_sandbox_mount::helper::PosixSpawnNamespaceHelper;
use aos_sandbox_mount::keeper::SystemdFdStore;
use aos_sandbox_mount::source_pin::recover_source_custody;
use aos_sandbox_mount::worker::{DescriptorMountWorker, RetainedMountObservation};
use aos_sandbox_mount::{DormantMountBrokerCompositionV1, MountError};
use aos_sandbox_protocol::mount_manager_startup::{
    MAXIMUM_STARTUP_POLICY_BYTES_V1, MountManagerStartupPolicyV1, StartupExecutableIdentityV1,
    decode_mount_manager_startup_policy_v1,
};
use aos_sandbox_source_provider_security::{
    RootMountSourceProviderOwnerV1, SourceProviderSecurityError,
    validate_fixed_root_mount_authority_v1,
};
use sha2::{Digest as _, Sha256};

const EXPECTED_FD_NAME: &str = "aos-sandbox-mount";
const MAXIMUM_RETAINED_MOUNTS: usize = 1_024;
const CATALOG_ROOT: &str = "/run/aos/sandbox-mount-catalog";
const STATE_ROOT: &str = "/var/lib/aos/sandbox-mount";
const STARTUP_POLICY_INPUT: &str = "startup-policy.pending";
const MOUNT_EXECUTABLE_CONTEXT: &str = "system_u:object_r:bin_t";
const SYSTEMD_EXECUTABLE_CONTEXT: &str = "system_u:object_r:init_exec_t";
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(45);
const PROVIDER_STARTUP_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Debug, thiserror::Error)]
enum MountDaemonErrorV1 {
    #[error("Mount broker must start with real and effective UID zero")]
    Identity,
    #[error("systemd authority credential directory is absent")]
    CredentialDirectory,
    #[error(
        "usage: aos-sandbox-mountd HELPER_PATH [--source-provider] | --check-source-provider-authority | --install-startup-policy | --install-startup-policy-with-carriers MOUNT_EXECUTABLE SYSTEMD_EXECUTABLE"
    )]
    Arguments,
    #[error("RootMount SourceProvider connector failed: {0}")]
    SourceProvider(#[from] ProductionRootMountSourceProviderErrorV1),
    #[error("Mount domain failed: {0}")]
    Mount(#[from] MountError),
    #[error("Mount journal failed: {0}")]
    Journal(#[from] JournalError),
    #[error("Mount-manager startup policy failed: {0}")]
    StartupPolicy(#[from] MountManagerSourceInventoryError),
    #[error("protected startup-policy input is absent, unsafe, or malformed")]
    StartupPolicyInput,
    #[error("startup executable carrier failed preflight: {0}")]
    ExecutableCarrier(#[from] aos_sandbox_linux::Error),
    #[error("startup executable carrier does not match the protected policy")]
    ExecutableCarrierMismatch,
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

    let arguments = env::args().collect::<Vec<_>>();
    if arguments
        .get(1)
        .is_some_and(|argument| argument == "--check-source-provider-authority")
    {
        if arguments.len() != 2 {
            return Err(MountDaemonErrorV1::Arguments);
        }
        validate_fixed_root_mount_authority_v1()
            .map_err(ProductionRootMountSourceProviderErrorV1::from)?;
        return Ok(());
    }
    if arguments
        .get(1)
        .is_some_and(|argument| argument == "--install-startup-policy")
    {
        if arguments.len() != 2 {
            return Err(MountDaemonErrorV1::Arguments);
        }
        let policy = read_protected_startup_policy()?;
        MountManagerStartupProtectedOwnerV1::provision_fixed_protected_policy_v1(policy)?;
        return Ok(());
    }
    if arguments
        .get(1)
        .is_some_and(|argument| argument == "--install-startup-policy-with-carriers")
    {
        let (mount_path, systemd_path) = carrier_arguments(&arguments)?;
        let policy = read_protected_startup_policy()?;
        preflight_startup_carriers(&policy, mount_path, systemd_path)?;
        MountManagerStartupProtectedOwnerV1::provision_fixed_protected_policy_v1(policy)?;
        return Ok(());
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

    let (helper_executable, source_provider_enabled) = parse_arguments(arguments)?;
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(STATE_ROOT),
        "mount.journal",
        JournalLimits::default(),
    )?;
    let source_recovery_required = requires_source_recovery(source_provider_enabled, &journal);
    if source_recovery_required {
        // Verify the fixed policy and complete replay before broker recovery
        // can make any durable repair or initiate a provider connection.
        MountManagerStartupJournalBorrowV1::borrow_fixed(&mut journal)?;
    }
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
    // Recover retained source state before opening the separate provider
    // connection. An unprovisioned, empty namespace-40 journal needs no source
    // owner when the connector is disabled. Legacy FD-store adoption is not
    // the protected AOSMMCAP1 startup claim: this borrows no SourceRoot
    // descriptor and grants no source effect. Only Reserved Inventory can be
    // read back.
    let cold_inventory_count = if source_recovery_required {
        broker.with_fixed_source_acquisition_owner(|source| {
            source.qualify_inventory_only_cold_recovery()
        })?
    } else {
        0
    };
    if !source_provider_enabled && cold_inventory_count != 0 {
        return Err(MountError::State(
            "cold SourceProvider recovery requires the fixed provider connector".to_owned(),
        )
        .into());
    }
    // The opt-in owner retains the authenticated carrier for this daemon
    // lifetime. A failed or ambiguous recovery restarts the process while
    // the original attempt remains in the sole protected Mount journal.
    let mut source_provider_owner = if source_provider_enabled {
        let deadline = production_deadline_after(PROVIDER_STARTUP_TIMEOUT)?;
        let mut owner = connect_authenticated_fixed_source_provider(deadline)?;
        observe_original_pending_acquires(&mut owner, &mut broker, deadline)?;
        recover_reserved_remote_inventories(&mut owner, &mut broker, deadline)?;
        Some(owner)
    } else {
        None
    };
    let mut mount = DormantMountBrokerCompositionV1::new(&mut broker);

    loop {
        ensure_provider_current(&mut source_provider_owner)?;
        let accept_deadline = production_deadline_after(ACCEPT_TIMEOUT)?;
        let mut session = match activation.accept_authenticated(accept_deadline) {
            Ok(session) => session,
            Err(ProductionBrokerSessionActivationErrorV1::Deadline) => continue,
            Err(error) => return Err(error.into()),
        };
        loop {
            ensure_provider_current(&mut source_provider_owner)?;
            let request_deadline = production_deadline_after(REQUEST_TIMEOUT)?;
            let owners = ProductionMountBrokerOwnersV1 {
                mount: &mut mount,
                catalog_scope: None,
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

fn requires_source_recovery(source_provider_enabled: bool, journal: &Journal) -> bool {
    source_provider_enabled
        || journal
            .records(RecordNamespace::MountSourceAcquisition)
            .next()
            .is_some()
}

fn read_protected_startup_policy() -> Result<MountManagerStartupPolicyV1, MountDaemonErrorV1> {
    read_protected_startup_policy_at(Path::new(STATE_ROOT), 0)
}

fn preflight_startup_carriers(
    policy: &MountManagerStartupPolicyV1,
    mount_path: &Path,
    systemd_path: &Path,
) -> Result<(), MountDaemonErrorV1> {
    let mount = observe_provisioned_startup_executable(mount_path, MOUNT_EXECUTABLE_CONTEXT)?;
    let systemd = observe_provisioned_startup_executable(systemd_path, SYSTEMD_EXECUTABLE_CONTEXT)?;
    if !carrier_matches_policy(mount, &policy.service_executable)
        || !carrier_matches_policy(systemd, &policy.launcher_executable)
        || (mount.device, mount.inode) == (systemd.device, systemd.inode)
    {
        return Err(MountDaemonErrorV1::ExecutableCarrierMismatch);
    }
    Ok(())
}

fn carrier_arguments(arguments: &[String]) -> Result<(&Path, &Path), MountDaemonErrorV1> {
    let [_, command, mount, systemd] = arguments else {
        return Err(MountDaemonErrorV1::Arguments);
    };
    if command != "--install-startup-policy-with-carriers" {
        return Err(MountDaemonErrorV1::Arguments);
    }
    Ok((Path::new(mount), Path::new(systemd)))
}

fn carrier_matches_policy(
    observed: StartupExecutableObservationV1,
    expected: &StartupExecutableIdentityV1,
) -> bool {
    let build_digest: [u8; 32] = Sha256::digest(observed.build_identity.as_bytes()).into();

    observed.device == expected.device
        && observed.inode == expected.inode
        && observed.size == expected.size
        && observed.mode == expected.mode
        && observed.fs_verity_sha256 == expected.fs_verity_sha256
        && build_digest == expected.build_identity_digest
}

fn read_protected_startup_policy_at(
    root: &Path,
    owner_uid: u32,
) -> Result<MountManagerStartupPolicyV1, MountDaemonErrorV1> {
    let bytes = read_protected_startup_policy_bytes_at(root, owner_uid)?;
    decode_mount_manager_startup_policy_v1(&bytes)
        .map_err(|_| MountDaemonErrorV1::StartupPolicyInput)
}

fn read_protected_startup_policy_bytes_at(
    root: &Path,
    owner_uid: u32,
) -> Result<Vec<u8>, MountDaemonErrorV1> {
    let directory = rustix::fs::open(
        root,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| MountDaemonErrorV1::StartupPolicyInput)?;
    let directory_stat =
        rustix::fs::fstat(&directory).map_err(|_| MountDaemonErrorV1::StartupPolicyInput)?;
    if directory_stat.st_uid != owner_uid || directory_stat.st_mode & 0o7777 != 0o700 {
        return Err(MountDaemonErrorV1::StartupPolicyInput);
    }

    let descriptor = open_nofollow_child(&directory, STARTUP_POLICY_INPUT)
        .map_err(|_| MountDaemonErrorV1::StartupPolicyInput)?;
    let before =
        rustix::fs::fstat(&descriptor).map_err(|_| MountDaemonErrorV1::StartupPolicyInput)?;
    let size =
        usize::try_from(before.st_size).map_err(|_| MountDaemonErrorV1::StartupPolicyInput)?;
    if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::RegularFile
        || before.st_mode & 0o7777 != 0o600
        || before.st_uid != owner_uid
        || before.st_nlink != 1
        || size == 0
        || size > MAXIMUM_STARTUP_POLICY_BYTES_V1
    {
        return Err(MountDaemonErrorV1::StartupPolicyInput);
    }

    let mut bytes = vec![0; size];
    read_exact_positioned(&descriptor, &mut bytes)
        .map_err(|_| MountDaemonErrorV1::StartupPolicyInput)?;
    let after =
        rustix::fs::fstat(&descriptor).map_err(|_| MountDaemonErrorV1::StartupPolicyInput)?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_mode != after.st_mode
        || before.st_uid != after.st_uid
        || before.st_nlink != after.st_nlink
        || before.st_size != after.st_size
        || before.st_mtime != after.st_mtime
        || before.st_mtime_nsec != after.st_mtime_nsec
        || before.st_ctime != after.st_ctime
        || before.st_ctime_nsec != after.st_ctime_nsec
    {
        return Err(MountDaemonErrorV1::StartupPolicyInput);
    }
    Ok(bytes)
}

fn ensure_provider_current(
    owner: &mut Option<RootMountSourceProviderOwnerV1>,
) -> Result<(), MountDaemonErrorV1> {
    if let Some(owner) = owner {
        owner
            .with_current_session(|_| ())
            .map_err(ProductionRootMountSourceProviderErrorV1::from)?
            .ok_or(ProductionRootMountSourceProviderErrorV1::Security(
                SourceProviderSecurityError::SessionContinuity,
            ))?;
    }
    Ok(())
}

fn parse_arguments(
    arguments: impl IntoIterator<Item = String>,
) -> Result<(String, bool), MountDaemonErrorV1> {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let helper = arguments.next().ok_or(MountDaemonErrorV1::Arguments)?;
    let source_provider_enabled = match arguments.next().as_deref() {
        None => false,
        Some("--source-provider") => true,
        Some(_) => return Err(MountDaemonErrorV1::Arguments),
    };
    if arguments.next().is_some() || helper.starts_with('-') {
        return Err(MountDaemonErrorV1::Arguments);
    }

    Ok((helper, source_provider_enabled))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use aos_sandbox::journal::{JournalRecord, JournalTransaction};

    #[test]
    fn carrier_policy_install_requires_both_paths() {
        let arguments = [
            "mountd",
            "--install-startup-policy-with-carriers",
            "/mount",
            "/systemd",
        ]
        .map(str::to_owned);
        assert_eq!(
            carrier_arguments(&arguments).unwrap(),
            (Path::new("/mount"), Path::new("/systemd"))
        );
        assert!(carrier_arguments(&arguments[..3]).is_err());
        assert!(carrier_arguments(&arguments[..2]).is_err());
        assert!(
            carrier_arguments(&[arguments.as_slice(), &["extra".to_owned()]].concat()).is_err()
        );
        let mut other_command = arguments;
        other_command[1] = "--install-startup-policy".to_owned();
        assert!(carrier_arguments(&other_command).is_err());
    }

    #[test]
    fn provider_connector_requires_exact_opt_in_argument() {
        let base = ["mountd", "/fixed/helper"];
        assert_eq!(
            parse_arguments(base.map(str::to_owned)).unwrap(),
            ("/fixed/helper".to_owned(), false)
        );
        assert_eq!(
            parse_arguments(["mountd", "/fixed/helper", "--source-provider"].map(str::to_owned))
                .unwrap(),
            ("/fixed/helper".to_owned(), true)
        );
        for invalid in [
            vec!["mountd", "/fixed/helper", "--other"],
            vec!["mountd", "/fixed/helper", "--source-provider", "extra"],
            vec!["mountd", "--source-provider"],
        ] {
            assert!(parse_arguments(invalid.into_iter().map(str::to_owned)).is_err());
        }
    }

    #[test]
    fn startup_policy_input_rejects_unsafe_files() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let input = root.join(STARTUP_POLICY_INPUT);
        let owner_uid = rustix::process::geteuid().as_raw();

        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&input, b"not an AOSMMSTA1 policy").unwrap();
        fs::set_permissions(&input, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_protected_startup_policy_bytes_at(root, owner_uid).unwrap(),
            b"not an AOSMMSTA1 policy"
        );
        assert!(matches!(
            read_protected_startup_policy_bytes_at(root, owner_uid.wrapping_add(1)),
            Err(MountDaemonErrorV1::StartupPolicyInput)
        ));
        assert!(matches!(
            read_protected_startup_policy_at(root, owner_uid),
            Err(MountDaemonErrorV1::StartupPolicyInput)
        ));

        fs::set_permissions(root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            read_protected_startup_policy_bytes_at(root, owner_uid),
            Err(MountDaemonErrorV1::StartupPolicyInput)
        ));
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();

        fs::set_permissions(&input, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            read_protected_startup_policy_bytes_at(root, owner_uid),
            Err(MountDaemonErrorV1::StartupPolicyInput)
        ));

        fs::set_permissions(&input, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&input, root.join("second-name")).unwrap();
        assert!(matches!(
            read_protected_startup_policy_bytes_at(root, owner_uid),
            Err(MountDaemonErrorV1::StartupPolicyInput)
        ));
        fs::remove_file(root.join("second-name")).unwrap();

        fs::remove_file(&input).unwrap();
        symlink("second-name", &input).unwrap();
        assert!(matches!(
            read_protected_startup_policy_bytes_at(root, owner_uid),
            Err(MountDaemonErrorV1::StartupPolicyInput)
        ));

        fs::remove_file(&input).unwrap();
        fs::write(&input, vec![0; MAXIMUM_STARTUP_POLICY_BYTES_V1 + 1]).unwrap();
        fs::set_permissions(&input, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            read_protected_startup_policy_bytes_at(root, owner_uid),
            Err(MountDaemonErrorV1::StartupPolicyInput)
        ));
    }

    #[test]
    fn retained_source_state_requires_policy_recovery_without_opt_in() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("mount.journal");
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        assert!(!requires_source_recovery(false, &journal));
        assert!(requires_source_recovery(true, &journal));

        let record = JournalRecord::put(
            RecordNamespace::MountSourceAcquisition,
            b"retained-source".to_vec(),
            b"untrusted".to_vec(),
        );
        journal
            .commit(&JournalTransaction::new([1; 16], vec![record]).unwrap())
            .unwrap();
        assert!(requires_source_recovery(false, &journal));
    }
}
