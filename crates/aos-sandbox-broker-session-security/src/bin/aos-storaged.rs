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
    DormantAuthenticatedBrokerSessionV1, ProductionBrokerSessionActivationErrorV1,
    ProductionBrokerSessionActivationV1, production_deadline_after,
};
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_storage::activation::take_systemd_listeners;
use aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1;
use aos_sandbox_storage::existing_output_query::serve_existing_output_query_once;
use aos_sandbox_storage::guest_root_inventory::ProtectedGuestRootTemplateV1;
use aos_sandbox_storage::operator_recovery_credentials::StorageOperatorRecoveryCredentialsV1;
use aos_sandbox_storage::peer::{
    ControllerPeerVerifier, HostRootExportPeerVerifier, ProviderLiveExportPeerVerifier,
};
use aos_sandbox_storage::storage_zfs_hold_key::StorageZfsHoldKeyV1;
use aos_sandbox_storage::{
    DormantStorageApplyCompositionV1, StorageIdentityPoolV1, StoragePrepareReadiness,
    StorageRuntimeError, StorageServiceError, SystemdZfsExecutor,
};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const STATE_ROOT: &str = "/var/lib/aos/sandbox-storage";
const ZFS_WORKER_SOCKET: &str = "/run/aos/sandbox-zfs-worker/control.sock";
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(45);
const CONTROLLER_CGROUP: &str = "aos.slice/aos-control.slice/aos-sandboxd.service";
const HOST_CGROUP: &str = "system.slice/aos-sandbox-hostd.service";
const SOURCE_PROVIDER_CGROUP: &str = "aos.slice/aos-control.slice/aos-source-providerd.service";

fn main() -> ExitCode {
    if let Err(error) = aos_sandbox_linux::no_setid::require_guarded_startup() {
        eprintln!("aos-storaged: {error}");
        return ExitCode::FAILURE;
    }

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
    let state_root = Path::new(STATE_ROOT);

    // Claim the complete systemd table before any inherited slot can be
    // reused. The broker session owns only its fixed control listener.
    let (
        control_listener,
        mut export_listener,
        mut live_export_listener,
        mut operator_listener,
        mut existing_output_listener,
    ) = take_systemd_listeners()?;
    let output_custody = if let Some(source) = &arguments.output_key_source {
        Some(StorageExecutionOutputCustodyV1::open(state_root, source)?)
    } else {
        None
    };
    if output_custody.is_some() != existing_output_listener.is_some() {
        return Err(StorageServiceError::Activation(
            "existing-output listener and protected custody must be provisioned together"
                .to_owned(),
        ));
    }
    let zfs_hold_key = if arguments.zfs_hold_key_configured {
        Some(StorageZfsHoldKeyV1::load()?)
    } else {
        None
    };
    let mut activation =
        ProductionBrokerSessionActivationV1::adopt_storage_listener(control_listener)
            .map_err(production_error)?;
    let identity_pool =
        StorageIdentityPoolV1::new(arguments.identity_pool_start, arguments.identity_pool_size)
            .map_err(StorageRuntimeError::WorkspaceCatalog)?;
    let executor = SystemdZfsExecutor::new(PathBuf::from(ZFS_WORKER_SOCKET), open_cgroup_root()?)
        .map_err(StorageRuntimeError::Worker)?;
    let guest_root_template = ProtectedGuestRootTemplateV1::open(&arguments.guest_root_template)
        .map_err(|error| StorageServiceError::Activation(error.to_string()))?;
    let mut storage = DormantStorageApplyCompositionV1::open_root_owned(
        &arguments.authority_directory,
        &arguments.bootstrap_directory,
        state_root,
        arguments.resolver_policy_directory.as_deref(),
        identity_pool,
        arguments.zfs_executable,
        executor,
    )?
    .with_guest_root_template(guest_root_template);
    if live_export_listener.is_some() {
        storage = storage.with_private_live_export_cold_audit(Path::new(STATE_ROOT))?;
    }
    let (operator_credentials, mut operator_owner) = if operator_listener.is_some() {
        let credentials = StorageOperatorRecoveryCredentialsV1::load()?;
        let owner = credentials.open_owner(Path::new(STATE_ROOT))?;
        (Some(credentials), Some(owner))
    } else {
        (None, None)
    };
    if let Some(diagnostic) = prepare_readiness_diagnostic(storage.runtime().prepare_readiness()) {
        eprintln!("aos-storaged: {diagnostic}");
    }
    // The production handshake has a static complete Storage method profile.
    // Do not accept any session until the method-31 publisher is actually
    // installed, authenticates, and exits from a mutation-free health request.
    storage.probe_guest_root_publisher()?;

    let mut active_session: Option<DormantAuthenticatedBrokerSessionV1> = None;
    loop {
        if let Some(key) = &zfs_hold_key {
            key.recheck()?;
        }
        if let Some(custody) = &output_custody {
            custody.recheck(state_root)?;
        }
        if !storage.runtime().is_inventory_ready() {
            return Err(StorageRuntimeError::Recovery.into());
        }

        let mut ready = Vec::with_capacity(5);
        if let Some(session) = active_session.as_ref() {
            let session_fd = session
                .as_fd()
                .map_err(|error| StorageServiceError::Activation(error.to_string()))?;
            ready.push(rustix::event::PollFd::from_borrowed_fd(
                session_fd,
                rustix::event::PollFlags::IN,
            ));
        } else {
            let listener_fd = activation.storage_listener_fd().map_err(production_error)?;
            ready.push(rustix::event::PollFd::from_borrowed_fd(
                listener_fd,
                rustix::event::PollFlags::IN,
            ));
        }
        ready.push(rustix::event::PollFd::from_borrowed_fd(
            export_listener.as_fd(),
            rustix::event::PollFlags::IN,
        ));
        let live_export_index = live_export_listener.as_ref().map(|listener| {
            let index = ready.len();
            ready.push(rustix::event::PollFd::from_borrowed_fd(
                listener.as_fd(),
                rustix::event::PollFlags::IN,
            ));
            index
        });
        let operator_index = operator_listener.as_ref().map(|listener| {
            let index = ready.len();
            ready.push(rustix::event::PollFd::from_borrowed_fd(
                listener.as_fd(),
                rustix::event::PollFlags::IN,
            ));
            index
        });
        let existing_output_index = existing_output_listener.as_ref().map(|listener| {
            let index = ready.len();
            ready.push(rustix::event::PollFd::from_borrowed_fd(
                listener.as_fd(),
                rustix::event::PollFlags::IN,
            ));
            index
        });
        match rustix::event::poll(&mut ready, None) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
        let broker_ready = ready[0].revents().contains(rustix::event::PollFlags::IN);
        let broker_disconnected = ready[0]
            .revents()
            .intersects(rustix::event::PollFlags::HUP | rustix::event::PollFlags::ERR);
        let export_ready = ready[1].revents().contains(rustix::event::PollFlags::IN);
        let live_export_ready = live_export_index
            .and_then(|index| ready.get(index))
            .is_some_and(|entry| entry.revents().contains(rustix::event::PollFlags::IN));
        let operator_ready = operator_index
            .and_then(|index| ready.get(index))
            .is_some_and(|entry| entry.revents().contains(rustix::event::PollFlags::IN));
        let existing_output_ready = existing_output_index
            .and_then(|index| ready.get(index))
            .is_some_and(|entry| entry.revents().contains(rustix::event::PollFlags::IN));
        drop(ready);
        if let Some(key) = &zfs_hold_key {
            key.recheck()?;
        }
        if let Some(custody) = &output_custody {
            custody.recheck(state_root)?;
        }
        if !broker_ready
            && !broker_disconnected
            && !export_ready
            && !live_export_ready
            && !operator_ready
            && !existing_output_ready
        {
            return Err(StorageServiceError::Activation(
                "activated Storage endpoint reported invalid readiness".to_owned(),
            ));
        }

        if broker_disconnected && active_session.is_none() {
            return Err(StorageServiceError::Activation(
                "protected Storage broker listener was retired".to_owned(),
            ));
        }
        if broker_ready {
            if let Some(session) = active_session.take() {
                let request_deadline = production_deadline_after(REQUEST_TIMEOUT)
                    .map_err(|error| StorageServiceError::Activation(error.to_string()))?;
                match session.serve_production_storage_request(&mut storage, request_deadline) {
                    Ok(retained) => active_session = Some(retained),
                    Err(error) => eprintln!("aos-storaged: authenticated request failed: {error}"),
                }
            } else {
                let accept_deadline = production_deadline_after(ACCEPT_TIMEOUT)
                    .map_err(|error| StorageServiceError::Activation(error.to_string()))?;
                match activation.accept_authenticated(accept_deadline) {
                    Ok(session) => active_session = Some(session),
                    Err(ProductionBrokerSessionActivationErrorV1::Deadline) => {}
                    Err(error) => return Err(production_error(error)),
                }
            }
        } else if broker_disconnected {
            // A retired child is local to that session; a retired listener is fatal.
            active_session = None;
        }
        if export_ready {
            let host_cgroup = open_cgroup_root()?.resolve(Path::new(HOST_CGROUP));
            if let Ok(host_cgroup) = host_cgroup {
                let verifier = HostRootExportPeerVerifier::new(host_cgroup)?;
                storage.serve_root_export_once(&mut export_listener, &verifier)?;
            } else {
                export_listener.validate_current()?;
                let _ = export_listener.accept_descriptor_subject();
            }
        }
        if live_export_ready {
            let listener = live_export_listener.as_mut().ok_or_else(|| {
                StorageServiceError::Activation("live-export listener disappeared".to_owned())
            })?;
            let provider_cgroup = open_cgroup_root()?.resolve(Path::new(SOURCE_PROVIDER_CGROUP));
            if let Ok(provider_cgroup) = provider_cgroup {
                let verifier = ProviderLiveExportPeerVerifier::new(provider_cgroup)?;
                storage.serve_live_export_request_once(
                    listener,
                    &verifier,
                    &arguments.authority_directory,
                    Path::new(STATE_ROOT),
                )?;
            } else {
                listener.validate_current()?;
                let _ = listener.accept();
            }
        }
        if operator_ready {
            let listener = operator_listener.as_mut().ok_or_else(|| {
                StorageServiceError::Activation("operator Repair listener disappeared".to_owned())
            })?;
            let credentials = operator_credentials.as_ref().ok_or_else(|| {
                StorageServiceError::Activation(
                    "operator Repair credentials disappeared".to_owned(),
                )
            })?;
            let owner = operator_owner.as_mut().ok_or_else(|| {
                StorageServiceError::Activation("operator Repair owner disappeared".to_owned())
            })?;
            credentials.recheck()?;
            let controller_cgroup = open_cgroup_root()?.resolve(Path::new(CONTROLLER_CGROUP));
            if let Ok(controller_cgroup) = controller_cgroup {
                let verifier =
                    ControllerPeerVerifier::new(controller_cgroup, arguments.controller_identity)?;
                storage.serve_operator_repair_once(listener, &verifier, owner)?;
            } else {
                // A queued stale child cannot create Controller authority.
                listener.validate_current()?;
                let _ = listener.accept();
            }
            credentials.recheck()?;
        }
        if existing_output_ready {
            let listener = existing_output_listener.as_mut().ok_or_else(|| {
                StorageServiceError::Activation("existing-output listener disappeared".to_owned())
            })?;
            let custody = output_custody.as_ref().ok_or_else(|| {
                StorageServiceError::Activation("existing-output custody disappeared".to_owned())
            })?;
            let host_cgroup = open_cgroup_root()?.resolve(Path::new(HOST_CGROUP));
            if let Ok(host_cgroup) = host_cgroup {
                let verifier = HostRootExportPeerVerifier::new(host_cgroup)?;
                serve_existing_output_query_once(listener, &verifier, custody, state_root)?;
            } else {
                listener.validate_current()?;
                let _ = listener.accept_descriptor_subject();
            }
        }
        if let Some(key) = &zfs_hold_key {
            key.recheck()?;
        }
        if let Some(custody) = &output_custody {
            custody.recheck(state_root)?;
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
    guest_root_template: PathBuf,
    zfs_hold_key_configured: bool,
    output_key_source: Option<PathBuf>,
}

fn arguments() -> Result<Arguments, StorageServiceError> {
    parse_arguments(env::args_os())
}

fn parse_arguments(
    arguments: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<Arguments, StorageServiceError> {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let controller_uid = parse_controller_identity(arguments.next(), "controller UID")?;
    let controller_gid = parse_controller_identity(arguments.next(), "controller GID")?;
    let identity_pool_start = parse_u32(arguments.next(), "identity-pool start")?;
    let identity_pool_size = parse_u32(arguments.next(), "identity-pool size")?;
    let zfs_executable = required_path(arguments.next(), "ZFS executable")?;
    let authority_directory = required_path(arguments.next(), "authority directory")?;
    let bootstrap_directory = required_path(arguments.next(), "bootstrap directory")?;
    let resolver_policy_directory = optional_path(arguments.next(), "resolver policy directory")?;
    let guest_root_template = required_path(arguments.next(), "guest root template")?;
    let zfs_hold_key_configured = match arguments.next().as_deref() {
        Some(value) if value == "zfs-hold-key-v1" => true,
        Some(value) if value == "-" => false,
        _ => return Err(usage_error()),
    };
    let output_key_source = match arguments.next() {
        Some(value) => optional_path(Some(value), "output key source")?,
        None => return Err(usage_error()),
    };
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
        guest_root_template,
        zfs_hold_key_configured,
        output_key_source,
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
        "usage: aos-storaged CONTROLLER_UID CONTROLLER_GID IDENTITY_START IDENTITY_SIZE ZFS_PATH AUTHORITY_DIRECTORY BOOTSTRAP_DIRECTORY RESOLVER_POLICY_DIRECTORY|- GUEST_ROOT_TEMPLATE ZFS_HOLD_KEY_V1|- OUTPUT_KEY_SOURCE|-"
            .to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::parse_arguments;

    fn service_arguments(zfs_key: &str, output_key: &str) -> Vec<OsString> {
        [
            "aos-storaged",
            "1000",
            "1000",
            "65536",
            "65536",
            "/nix/store/zfs/bin/zfs",
            "/var/lib/aos/storage-authority",
            "/var/lib/aos/storage-bootstrap",
            "-",
            "/etc/aos/guest-root-template",
            zfs_key,
            output_key,
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn service_arguments_match_nix_command_for_disabled_and_configured_keys() {
        let disabled = parse_arguments(service_arguments("-", "-")).unwrap();
        assert!(!disabled.zfs_hold_key_configured);
        assert!(disabled.output_key_source.is_none());

        let configured = parse_arguments(service_arguments(
            "zfs-hold-key-v1",
            "/etc/aos/secrets/output.key",
        ))
        .unwrap();
        assert!(configured.zfs_hold_key_configured);
        assert_eq!(
            configured.output_key_source.as_deref(),
            Some(std::path::Path::new("/etc/aos/secrets/output.key"))
        );
    }

    #[test]
    fn service_arguments_reject_missing_or_extra_key_slots() {
        let mut missing = service_arguments("-", "-");
        missing.pop();
        assert!(parse_arguments(missing).is_err());

        let mut extra = service_arguments("-", "-");
        extra.push("unexpected".into());
        assert!(parse_arguments(extra).is_err());
    }
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
