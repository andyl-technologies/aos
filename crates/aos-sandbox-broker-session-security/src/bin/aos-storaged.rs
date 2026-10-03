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
    production_deadline_after,
};
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use aos_sandbox_storage::execution_output_credential::{
    StorageExecutionOutputCustodyV1, provision_execution_output_ledger,
};
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

// The legacy diagnostic remains transparent. New startup failures keep their
// concrete cause and owning custody instead of becoming Activation strings.
#[derive(Debug, thiserror::Error)]
enum StorageStartupRunErrorV3 {
    #[error(transparent)]
    Service(#[from] StorageServiceError),
    #[error(transparent)]
    Original(#[from] aos_sandbox_storage::activation::StorageOriginalWorkerStartupErrorV3),
    #[error(transparent)]
    OriginalConstruction(#[from] aos_sandbox_storage::runtime::StorageOriginalNativeConstructionClosedV1),
    #[error(transparent)]
    Template(aos_sandbox_storage::guest_root_inventory::GuestRootInventoryErrorV1),
}

// The legacy arm borrows the local composition at its old drop position. The selected
// arm only borrows the parent-held composition/trust. The fixed enum shares the
// one daemon loop without consuming a selected owner or using legacy early-send.
enum StorageRunCompositionV1<'original> {
    Legacy(&'original mut Option<DormantStorageApplyCompositionV1>),
    Original {
        composition: &'original mut DormantStorageApplyCompositionV1,
        trust: aos_sandbox_storage::runtime::StorageOriginalNativeTrustLoanV1<'original>,
    },
}

impl StorageRunCompositionV1<'_> {
    fn is_original(&self) -> bool {
        matches!(self, Self::Original { .. })
    }

    fn composition_mut(&mut self) -> &mut DormantStorageApplyCompositionV1 {
        match self {
            Self::Legacy(slot) => match slot.as_mut() {
                Some(composition) => composition,
                None => std::process::abort(),
            },
            Self::Original { composition, .. } => composition,
        }
    }

    fn cold_audit(&mut self, state: &Path) -> Result<(), StorageServiceError> {
        match self {
            Self::Legacy(slot) => {
                let composition = match slot.take() {
                    Some(composition) => composition,
                    None => std::process::abort(),
                };
                **slot = Some(composition.with_private_live_export_cold_audit(state)?);
                Ok(())
            }
            Self::Original { composition, .. } => composition.retain_private_live_export_cold_audit(state),
        }
    }

    fn serve_native(
        &mut self, listener: &mut RecordSubjectListener,
        verifier: &ProviderLiveExportPeerVerifier, authority: &Path,
        key: Option<&StorageZfsHoldKeyV1>,
    ) -> Result<aos_sandbox_storage::zfs_hold_transport::StorageZfsHoldTransportOutcomeV1, StorageServiceError> {
        match self {
            Self::Legacy(slot) => match slot.as_mut() {
                Some(composition) => composition.serve_zfs_hold_request_once(
                    listener, verifier, authority, key,
                ),
                None => std::process::abort(),
            },
            Self::Original { composition, trust } => {
                let key = key.ok_or(StorageRuntimeError::Recovery)?;
                composition.serve_original_held_offer_once(listener, verifier, trust, key)
            }
        }
    }
}

impl std::ops::Deref for StorageRunCompositionV1<'_> {
    type Target = DormantStorageApplyCompositionV1;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Legacy(slot) => match slot.as_ref() {
                Some(composition) => composition,
                None => std::process::abort(),
            },
            Self::Original { composition, .. } => composition,
        }
    }
}

impl std::ops::DerefMut for StorageRunCompositionV1<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.composition_mut()
    }
}

impl From<StorageRuntimeError> for StorageStartupRunErrorV3 {
    fn from(error: StorageRuntimeError) -> Self {
        Self::Service(error.into())
    }
}

impl From<aos_sandbox_linux::Error> for StorageStartupRunErrorV3 {
    fn from(error: aos_sandbox_linux::Error) -> Self {
        Self::Service(error.into())
    }
}

impl From<rustix::io::Errno> for StorageStartupRunErrorV3 {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Service(error.into())
    }
}

impl From<aos_sandbox_linux::seqpacket::SeqpacketError> for StorageStartupRunErrorV3 {
    fn from(error: aos_sandbox_linux::seqpacket::SeqpacketError) -> Self {
        Self::Service(error.into())
    }
}

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

// This exclusive loan is scoped inside each existing accept boundary, so its
// unwind fence runs before lower Storage/operator/output originals can drop.
// No cold debt means the exact old return/drop disposition remains selected.
struct StorageColdAcceptUnwindV1<'activation>(
    &'activation mut aos_sandbox_broker_session_security::ProductionBrokerSessionActivationV1,
);

impl Drop for StorageColdAcceptUnwindV1<'_> {
    fn drop(&mut self) {
        if self.0.has_failed_storage_cold() {
            std::process::abort();
        }
    }
}

fn run() -> Result<(), StorageStartupRunErrorV3> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(StorageServiceError::Activation(
            "broker must start with real and effective UID zero".to_owned(),
        )
        .into());
    }
    let state_root = Path::new(STATE_ROOT);
    let command_line: Vec<_> = env::args_os().collect();
    if command_line
        .get(1)
        .is_some_and(|value| value == "--provision-output")
    {
        let source = parse_provision_source(&command_line)?;
        return provision_execution_output_ledger(state_root, &source).map_err(Into::into);
    }
    let (command, arguments) = parse_startup_command(command_line)?;

    // Claim the complete systemd table before any inherited slot can be
    // reused. The broker session owns only its fixed control listener.
    let (startup, original_worker_startup) = if command == StorageStartupCommandV4::Serve
        && arguments.zfs_hold_key_configured
    {
        aos_sandbox_broker_session_security::ProductionStorageStartupV1::capture_original_worker_startup()?
    } else {
        (
            aos_sandbox_broker_session_security::ProductionStorageStartupV1::capture()?,
            None,
        )
    };
    let mut original_attempt = original_worker_startup.map(
        aos_sandbox_storage::runtime::StorageOriginalNativeConstructionV1::begin,
    );
    // Selected credentials remain outside the fallible run scope too. Legacy
    // locals below retain their old creation and reverse destruction positions.
    let mut original_key = None;
    let mut original_operator_credentials = None;
    let _original_crossing = original_attempt.as_ref().map(|owner| owner.unwind_fence());
    let result: Result<(), StorageStartupRunErrorV3> = (|| {
        let (
            mut activation,
            mut export_listener,
            mut live_export_listener,
            mut zfs_hold_listener,
            mut operator_listener,
            mut existing_output_listener,
        ) = startup.into_parts();
        let output_custody = if let Some(source) = &arguments.output_key_source {
            Some(StorageExecutionOutputCustodyV1::open(state_root, source)?)
        } else {
            None
        };
        if output_custody.is_some() != existing_output_listener.is_some() {
            return Err(StorageServiceError::Activation(
                "existing-output listener and protected custody must be provisioned together"
                    .to_owned(),
            )
            .into());
        }
        let mut legacy_key = None;
        let zfs_hold_key = if original_attempt.is_some() {
            original_key = Some(StorageZfsHoldKeyV1::load()?);
            &original_key
        } else {
            if arguments.zfs_hold_key_configured {
                legacy_key = Some(StorageZfsHoldKeyV1::load()?);
            }
            &legacy_key
        };
        let identity_pool =
            StorageIdentityPoolV1::new(arguments.identity_pool_start, arguments.identity_pool_size)
                .map_err(StorageRuntimeError::WorkspaceCatalog)?;
        let executor = SystemdZfsExecutor::new(PathBuf::from(ZFS_WORKER_SOCKET), open_cgroup_root()?)
            .map_err(StorageRuntimeError::Worker)?;
        let guest_root_template = ProtectedGuestRootTemplateV1::open(&arguments.guest_root_template)
            .map_err(|cause| {
                if original_attempt.is_some() {
                    StorageStartupRunErrorV3::Template(cause)
                } else {
                    StorageStartupRunErrorV3::Service(StorageServiceError::Activation(cause.to_string()))
                }
            })?;
        let mut legacy_operator_credentials = None;
        let operator_credentials = if original_attempt.is_some() {
            if operator_listener.is_some() {
                original_operator_credentials = Some(StorageOperatorRecoveryCredentialsV1::load()?);
            }
            &original_operator_credentials
        } else {
            if operator_listener.is_some() {
                legacy_operator_credentials = Some(StorageOperatorRecoveryCredentialsV1::load()?);
            }
            &legacy_operator_credentials
        };
        if command == StorageStartupCommandV4::ProvisionOperator {
            let credentials = operator_credentials.as_ref().ok_or_else(|| {
                StorageServiceError::Activation(
                    "operator provisioning requires the existing operator listener role".to_owned(),
                )
            })?;
            activation.storage_listener_fd().map_err(production_error)?;
            let provisioning_listeners = [
                Some(&export_listener),
                live_export_listener.as_ref(),
                zfs_hold_listener.as_ref(),
                operator_listener.as_ref(),
                existing_output_listener.as_ref(),
            ];
            validate_operator_provisioning_listeners(&provisioning_listeners)?;
            credentials.recheck()?;

            DormantStorageApplyCompositionV1::provision_empty_operator_repair_v4(
                &arguments.authority_directory,
                &arguments.bootstrap_directory,
                state_root,
                arguments.resolver_policy_directory.as_deref(),
                identity_pool,
                arguments.zfs_executable,
                executor,
                credentials,
            )?;

            credentials.recheck()?;
            activation.storage_listener_fd().map_err(production_error)?;
            validate_operator_provisioning_listeners(&provisioning_listeners)?;
            if let Some(key) = &zfs_hold_key {
                key.recheck()?;
            }
            if let Some(custody) = &output_custody {
                custody.recheck(state_root)?;
            }
            let current_template = ProtectedGuestRootTemplateV1::open(&arguments.guest_root_template)
                .map_err(|error| StorageServiceError::Activation(error.to_string()))?;
            if current_template.root() != guest_root_template.root()
                || current_template.package_binding() != guest_root_template.package_binding()
                || current_template.root_tree_digest() != guest_root_template.root_tree_digest()
            {
                return Err(StorageServiceError::Activation(
                    "guest-root template changed during operator provisioning".to_owned(),
                )
                .into());
            }
            // Keep the actual template and complete inherited table until all
            // provisioning bookends finish. No actor or effect owner is returned.
            drop(guest_root_template);
            return Ok(());
        }
        // Declare these in the original tuple's order: on legacy error the fourth
        // writer drops before the composition. The route enum borrows both slots.
        let mut legacy_storage = None;
        let mut legacy_operator_owner = None;
        let (mut storage, operator_owner) = if let Some(original) = original_attempt.as_mut() {
            original.open_once(
                &arguments.authority_directory, &arguments.bootstrap_directory,
                state_root, arguments.resolver_policy_directory.as_deref(),
                identity_pool, arguments.zfs_executable, executor,
                zfs_hold_key.as_ref().ok_or(StorageRuntimeError::Recovery)?,
                operator_credentials.as_ref(), guest_root_template,
            )?;
            let (composition, owner, trust) = original.ready_parts()?;
            (StorageRunCompositionV1::Original { composition, trust }, owner)
        } else {
            let (composition, owner) = match operator_credentials.as_ref() {
                Some(credentials) => {
                    let (storage, owner) = DormantStorageApplyCompositionV1::open_existing_operator_repair_v4(
                        &arguments.authority_directory,
                        &arguments.bootstrap_directory,
                        state_root,
                        arguments.resolver_policy_directory.as_deref(),
                        identity_pool,
                        arguments.zfs_executable,
                        executor,
                        credentials,
                    )?;
                    (storage.with_guest_root_template(guest_root_template), Some(owner))
                }
                None => (
                    DormantStorageApplyCompositionV1::open_root_owned(
                        &arguments.authority_directory,
                        &arguments.bootstrap_directory,
                        state_root,
                        arguments.resolver_policy_directory.as_deref(),
                        identity_pool,
                        arguments.zfs_executable,
                        executor,
                    )?.with_guest_root_template(guest_root_template),
                    None,
                ),
            };
            legacy_storage = Some(composition);
            legacy_operator_owner = owner;
            (StorageRunCompositionV1::Legacy(&mut legacy_storage), &mut legacy_operator_owner)
        };
        if let Some(diagnostic) = prepare_readiness_diagnostic(storage.runtime().prepare_readiness()) {
            eprintln!("aos-storaged: {diagnostic}");
        }
        // Auxiliary cold audit and ordinary publisher admission follow exact
        // settlement. Neither may create journal names while Repair debt is held.
        let mut ordinary_services_initialized = false;
        let mut active_session: Option<DormantAuthenticatedBrokerSessionV1> = None;
        loop {
            // An unresolved sidecar hold admits its same-socket recovery and a
            // fresh authenticated handshake for historical checkpoint verification.
            // No ordinary method request is served until exact settlement.
            while let Some(owner) = operator_owner.as_mut() {
                if !storage.retain_operator_terminal_cold_hold(owner)? {
                    break;
                }
                let listener = operator_listener.as_mut().ok_or_else(|| {
                    StorageServiceError::Activation("unresolved operator hold has no listener".to_owned())
                })?;
                let credentials = operator_credentials.as_ref().ok_or_else(|| {
                    StorageServiceError::Activation("unresolved operator hold has no credentials".to_owned())
                })?;
                credentials.recheck()?;
                let broker_listener = activation.storage_listener_fd().map_err(production_error)?;
                let mut recovery_ready = vec![
                    rustix::event::PollFd::from_borrowed_fd(listener.as_fd(), rustix::event::PollFlags::IN),
                    rustix::event::PollFd::from_borrowed_fd(broker_listener, rustix::event::PollFlags::IN),
                ];
                let pending_request_index = if let Some(session) = active_session.as_ref() {
                    let index = recovery_ready.len();
                    recovery_ready.push(rustix::event::PollFd::from_borrowed_fd(
                        session.as_fd().map_err(|error| StorageServiceError::Activation(error.to_string()))?,
                        rustix::event::PollFlags::IN,
                    ));
                    Some(index)
                } else {
                    None
                };
                match rustix::event::poll(&mut recovery_ready, None) {
                    Ok(_) => {}
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(error) => return Err(error.into()),
                }
                let operator_ready = recovery_ready[0].revents().contains(rustix::event::PollFlags::IN);
                let handshake_ready = recovery_ready[1].revents().contains(rustix::event::PollFlags::IN);
                let request_ready = pending_request_index.is_some_and(|index| recovery_ready[index].revents().contains(rustix::event::PollFlags::IN));
                let request_disconnected = pending_request_index.is_some_and(|index| recovery_ready[index].revents().intersects(rustix::event::PollFlags::HUP | rustix::event::PollFlags::ERR));
                if recovery_ready[..2].iter().any(|ready| ready.revents().intersects(rustix::event::PollFlags::HUP | rustix::event::PollFlags::ERR)) {
                    return Err(StorageServiceError::Activation(
                        "operator recovery listener retired".to_owned(),
                    )
                    .into());
                }
                drop(recovery_ready);
                if request_ready {
                    if let Some(session) = active_session.take() {
                        let deadline = production_deadline_after(REQUEST_TIMEOUT)
                            .map_err(|error| StorageServiceError::Activation(error.to_string()))?;
                        match session.serve_operator_repair_unresolved_rejection(deadline) {
                            Ok(session) => active_session = Some(session),
                            Err(error) => eprintln!("aos-storaged: held request rejected: {error}"),
                        }
                    }
                } else if request_disconnected {
                    active_session = None;
                }
                if handshake_ready {
                    let deadline = production_deadline_after(ACCEPT_TIMEOUT)
                        .map_err(|error| StorageServiceError::Activation(error.to_string()))?;
                    let acceptance = StorageColdAcceptUnwindV1(&mut activation);
                    match acceptance.0.accept_authenticated(deadline) {
                        Ok(session) => active_session = Some(session),
                        Err(error) if acceptance.0.has_failed_storage_cold() => {
                            // Original cold owners and typed cause remain in the
                            // activation stack. Exit before returning through lower
                            // Storage/operator disposal or accepting a replacement.
                            eprintln!("aos-storaged: resident Storage cold admission failed: {error}");
                            std::process::exit(1);
                        }
                        Err(ProductionBrokerSessionActivationErrorV1::Deadline) => {}
                        Err(error) => return Err(production_error(error).into()),
                    }
                }
                if operator_ready {
                    let controller_cgroup = open_cgroup_root()?.resolve(Path::new(CONTROLLER_CGROUP))?;
                    let verifier = ControllerPeerVerifier::new(controller_cgroup, arguments.controller_identity)?;
                    storage.serve_operator_repair_once(listener, &verifier, owner)?;
                }
                credentials.recheck()?;
            }
            if !ordinary_services_initialized {
                if live_export_listener.is_some() {
                    storage.cold_audit(state_root)?;
                }
                // Normal admission still requires the real no-effect health probe.
                storage.probe_guest_root_publisher()?;
                ordinary_services_initialized = true;
            }
            if let Some(key) = &zfs_hold_key {
                key.recheck()?;
            }
            if let Some(custody) = &output_custody {
                custody.recheck(state_root)?;
            }
            if !storage.runtime().is_inventory_ready() {
                return Err(StorageRuntimeError::Recovery.into());
            }

            let mut ready = Vec::with_capacity(6);
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
            let zfs_hold_index = zfs_hold_listener.as_ref().map(|listener| {
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
            let zfs_hold_ready = zfs_hold_index
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
                && !zfs_hold_ready
                && !operator_ready
                && !existing_output_ready
            {
                return Err(StorageServiceError::Activation(
                    "activated Storage endpoint reported invalid readiness".to_owned(),
                )
                .into());
            }

            if broker_disconnected && active_session.is_none() {
                return Err(StorageServiceError::Activation(
                    "protected Storage broker listener was retired".to_owned(),
                )
                .into());
            }
            if broker_ready {
                if let Some(session) = active_session.take() {
                    let request_deadline = production_deadline_after(REQUEST_TIMEOUT)
                        .map_err(|error| StorageServiceError::Activation(error.to_string()))?;
                    match session.serve_production_storage_request(storage.composition_mut(), request_deadline) {
                        Ok(retained) => active_session = Some(retained),
                        Err(error) => eprintln!("aos-storaged: authenticated request failed: {error}"),
                    }
                } else {
                    let accept_deadline = production_deadline_after(ACCEPT_TIMEOUT)
                        .map_err(|error| StorageServiceError::Activation(error.to_string()))?;
                    let acceptance = StorageColdAcceptUnwindV1(&mut activation);
                    match acceptance.0.accept_authenticated(accept_deadline) {
                        Ok(session) => active_session = Some(session),
                        Err(error) if acceptance.0.has_failed_storage_cold() => {
                            // Original cold owners and typed cause remain in the
                            // activation stack. Exit before returning through lower
                            // Storage/operator disposal or accepting a replacement.
                            eprintln!("aos-storaged: resident Storage cold admission failed: {error}");
                            std::process::exit(1);
                        }
                        Err(ProductionBrokerSessionActivationErrorV1::Deadline) => {}
                        Err(error) => return Err(production_error(error).into()),
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
            if zfs_hold_ready {
                let listener = zfs_hold_listener.as_mut().ok_or_else(|| {
                    StorageServiceError::Activation("ZFS hold listener disappeared".to_owned())
                })?;
                let provider_cgroup = open_cgroup_root()?.resolve(Path::new(SOURCE_PROVIDER_CGROUP));
                match provider_cgroup {
                    Ok(provider_cgroup) => {
                        let verifier = ProviderLiveExportPeerVerifier::new(provider_cgroup)?;
                        storage.serve_native(
                            listener,
                            &verifier,
                            &arguments.authority_directory,
                            zfs_hold_key.as_ref(),
                        )?;
                    }
                    Err(cause) if storage.is_original() => return Err(cause.into()),
                    Err(_) => {
                        listener.validate_current()?;
                        let _ = listener.accept();
                    }
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
    })();
    match (original_attempt.as_mut(), result) {
        (None, outcome) => outcome,
        (Some(owner), Err(StorageStartupRunErrorV3::Service(cause))) => {
            owner.retain_service_failure(cause);
            if let Some(cause) = owner.first_cause() {
                eprintln!("aos-storaged: resident original native failure: {cause}");
            }
            std::process::exit(1);
        }
        (Some(owner), Err(cause)) => {
            owner.close_resident();
            if let Some(first) = owner.first_cause() {
                eprintln!("aos-storaged: resident original native failure: {first}");
            } else {
                eprintln!("aos-storaged: resident original native failure: {cause}");
            }
            std::process::exit(1);
        }
        (Some(owner), Ok(())) => {
            // No local success is a release/Drain proof for this selected owner.
            owner.close_resident();
            std::process::exit(1);
        }
    }
}

// Both provisioning bookends inspect the same borrowed original listeners.
fn validate_operator_provisioning_listeners(
    listeners: &[Option<&RecordSubjectListener>; 5],
) -> Result<(), StorageServiceError> {
    for listener in listeners.iter().flatten() {
        listener.validate_current()?;
    }

    Ok(())
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StorageStartupCommandV4 {
    Serve,
    ProvisionOperator,
}

fn parse_startup_command(
    mut arguments: Vec<std::ffi::OsString>,
) -> Result<(StorageStartupCommandV4, Arguments), StorageServiceError> {
    let command = if arguments
        .get(1)
        .is_some_and(|argument| argument == "--provision-operator-recovery")
    {
        arguments.remove(1);
        StorageStartupCommandV4::ProvisionOperator
    } else {
        StorageStartupCommandV4::Serve
    };
    parse_arguments(arguments).map(|arguments| (command, arguments))
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

fn parse_provision_source(
    arguments: &[std::ffi::OsString],
) -> Result<PathBuf, StorageServiceError> {
    if arguments.len() != 3 {
        return Err(usage_error());
    }
    required_path(arguments.get(2).cloned(), "output key source")
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
        "usage: aos-storaged --provision-output OUTPUT_KEY_SOURCE | aos-storaged [--provision-operator-recovery] CONTROLLER_UID CONTROLLER_GID IDENTITY_START IDENTITY_SIZE ZFS_PATH AUTHORITY_DIRECTORY BOOTSTRAP_DIRECTORY RESOLVER_POLICY_DIRECTORY|- GUEST_ROOT_TEMPLATE ZFS_HOLD_KEY_V1|- OUTPUT_KEY_SOURCE|-"
            .to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{
        StorageStartupCommandV4, parse_arguments, parse_provision_source, parse_startup_command,
    };

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
    fn operator_provisioning_keeps_the_complete_normal_argument_contract() {
        let ordinary = service_arguments("-", "-");
        let (command, arguments) = parse_startup_command(ordinary.clone()).unwrap();
        assert_eq!(command, StorageStartupCommandV4::Serve);
        assert_eq!(arguments.identity_pool_start, 65536);

        let mut provisioning = ordinary;
        provisioning.insert(1, "--provision-operator-recovery".into());
        let (command, arguments) = parse_startup_command(provisioning).unwrap();
        assert_eq!(command, StorageStartupCommandV4::ProvisionOperator);
        assert_eq!(arguments.identity_pool_start, 65536);
        assert_eq!(arguments.controller_identity, (1000, 1000));
        assert!(arguments.output_key_source.is_none());
    }

    #[test]
    fn operator_provisioning_refuses_short_extra_and_repeated_verbs() {
        let mut complete = service_arguments("-", "-");
        complete.insert(1, "--provision-operator-recovery".into());
        assert!(parse_startup_command(complete[..2].to_vec()).is_err());

        let mut extra = complete.clone();
        extra.push("/var/lib/aos/alternate-state".into());
        assert!(parse_startup_command(extra).is_err());

        complete.insert(1, "--provision-operator-recovery".into());
        assert!(parse_startup_command(complete).is_err());
    }

    #[test]
    fn operator_provisioning_refuses_a_similar_unknown_verb() {
        let mut arguments = service_arguments("-", "-");
        arguments.insert(1, "--provision-operator".into());
        assert!(parse_startup_command(arguments).is_err());
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

    #[test]
    fn offline_provisioning_requires_one_absolute_source() {
        let valid =
            ["aos-storaged", "--provision-output", "/etc/aos/output.key"].map(OsString::from);
        assert_eq!(
            parse_provision_source(&valid).unwrap(),
            std::path::Path::new("/etc/aos/output.key")
        );
        assert!(parse_provision_source(&valid[..2]).is_err());
        assert!(
            parse_provision_source(&[valid.as_slice(), &[OsString::from("extra")]].concat())
                .is_err()
        );
        let relative = ["aos-storaged", "--provision-output", "output.key"].map(OsString::from);
        assert!(parse_provision_source(&relative).is_err());
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
