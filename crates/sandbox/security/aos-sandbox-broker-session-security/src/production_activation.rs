//! Exact systemd activation ownership for authenticated broker sessions.
//!
//! The activation owner admits only the repository's fixed service profiles.
//! Storage, Mount, and Network each require one specifically named listener;
//! Host requires distinct controller, RootMount, and Storage listeners so their
//! signed audiences, journals, and key custody cannot be confused. Accepted sockets
//! complete the fixed protected handshake before leaving this module.

mod host;

pub(crate) use host::verify_storage_session_peer;
pub use host::{ProductionHostActivationV1, ProductionHostReadinessV1, ProductionHostRoleV1};

use std::collections::BTreeMap;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::Path;

use aos_sandbox_linux::inherited_fd::claim_systemd_activation_descriptor_range;
use aos_sandbox_linux::seqpacket::{RecordSubjectListener, SeqpacketError};

mod storage_continuation;
pub(crate) use storage_continuation::StorageRetainedSocketAcceptanceV1;

pub(crate) fn retained_storage_session_carrier_bytes_v1() -> Option<usize> {
    std::mem::size_of::<crate::production_service::ProductionStorageSessionContinuationV1>()
        .checked_add(std::mem::size_of::<crate::production_service::ProductionOriginalStorageLifecycleSessionV1>())?
        .checked_add(3 * std::mem::size_of::<crate::production_service::ProductionOriginalStorageConnectionV1>())
}

use rustix::event::{PollFd, PollFlags, Timespec, poll};

use crate::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1,
    ProtectedBrokerSessionFixedCustodyV1, ProtectedBrokerSessionFixedEndpointV1,
};

const HOST_CONTROLLER_FD_NAME: &str = "aos-sandbox-host";
const HOST_ROOT_MOUNT_FD_NAME: &str = "aos-sandbox-host-root-mount";
const HOST_STORAGE_FD_NAME: &str = "aos-sandbox-host-storage";
const STORAGE_FD_NAME: &str = "aos-storaged";
const MOUNT_FD_NAME: &str = "aos-sandbox-mount";
const NETWORK_FD_NAME: &str = "aos-netd";

/// Reports rejection while adopting or accepting a fixed broker activation.
#[derive(Debug, thiserror::Error)]
pub enum ProductionBrokerSessionActivationErrorV1 {
    /// The actual Host startup financial/native original refused cold entry.
    #[error(transparent)]
    HostCold(#[from] aos_sandbox_host::HostControlColdSessionClosedV1),
    /// The sealed Host callsite could not lend its actual startup owner.
    #[error(transparent)]
    HostColdCallsite(#[from] aos_sandbox_host::DormantHostBrokerCallErrorV1),
    /// The shared cold engine retains the original native failure and debt.
    #[error(transparent)]
    HostColdNative(#[from] crate::FixedServiceSessionClosedV4),
    /// Checked native/model representation arithmetic failed before growth.
    #[error(transparent)]
    HostColdAccounting(#[from] aos_sandbox_model::AccountingError),
    /// systemd did not supply the exact fixed descriptor table.
    #[error("broker-session systemd activation is invalid: {0}")]
    Activation(&'static str),
    /// The fixed selected Host destination could not be reserved before handoff.
    #[error("original Host Control listener destination cannot be reserved: {0}")]
    HostControlDestination(#[source] std::collections::TryReserveError),
    /// Descriptor adoption or listener validation failed.
    #[error("broker-session listener is invalid: {0}")]
    Listener(#[from] SeqpacketError),
    /// The protected handshake rejected an accepted peer or local custody.
    #[error("broker-session handshake failed: {0}")]
    Handshake(#[from] DormantBrokerSessionHandshakeErrorV1),
    /// The original Mount cohort failed before selected acceptance.
    #[error(transparent)]
    CoverageMount(aos_sandbox_mount::DormantMountBrokerCallErrorV1),
    /// The original Storage/output cohort failed before selected acceptance.
    #[error(transparent)]
    CoverageStorage(aos_sandbox_storage::DormantStorageBrokerCallErrorV1),
    /// The same genuine receiving interval rejected its currentness check.
    #[error(transparent)]
    StorageReceiving(aos_sandbox_controller_domain::StorageReceivingClosedV1),
    /// The next authenticated session did not arrive before its boot-time deadline.
    #[error("broker-session acceptance deadline expired")]
    Deadline,
    /// A kernel clock, poll, or activation-descriptor operation failed.
    #[error("broker-session activation kernel operation failed")]
    Kernel,
}

struct FixedListenerV1 {
    endpoint: ProtectedBrokerSessionFixedEndpointV1,
    listener: RecordSubjectListener,
}

#[derive(Clone, Copy)]
enum ActivationAcceptPurposeV1 {
    Ordinary,
    NixGeneration,
    OutputCapture,
}

/// Owns the complete fixed listener set for one production broker service.
///
/// Construction consumes systemd's descriptor table once during the
/// single-threaded startup interval. The owner is non-cloneable and keeps every
/// listener exclusively retained while accepting one authenticated session at
/// a time.
#[must_use = "retain the activation owner while accepting broker sessions"]
pub struct ProductionBrokerSessionActivationV1 {
    // Fence a failed selected cold flight before any activation field drops.
    storage_cold: Option<crate::handshake::RetainedStorageColdOpenV1>,
    storage_initial_acceptance: Option<StorageRetainedSocketAcceptanceV1>,
    storage_initial: Option<crate::handshake::StorageInitialSessionHandshakeV1>,
    // One selected attempt parks its complete upfront Result and first outer
    // rejection before exposing only a closed status to the daemon.
    storage_prepare_fixed: Option<Result<(), crate::BrokerSessionSecurityError>>,
    storage_prepare_failure: Option<ProductionBrokerSessionActivationErrorV1>,
    // Completed cold Session stays resident before Native cleanup may refuse.
    storage_prepare_session: Option<DormantAuthenticatedBrokerSessionV1>,
    storage_prepare_complete: bool,
    // Selected startup fences unwind before its control/image fields release.
    selected_storage_startup: Option<crate::production_startup::StorageResourceRecipientStartupCustodyV1>,
    listeners: Vec<FixedListenerV1>,
    launch_image: Option<crate::production_startup::Pid1LaunchImageV1>,
}

impl Drop for ProductionBrokerSessionActivationV1 {
    fn drop(&mut self) {
        if self.storage_prepare_session.is_some() || self.storage_initial.is_some()
            || self.storage_initial_acceptance.is_some()
        {
            // A refused or unwinding cleanup cannot silently discard the
            // actual returned Session, facade and native refusal custody.
            std::process::abort();
        }
    }
}

impl core::fmt::Debug for ProductionBrokerSessionActivationV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionBrokerSessionActivationV1")
            .field("listener_count", &self.listeners.len())
            .finish_non_exhaustive()
    }
}

impl ProductionBrokerSessionActivationV1 {
    /// Reports resident unfinished or failed selected Storage admission.
    ///
    /// This is a terminal diagnostic, never drain, readiness or retry evidence.
    pub fn has_failed_storage_cold(&self) -> bool {
        (self.storage_prepare_fixed.is_some() && !self.storage_prepare_complete)
            || self.storage_cold.as_ref()
                .is_some_and(crate::handshake::RetainedStorageColdOpenV1::is_failed)
    }

    /// Reports the actual fixed launch prerequisite for output inspection.
    ///
    /// This checks retained provenance only; it is not capture or Create readiness.
    #[must_use]
    pub fn has_original_output_capture_launch(&self) -> bool {
        matches!(self.listeners.as_slice(), [fixed]
            if fixed.endpoint == ProtectedBrokerSessionFixedEndpointV1::StorageBroker)
            && self.launch_image.as_ref().is_some_and(|image|
                image.require_endpoint(ProtectedBrokerSessionFixedEndpointV1::StorageBroker).is_ok())
    }

    pub(crate) fn retain_launch_image(
        &mut self,
        image: Option<crate::production_startup::Pid1LaunchImageV1>,
    ) {
        self.launch_image = image;
    }

    /// Preallocates the fixed destination before selected original capture.
    pub(crate) fn prearm_storage_resource_recipient() -> Self {
        Self {
            storage_cold: None,
            storage_initial_acceptance: None,
            storage_initial: None,
            storage_prepare_fixed: None,
            storage_prepare_failure: None,
            storage_prepare_session: None,
            storage_prepare_complete: false,
            selected_storage_startup: None,
            listeners: Vec::with_capacity(1),
            launch_image: None,
        }
    }

    /// Admits the resident selected control without consuming a rejected original.
    ///
    /// # Errors
    /// Rejects a reused destination, missing control or the same fixed-path
    /// failure as ordinary Storage listener adoption.
    pub(crate) fn admit_retained_storage_listener(
        &mut self,
        control: &mut Option<RecordSubjectListener>,
    ) -> Result<(), ProductionBrokerSessionActivationErrorV1> {
        if !self.listeners.is_empty() || self.listeners.capacity() < 1
            || self.launch_image.is_some() || self.storage_cold.is_some()
            || self.selected_storage_startup.is_some()
        {
            return Err(ProductionBrokerSessionActivationErrorV1::Activation(
                "selected Storage listener destination is unavailable",
            ));
        }
        let original = control.as_ref().ok_or(
            ProductionBrokerSessionActivationErrorV1::Activation(
                "selected Storage control listener is absent",
            ),
        )?;
        require_storage_listener_path(original)?;

        // All checks and allocation precede removal of the same original.
        let Some(listener) = control.take() else {
            std::process::abort();
        };
        self.listeners.push(FixedListenerV1 {
            endpoint: ProtectedBrokerSessionFixedEndpointV1::StorageBroker,
            listener,
        });
        Ok(())
    }

    /// Moves the same selected startup observations into their fixed activation.
    pub(crate) fn retain_storage_recipient_startup(
        &mut self,
        custody: crate::production_startup::StorageResourceRecipientStartupCustodyV1,
    ) {
        if self.selected_storage_startup.is_some()
            || !matches!(self.listeners.as_slice(), [fixed]
                if fixed.endpoint == ProtectedBrokerSessionFixedEndpointV1::StorageBroker)
        {
            std::process::abort();
        }
        self.selected_storage_startup = Some(custody);
    }

    /// Borrows the same selected Required image for a later private floor crossing.
    ///
    /// This grants no Required47 admission and never reopens or clones an image.
    ///
    /// # Errors
    /// Rejects another endpoint, absent selected custody or a missing/unbound image.
    pub(crate) fn borrow_storage_resource_recipient_launch_image(
        &self,
    ) -> Result<&crate::production_startup::Pid1LaunchImageV1, crate::BrokerSessionSecurityError> {
        if self.selected_storage_startup.is_none()
            || !matches!(self.listeners.as_slice(), [fixed]
                if fixed.endpoint == ProtectedBrokerSessionFixedEndpointV1::StorageBroker)
        {
            return Err(crate::BrokerSessionSecurityError::Currentness);
        }
        let image = self.launch_image.as_ref()
            .ok_or(crate::BrokerSessionSecurityError::Currentness)?;
        image.require_endpoint(ProtectedBrokerSessionFixedEndpointV1::StorageBroker)?;
        Ok(image)
    }

    /// Adopts the controller-, RootMount-, and Storage-facing Host listeners.
    ///
    /// # Safety
    ///
    /// The caller must be the single-threaded startup owner of systemd FDs 3
    /// through 5. No Rust owner, thread, signal handler, or concurrent operation
    /// may open, close, duplicate, or replace them until this returns.
    ///
    /// # Errors
    ///
    /// Returns an error unless systemd supplies exactly the three fixed named
    /// listeners with record-subject reporting enabled.
    pub unsafe fn adopt_host() -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        // SAFETY: forwarded from this method's exact startup ownership contract.
        unsafe {
            Self::adopt(&[
                (
                    HOST_CONTROLLER_FD_NAME,
                    ProtectedBrokerSessionFixedEndpointV1::HostBroker,
                ),
                (
                    HOST_ROOT_MOUNT_FD_NAME,
                    ProtectedBrokerSessionFixedEndpointV1::RootMountHostBroker,
                ),
                (
                    HOST_STORAGE_FD_NAME,
                    ProtectedBrokerSessionFixedEndpointV1::StorageHostBroker,
                ),
            ])
        }
    }

    /// Adopts the listeners from the genuine complete selected Host startup.
    ///
    /// The startup owner has already captured all five initial entries before
    /// protected opens. This does not parse or duplicate another startup table,
    /// and does not establish canary or backend readiness.
    ///
    /// # Errors
    /// Refuses an incomplete, failed or previously transferred original table,
    /// or a listener whose exact production filesystem path has changed.
    pub fn adopt_original_host_canary(
        startup: &mut aos_sandbox_host::plan::HostCanaryStartupV1,
    ) -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        // Reserve before transferring originals. Their same selected startup
        // owner has already checked the exact paths; no new observation or
        // allocation follows this complete handoff.
        let mut listeners = Vec::with_capacity(3);
        let (controller, root_mount, storage) = startup.take_original_listeners()
            .map_err(|_| ProductionBrokerSessionActivationErrorV1::Activation(
                "selected Host original table is incomplete",
            ))?;
        for (endpoint, listener) in [
            (ProtectedBrokerSessionFixedEndpointV1::HostBroker, controller),
            (ProtectedBrokerSessionFixedEndpointV1::RootMountHostBroker, root_mount),
            (ProtectedBrokerSessionFixedEndpointV1::StorageHostBroker, storage),
        ] {
            listeners.push(FixedListenerV1 { endpoint, listener });
        }
        Ok(Self {
            storage_cold: None,
            storage_initial_acceptance: None,
            storage_initial: None,
            storage_prepare_fixed: None,
            storage_prepare_failure: None,
            storage_prepare_session: None,
            storage_prepare_complete: false,
            selected_storage_startup: None,
            listeners,
            launch_image: None,
        })
    }

    /// Adopts the admitted original Control owner's same fixed three endpoints.
    ///
    /// # Errors
    /// Refuses a failed or spent original, an allocation failure before handoff,
    /// or an incomplete named destination. The original retains rich admission
    /// causes; no descriptor is returned or relabeled as Canary provenance.
    pub fn adopt_original_host_control(
        startup: &mut aos_sandbox_host::plan::HostComponentControlStartupV2,
    ) -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        let mut destination = [None, None, None];
        let mut listeners = Vec::new();
        listeners.try_reserve_exact(3)
            .map_err(ProductionBrokerSessionActivationErrorV1::HostControlDestination)?;
        startup.transfer_original_listeners_into(&mut destination)
            .map_err(|_| ProductionBrokerSessionActivationErrorV1::Activation(
                "original Host Control listener handoff is unavailable",
            ))?;

        // Vacant slots, all three originals and Vec capacity were checked
        // before transfer. Only infallible fixed endpoint parking follows.
        match destination {
            [Some(controller), Some(root_mount), Some(storage)] => {
                for (endpoint, listener) in [
                    (ProtectedBrokerSessionFixedEndpointV1::HostBroker, controller),
                    (ProtectedBrokerSessionFixedEndpointV1::RootMountHostBroker, root_mount),
                    (ProtectedBrokerSessionFixedEndpointV1::StorageHostBroker, storage),
                ] {
                    listeners.push(FixedListenerV1 { endpoint, listener });
                }
                Ok(Self {
                    storage_cold: None,
                    storage_initial_acceptance: None,
                    storage_initial: None,
                    storage_prepare_fixed: None,
                    storage_prepare_failure: None,
                    storage_prepare_session: None,
                    storage_prepare_complete: false,
                    selected_storage_startup: None,
                    listeners,
                    launch_image: None,
                })
            }
            _ => std::process::abort(),
        }
    }

    /// Adopts the complete fixed Host listener set for VM qualification.
    ///
    /// This is the descriptor-owned counterpart of [`Self::adopt_host`]. All three
    /// audience-specific listeners are required, and each must retain its exact
    /// production filesystem path and record-subject configuration.
    /// This checked adopter is available only to tests and the explicit
    /// `kernel-tests` qualification feature; production startup remains unchanged.
    ///
    /// # Errors
    ///
    /// Rejects any listener whose kernel socket properties or fixed path differ.
    #[cfg(any(test, feature = "kernel-tests"))]
    pub fn adopt_host_listeners(
        controller: RecordSubjectListener,
        root_mount: RecordSubjectListener,
        storage: RecordSubjectListener,
    ) -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        Self::from_complete_host_listeners(controller, root_mount, storage)
    }

    fn from_complete_host_listeners(
        controller: RecordSubjectListener,
        root_mount: RecordSubjectListener,
        storage: RecordSubjectListener,
    ) -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        let listeners = [
            (
                ProtectedBrokerSessionFixedEndpointV1::HostBroker,
                controller,
            ),
            (
                ProtectedBrokerSessionFixedEndpointV1::RootMountHostBroker,
                root_mount,
            ),
            (
                ProtectedBrokerSessionFixedEndpointV1::StorageHostBroker,
                storage,
            ),
        ];
        let mut fixed = Vec::with_capacity(listeners.len());
        for (endpoint, listener) in listeners {
            listener.require_local_filesystem_path(Path::new(endpoint.production_socket_path()))?;
            fixed.push(FixedListenerV1 { endpoint, listener });
        }
        Ok(Self {
            listeners: fixed,
            launch_image: None,
            storage_cold: None,
            storage_initial_acceptance: None,
            storage_initial: None,
            storage_prepare_fixed: None,
            storage_prepare_failure: None,
            storage_prepare_session: None,
            storage_prepare_complete: false,
            selected_storage_startup: None,
        })
    }

    /// Adopts the sole fixed Storage listener.
    ///
    /// # Safety
    ///
    /// The caller must be the single-threaded startup owner of systemd FD 3.
    /// No other owner or concurrent descriptor-table mutation may exist.
    ///
    /// # Errors
    ///
    /// Returns an error unless the exact named record-subject listener is present.
    pub unsafe fn adopt_storage() -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        // SAFETY: forwarded from this method's exact startup ownership contract.
        unsafe {
            Self::adopt(&[(
                STORAGE_FD_NAME,
                ProtectedBrokerSessionFixedEndpointV1::StorageBroker,
            )])
        }
    }

    /// Adopts Storage's fixed broker listener after its complete socket table is claimed.
    ///
    /// The Storage daemon must first classify every systemd descriptor,
    /// including root-export and operator sidecar listeners. This constructor
    /// transfers only the broker-session listener into authenticated custody.
    ///
    /// # Errors
    ///
    /// Rejects any listener outside the fixed Storage broker socket path.
    pub fn adopt_storage_listener(
        listener: RecordSubjectListener,
    ) -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        let endpoint = ProtectedBrokerSessionFixedEndpointV1::StorageBroker;
        require_storage_listener_path(&listener)?;
        Ok(Self {
            listeners: vec![FixedListenerV1 { endpoint, listener }],
            launch_image: None,
            storage_cold: None,
            storage_initial_acceptance: None,
            storage_initial: None,
            storage_prepare_fixed: None,
            storage_prepare_failure: None,
            storage_prepare_session: None,
            storage_prepare_complete: false,
            selected_storage_startup: None,
        })
    }

    /// Borrows only the fixed Storage listener for a multi-socket event loop.
    ///
    /// # Errors
    ///
    /// Rejects a non-Storage activation or a retired listener.
    pub fn storage_listener_fd(
        &self,
    ) -> Result<BorrowedFd<'_>, ProductionBrokerSessionActivationErrorV1> {
        let [fixed] = self.listeners.as_slice() else {
            return Err(ProductionBrokerSessionActivationErrorV1::Activation(
                "Storage activation does not own exactly one broker listener",
            ));
        };
        if fixed.endpoint != ProtectedBrokerSessionFixedEndpointV1::StorageBroker {
            return Err(ProductionBrokerSessionActivationErrorV1::Activation(
                "activation endpoint is not Storage",
            ));
        }
        fixed.listener.validate_current()?;
        Ok(fixed.listener.as_fd())
    }

    /// Adopts the sole fixed Mount listener.
    ///
    /// # Safety
    ///
    /// The caller must be the single-threaded startup owner of systemd FD 3.
    /// No other owner or concurrent descriptor-table mutation may exist.
    ///
    /// # Errors
    ///
    /// Returns an error unless the exact named record-subject listener is present.
    pub unsafe fn adopt_mount() -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        // SAFETY: forwarded from this method's exact startup ownership contract.
        unsafe {
            Self::adopt(&[(
                MOUNT_FD_NAME,
                ProtectedBrokerSessionFixedEndpointV1::MountBroker,
            )])
        }
    }

    /// Adopts the fixed Mount listener after the Mount FD store claims activation.
    ///
    /// The Mount service receives retained mount and source descriptors beside
    /// its listener. Its FD-store owner must claim and classify that complete
    /// systemd table first, then transfer only the named listener here. This
    /// constructor still requires the fixed pathname and record-subject socket
    /// options and cannot select another endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error unless `listener` is the fixed Mount filesystem
    /// listener with record-subject reporting enabled.
    pub fn adopt_mount_listener(
        listener: OwnedFd,
    ) -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        Self::from_owned_listener(ProtectedBrokerSessionFixedEndpointV1::MountBroker, listener)
    }

    /// Adopts the fixed Network listener after the Network FD store claims activation.
    ///
    /// The Network service receives retained namespace descriptors beside its
    /// listener. Its FD-store owner must claim and classify that complete table
    /// first, then transfer only the typed listener here.
    ///
    /// # Errors
    ///
    /// Returns an error unless `listener` is the fixed Network filesystem
    /// listener with record-subject reporting enabled.
    pub fn adopt_network_listener(
        listener: RecordSubjectListener,
    ) -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        let endpoint = ProtectedBrokerSessionFixedEndpointV1::NetworkBroker;
        listener.require_local_filesystem_path(Path::new(endpoint.production_socket_path()))?;
        Ok(Self {
            listeners: vec![FixedListenerV1 { endpoint, listener }],
            launch_image: None,
            storage_cold: None,
            storage_initial_acceptance: None,
            storage_initial: None,
            storage_prepare_fixed: None,
            storage_prepare_failure: None,
            storage_prepare_session: None,
            storage_prepare_complete: false,
            selected_storage_startup: None,
        })
    }

    /// Adopts the sole fixed Network listener.
    ///
    /// # Safety
    ///
    /// The caller must be the single-threaded startup owner of systemd FD 3.
    /// No other owner or concurrent descriptor-table mutation may exist.
    ///
    /// # Errors
    ///
    /// Returns an error unless the exact named record-subject listener is present.
    pub unsafe fn adopt_network() -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        // SAFETY: forwarded from this method's exact startup ownership contract.
        unsafe {
            Self::adopt(&[(
                NETWORK_FD_NAME,
                ProtectedBrokerSessionFixedEndpointV1::NetworkBroker,
            )])
        }
    }

    /// Accepts and authenticates the next session before a boot-time deadline.
    ///
    /// Host polls both audience-specific listeners and selects protected custody
    /// solely from the ready listener's fixed descriptor name. Callers cannot
    /// substitute an audience, protocol, socket path, journal, or key root.
    ///
    /// # Errors
    ///
    /// Returns an error for changed listener configuration, failed acceptance,
    /// expired polling, or any protected-handshake rejection.
    /// A genuine Required Storage launch retains post-verified cold failure
    /// here; callers must terminate/hold rather than accept a replacement.
    pub fn accept_authenticated(
        &mut self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, ProductionBrokerSessionActivationErrorV1> {
        self.accept_authenticated_with_coverage_v1(deadline_boottime_nanoseconds, None)
    }

    /// Accepts a Storage HELLO through the original Storage receiving owner.
    ///
    /// The complete fixed Security/HELLO reservation is retained before polling,
    /// accepted endpoint custody or HELLO materialization. This selects neither
    /// a TPM floor nor the Output/Nix profiles. The same original cutoff and
    /// typed loan reach the protected main-journal continuation. The verified
    /// signed method subset is selected later by the daemon; this acquisition
    /// does not authorize a method or its domain effects.
    ///
    /// # Errors
    /// Refuses another listener table, a repeated selected attempt, receiving
    /// exhaustion/currentness failure, or any ordinary protected handshake error.
    /// The first actual outer error remains available through the diagnostic
    /// accessor; a retry cannot replace it or start another reservation.
    pub fn accept_authenticated_storage_prepare_v1(
        &mut self,
        deadline_boottime_nanoseconds: u64,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, ProductionBrokerSessionActivationErrorV1> {
        if self.storage_prepare_fixed.is_some() || self.has_failed_storage_cold() {
            return Err(Self::storage_prepare_closed_v1());
        }
        self.storage_prepare_fixed = Some(
            crate::recovery::BrokerMainOpenV1::reserve_storage_prepare_fixed_v1(receiving),
        );
        if !matches!(self.storage_prepare_fixed, Some(Ok(()))) {
            return Err(Self::storage_prepare_closed_v1());
        }

        let result = self.accept_initial_storage_session_v1(deadline_boottime_nanoseconds, receiving);
        match result {
            Ok(session) => {
                // Cold schema/floor/checkpoint/currentness and final same-D
                // retirement completed before its pure owning handoff here.
                self.storage_prepare_session = Some(session);
                let prefix = match self.storage_initial.take() {
                    Some(prefix) => prefix,
                    None => {
                        self.storage_prepare_failure = Some(Self::storage_prepare_closed_v1());
                        return Err(Self::storage_prepare_closed_v1());
                    }
                };
                let cold = match self.storage_cold.take() {
                    Some(cold) => cold,
                    None => {
                        self.storage_initial = Some(prefix);
                        self.storage_prepare_failure = Some(Self::storage_prepare_closed_v1());
                        return Err(Self::storage_prepare_closed_v1());
                    }
                };
                let session = match self.storage_prepare_session.as_mut() {
                    Some(session) => session,
                    None => std::process::abort(),
                };
                if let Err((cold, prefix)) = session.dispose_initial_storage_hello_v1(cold, receiving, prefix) {
                    // Keep the whole actual cold/Sent/facade and completed Session
                    // on refusal. No replacement accept can overwrite them.
                    self.storage_cold = Some(cold);
                    self.storage_initial = Some(prefix);
                    self.storage_prepare_failure = Some(Self::storage_prepare_closed_v1());
                    return Err(Self::storage_prepare_closed_v1());
                }

                // The facade was actually disposed under the same original
                // receiving currentness. Only pure moves follow that cleanup;
                // this does not renew D or initialize any request/history CAS.
                self.storage_prepare_complete = true;
                match self.storage_prepare_session.take() {
                    Some(session) => Ok(session),
                    None => std::process::abort(),
                }
            }
            Err(error) => {
                self.storage_prepare_failure = Some(error);
                Err(Self::storage_prepare_closed_v1())
            }
        }
    }

    fn accept_initial_storage_session_v1(
        &mut self,
        deadline: u64,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, ProductionBrokerSessionActivationErrorV1> {
        if self.storage_initial.is_some() || self.storage_initial_acceptance.is_some()
            || self.storage_cold.is_some()
        {
            return Err(Self::storage_prepare_closed_v1());
        }
        loop {
            // The fixed resident/FD shape was paid before this original poll.
            // No wire operation is consumed until a real socket is adopted.
            self.storage_initial_acceptance = Some(StorageRetainedSocketAcceptanceV1::new());
            let Some(acceptance) = self.storage_initial_acceptance.as_mut() else {
                std::process::abort()
            };
            Self::accept_storage_initial_socket_v1(&mut self.listeners, receiving, deadline, acceptance);
            if acceptance.failure().is_some() {
                return Err(Self::storage_prepare_closed_v1());
            }
            if acceptance.is_idle() {
                // Only actual poll0/no acquisition plus every available post
                // positive reaches disposal. The SAME finite cutoff remains.
                self.storage_initial_acceptance = None;
                continue;
            }
            let Some(socket) = acceptance.take_socket() else {
                return Err(Self::storage_prepare_closed_v1());
            };
            let Some(acceptance) = self.storage_initial_acceptance.take() else {
                std::process::abort()
            };
            self.storage_initial = Some(crate::handshake::StorageInitialSessionHandshakeV1::new(
                socket, acceptance, crate::handshake::OriginalBrokerColdDeadlineV1::storage_accept(deadline),
            ));
            let Some(initial) = self.storage_initial.as_mut() else {
                std::process::abort()
            };
            initial.drive_once(receiving, self.launch_image.clone(), &mut self.storage_cold);
            return initial.take_completed().ok_or_else(Self::storage_prepare_closed_v1);
        }
    }

    /// Borrows the original fixed-reservation or first outer selected failure.
    ///
    /// Native opening, cold-clock and receiving-accounting causes remain on
    /// their respective original owners and are exposed separately.
    pub fn storage_prepare_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let returned: &(dyn std::error::Error + 'static) = match self.storage_prepare_fixed.as_ref()? {
            Err(error) => Some(error as &dyn std::error::Error),
            Ok(()) => self.storage_initial_acceptance.as_ref().and_then(StorageRetainedSocketAcceptanceV1::failure)
                .or_else(|| self.storage_initial.as_ref().and_then(crate::handshake::StorageInitialSessionHandshakeV1::failure))
                .or_else(|| self.storage_prepare_failure.as_ref().map(|error| error as &dyn std::error::Error)),
        }?;
        let protected = match returned.downcast_ref::<DormantBrokerSessionHandshakeErrorV1>() {
            Some(DormantBrokerSessionHandshakeErrorV1::Protected(cause)) => Some(cause),
            _ => match returned.downcast_ref::<ProductionBrokerSessionActivationErrorV1>() {
                Some(ProductionBrokerSessionActivationErrorV1::Handshake(
                    DormantBrokerSessionHandshakeErrorV1::Protected(cause),
                )) => Some(cause),
                _ => None,
            },
        };
        protected.and_then(|cause| self.storage_cold.as_ref()
            .and_then(|cold| cold.retained_revalidation_failure_for(cause)))
            .or(Some(returned))
    }

    /// Borrows the actual captured Native journal-opening failure, if retained.
    pub fn storage_prepare_native_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.storage_prepare_session.as_ref()
            .and_then(DormantAuthenticatedBrokerSessionV1::storage_prepare_native_failure_v1)
            .or_else(|| self.storage_cold.as_ref()
                .and_then(|cold| cold.storage_prepare_native_failure_v1()))
    }

    /// Borrows the original ordinary cold-cutoff failure, if retained.
    pub fn storage_prepare_cold_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.storage_cold.as_ref()?.storage_prepare_cold_failure_v1()
    }

    fn storage_prepare_closed_v1() -> ProductionBrokerSessionActivationErrorV1 {
        DormantBrokerSessionHandshakeErrorV1::Protected(
            crate::BrokerSessionSecurityError::Currentness,
        ).into()
    }

    /// Accepts the selected Nix generation profile on the original Storage listener.
    ///
    /// The fixed Storage endpoint and genuine retained launch image are required
    /// before polling or acceptance. The same verified cold destination retains
    /// returned originals; the selected mode is not authority or a new deadline.
    ///
    /// # Errors
    ///
    /// Rejects another listener table, a missing original image, failed cold
    /// custody, expired polling or any unchanged protected-handshake failure.
    pub fn accept_authenticated_nix_generation_storage_v1(
        &mut self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, ProductionBrokerSessionActivationErrorV1> {
        self.accept_authenticated_with_purpose_v1(
            deadline_boottime_nanoseconds, None, ActivationAcceptPurposeV1::NixGeneration,
        )
    }

    /// Accepts the selected capture profile on the same original Storage listener.
    ///
    /// The daemon selects this only alongside its actual output custody. Neither
    /// this method nor the HELLO roster grants physical backing or execution.
    ///
    /// # Errors
    /// Rejects absent original launch custody, another listener or coverage
    /// purpose, and every unchanged cold-handshake or deadline failure.
    pub fn accept_authenticated_output_capture_storage_v1(
        &mut self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, ProductionBrokerSessionActivationErrorV1> {
        self.accept_authenticated_with_purpose_v1(
            deadline_boottime_nanoseconds, None, ActivationAcceptPurposeV1::OutputCapture,
        )
    }

    /// Accepts the opt-in Mount profile only after its actual owner comparison.
    ///
    /// # Errors
    /// Retains domain refusal before acceptance, or returns the unchanged
    /// activation/handshake failure. Lower constructor custody is not widened.
    pub fn accept_authenticated_mount_git_coverage_v1(
        &mut self,
        deadline_boottime_nanoseconds: u64,
        mount: &mut dyn aos_sandbox_mount::DormantMountBrokerCallsiteV1,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, ProductionBrokerSessionActivationErrorV1> {
        mount.recheck_git_coverage_response_v1(deadline_boottime_nanoseconds)
            .map_err(ProductionBrokerSessionActivationErrorV1::CoverageMount)?;
        self.accept_authenticated_with_coverage_v1(
            deadline_boottime_nanoseconds,
            Some(aos_sandbox_model::format::git_upload_enrollment::GitCoverageBrokerRoleV1::Mount),
        )
    }

    /// Accepts the opt-in Storage profile through the same retained cold engine.
    ///
    /// # Errors
    /// Retains unavailable or changed Storage/output originals before
    /// acceptance, or preserves the original activation/cold failure.
    pub fn accept_authenticated_storage_git_coverage_v1(
        &mut self,
        deadline_boottime_nanoseconds: u64,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, ProductionBrokerSessionActivationErrorV1> {
        storage.recheck_git_coverage_response_v1(output, deadline_boottime_nanoseconds)
            .map_err(ProductionBrokerSessionActivationErrorV1::CoverageStorage)?;
        self.accept_authenticated_with_coverage_v1(
            deadline_boottime_nanoseconds,
            Some(aos_sandbox_model::format::git_upload_enrollment::GitCoverageBrokerRoleV1::Storage),
        )
    }

    fn accept_authenticated_with_coverage_v1(
        &mut self,
        deadline_boottime_nanoseconds: u64,
        coverage: Option<aos_sandbox_model::format::git_upload_enrollment::GitCoverageBrokerRoleV1>,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, ProductionBrokerSessionActivationErrorV1> {
        self.accept_authenticated_with_purpose_v1(
            deadline_boottime_nanoseconds, coverage, ActivationAcceptPurposeV1::Ordinary,
        )
    }

    fn accept_authenticated_with_purpose_v1(
        &mut self,
        deadline_boottime_nanoseconds: u64,
        coverage: Option<aos_sandbox_model::format::git_upload_enrollment::GitCoverageBrokerRoleV1>,
        purpose: ActivationAcceptPurposeV1,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, ProductionBrokerSessionActivationErrorV1> {
        if matches!(purpose, ActivationAcceptPurposeV1::OutputCapture)
            && (coverage.is_some() || !self.has_original_output_capture_launch())
        {
            return Err(ProductionBrokerSessionActivationErrorV1::Activation(
                "selected capture inspection requires the original fixed Storage launch",
            ));
        }
        if matches!(purpose, ActivationAcceptPurposeV1::NixGeneration)
            && (coverage.is_some() || self.launch_image.is_none()
                || self.listeners.len() != 1
                || self.listeners[0].endpoint
                    != ProtectedBrokerSessionFixedEndpointV1::StorageBroker)
        {
            return Err(ProductionBrokerSessionActivationErrorV1::Activation(
                "selected Nix generation requires the original fixed Storage launch",
            ));
        }
        if self.storage_cold.as_ref()
            .is_some_and(crate::handshake::RetainedStorageColdOpenV1::is_failed)
            || (self.storage_prepare_fixed.is_some() && !self.storage_prepare_complete)
        {
            return Err(DormantBrokerSessionHandshakeErrorV1::Protected(
                crate::BrokerSessionSecurityError::Currentness,
            )
            .into());
        }
        loop {
            self.wait_until_ready(deadline_boottime_nanoseconds)?;

            for fixed in &mut self.listeners {
                fixed.listener.validate_current()?;
                let socket = match fixed.listener.accept() {
                    Ok(socket) => socket,
                    Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => continue,
                    Err(error) => return Err(error.into()),
                };
                if fixed.endpoint == ProtectedBrokerSessionFixedEndpointV1::StorageBroker
                    && self.launch_image.is_none()
                {
                    // Stable peer evidence alone does not select the Controller
                    // service. Check its exact unit before opening protected
                    // custody or publishing any ordinary handshake flight.
                    host::verify_controller_connection_peer(socket.peer())?;
                }
                let custody =
                    ProtectedBrokerSessionFixedCustodyV1::open_fixed_protected(fixed.endpoint)
                        .map_err(DormantBrokerSessionHandshakeErrorV1::Protected)?;
                let custody = custody
                    .retain_launch_image(self.launch_image.clone())
                    .map_err(DormantBrokerSessionHandshakeErrorV1::Protected)?;
                if fixed.endpoint == ProtectedBrokerSessionFixedEndpointV1::StorageBroker
                    && self.launch_image.is_some()
                {
                    let deadline = crate::handshake::OriginalBrokerColdDeadlineV1::storage_accept(
                        deadline_boottime_nanoseconds,
                    );
                    if matches!(purpose, ActivationAcceptPurposeV1::NixGeneration) {
                        return custody.complete_retained_nix_generation_storage_handshake(
                            socket, deadline, &mut self.storage_cold,
                        ).map_err(Into::into);
                    }
                    if matches!(purpose, ActivationAcceptPurposeV1::OutputCapture) {
                        return custody.complete_retained_output_capture_storage_handshake(
                            socket, deadline, &mut self.storage_cold,
                        ).map_err(Into::into);
                    }
                    return custody
                        .complete_retained_storage_handshake_with_coverage_v1(
                            socket, deadline, &mut self.storage_cold, coverage,
                        )
                        .map_err(Into::into);
                }
                return custody
                    .complete_production_broker_handshake_with_coverage_v1(
                        socket, deadline_boottime_nanoseconds, coverage,
                    )
                    .map_err(Into::into);
            }
        }
    }

    unsafe fn adopt(
        expected: &[(&'static str, ProtectedBrokerSessionFixedEndpointV1)],
    ) -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        validate_activation_process(expected.len())?;
        let names = activation_names(expected.len())?;
        // SAFETY: forwarded from each public constructor's exact ownership
        // contract after validating the complete systemd activation envelope.
        let descriptors = unsafe { claim_systemd_activation_descriptor_range(0, expected.len()) }
            .map_err(|_| ProductionBrokerSessionActivationErrorV1::Kernel)?
            .into_descriptors();
        let supplied = names
            .into_iter()
            .zip(descriptors)
            .collect::<BTreeMap<_, _>>();
        if supplied.len() != expected.len() {
            return Err(ProductionBrokerSessionActivationErrorV1::Activation(
                "descriptor names are duplicated",
            ));
        }

        let mut supplied = supplied;
        let mut listeners = Vec::with_capacity(expected.len());
        for (name, endpoint) in expected {
            let descriptor = supplied.remove(*name).ok_or(
                ProductionBrokerSessionActivationErrorV1::Activation(
                    "a fixed descriptor name is absent",
                ),
            )?;
            let listener = RecordSubjectListener::from_owned(descriptor)?;
            listener.require_local_filesystem_path(Path::new(endpoint.production_socket_path()))?;
            listeners.push(FixedListenerV1 {
                endpoint: *endpoint,
                listener,
            });
        }
        if !supplied.is_empty() {
            return Err(ProductionBrokerSessionActivationErrorV1::Activation(
                "an unexpected descriptor name is present",
            ));
        }

        Ok(Self {
            listeners,
            launch_image: None,
            storage_cold: None,
            storage_initial_acceptance: None,
            storage_initial: None,
            storage_prepare_fixed: None,
            storage_prepare_failure: None,
            storage_prepare_session: None,
            storage_prepare_complete: false,
            selected_storage_startup: None,
        })
    }

    fn from_owned_listener(
        endpoint: ProtectedBrokerSessionFixedEndpointV1,
        descriptor: OwnedFd,
    ) -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        let listener = RecordSubjectListener::from_owned(descriptor)?;
        listener.require_local_filesystem_path(Path::new(endpoint.production_socket_path()))?;
        Ok(Self {
            listeners: vec![FixedListenerV1 { endpoint, listener }],
            launch_image: None,
            storage_cold: None,
            storage_initial_acceptance: None,
            storage_initial: None,
            storage_prepare_fixed: None,
            storage_prepare_failure: None,
            storage_prepare_session: None,
            storage_prepare_complete: false,
            selected_storage_startup: None,
        })
    }

    fn wait_until_ready(
        &self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<(), ProductionBrokerSessionActivationErrorV1> {
        self.wait_until_ready_inner_v1(deadline_boottime_nanoseconds, None)
    }

    fn wait_until_ready_inner_v1(
        &self,
        deadline_boottime_nanoseconds: u64,
        native: Option<&mut Option<Result<usize, rustix::io::Errno>>>,
    ) -> Result<(), ProductionBrokerSessionActivationErrorV1> {
        wait_fixed_listeners_until_ready_v1(&self.listeners, deadline_boottime_nanoseconds, native)
    }
}

fn wait_fixed_listeners_until_ready_v1(
    listeners: &[FixedListenerV1],
    deadline_boottime_nanoseconds: u64,
    native: Option<&mut Option<Result<usize, rustix::io::Errno>>>,
) -> Result<(), ProductionBrokerSessionActivationErrorV1> {
    let remaining = remaining_duration(deadline_boottime_nanoseconds)?;
    let timeout = Timespec {
        tv_sec: i64::try_from(remaining / 1_000_000_000)
            .map_err(|_| ProductionBrokerSessionActivationErrorV1::Deadline)?,
        tv_nsec: i64::try_from(remaining % 1_000_000_000)
            .map_err(|_| ProductionBrokerSessionActivationErrorV1::Deadline)?,
    };
    let mut descriptors = listeners
        .iter()
        .map(|fixed| PollFd::from_borrowed_fd(fixed.listener.as_fd(), PollFlags::IN))
        .collect::<Vec<_>>();

    let observed = poll(&mut descriptors, Some(&timeout));
    if let Some(native) = native {
        *native = Some(observed);
    }
    match observed {
        Ok(0) => Err(ProductionBrokerSessionActivationErrorV1::Deadline),
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(_) => Err(ProductionBrokerSessionActivationErrorV1::Kernel),
    }
}

// Both ordinary and selected Storage admission borrow the same fixed predicate.
fn require_storage_listener_path(
    listener: &RecordSubjectListener,
) -> Result<(), ProductionBrokerSessionActivationErrorV1> {
    let endpoint = ProtectedBrokerSessionFixedEndpointV1::StorageBroker;
    listener.require_local_filesystem_path(Path::new(endpoint.production_socket_path()))?;
    Ok(())
}

pub(crate) use crate::activation_envelope::{
    activation_names, remaining_duration, validate_activation_process,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_listener_adoption_rejects_nonproduction_socket_paths() {
        let directory = tempfile::tempdir().unwrap();
        let controller =
            RecordSubjectListener::bind(&directory.path().join("controller.sock"), 1).unwrap();
        let root_mount =
            RecordSubjectListener::bind(&directory.path().join("mount.sock"), 1).unwrap();
        let storage =
            RecordSubjectListener::bind(&directory.path().join("storage.sock"), 1).unwrap();

        assert!(matches!(
            ProductionBrokerSessionActivationV1::adopt_host_listeners(
                controller, root_mount, storage,
            ),
            Err(ProductionBrokerSessionActivationErrorV1::Listener(_))
        ));
    }
}
