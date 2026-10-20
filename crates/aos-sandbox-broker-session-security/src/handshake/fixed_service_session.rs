//! Owns one image-enrolled Mount or Network cold Session from its real originals.
//!
//! A matching opening loan, fixed installer, captured Journal and inherited
//! listener stay together. The sole HELLO/cold engines retain their failures;
//! this owner always finishes the opening's native afters before lending a
//! completed Session. No raw Journal, descriptor or successful-marker factory
//! is exposed.

use super::*;
use crate::recovery::{FixedServiceColdJournalReceivingV4, ProtectedBrokerSessionFixedEndpointV1};
use crate::{
    SelectedFixedEndpointInstallClosedV4, SelectedMountEndpointInstallOriginalV4,
    SelectedNetworkEndpointInstallOriginalV4,
};
use aos_sandbox::journal::broker_session_receiving as geometry;
use aos_sandbox::journal::{
    CapturedJournalOpenModeV1, MountBrokerSessionCapturedJournalOpenV4,
    NetworkSessionSemanticReplayOriginalV1, ProtectedJournalPreopenReplayExtentV1,
    HostBrokerSessionCapturedJournalOpenV1,
};
use aos_sandbox_broker::canonical_journal::network_opening::NetworkBrokerSessionCapturedJournalOpenV4;
use aos_sandbox_broker::receiving::{
    FixedServiceListenerOriginalV4, FixedServiceOperationClosedV4,
    MountServiceSessionOpeningLoanV4 as Loan,
};
use aos_sandbox_broker::{
    BrokerAuthorityConfigError, ProtectedBrokerPublicCredentialRevalidationOriginalV1,
    ProtectedBrokerPublicCredentialRole, ProtectedBrokerPublicCredentialSnapshot,
    ProtectedBrokerPublicCredentials,
};
use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::seqpacket::{RecordSubjectListener, RetainedSeqpacketAdmissionErrorV1};
use sha2::{Digest as _, Sha256};

/// Reports a closed opening while all actual partial originals remain held.
#[derive(Debug, thiserror::Error)]
#[error("the original fixed-service cold Session remains closed")]
pub struct FixedServiceSessionClosedV4;

#[derive(Clone, Copy)]
enum Kind {
    Mount,
    Network,
    Host(aos_sandbox_host::HostControlColdSessionPurposeV1),
}

impl Kind {
    fn endpoint(self) -> ProtectedBrokerSessionFixedEndpointV1 {
        match self {
            Self::Mount => ProtectedBrokerSessionFixedEndpointV1::MountBroker,
            Self::Network => ProtectedBrokerSessionFixedEndpointV1::NetworkBroker,
            Self::Host(_) => ProtectedBrokerSessionFixedEndpointV1::HostBroker,
        }
    }

    fn root(self) -> &'static str {
        match self {
            Self::Mount => "/var/lib/aos/sandbox-mount/broker-session",
            Self::Network => "/var/lib/aos/sandbox-network/broker-session",
            Self::Host(_) => "/var/lib/aos/sandbox-host/broker-session",
        }
    }

    fn protocol(self) -> BrokerSessionProtocolV1 {
        match self {
            Self::Mount => BrokerSessionProtocolV1::Mount,
            Self::Network => BrokerSessionProtocolV1::Network,
            Self::Host(_) => BrokerSessionProtocolV1::Host,
        }
    }

    fn require(self, loan: &mut crate::endpoint::FixedServiceOpeningLoanV5<'_, '_>) -> Result<(), FixedServiceOperationClosedV4> {
        match (self, loan) {
            (Self::Mount, crate::endpoint::FixedServiceOpeningLoanV5::Fixed(loan)) => loan.require_mount_session_opening_current_v4(),
            (Self::Network, crate::endpoint::FixedServiceOpeningLoanV5::Fixed(loan)) => loan.require_network_session_opening_current_v4(),
            (Self::Host(purpose), crate::endpoint::FixedServiceOpeningLoanV5::Host(loan))
                if purpose == aos_sandbox_host::HostControlColdSessionPurposeV1::Bootstrap && loan.purpose_v1() == purpose =>
                loan.require_current_v1().map_err(|_| Default::default()),
            _ => Err(Default::default()),
        }
    }
}

enum Captured<'held> {
    Mount(&'held mut MountBrokerSessionCapturedJournalOpenV4),
    Network(&'held mut NetworkBrokerSessionCapturedJournalOpenV4),
    Host(&'held mut HostBrokerSessionCapturedJournalOpenV1),
}

enum ListenerV5<'held> {
    Fixed(&'held mut FixedServiceListenerOriginalV4),
    Host(&'held mut RecordSubjectListener),
}

enum PublicV5<'held> {
    Fixed(&'held ProtectedBrokerPublicCredentials),
    Host,
}

impl Captured<'_> {
    fn fixed(&self) -> Result<ResourceVector, GeometryFailure> {
        Ok(match self {
            Self::Mount(_) => MountBrokerSessionCapturedJournalOpenV4::fixed_preparation_demand()
                .map_err(GeometryFailure::Accounting)?,
            Self::Network(_) => NetworkBrokerSessionCapturedJournalOpenV4::fixed_preparation_demand()
                .map_err(GeometryFailure::Native)?,
            Self::Host(_) => HostBrokerSessionCapturedJournalOpenV1::fixed_preparation_demand()
                .map_err(GeometryFailure::Accounting)?,
        })
    }

    fn prepare(&mut self) {
        let limits = geometry::protected_session_journal_limits_v1();
        match self {
            Self::Mount(original) => original.prepare_once(limits, CapturedJournalOpenModeV1::CreateAndRepair),
            Self::Network(original) => original.prepare_once(limits, true),
            Self::Host(original) => original.prepare_once(limits, CapturedJournalOpenModeV1::ExistingOnly),
        }
    }

    fn extent(&self) -> Result<Option<ProtectedJournalPreopenReplayExtentV1>, GeometryFailure> {
        Ok(match self {
            Self::Mount(original) => original.captured_extent().copied(),
            Self::Network(original) => original.captured_extent().map(|extent|
                aos_sandbox::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
                    extent.limits(), extent.native_bytes())).transpose()?,
            Self::Host(original) => original.captured_extent().copied(),
        })
    }

    fn replay(&mut self, receiver: Option<&mut NetworkSessionSemanticReplayOriginalV1>,
        loan: &mut crate::endpoint::FixedServiceOpeningLoanV5<'_, '_>)
    {
        match self {
            Self::Mount(original) => original.replay_once(),
            Self::Network(original) => {
                if let (Some(receiver), crate::endpoint::FixedServiceOpeningLoanV5::Fixed(loan)) = (receiver, loan) {
                    receiver.observe_once(original, loan);
                }
            }
            Self::Host(original) => original.replay_once(),
        }
    }

    fn take(&mut self, receiver: Option<&mut NetworkSessionSemanticReplayOriginalV1>) -> Option<aos_sandbox::Journal> {
        match self {
            Self::Mount(original) => original.take_opened().map(|(journal, _)| journal),
            Self::Network(original) => receiver?.take_opened_once(original),
            Self::Host(original) => original.take_opened().map(|(journal, _)| journal),
        }
    }

    fn failure<'owner>(&'owner self, receiver: Option<&'owner NetworkSessionSemanticReplayOriginalV1>)
        -> Option<&'owner (dyn std::error::Error + 'static)>
    {
        match self {
            Self::Mount(original) => original.failure(),
            Self::Network(original) => match receiver {
                Some(receiver) => receiver.failure(original),
                None => original.failure(),
            },
            Self::Host(original) => original.failure(),
        }
    }

    fn external_failure_selected(&self, receiver: Option<&NetworkSessionSemanticReplayOriginalV1>) -> bool {
        match (self, receiver) {
            (Self::Network(original), Some(receiver)) => receiver.external_native_failure_selected_v1(original),
            _ => true,
        }
    }

}

enum Installer {
    Mount(SelectedMountEndpointInstallOriginalV4),
    Network(SelectedNetworkEndpointInstallOriginalV4),
}

impl Installer {
    fn run(&mut self, loan: &mut crate::endpoint::FixedServiceOpeningLoanV5<'_, '_>) -> Result<(), SelectedFixedEndpointInstallClosedV4> {
        let crate::endpoint::FixedServiceOpeningLoanV5::Fixed(loan) = loan else {
            return Err(SelectedFixedEndpointInstallClosedV4);
        };
        match self {
            Self::Mount(original) => original.install_once_v4(loan),
            Self::Network(original) => original.install_once_v4(loan),
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Mount(original) => original.failure(),
            Self::Network(original) => original.failure(),
        }
    }

    fn original_failure_selected(&self) -> bool {
        match self {
            Self::Mount(original) => original.original_failure_selected_v4(),
            Self::Network(original) => original.original_failure_selected_v4(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum GeometryFailure {
    #[error(transparent)]
    Native(#[from] aos_sandbox_broker::canonical_journal::NativeJournalDataErrorV1),
    #[error(transparent)]
    Journal(#[from] aos_sandbox::JournalError),
    #[error(transparent)]
    Schema(#[from] geometry::StorageSessionGeometryRefusalV1),
    #[error(transparent)]
    Accounting(#[from] aos_sandbox_core::AccountingError),
    #[error("the original captured extent is unavailable")]
    Missing,
}

#[derive(Clone, Copy)]
enum First {
    Order,
    Funding,
    Before,
    Clock,
    Installer,
    Journal,
    Endpoint,
    Credentials,
    Node,
    Listener,
    Wait,
    Accept,
    Start,
    Handshake,
    Cold,
    After,
}

/// Borrows only the actual fully completed fixed-service protected Session.
///
/// Construction is private to the owning cold recipe after native HELLO,
/// captured Journal, floor and independent opening closure all succeed.
pub struct FixedServiceSessionBorrowV4<'held> {
    pub(in crate::handshake) inner: &'held mut DormantAuthenticatedBrokerSessionV1,
}

/// Retains a complete finite cold attempt and every reached native prefix.
pub struct FixedServiceSessionOpenOriginalV4 {
    endpoint: crate::endpoint::ProtectedBrokerSessionBrokerOpeningV1,
    endpoint_custody: Option<ProtectedBrokerSessionBrokerV1>,
    installer: Option<Installer>,
    installed: Option<Result<(), SelectedFixedEndpointInstallClosedV4>>,
    public: ProtectedBrokerPublicCredentialRevalidationOriginalV1,
    credentials: Option<
        Result<
            [(
                ProtectedBrokerPublicCredentialRole,
                ProtectedBrokerPublicCredentialSnapshot,
            ); 6],
            BrokerAuthorityConfigError,
        >,
    >,
    extent: Option<ProtectedJournalPreopenReplayExtentV1>,
    geometry: Option<Result<ResourceVector, GeometryFailure>>,
    network_semantic: Option<Box<NetworkSessionSemanticReplayOriginalV1>>,
    funding: Option<Result<(), FixedServiceOperationClosedV4>>,
    before: Option<Result<(), FixedServiceOperationClosedV4>>,
    opening: Option<Result<RawPairedClockSample, FixedServiceOperationClosedV4>>,
    cutoff: Option<u64>,
    frontier: [Option<Result<RawPairedClockSample, FixedServiceOperationClosedV4>>; 2],
    listener: Option<RecordSubjectListener>,
    accepted: Option<Result<SeqpacketSocket, RetainedSeqpacketAdmissionErrorV1>>,
    start: Option<Box<storage_broker_start::StorageBrokerHandshakeStartV1>>,
    handshake: Option<Box<DormantBrokerEndpointHandshakeV1>>,
    handshake_error: Option<DormantBrokerSessionHandshakeErrorV1>,
    poll_native: Option<Result<usize, rustix::io::Errno>>,
    poll: Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    cold: Option<Box<RetainedStorageColdOpenV1>>,
    session: Option<
        Result<
            Box<DormantAuthenticatedBrokerSessionV1>,
            crate::DormantBrokerSessionHandshakeErrorV1,
        >,
    >,
    body: Option<Result<(), FixedServiceSessionClosedV4>>,
    body_marker: Option<Result<(), FixedServiceOperationClosedV4>>,
    captured_native_selected: bool,
    original_selected: bool,
    after: Option<Result<(), FixedServiceOperationClosedV4>>,
    first: Option<First>,
    kind: Option<Kind>,
    reentry: Option<FixedServiceSessionClosedV4>,
    reentry_marker: Option<Result<(), FixedServiceOperationClosedV4>>,
    reentry_after: Option<Result<(), FixedServiceOperationClosedV4>>,
    host_prefix: Option<aos_sandbox_host::HostControlColdSessionNativeRetentionV1>,
    host_after: Option<Result<(), aos_sandbox_host::HostControlColdSessionClosedV1>>,
    host_complete: Option<Result<(), aos_sandbox_host::HostControlColdSessionClosedV1>>,
}

impl FixedServiceSessionOpenOriginalV4 {
    /// Constructs only inert destinations; the actual runtime prepays its header.
    #[must_use]
    pub fn new() -> Self {
        Self {
            endpoint: crate::endpoint::ProtectedBrokerSessionBrokerOpeningV1::new(),
            endpoint_custody: None,
            installer: None,
            installed: None,
            public: Default::default(),
            credentials: None,
            extent: None,
            geometry: None,
            network_semantic: None,
            funding: None,
            before: None,
            opening: None,
            cutoff: None,
            frontier: [None, None],
            listener: None,
            accepted: None,
            start: None,
            handshake: None,
            handshake_error: None,
            poll_native: None,
            poll: None,
            cold: None,
            session: None,
            body: None,
            body_marker: None,
            captured_native_selected: false,
            original_selected: false,
            after: None,
            first: None,
            kind: None,
            reentry: None,
            reentry_marker: None,
            reentry_after: None,
            host_prefix: None,
            host_after: None,
            host_complete: None,
        }
    }

    /// Prices the shared actual broker HELLO and retained public-credential graph.
    ///
    /// The constructor header is included in this passive amount. The installer,
    /// endpoint and captured Journal add their actual supplier demands before
    /// their own native growth. Returns `None` on checked geometry overflow.
    #[must_use]
    pub fn fixed_opening_demand_v4() -> Option<ResourceVector> {
        Self::opening_demand_v5(false)
    }

    /// Prices all three authenticated Host choices on their shared cold engine.
    ///
    /// The complete HELLO/checkpoint ceilings dominate ordinary Host and each
    /// finite cleanup profile. This passive amount supplies no financial loan.
    #[must_use]
    pub fn host_cleanup_opening_demand_v1() -> Option<ResourceVector> {
        Self::opening_demand_v5(true)
    }

    fn opening_demand_v5(host: bool) -> Option<ResourceVector> {
        let (failure, _) = storage_preparation_handshake_failure_obligations_v1()?;
        let hello = CLIENT_HELLO_MAXIMUM_BYTES.checked_add(SERVER_HELLO_MAXIMUM_BYTES)?;
        let checkpoint = HistoricalSessionCheckpointConstructionCaptureV1::receiving_nonprojection_heap_bytes_v1(hello)?
            .checked_add(HistoricalSessionCheckpointConstructionCaptureV1::construction_bytes_v1())?;
        let private = geometry::StorageHandshakePrivateFootprintV1 {
            // Every lazy boxed owner is paid before construction; its moved
            // temporary can coexist with the boxed destination. Empty runtime
            // headers allocate none of these large native/cold variants.
            actual_inline_bytes: std::mem::size_of::<Self>()
                .checked_mul(2)?
                .checked_add(
                    std::mem::size_of::<storage_broker_start::StorageBrokerHandshakeStartV1>()
                        .checked_mul(2)?,
                )?
                .checked_add(
                    std::mem::size_of::<DormantBrokerEndpointHandshakeV1>().checked_mul(2)?,
                )?
                .checked_add(std::mem::size_of::<RetainedStorageColdOpenV1>().checked_mul(2)?)?
                .checked_add(
                    std::mem::size_of::<DormantAuthenticatedBrokerSessionV1>().checked_mul(2)?,
                )?,
            actual_failure_bytes: failure.checked_add(checkpoint)?,
            actual_failure_cells: 0,
        };
        let demand = geometry::fixed_service_broker_handshake_receiving_demand_v4(private).ok()?;
        let (bytes, files) = if host { (0, 0) } else {
            let (bytes, files, _) = ProtectedBrokerPublicCredentialRevalidationOriginalV1::receiving_obligations_v1()?;
            (bytes, files)
        };
        let floor = crate::recovery::floor_initial_capture_shape_v1(
            if host { aos_sandbox::ControllerInitialBrokerSessionRoleV1::Host }
                else { aos_sandbox::ControllerInitialBrokerSessionRoleV1::Mount },
        )?;
        let process = storage_process_evidence_footprint_v1()?;
        let memory = bytes
            .checked_add(floor.inline_bytes)?
            .checked_add(floor.heap_bytes)?
            .checked_add(process.inline_bytes)?
            .checked_add(process.heap_bytes)?;
        let files = files
            .checked_add(floor.open_files)?
            .checked_add(process.file_descriptors)?;
        demand
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, u64::try_from(memory).ok()?)
                    .with(D::OpenFiles, u64::try_from(files).ok()?),
            )
            .ok()
    }

    /// Opens Mount's real captured Session and always finishes its F opening.
    ///
    /// # Errors
    /// Retains every reached installer, journal, endpoint, HELLO or after refusal.
    pub fn open_mount_once_v4(
        &mut self,
        loan: &mut Loan<'_>,
        journal: &mut MountBrokerSessionCapturedJournalOpenV4,
        listener: &mut FixedServiceListenerOriginalV4,
        public: &ProtectedBrokerPublicCredentials,
    ) -> Result<(), FixedServiceSessionClosedV4> {
        self.open(
            loan,
            Captured::Mount(journal),
            listener,
            public,
            Kind::Mount,
        )
    }

    /// Opens Network's real captured Session and always finishes its F opening.
    ///
    /// # Errors
    /// Refuses another actual role or any retained native/protected failure.
    pub fn open_network_once_v4(
        &mut self,
        loan: &mut Loan<'_>,
        journal: &mut NetworkBrokerSessionCapturedJournalOpenV4,
        listener: &mut FixedServiceListenerOriginalV4,
        public: &ProtectedBrokerPublicCredentials,
    ) -> Result<(), FixedServiceSessionClosedV4> {
        self.open(
            loan,
            Captured::Network(journal),
            listener,
            public,
            Kind::Network,
        )
    }

    /// Opens a finite Host cleanup Session on the same captured current Control.
    ///
    /// The actual loan owns Source/native accounting. The listener remains with
    /// its installed service, while the accepted socket moves into this Session.
    /// Failed native prefixes and the private retention token stay on this owner.
    ///
    /// # Errors
    /// Refuses reentry, missing actual Source/native observations or any shared
    /// cold-engine failure. Independent Source and clock posts remain required.
    pub async fn open_host_cleanup_once_v1(
        &mut self,
        mut loan: aos_sandbox_host::HostControlColdSessionLoanV1<'_>,
        journal: &mut HostBrokerSessionCapturedJournalOpenV1,
        listener: &mut RecordSubjectListener,
        transport_cutoff: u64,
    ) -> Result<(), FixedServiceSessionClosedV4> {
        if self.kind.is_some() || loan.purpose_v1() != aos_sandbox_host::HostControlColdSessionPurposeV1::Bootstrap {
            self.first.get_or_insert(First::Order);
            let _ = loan.record_body_result_v1(Err(aos_sandbox_host::HostControlColdSessionClosedV1));
            self.host_after = Some(loan.observe_after_once_v1().await);
            self.after = Some(loan.finish_native_once_v1().map_err(|_| Default::default()));
            return Err(FixedServiceSessionClosedV4);
        }
        let kind = Kind::Host(loan.purpose_v1());
        self.kind = Some(kind);
        match loan.retain_native_prefix_once_v1() {
            Ok(token) => self.host_prefix = Some(token),
            Err(_) => { self.original_selected = true; self.first = Some(First::Funding); }
        }
        self.before = Some(loan.observe_before_once_v1().await.map_err(|_| Default::default()));
        if !matches!(self.before, Some(Ok(()))) && self.first.is_none() {
            self.original_selected = true;
            self.first = Some(First::Before);
        }
        self.body = Some(if self.first.is_none() {
            self.drive(&mut crate::endpoint::FixedServiceOpeningLoanV5::Host(&mut loan),
                &mut Captured::Host(journal), ListenerV5::Host(listener), PublicV5::Host, kind,
                Some(transport_cutoff))
        } else { Err(FixedServiceSessionClosedV4) });
        let body = if matches!(self.body, Some(Ok(()))) { Ok(()) }
            else { Err(aos_sandbox_host::HostControlColdSessionClosedV1) };
        self.body_marker = Some(loan.record_body_result_v1(body).map_err(|_| Default::default()));
        self.host_after = Some(loan.observe_after_once_v1().await);
        self.after = Some(loan.finish_native_once_v1().map_err(|_| Default::default()));
        if self.first.is_some() || !matches!(self.body_marker, Some(Ok(())))
            || !matches!(self.host_after, Some(Ok(()))) || !matches!(self.after, Some(Ok(())))
        {
            if self.first.is_none() { self.original_selected = true; self.first = Some(First::After); }
            return Err(FixedServiceSessionClosedV4);
        }

        self.retire_host_temporary_prefix_v1(journal)?;
        self.host_complete = Some(loan.complete_after_native_drop_v1());
        if !matches!(self.host_complete, Some(Ok(()))) {
            self.original_selected = true;
            return self.close(First::After);
        }
        Ok(())
    }

    fn retire_host_temporary_prefix_v1(&mut self, journal: &mut HostBrokerSessionCapturedJournalOpenV1)
        -> Result<(), FixedServiceSessionClosedV4> {
        if !matches!(self.kind, Some(Kind::Host(_))) || self.host_prefix.is_none()
            || !journal.was_taken_positive_v1()
            || !self.cold.as_ref().is_some_and(|cold| cold.completed_transfer_shell_v1())
            || !self.start.as_ref().is_some_and(|start| start.completed_transfer_shell_v1())
            || !self.endpoint.completed_transfer_shell_v1()
            || self.endpoint_custody.is_some() || self.handshake.is_some()
            || self.handshake_error.is_some() || self.accepted.is_some()
            || !matches!(self.session, Some(Ok(_)))
        { return self.close(First::Order); }

        // These shells no longer own the Journal, floor, endpoint, transcript,
        // socket or checkpoint: those SAME owners remain in `self.session`.
        drop(self.cold.take());
        drop(self.start.take());
        drop(std::mem::replace(&mut self.endpoint, crate::endpoint::ProtectedBrokerSessionBrokerOpeningV1::new()));
        drop(std::mem::take(&mut self.public));
        drop(self.credentials.take());
        drop(std::mem::take(journal));
        drop(self.host_prefix.take());
        Ok(())
    }

    fn close<T>(&mut self, stage: First) -> Result<T, FixedServiceSessionClosedV4> {
        if self.first.is_none() {
            self.original_selected = match stage {
                First::Funding | First::Before | First::After => true,
                First::Clock => {
                    self.opening.as_ref().is_some_and(Result::is_err)
                        || self
                            .frontier
                            .iter()
                            .any(|value| value.as_ref().is_some_and(Result::is_err))
                }
                _ => self.original_selected,
            };
            self.first = Some(stage);
        }
        Err(FixedServiceSessionClosedV4)
    }

    fn open(
        &mut self,
        loan: &mut Loan<'_>,
        mut journal: Captured<'_>,
        listener: &mut FixedServiceListenerOriginalV4,
        public: &ProtectedBrokerPublicCredentials,
        kind: Kind,
    ) -> Result<(), FixedServiceSessionClosedV4> {
        if self.kind.is_some() {
            // No SDK native body is re-entered. The caller still supplied an
            // actual already-armed opening: its prearmed before/after remain
            // independently owed, and this refusal must poison that interval.
            self.reentry.get_or_insert(FixedServiceSessionClosedV4);
            self.first.get_or_insert(First::Order);
            let marker = loan.record_body_result_v4(Err(FixedServiceOperationClosedV4::default()));
            let after = loan.finish_native_once_v4();
            if self.reentry_marker.is_none() { self.reentry_marker = Some(marker); }
            if self.reentry_after.is_none() { self.reentry_after = Some(after); }
            // Any additional refusal contains only the closed status. Its
            // actual native graphs/results remain on the supplied operation;
            // original body/after and the first reentry are never replaced.
            return Err(FixedServiceSessionClosedV4);
        }
        self.kind = Some(kind);
        self.body = Some(self.drive(&mut crate::endpoint::FixedServiceOpeningLoanV5::Fixed(loan), &mut journal, ListenerV5::Fixed(listener), PublicV5::Fixed(public), kind, None));
        // The exact original cause is latched before independent native debt.
        let body = if matches!(self.body, Some(Ok(()))) {
            Ok(())
        } else {
            Err(FixedServiceOperationClosedV4::default())
        };
        self.body_marker = Some(loan.record_body_result_v4(body));
        self.after = Some(loan.finish_native_once_v4());
        if !matches!(self.body_marker, Some(Ok(()))) || !matches!(self.after, Some(Ok(()))) {
            if self.first.is_none() {
                self.original_selected = true;
                self.first = Some(First::After);
            }
        }
        if self.first.is_none() && matches!(self.body, Some(Ok(()))) {
            Ok(())
        } else {
            Err(FixedServiceSessionClosedV4)
        }
    }

    fn drive(
        &mut self,
        loan: &mut crate::endpoint::FixedServiceOpeningLoanV5<'_, '_>,
        journal: &mut Captured<'_>,
        listener: ListenerV5<'_>,
        public: PublicV5<'_>,
        kind: Kind,
        cutoff_limit: Option<u64>,
    ) -> Result<(), FixedServiceSessionClosedV4> {
        // The public entry verifies its own compiled invoice on the actual
        // loan. A caller-supplied initial amount cannot waive these native
        // destinations; enclosing headers were independently paid at startup.
        let Some(fixed) = Self::opening_demand_v5(matches!(kind, Kind::Host(_))) else {
            return self.close(First::Order);
        };
        self.funding = Some(loan.require_fixed_representation_v5(fixed));
        if !matches!(self.funding, Some(Ok(()))) {
            return self.close(First::Funding);
        }
        self.before = Some(loan.observe_before_once_v4());
        if !matches!(self.before, Some(Ok(()))) {
            return self.close(First::Before);
        }
        self.opening = Some(loan.actual_before_clock_v4());
        let Some(Ok(origin)) = self.opening.as_ref() else {
            return self.close(First::Clock);
        };
        // This is the installed broker's existing 30-second accept duration,
        // anchored to the actual paid opening sample rather than a later clock.
        self.cutoff = origin.boottime_nanoseconds().checked_add(30_000_000_000)
            .map(|cutoff| cutoff_limit.map_or(cutoff, |limit| cutoff.min(limit)));
        let Some(cutoff) = self.cutoff else {
            return self.close(First::Clock);
        };
        self.funding = Some(
            loan.narrow_deadline_data_v4(cutoff, None)
                .and_then(|_| kind.require(loan)),
        );
        if !matches!(self.funding, Some(Ok(()))) {
            return self.close(First::Funding);
        }
        self.installer = match kind {
            Kind::Mount => Some(Installer::Mount(SelectedMountEndpointInstallOriginalV4::new())),
            Kind::Network => Some(Installer::Network(SelectedNetworkEndpointInstallOriginalV4::new())),
            // Current Host custody already exists. Cleanup never re-enrolls it.
            Kind::Host(_) => None,
        };
        self.installed = self.installer.as_mut().map(|installer| installer.run(loan));
        if !matches!(kind, Kind::Host(_)) && !matches!(self.installed, Some(Ok(()))) {
            self.original_selected = self
                .installer
                .as_ref()
                .is_some_and(Installer::original_failure_selected);
            return self.close(First::Installer);
        }

        self.geometry = Some(journal.fixed());
        let Some(journal_fixed) = self.geometry.as_ref().and_then(|shape| shape.as_ref().ok()).copied() else {
            return self.close(First::Journal);
        };
        self.funding = Some(match loan {
            crate::endpoint::FixedServiceOpeningLoanV5::Fixed(loan) =>
                loan.require_additional_representation_v4(journal_fixed),
            crate::endpoint::FixedServiceOpeningLoanV5::Host(loan) =>
                match fixed.checked_add(journal_fixed) {
                    Ok(complete) => loan.raise_complete_v1(complete).map_err(|_| Default::default()),
                    Err(_) => Err(Default::default()),
                },
        });
        if !matches!(self.funding, Some(Ok(()))) {
            return self.close(First::Funding);
        }
        journal.prepare();
        self.geometry = Some(journal.extent().map(|extent| {
            self.extent = extent;
            ResourceVector::ZERO
        }));
        if !matches!(self.geometry, Some(Ok(_))) { return self.close(First::Journal); }
        if journal.failure(self.network_semantic.as_deref()).is_some() {
            self.captured_native_selected = true;
            return self.close(First::Journal);
        }
        self.geometry = Some((|| {
            let extent = self.extent.as_ref().ok_or(GeometryFailure::Missing)?;
            let receiver = if matches!(kind, Kind::Network) {
                NetworkSessionSemanticReplayOriginalV1::receiving_demand_v1()?
            } else { ResourceVector::ZERO };
            let native = match journal {
                Captured::Network(original) => NetworkSessionSemanticReplayOriginalV1::native_receiving_demand_v1(original)?,
                _ => extent.dominant_native_receiving_demand_v1()?,
            };
            Ok(native.checked_add(extent.dominant_semantic_receiving_demand_v1()?)?
                .checked_add(geometry::schema_demand(extent)?)?
                .checked_add(geometry::initialization_demand(extent)?)?
                .checked_add(receiver)?)
        })());
        let Some(shape) = self
            .geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
        else {
            return self.close(First::Journal);
        };
        self.funding = Some(loan.require_additional_representation_v4(shape));
        if !matches!(self.funding, Some(Ok(()))) {
            return self.close(First::Funding);
        }
        if matches!(kind, Kind::Network) {
            self.network_semantic = Some(Box::new(NetworkSessionSemanticReplayOriginalV1::new()));
        }
        journal.replay(self.network_semantic.as_deref_mut(), loan);
        if journal.failure(self.network_semantic.as_deref()).is_some() {
            self.captured_native_selected = journal.external_failure_selected(self.network_semantic.as_deref());
            return self.close(First::Journal);
        }

        match (kind, &mut *loan) {
            (Kind::Mount, crate::endpoint::FixedServiceOpeningLoanV5::Fixed(loan)) => self.endpoint.load_mount_session_opening_once_v4(loan),
            (Kind::Network, crate::endpoint::FixedServiceOpeningLoanV5::Fixed(loan)) => self.endpoint.load_network_session_opening_once_v4(loan),
            (Kind::Host(_), crate::endpoint::FixedServiceOpeningLoanV5::Host(loan)) => self.endpoint.load_host_cleanup_session_opening_once_v1(loan),
            _ => return self.close(First::Order),
        }
        let Some(endpoint) = self.endpoint.take_completed() else {
            self.original_selected = self.endpoint.fixed_service_original_failure_selected_v4();
            return self.close(First::Endpoint);
        };
        self.endpoint_custody = Some(endpoint);
        let Some(endpoint) = self.endpoint_custody.as_ref() else {
            return self.close(First::Endpoint);
        };
        let (_, node) = endpoint.protected_protocol_and_node();
        // Fixed services join their actual public-credential owner. Host joins
        // the node already protected by its same current-Control Source loan.
        if let PublicV5::Fixed(public) = public {
            self.credentials = Some(
                public.revalidated_descriptor_evidence_retaining_v1(&mut self.public)
                    .map(|rows| rows.map(|(role, _, snapshot)| (role, snapshot))),
            );
            if !matches!(self.credentials, Some(Ok(_))) {
                return self.close(First::Credentials);
            }
            let node_digest: [u8; 32] = Sha256::digest(node).into();
            if !self.credentials.as_ref().and_then(|value| value.as_ref().ok())
                .is_some_and(|rows| {
                    rows.iter().any(|(role, snapshot)| {
                        *role == ProtectedBrokerPublicCredentialRole::NodeId
                            && snapshot.bytes() == 16
                            && snapshot.sha256() == node_digest
                    })
                })
            {
                return self.close(First::Node);
            }
        } else {
            let crate::endpoint::FixedServiceOpeningLoanV5::Host(loan) = loan else {
                return self.close(First::Order);
            };
            self.funding = Some(loan.require_node_data_v1(node).map_err(|_| Default::default()));
            if !matches!(self.funding, Some(Ok(()))) {
                self.original_selected = true;
                return self.close(First::Node);
            }
        }
        let listener = match listener {
            ListenerV5::Fixed(original) => {
                self.listener = original.take_completed_listener_once_v4();
                let Some(listener) = self.listener.as_mut() else {
                    return self.close(First::Listener);
                };
                listener
            }
            ListenerV5::Host(original) => original,
        };
        self.poll = Some(
            crate::dormant_handshake::wait_for_handshake_readiness_retaining_v1(
                listener.as_fd(),
                false,
                cutoff,
                &mut self.poll_native,
            ),
        );
        if !matches!(self.poll, Some(Ok(()))) {
            return self.close(First::Wait);
        }
        self.accepted = Some(listener.accept_retaining());
        if !matches!(self.accepted, Some(Ok(_))) {
            return self.close(First::Accept);
        }
        let Some(Ok(socket)) = self.accepted.take() else {
            std::process::abort()
        };
        let Some(endpoint) = self.endpoint_custody.take() else {
            return self.close(First::Endpoint);
        };
        self.start = Some(Box::new(
            storage_broker_start::StorageBrokerHandshakeStartV1::new(
                kind.root(),
                BrokerHandshakeCustodyV1::Fresh(endpoint),
                socket,
            ),
        ));
        let Some(start) = self.start.as_mut() else {
            return self.close(First::Start);
        };
        match kind {
            Kind::Host(_) => start.initialize_host_cleanup_once_v1(),
            _ => start.initialize_fixed_service_once_v4(kind.protocol()),
        }
        self.handshake = self
            .start
            .as_mut()
            .and_then(|start| start.take_ready())
            .map(Box::new);
        if self.handshake.is_none() {
            return self.close(First::Start);
        }
        let mut sends = 0;
        for _ in 0..3 {
            let Some(pending) = self.handshake.as_ref() else {
                return self.close(First::Handshake);
            };
            let writing = pending.wants_write();
            if writing {
                let Some(slot) = self.frontier.get_mut(sends) else {
                    return self.close(First::Order);
                };
                *slot = Some(loan.fresh_before_effect_clock_v4());
                if !matches!(slot, Some(Ok(_))) {
                    return self.close(First::Clock);
                }
                sends += 1;
            } else {
                let fd = match pending.as_fd() {
                    Ok(fd) => fd,
                    Err(cause) => {
                        self.handshake_error = Some(cause);
                        return self.close(First::Handshake);
                    }
                };
                self.poll = Some(
                    crate::dormant_handshake::wait_for_handshake_readiness_retaining_v1(
                        fd,
                        false,
                        cutoff,
                        &mut self.poll_native,
                    ),
                );
                if !matches!(self.poll, Some(Ok(()))) {
                    return self.close(First::Wait);
                }
            }
            let Some(pending) = self.handshake.take() else {
                std::process::abort()
            };
            match (*pending).advance_retaining_storage() {
                Ok(ColdBrokerHandshakeProgressV1::Pending(pending)) => {
                    let advanced = pending.wants_write() != writing;
                    self.handshake = Some(Box::new(pending));
                    if !advanced {
                        return self.close(First::Handshake);
                    }
                }
                Ok(ColdBrokerHandshakeProgressV1::Verified(verified)) => {
                    self.cold = Some(Box::new(RetainedStorageColdOpenV1::retain(
                        verified,
                        OriginalBrokerColdDeadlineV1::storage_accept(cutoff),
                    )));
                    let mut context = Context {
                        kind,
                        loan,
                        journal,
                        network_semantic: self.network_semantic.as_deref_mut(),
                        captured_native_selected: &mut self.captured_native_selected,
                        original_selected: &mut self.original_selected,
                    };
                    self.session = self
                        .cold
                        .as_mut()
                        .map(|cold| cold.finish_fixed_service_v4(&mut context).map(Box::new));
                    if matches!(self.session, Some(Ok(_))) {
                        return Ok(());
                    }
                    return self.close(First::Cold);
                }
                Ok(ColdBrokerHandshakeProgressV1::Complete(session)) => {
                    self.session = Some(Ok(Box::new(session)));
                    return self.close(First::Handshake);
                }
                Err(cause) => {
                    self.handshake_error = Some(cause);
                    return self.close(First::Handshake);
                }
            }
        }
        self.close(First::Handshake)
    }

    /// Identifies the actual captured Journal's earlier native refusal.
    ///
    /// Its source remains on the SAME actual Domain-owned captured original;
    /// this diagnostic selector creates no Journal, loan or completion proof.
    #[must_use]
    pub fn captured_journal_failure_selected_v4(&self) -> bool {
        self.captured_native_selected
    }

    /// Identifies only the actual loan gate selected before later owed afters.
    #[must_use]
    pub fn original_failure_selected_v4(&self) -> bool {
        self.original_selected
    }

    /// Borrows the selected original failure while all reached owners stay held.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Funding => self
                .funding
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Before => self.before.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Clock => self
                .opening
                .as_ref()
                .and_then(|v| v.as_ref().err())
                .map(|cause| cause as _)
                .or_else(|| {
                    self.frontier
                        .iter()
                        .find_map(|v| v.as_ref()?.as_ref().err())
                        .map(|cause| cause as _)
                })
                .or(Some(&FixedServiceSessionClosedV4)),
            First::Installer => self.installer.as_ref().and_then(Installer::failure),
            First::Journal => self.network_semantic.as_ref()
                .and_then(|original| original.local_failure_v1())
                .or_else(|| self.geometry
                .as_ref()
                .and_then(|v| v.as_ref().err())
                .map(|cause| cause as _))
                .or(Some(&FixedServiceSessionClosedV4)),
            First::Endpoint => self.endpoint.failure(),
            First::Credentials => self.public.failure().or_else(|| {
                self.credentials
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            }),
            First::Wait => self
                .poll_native
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as _)
                .or_else(|| self.poll.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Accept => self
                .accepted
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Start => self.start.as_ref().and_then(|start| start.failure()),
            First::Handshake => self
                .handshake_error
                .as_ref()
                .map(|cause| cause as _)
                .or_else(|| {
                    self.handshake
                        .as_ref()
                        .and_then(|pending| pending.pending_native_failure_v4())
                })
                .or(Some(&FixedServiceSessionClosedV4)),
            First::Cold => self
                .cold
                .as_ref()
                .and_then(|cold| match cold.first_failure.as_ref()? {
                    crate::DormantBrokerSessionHandshakeErrorV1::Protected(cause) => cold
                        .retained_revalidation_failure_for(cause)
                        .or_else(|| cold.controller_initial_native_failure_v1())
                        .or(Some(cause as &(dyn std::error::Error + 'static))),
                    cause => Some(cause as &(dyn std::error::Error + 'static)),
                })
                .or_else(|| {
                    self.session
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            First::After => self
                .body_marker
                .as_ref()
                .and_then(|v| v.as_ref().err())
                .map(|cause| cause as _)
                .or_else(|| self.after.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Order | First::Node | First::Listener => Some(&FixedServiceSessionClosedV4),
        }
    }

    /// Borrows the same completed Session after all opening obligations succeed.
    ///
    /// # Errors
    /// Refuses any incomplete native/HELLO/body or independent opening after.
    pub fn session_mut_v4(
        &mut self,
    ) -> Result<FixedServiceSessionBorrowV4<'_>, FixedServiceSessionClosedV4> {
        if self.first.is_some()
            || !matches!(self.body, Some(Ok(())))
            || !matches!(self.after, Some(Ok(())))
            || (matches!(self.kind, Some(Kind::Host(_))) && !matches!(self.host_complete, Some(Ok(()))))
        {
            return Err(FixedServiceSessionClosedV4);
        }
        match self.session.as_mut() {
            Some(Ok(inner)) => Ok(FixedServiceSessionBorrowV4 {
                inner: inner.as_mut(),
            }),
            _ => Err(FixedServiceSessionClosedV4),
        }
    }

    pub(crate) fn take_completed_host_session_v1(&mut self)
        -> Result<DormantAuthenticatedBrokerSessionV1, FixedServiceSessionClosedV4> {
        self.original_transport_deadline_data_v4()?;
        if !matches!(self.kind, Some(Kind::Host(_))) || self.host_prefix.is_some()
            || self.cold.is_some() || self.start.is_some()
        { return Err(FixedServiceSessionClosedV4); }
        match self.session.take() {
            Some(Ok(session)) => Ok(*session),
            _ => Err(FixedServiceSessionClosedV4),
        }
    }

    /// Returns the original transport cutoff without sampling or renewing it.
    ///
    /// # Errors
    /// Refuses an incomplete opening or missing original paid clock/cutoff.
    pub fn original_transport_deadline_data_v4(&self) -> Result<u64, FixedServiceSessionClosedV4> {
        if self.first.is_some()
            || !matches!(self.body, Some(Ok(())))
            || !matches!(self.after, Some(Ok(())))
            || (matches!(self.kind, Some(Kind::Host(_))) && !matches!(self.host_complete, Some(Ok(()))))
        {
            return Err(FixedServiceSessionClosedV4);
        }
        self.cutoff.ok_or(FixedServiceSessionClosedV4)
    }

    /// Selects a read-only first request from the actual authenticated HELLO.
    ///
    /// This DATA changes only finite service scheduling. The distinct native
    /// inventory loan still independently pays and authenticates each request.
    ///
    /// # Errors
    /// Refuses incomplete opening/native posts or a missing original Session.
    pub fn inventory_only_profile_data_v2(&self) -> Result<bool, FixedServiceSessionClosedV4> {
        self.original_transport_deadline_data_v4()?;
        let session = self.session.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(FixedServiceSessionClosedV4)?;
        let method = match self.kind.ok_or(FixedServiceSessionClosedV4)? {
            Kind::Mount => BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS,
            Kind::Network => BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
            Kind::Host(_) => return Err(FixedServiceSessionClosedV4),
        };
        Ok(session.transcript.required_methods() == [method])
    }

    /// Requires the actual new full Network profile or its read-only singleton.
    ///
    /// # Errors
    /// Refuses incomplete opening, another role, or the historical two-method
    /// profile. This comparison grants no request or effect permission.
    pub fn require_network_service_profile_v5(&self) -> Result<(), FixedServiceSessionClosedV4> {
        self.original_transport_deadline_data_v4()?;
        let session = self.session.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(FixedServiceSessionClosedV4)?;
        if !matches!(self.kind, Some(Kind::Network))
            || !(aos_sandbox_broker_session_protocol::profile::is_network_service_transcript_v5(&session.transcript)
                || aos_sandbox_broker_session_protocol::profile::is_network_inventory_transcript_v5(&session.transcript)) {
            return Err(FixedServiceSessionClosedV4);
        }
        Ok(())
    }
}

struct Context<'held, 'loan, 'turn, 'capture> {
    kind: Kind,
    loan: &'held mut crate::endpoint::FixedServiceOpeningLoanV5<'loan, 'turn>,
    journal: &'held mut Captured<'capture>,
    network_semantic: Option<&'held mut NetworkSessionSemanticReplayOriginalV1>,
    captured_native_selected: &'held mut bool,
    original_selected: &'held mut bool,
}

impl FixedServiceColdJournalReceivingV4 for Context<'_, '_, '_, '_> {
    fn host_cleanup_purpose_v1(&self) -> Option<aos_sandbox_host::HostControlColdSessionPurposeV1> {
        match self.kind { Kind::Host(purpose) => Some(purpose), _ => None }
    }
    fn fixed_endpoint_v4(&self) -> ProtectedBrokerSessionFixedEndpointV1 {
        self.kind.endpoint()
    }
    fn require_current_v4(&mut self) -> Result<(), BrokerSessionSecurityError> {
        self.kind.require(self.loan).map_err(|_| {
            *self.original_selected = true;
            BrokerSessionSecurityError::Currentness
        })
    }
    fn take_captured_journal_v4(
        &mut self,
    ) -> Result<aos_sandbox::Journal, BrokerSessionSecurityError> {
        self.require_current_v4()?;
        match self.journal.take(self.network_semantic.as_deref_mut()) {
            Some(journal) => Ok(journal),
            None => {
                *self.captured_native_selected = self.journal.external_failure_selected(self.network_semantic.as_deref())
                    && self.journal.failure(self.network_semantic.as_deref()).is_some();
                Err(BrokerSessionSecurityError::Currentness)
            }
        }
    }
}

impl Default for FixedServiceSessionOpenOriginalV4 {
    fn default() -> Self {
        Self::new()
    }
}
