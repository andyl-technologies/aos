//! Authenticated broker-session custody, transport, and domain integration.
//!
//! Explicitly adopted sequenced-packet sockets progress through sealed hello
//! states in `crate::handshake`. This module retains exact request/response
//! custody and joins concrete domain effects to protected terminal commits and
//! recovery. Its private `host_catalog_publication` child owns catalog
//! publication integration, descriptor custody, and readback/retry recipes;
//! `host_scope_terminal` owns Host scope descriptor reservoirs and their
//! terminal commit, finalization, replay reopening, and transport recipes.
//! Shared session mechanics remain with their original owners. These private
//! groups do not isolate the concrete domain dependency closure.
//!
//! This module performs no listener or route registration.

enum StorageApplyDispatchV1<'owner, 'cut, 'original> {
    Ordinary(crate::DormantStorageBrokerEffectAdapterV1<'owner>),
    Receiving {
        storage: &'owner mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        receiving: &'owner mut aos_sandbox::StorageLifecycleSessionLoanV1<'cut, 'original>,
        native_admission: &'owner mut Option<aos_sandbox::StorageReceivingClosedV1>,
    },
}

enum StorageOperationDispatchV1<'owner, 'cut, 'original> {
    Ordinary(crate::DormantStorageBrokerEffectAdapterV1<'owner>),
    Lifecycle {
        storage: &'owner mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        receiving: &'owner mut aos_sandbox::StorageLifecycleSessionLoanV1<'cut, 'original>,
        native_admission: &'owner mut Option<aos_sandbox::StorageReceivingClosedV1>,
    },
}

enum StorageInventoryDispatchV1<'owner, 'cut, 'original> {
    Ordinary,
    Prepare(&'owner mut aos_sandbox::StoragePrepareReceivingLoanV1<'original>),
    Lifecycle {
        receiving: &'owner mut aos_sandbox::StorageLifecycleSessionLoanV1<'cut, 'original>,
        native_admission: &'owner mut Option<aos_sandbox::StorageReceivingClosedV1>,
    },
}

enum StorageOutcomeReceivingV1<'owner, 'cut, 'original> {
    Prepare(&'owner mut aos_sandbox::StoragePrepareReceivingLoanV1<'original>),
    Lifecycle(&'owner mut aos_sandbox::StorageLifecycleSessionLoanV1<'cut, 'original>),
}

impl StorageOutcomeReceivingV1<'_, '_, '_> {
    fn source_v3(&mut self) -> &mut dyn crate::recovery::StorageFloorFinancialSourceV2 {
        match self {
            Self::Prepare(source) => &mut **source,
            Self::Lifecycle(source) => &mut **source,
        }
    }
}

mod consumer_cgroup_terminal;
mod fuse_worker_preparation;
mod host_catalog_publication;
mod host_scope_terminal;
mod host_worker_comparison;
mod storage_client_continuation;
mod storage_execution_availability;
mod host_execution_availability;
mod delete_inventory;
pub use delete_inventory::OriginalDeleteInventoryClientV1;
mod readiness;
pub(crate) use readiness::HandshakeReadinessOriginalsV1;
#[doc(hidden)]
pub use storage_client_continuation::{OriginalStorageClientSessionTransitionV1, OriginalStorageClientTransitionClosedV1};

pub use host_catalog_publication::{
    DormantBrokerPublicationExecutionFailureV1, DormantHostCatalogPublicationRecoveryProgressV1,
    DormantHostCatalogPublicationRetryV1, DormantHostCatalogPublicationUnknownV1,
};

pub use host_scope_terminal::{
    DormantReadyBrokerDescriptorTerminalReplayV1,
    DormantBrokerDescriptorOutcomeUnknownV1,
    DormantBrokerDescriptorExecutionFailureV1,
    DormantBrokerDescriptorResponseProgressV1,
    DormantHostConsumerCgroupResponseProgressV1,
    DormantHostMountScopeIdentityResponseProgressV1,
    DormantBrokerDescriptorTerminalReplayRecoveryProgressV1,
    DormantBrokerDescriptorTerminalReplaySendProgressV1,
    DormantBrokerDescriptorCommitResultV1,
    DormantHostScopeTerminalFinalizationV1,
    DormantCommittedBrokerDescriptorResponseV1,
    DormantBrokerDescriptorCommitRecoveryV1,
    DormantBrokerDescriptorSendRecoveryV1,
    DormantBrokerDescriptorSendProgressV1,
};

pub(crate) use host_worker_comparison::{
    DormantOriginalHostWorkerComparisonV1, OriginalHostWorkerComparisonSendProgressV1,
    OriginalMountHostWorkerComparisonProgressV1,
};

use crate::handshake::output_registration_continuation::{
    OriginalStorageCreatePreparationFlightV1, StoragePreparationClientProgressV1,
};

use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::Path;

use aos_proto::aos::sandbox::local::v1::{
    AcquireMountSourceRequest, ApplyDestinationSlotRequest, ApplyMountRequest, Audience,
    BrokerDescriptorRole, BrokerError, BrokerErrorCode, BrokerMethod,
    BrokerRequestEnvelope, BrokerResponseEnvelope, InventoryRuntimeResponse,
    QueryRuntimeEffectRequest, ReleaseMountSourceAcquisitionRequest, RequestHeader,
};
use aos_sandbox::attachment_source::{
    AttachmentSourceAttemptKindV1, DurableCurrentAttachmentSourceDispatchV1,
};
use aos_sandbox::mount_attempt::DurableCurrentMountAttemptV1;
use aos_sandbox::mount_preparation::PreparedCurrentMountCatalogQueryV1;
use aos_sandbox::{
    DurableCurrentDestinationSlotAttemptV1, EffectFailure, PreparedAuthorityEffectV1,
    ValidatedAuthorityEffectReceiptV1,
};
use aos_sandbox_broker_session_protocol::{
    AUTHENTICATED_RESPONSE_MAXIMUM_BYTES, ProtectedBrokerSessionVerificationContextV1,
    decode_canonical_response_v1,
    hello_message::{BrokerClientHello, BrokerServerHello},
    production_broker_client_hello_v1, production_broker_server_hello_v1,
};
use aos_sandbox_core::ProtocolVersion;
use aos_sandbox_linux::seqpacket::SeqpacketSocket;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;

pub(crate) mod git_coverage;
use buffa::Message as _;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use sha2::{Digest as _, Sha256};

use crate::handshake;
use crate::{
    BrokerSessionSecurityError, ProtectedBrokerEffectHandoffV1,
    ProtectedBrokerOutcomeAdmissionGateV1, ProtectedBrokerOutcomeCommitRecoveryV1,
    ProtectedBrokerOutcomeCommitResultV1, ProtectedBrokerOutcomeCommittedAdvancementV1,
    ProtectedBrokerOutcomeCurrentV1, ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ProtectedBrokerOutcomePendingAdvancementV1, ProtectedBrokerOutcomeReplayV1,
    ProtectedBrokerRequestCommitRecoveryV1, ProtectedBrokerRequestCommitResultV1,
    ProtectedBrokerSessionFixedCustodyV1, ProtectedBrokerSessionInitializationRecoveryV1,
    ProtectedBrokerSessionInitializationResultV1,
};

/// Reports failure of an explicitly driven dormant protected handshake.
#[derive(Debug, thiserror::Error)]
pub enum DormantBrokerSessionHandshakeErrorV1 {
    /// The fixed endpoint role does not match the selected client or broker flow.
    #[error("fixed broker-session endpoint has the wrong handshake role")]
    EndpointRole,
    /// Protected endpoint or journal custody failed closed.
    #[error("protected broker-session custody failed: {0}")]
    Protected(#[from] BrokerSessionSecurityError),
    /// The remote hello or endpoint publication was malformed or inconsistent.
    #[error("remote broker-session handshake flight is invalid")]
    RemoteInvalid,
    /// Kernel peer or record-subject observations changed or did not agree.
    #[error("broker-session kernel peer evidence is invalid")]
    KernelEvidence,
    /// An actual selected receive failed with its lower native custody retained.
    #[error("selected Storage receive failed with native custody retained")]
    RetainedReceive(#[source] aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1),
    /// An actual selected send failed with its lower native custody retained.
    #[error("selected Storage send failed with native custody retained")]
    RetainedSend(#[source] aos_sandbox_linux::seqpacket::RetainedSeqpacketSendErrorV1),
    /// The selected HELLO keeps its whole native send observation on refusal.
    #[error("selected HELLO send failed with original custody retained")]
    SelectedSend(#[source] handshake::RetainedStorageHandshakeSendFailureV1),
    /// A parked selected record failed its original carrier comparison.
    #[error("selected Storage original carrier comparison failed")]
    RecordBinding(#[source] aos_sandbox_linux::seqpacket::RecordBindingError),
    /// The selected handshake retains its actual failed raw reducer owner.
    #[error("selected Storage handshake failed with original custody retained")]
    StoragePreparation(#[source] Box<handshake::RetainedStoragePreparationHandshakeFailureV1>),
    /// The adopted socket failed outside the retryable interruption profile.
    #[error("broker-session handshake transport failed")]
    Transport,
    /// The protected hello exchange did not finish before its fixed deadline.
    #[error("broker-session handshake deadline expired")]
    Deadline,
}

impl From<handshake::DormantBrokerSessionHandshakeErrorV1>
    for DormantBrokerSessionHandshakeErrorV1
{
    fn from(error: handshake::DormantBrokerSessionHandshakeErrorV1) -> Self {
        match error {
            handshake::DormantBrokerSessionHandshakeErrorV1::EndpointRole => Self::EndpointRole,
            handshake::DormantBrokerSessionHandshakeErrorV1::Protected(error) => {
                Self::Protected(error)
            }
            handshake::DormantBrokerSessionHandshakeErrorV1::RemoteInvalid => Self::RemoteInvalid,
            handshake::DormantBrokerSessionHandshakeErrorV1::KernelEvidence => Self::KernelEvidence,
            handshake::DormantBrokerSessionHandshakeErrorV1::Transport => Self::Transport,
            handshake::DormantBrokerSessionHandshakeErrorV1::StoragePreparation(error) =>
                Self::StoragePreparation(error),
            handshake::DormantBrokerSessionHandshakeErrorV1::RetainedReceive(error) => Self::RetainedReceive(error),
            handshake::DormantBrokerSessionHandshakeErrorV1::RetainedSend(error) => Self::RetainedSend(error),
            handshake::DormantBrokerSessionHandshakeErrorV1::SelectedSend(error) => Self::SelectedSend(error),
            handshake::DormantBrokerSessionHandshakeErrorV1::RecordBinding(error) => Self::RecordBinding(error),
        }
    }
}

mod deadline_observation;
pub(crate) use deadline_observation::BrokerColdDeadlineObservationV1;

pub(crate) fn remaining_handshake_nanoseconds(
    deadline_boottime_nanoseconds: u64,
) -> Result<u64, DormantBrokerSessionHandshakeErrorV1> {
    remaining_handshake_nanoseconds_observed(deadline_boottime_nanoseconds, None)
}

fn remaining_handshake_nanoseconds_observed(
    deadline_boottime_nanoseconds: u64,
    original: Option<&mut Option<Timespec>>,
) -> Result<u64, DormantBrokerSessionHandshakeErrorV1> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    if let Some(original) = original {
        *original = Some(now);
    }
    remaining_handshake_nanoseconds_from_sample(now, deadline_boottime_nanoseconds)
}

fn remaining_handshake_nanoseconds_from_sample(
    now: Timespec,
    deadline_boottime_nanoseconds: u64,
) -> Result<u64, DormantBrokerSessionHandshakeErrorV1> {
    let seconds =
        u64::try_from(now.tv_sec).map_err(|_| DormantBrokerSessionHandshakeErrorV1::Transport)?;
    let nanoseconds =
        u64::try_from(now.tv_nsec).map_err(|_| DormantBrokerSessionHandshakeErrorV1::Transport)?;
    let now = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(DormantBrokerSessionHandshakeErrorV1::Transport)?;
    deadline_boottime_nanoseconds
        .checked_sub(now)
        .filter(|remaining| *remaining > 0)
        .ok_or(DormantBrokerSessionHandshakeErrorV1::Deadline)
}

/// Rejects expired production exchanges even when their sockets are already ready.
///
/// # Errors
/// Returns Deadline after expiry, or Transport if the BOOTTIME value is unrepresentable.
pub fn check_production_deadline(
    deadline_boottime_nanoseconds: u64,
) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
    remaining_handshake_nanoseconds(deadline_boottime_nanoseconds).map(|_| ())
}

#[cfg(test)]
mod production_deadline_tests {
    use std::io::Write as _;
    use std::os::fd::AsFd as _;
    use std::os::unix::net::UnixStream;

    use super::{
        DormantBrokerSessionHandshakeErrorV1, remaining_handshake_nanoseconds,
        wait_for_handshake_readiness,
    };

    #[test]
    fn expired_deadline_is_rejected_without_polling() {
        assert!(matches!(
            remaining_handshake_nanoseconds(0),
            Err(DormantBrokerSessionHandshakeErrorV1::Deadline)
        ));
    }

    #[test]
    fn writable_socket_does_not_override_expired_deadline() {
        let (socket, _peer) = UnixStream::pair().unwrap();

        let result = wait_for_handshake_readiness(socket.as_fd(), true, 0);

        assert!(matches!(
            result,
            Err(DormantBrokerSessionHandshakeErrorV1::Deadline)
        ));
    }

    #[test]
    fn writable_socket_is_accepted_before_deadline() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let deadline =
            crate::production_deadline_after(std::time::Duration::from_secs(10)).unwrap();

        wait_for_handshake_readiness(socket.as_fd(), true, deadline).unwrap();
    }

    #[test]
    fn response_readiness_waits_for_peer_data() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        let deadline =
            crate::production_deadline_after(std::time::Duration::from_secs(10)).unwrap();
        let sender = std::thread::spawn(move || peer.write_all(&[1]).unwrap());

        wait_for_handshake_readiness(socket.as_fd(), false, deadline).unwrap();

        sender.join().unwrap();
    }

    #[test]
    fn response_readiness_does_not_extend_the_original_deadline() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let deadline =
            crate::production_deadline_after(std::time::Duration::from_millis(10)).unwrap();

        let result = wait_for_handshake_readiness(socket.as_fd(), false, deadline);

        assert!(matches!(
            result,
            Err(DormantBrokerSessionHandshakeErrorV1::Deadline)
        ));
    }
}

/// Waits for original descriptor readiness without admitting traffic.
///
/// # Errors
/// Returns Deadline for expiry or a timed-out poll, and Transport for clock or poll failure.
pub fn wait_for_handshake_readiness(
    descriptor: BorrowedFd<'_>,
    wants_write: bool,
    deadline_boottime_nanoseconds: u64,
) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
    wait_for_handshake_readiness_inner(descriptor, wants_write, deadline_boottime_nanoseconds, None, None)
}

pub(crate) fn wait_for_handshake_readiness_retaining_v1(
    descriptor: BorrowedFd<'_>,
    wants_write: bool,
    deadline_boottime_nanoseconds: u64,
    native: &mut Option<Result<usize, rustix::io::Errno>>,
) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
    wait_for_handshake_readiness_inner(descriptor, wants_write, deadline_boottime_nanoseconds, Some(native), None)
}

fn wait_for_handshake_readiness_inner(
    descriptor: BorrowedFd<'_>,
    wants_write: bool,
    deadline_boottime_nanoseconds: u64,
    native: Option<&mut Option<Result<usize, rustix::io::Errno>>>,
    mut originals: Option<&mut HandshakeReadinessOriginalsV1>,
) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    if let Some(originals) = originals.as_deref_mut() {
        originals.clock = Some(now);
    }
    let remaining = remaining_handshake_nanoseconds_from_sample(now, deadline_boottime_nanoseconds)?;
    if let Some(originals) = originals.as_deref_mut() {
        originals.remaining = Some(remaining);
    }
    let timeout = Timespec {
        tv_sec: i64::try_from(remaining / 1_000_000_000)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::Deadline)?,
        tv_nsec: i64::try_from(remaining % 1_000_000_000)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::Deadline)?,
    };
    if let Some(originals) = originals.as_deref_mut() {
        originals.timeout = Some(timeout);
    }
    let readiness = if wants_write {
        PollFlags::OUT
    } else {
        PollFlags::IN
    };
    let (observed, _) = sample_readiness_once_v5(descriptor, readiness, Some(&timeout));
    if let Some(native) = native {
        *native = Some(observed);
    }
    if let Some(originals) = originals {
        originals.native = Some(observed);
    }
    match observed {
        Ok(0) => Err(DormantBrokerSessionHandshakeErrorV1::Deadline),
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(_) => Err(DormantBrokerSessionHandshakeErrorV1::Transport),
    }
}

// One native poll recipe serves ordinary timed handshake waits and the
// separately prepaid idle inventory wait. No wait authenticates a request.
fn sample_readiness_once_v5(descriptor: BorrowedFd<'_>, readiness: PollFlags,
    timeout: Option<&Timespec>,
) -> (Result<usize, rustix::io::Errno>, PollFlags) {
    let mut descriptors = [PollFd::from_borrowed_fd(descriptor, readiness)];
    let observed = poll(&mut descriptors, timeout);
    (observed, descriptors[0].revents())
}

pub(crate) fn wait_for_inventory_readiness_retaining_v5(
    descriptor: BorrowedFd<'_>, native: &mut Option<Result<usize, rustix::io::Errno>>,
    events: &mut Option<PollFlags>,
) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
    let (observed, ready) = sample_readiness_once_v5(descriptor, PollFlags::IN, None);
    *native = Some(observed);
    *events = Some(ready);
    match observed {
        Ok(1) if ready.contains(PollFlags::IN)
            && !ready.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) => Ok(()),
        _ => Err(DormantBrokerSessionHandshakeErrorV1::Transport),
    }
}

/// Owns one explicitly adopted controller-client socket across hello flights.
#[must_use = "advance, retain, or drop the dormant client handshake"]
pub struct DormantControllerClientHandshakeV1(handshake::DormantControllerClientHandshakeV1);

/// Reports one bounded controller-client handshake step.
#[must_use = "advance pending state or retain the completed dormant session"]
pub enum DormantControllerClientHandshakeProgressV1 {
    /// A pending or retryable flight retained the complete handshake state.
    Pending(DormantControllerClientHandshakeV1),
    /// The protected hello exchange and fixed journal open both completed.
    Complete(DormantAuthenticatedBrokerSessionV1),
}

impl DormantControllerClientHandshakeV1 {
    /// Borrows the adopted socket for readiness polling.
    ///
    /// # Errors
    ///
    /// Returns an error after a fatal transport failure closes the socket.
    pub fn as_fd(&self) -> Result<BorrowedFd<'_>, DormantBrokerSessionHandshakeErrorV1> {
        self.0.as_fd().map_err(Into::into)
    }

    /// Reports whether the next handshake flight waits for writable readiness.
    #[must_use]
    pub const fn wants_write(&self) -> bool {
        self.0.wants_write()
    }

    /// Advances exactly one receive or send flight on the adopted socket.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid remote bytes, changed kernel evidence,
    /// protected-custody failure, or a non-retryable transport failure.
    pub fn advance(
        self,
    ) -> Result<DormantControllerClientHandshakeProgressV1, DormantBrokerSessionHandshakeErrorV1>
    {
        match self.0.advance()? {
            handshake::DormantControllerClientHandshakeProgressV1::Pending(pending) => Ok(
                DormantControllerClientHandshakeProgressV1::Pending(Self(pending)),
            ),
            handshake::DormantControllerClientHandshakeProgressV1::Complete(complete) => {
                Ok(DormantControllerClientHandshakeProgressV1::Complete(
                    DormantAuthenticatedBrokerSessionV1(complete, Vec::new()),
                ))
            }
        }
    }
}

/// Owns one explicitly adopted service-broker socket across hello flights.
#[must_use = "advance, retain, or drop the dormant broker handshake"]
pub struct DormantBrokerEndpointHandshakeV1(handshake::DormantBrokerEndpointHandshakeV1);

/// Reports one bounded service-broker handshake step.
#[must_use = "advance pending state or retain the completed dormant session"]
pub enum DormantBrokerEndpointHandshakeProgressV1 {
    /// A pending or retryable flight retained the complete handshake state.
    Pending(DormantBrokerEndpointHandshakeV1),
    /// The protected hello exchange and fixed journal open both completed.
    Complete(DormantAuthenticatedBrokerSessionV1),
}

impl DormantBrokerEndpointHandshakeV1 {
    /// Borrows the adopted socket for readiness polling.
    ///
    /// # Errors
    ///
    /// Returns an error after a fatal transport failure closes the socket.
    pub fn as_fd(&self) -> Result<BorrowedFd<'_>, DormantBrokerSessionHandshakeErrorV1> {
        self.0.as_fd().map_err(Into::into)
    }

    /// Reports whether the next handshake flight waits for writable readiness.
    #[must_use]
    pub const fn wants_write(&self) -> bool {
        self.0.wants_write()
    }

    /// Advances exactly one send or receive flight on the adopted socket.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid remote bytes, changed kernel evidence,
    /// protected-custody failure, or a non-retryable transport failure.
    pub fn advance(
        self,
    ) -> Result<DormantBrokerEndpointHandshakeProgressV1, DormantBrokerSessionHandshakeErrorV1>
    {
        match self.0.advance()? {
            handshake::DormantBrokerEndpointHandshakeProgressV1::Pending(pending) => Ok(
                DormantBrokerEndpointHandshakeProgressV1::Pending(Self(pending)),
            ),
            handshake::DormantBrokerEndpointHandshakeProgressV1::Complete(complete) => {
                Ok(DormantBrokerEndpointHandshakeProgressV1::Complete(
                    DormantAuthenticatedBrokerSessionV1(complete, Vec::new()),
                ))
            }
        }
    }
}

use crate::recovery::HostExecutionSessionReceivingOriginalV1;

/// Retains an authenticated adopted socket together with its fixed protected owner.
///
/// No service is registered and no request is dispatched. The callback keeps
/// the verified transcript scoped to the co-owned socket, journal, and exact
/// kernel peer observation.
#[must_use = "retain the authenticated dormant session while using protected history"]
pub struct DormantAuthenticatedBrokerSessionV1(
    handshake::DormantAuthenticatedBrokerSessionV1,
    Vec<aos_sandbox_host::DormantHostScopeReplayTicketV1>,
);

impl DormantAuthenticatedBrokerSessionV1 {
    /// Continuously borrows both original client Sessions under the same paid C18.
    ///
    /// The SDK original retains all request, transport and failure prefixes;
    /// canonical observations do not supply readiness or a replacement owner.
    ///
    /// # Errors
    /// Preserves changed fixed Session custody, repeated entry, and native or
    /// financial admission failure in the actual SDK and lower scope originals.
    pub fn borrow_execution_availability_client_once_v2<'turn>(
        &'turn mut self, storage: &'turn mut Self,
        scope: &'turn mut aos_sandbox::controller_execution_operation::ExecutionPublicAdmissionScopeV2,
        controller: &'turn mut aos_sandbox::Journal,
        original: &'turn mut crate::ExecutionAvailabilitySessionIoOriginalV2,
    ) -> Result<crate::ExecutionAvailabilityClientSessionBorrowV2<'turn>, crate::controller_composition::OutputPreparationClosedV1> {
        original.borrow_pair_v2(&mut self.0, &mut storage.0, scope, controller)
    }
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Borrows the same Host Session and actual C18 for a closed NoApply continuation.
    ///
    /// The completed availability original is borrowed, never consumed as an
    /// Apply disposal token. Every native and SDK prefix stays with its owner.
    ///
    /// # Errors
    /// Retains missing availability, reentry, funding and native Session failure.
    pub fn borrow_active_execution_no_apply_client_once_v2<'turn, 'source, 'original>(
        &'turn mut self,
        availability: &'turn crate::ExecutionAvailabilitySessionIoOriginalV2,
        original: &'turn mut crate::HostExecutionNoApplySessionIoOriginalV2,
        native: &'turn mut aos_sandbox::controller_execution_operation::ControllerExecutionNoApplyOriginalV2,
        controller: &'turn mut aos_sandbox::Journal,
        bank: &'turn aos_sandbox::ControllerResourceBankOpeningV1,
        profile: &'turn aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
        receiving: &'turn mut aos_sandbox::controller_execution_operation::ControllerExecutionReadReceivingLoanV1<'source, 'original>,
    ) -> Result<crate::HostExecutionNoApplyClientSessionBorrowV2<'turn, 'source, 'original>, crate::controller_composition::OutputPreparationClosedV1> {
        original.borrow_active_once_v2(&mut self.0, availability, native, controller, bank, profile, receiving)
    }
}

/// Carries the verified transcript of the retained Storage broker socket.
///
/// Only the protected session owner can mint this value after revalidating
/// its live peer, transcript, and journal custody. It is not effect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedStorageSessionBindingV1([u8; 32]);

impl ProtectedStorageSessionBindingV1 {
    /// Returns the exact complete-hello transcript binding.
    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.0
    }
}

/// Supplies protected request identity and deadline facts to a body builder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DormantBrokerRequestCoordinatesV1 {
    request_id: [u8; 16],
    deadline_boottime_nanoseconds: u64,
    maximum_response_bytes: u32,
    protocol_version: ProtocolVersion,
    audience: Audience,
}

impl DormantBrokerRequestCoordinatesV1 {
    /// Groups already-selected Session comparison DATA without admitting a request.
    pub(crate) const fn from_session_data_v1(
        request_id: [u8; 16],
        deadline_boottime_nanoseconds: u64,
        maximum_response_bytes: u32,
        protocol_version: ProtocolVersion,
        audience: Audience,
    ) -> Self {
        Self {
            request_id,
            deadline_boottime_nanoseconds,
            maximum_response_bytes,
            protocol_version,
            audience,
        }
    }

    /// Returns the kernel-random request identifier selected by protected custody.
    #[must_use]
    pub const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the protected absolute request deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    /// Returns the negotiated response ceiling.
    #[must_use]
    pub const fn maximum_response_bytes(self) -> u32 {
        self.maximum_response_bytes
    }

    /// Returns the fixed broker protocol version.
    #[must_use]
    pub const fn protocol_version(self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the protected session audience.
    #[must_use]
    pub const fn audience(self) -> Audience {
        self.audience
    }

    /// Builds the canonical request header from protected session coordinates.
    pub fn request_header(self) -> RequestHeader {
        RequestHeader {
            protocol_major: u32::from(self.protocol_version.major()),
            protocol_minor: u32::from(self.protocol_version.minor()),
            request_id: self.request_id.to_vec(),
            audience: self.audience.into(),
            deadline_boottime_nanoseconds: self.deadline_boottime_nanoseconds,
            maximum_response_bytes: self.maximum_response_bytes,
            ..Default::default()
        }
    }
}

/// Retains one protected, durably reserved request before atomic transport.
#[must_use = "send or retain the exact protected request"]
pub struct DormantPreparedBrokerRequestV1(AuthenticatedBrokerMethodRequestV1);

impl DormantPreparedBrokerRequestV1 {
    /// Borrows the literal prepared Host request for its Source dispatch binding.
    ///
    /// This DATA borrow preserves protected request custody and cannot send,
    /// recreate or authorize a request. Core checks the exact ordinary Stop.
    #[must_use]
    pub fn host_stop_dispatch_request_data_v1(&self) -> Option<&AuthenticatedBrokerMethodRequestV1> {
        (self.0.method() == BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME).then_some(&self.0)
    }

    /// Returns the signed deadline without releasing request custody.
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.0.deadline_boottime_nanoseconds()
    }
}

/// Retains one sent request while its exact terminal response is outstanding.
#[must_use = "receive or retain the exact outstanding request"]
pub struct DormantOutstandingBrokerRequestV1(AuthenticatedBrokerMethodRequestV1);

/// Retains returned execution response DATA and failed native admission.
#[derive(Default)]
pub struct ExecutionPublicationReceiveCustodyV1 {
    pub(crate) packet: Option<Vec<u8>>,
    pub(crate) raw: crate::handshake::ExecutionResponsePacketOriginalV1,
    pub(crate) decoded: Option<Result<
        aos_sandbox_broker_session_protocol::CanonicalBrokerResponseEnvelopeV1,
        aos_sandbox_broker_session_protocol::BrokerSessionProjectionError,
    >>,
    pub(crate) native_error: Option<BrokerSessionSecurityError>,
    pub(crate) rejected_replay: Option<ProtectedBrokerOutcomeReplayV1>,
}

impl ExecutionPublicationReceiveCustodyV1 {
    /// Borrows the first raw receive or subject-binding cause before decoding.
    #[must_use]
    pub fn raw_error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.raw.failure()
    }

    /// Borrows the original response decoder failure without releasing custody.
    pub fn decode_error(&self) -> Option<&aos_sandbox_broker_session_protocol::BrokerSessionProjectionError> {
        self.decoded.as_ref().and_then(|result| result.as_ref().err())
    }

    /// Borrows the original protected admission failure without releasing custody.
    pub fn native_error(&self) -> Option<&BrokerSessionSecurityError> {
        self.native_error.as_ref()
    }
}

impl DormantOutstandingBrokerRequestV1 {
    /// Borrows the actual pending Capture60 request for its Host readback.
    ///
    /// The request remains owned here; this comparison-only projection grants
    /// neither a replacement request nor a physical Capture flight.
    #[must_use]
    pub fn capture_preparation_request_v3(&self) -> Option<&AuthenticatedBrokerMethodRequestV1> {
        (self.0.method() == BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1)
            .then_some(&self.0)
    }

    /// Returns the original signed deadline for response readiness polling.
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.0.deadline_boottime_nanoseconds()
    }
}

/// Retains a protected request with the exact SCM_RIGHTS table it authenticates.
#[must_use = "send or retain the exact protected descriptor request"]
pub struct DormantPreparedBrokerDescriptorRequestV1 {
    request: AuthenticatedBrokerMethodRequestV1,
    descriptors: Vec<OwnedFd>,
}

impl DormantPreparedBrokerDescriptorRequestV1 {
    /// Borrows the original signed deadline without releasing descriptor custody.
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.request.deadline_boottime_nanoseconds()
    }
}

/// Retains one authenticated request received and committed by the broker owner.
#[must_use = "produce its exact response or retain the committed request"]
pub struct DormantReceivedBrokerRequestV1(AuthenticatedBrokerMethodRequestV1);

/// Retains an exact protected terminal response selected by request replay.
#[must_use = "resend or retain the exact protected terminal response"]
pub struct DormantBrokerTerminalReplayV1(ProtectedBrokerOutcomeReplayV1);

impl DormantBrokerTerminalReplayV1 {
    pub(crate) fn into_retained_storage_terminal_v1(self) -> crate::recovery::RetainedStorageTerminalV1 {
        self.0.into_retained_storage_terminal_v1()
    }

    pub(crate) fn method(&self) -> BrokerMethod {
        self.0.method()
    }
}

/// Retains a terminal Host scope replay until exact descriptor custody is reopened.
#[must_use = "reopen and send the exact signed descriptor table or retain replay custody"]
pub struct DormantBrokerDescriptorTerminalReplayV1(DormantBrokerTerminalReplayV1);

impl DormantBrokerDescriptorTerminalReplayV1 {
    /// Returns the replayed request's validated but still untrusted authorization artifacts.
    ///
    /// The sealed Host adapter must authenticate these exact artifacts again
    /// before it may reopen response descriptors.
    #[must_use]
    pub fn authorization_artifacts(
        &self,
    ) -> Option<&aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts> {
        self.0.0.request().authorization()
    }
}

/// Retains a request whose protected commit still requires exact readback.
#[must_use = "recover the exact protected commit before transport or response"]
pub struct DormantUnconfirmedBrokerRequestV1(AuthenticatedBrokerMethodRequestV1);

/// Retains a received request whose protected commit is still ambiguous.
#[must_use = "recover the exact protected commit before producing a response"]
pub struct DormantUnconfirmedReceivedBrokerRequestV1(AuthenticatedBrokerMethodRequestV1);

/// Retains one committed request and its exact incoming descriptor custody.
#[must_use = "execute the descriptor method or retain its exact custody"]
pub struct DormantReceivedBrokerDescriptorRequestV1 {
    request: AuthenticatedBrokerMethodRequestV1,
    descriptors: Vec<OwnedFd>,
}

/// Retains descriptor custody while request installation is ambiguous.
#[must_use = "recover the exact request commit before using any descriptor"]
pub struct DormantUnconfirmedBrokerDescriptorRequestV1 {
    request: AuthenticatedBrokerMethodRequestV1,
    descriptors: Vec<OwnedFd>,
}

/// Retains a sealed domain-produced successful response body.
///
/// The constructor is crate-private so public callers cannot turn arbitrary
/// bytes into authenticated broker success. Broker-specific adapters mint it
/// only after executing or observing their real protected domain owner.
#[derive(Clone)]
#[must_use = "commit the exact observation through its authenticated session"]
pub(crate) struct ProtectedBrokerDomainResponseV1 {
    method: BrokerMethod,
    request_id: [u8; 16],
    signed_request_digest: [u8; 32],
    body: Vec<u8>,
}

/// Identifies why an authenticated broker execution could not advance.
#[derive(Debug, thiserror::Error)]
pub enum DormantBrokerExecutionErrorV1<Domain> {
    /// The protected session or its exact request/outcome head was not current.
    #[error("protected broker-session currentness failed: {0}")]
    Currentness(BrokerSessionSecurityError),
    /// The selected protected domain adapter could not produce an exact observation.
    #[error("broker domain execution failed: {0}")]
    Domain(Domain),
}

/// Retains an authenticated request after dispatch when its outcome is unknown.
///
/// This custody deliberately has no public request extractor. A caller cannot
/// turn a possibly-applied operation into a generic signed error or execute it
/// again. When an exact domain observation was obtained before a currentness
/// failure, [`DormantAuthenticatedBrokerSessionV1::retry_observed_success_and_commit`]
/// can retry only its protected readback and terminal commit.
#[must_use = "recover the exact outcome or retain ambiguity custody"]
pub struct DormantBrokerOutcomeUnknownV1 {
    request: DormantReceivedBrokerRequestV1,
    observation: Option<ProtectedBrokerDomainResponseV1>,
}

/// Retains an exact descriptor-bearing replay of one in-flight request.
///
/// The request and descriptor table remain opaque and inseparable. Production
/// recovery may re-enter only the method-selected domain adapter; callers
/// cannot extract an FD or turn possibly-applied work into a generic error.
#[must_use = "resolve the exact in-flight effect or retain replay custody"]
pub struct DormantBrokerDescriptorInFlightReplayV1 {
    custody: DormantBrokerOutcomeUnknownV1,
    descriptors: Vec<OwnedFd>,
}

impl DormantBrokerOutcomeUnknownV1 {
    pub(crate) fn into_unobserved_request(self) -> Result<DormantReceivedBrokerRequestV1, Self> {
        if self.observation.is_some() {
            Err(self)
        } else {
            Ok(self.request)
        }
    }
}

impl crate::ProductionBrokerRequestEventV1 {
    pub(crate) fn is_original_capture_candidate_replay(&self) -> bool {
        let method = match self {
            Self::InFlightReplay(unknown) => unknown.request.method(),
            Self::TerminalReplay(replay) => replay.0.method(),
            _ => return false,
        };
        method == BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE
    }

    pub(crate) fn is_nix_generation(&self) -> bool {
        let method = match self {
            Self::Request(request) => request.method(),
            Self::InFlightReplay(unknown) => unknown.request.method(),
            Self::TerminalReplay(replay) => replay.0.method(),
            Self::DescriptorTerminalReplay(_) => return false,
        };
        method == BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_NIX_GENERATION_V1
    }

    /// Selects only the new physical Capture channel, never logical output.
    pub(crate) fn is_storage_execution_capture_request_v1(&self) -> bool {
        let method = match self {
            Self::Request(request) => request.method(),
            Self::InFlightReplay(unknown) => unknown.request.method(),
            Self::TerminalReplay(replay) => replay.0.method(),
            Self::DescriptorTerminalReplay(_) => return false,
        };
        matches!(method,
            BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1
            | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1)
    }

    pub(crate) fn is_original_output_replay(&self) -> bool {
        let method = match self {
            Self::InFlightReplay(unknown) => unknown.request.method(),
            Self::TerminalReplay(replay) => replay.0.method(),
            _ => return false,
        };
        matches!(method,
            BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT)
    }
}

impl DormantBrokerDescriptorInFlightReplayV1 {
    pub(crate) fn into_recovery_request(self) -> DormantReceivedBrokerDescriptorRequestV1 {
        DormantReceivedBrokerDescriptorRequestV1 {
            request: self.custody.request.0,
            descriptors: self.descriptors,
        }
    }
}

/// Retains one exact authenticated Mount Acquire/Release request across recovery.
///
/// The request and optional sealed response remain private. This value can
/// only re-enter the source-specific protected resume operation.
#[must_use = "resume the exact Mount source operation or retain its custody"]
pub struct DormantMountSourceBrokerRecoveryV1(DormantBrokerOutcomeUnknownV1);

/// Reports terminal response custody or another exact Mount source recovery boundary.
#[must_use = "consume the commit result or retain and resume source recovery"]
pub enum DormantMountSourceBrokerRecoveryProgressV1 {
    /// The exact authenticated response reached protected commit processing.
    Committed(ProtectedBrokerOutcomeCommitResultV1),
    /// Provider, transport, effect, or currentness recovery remains incomplete.
    RecoveryRequired(DormantMountSourceBrokerRecoveryV1),
}

/// Distinguishes failures before effect authority from unknown post-dispatch outcomes.
#[must_use = "retain or explicitly resolve the returned request custody"]
pub enum DormantBrokerExecutionFailureV1<Domain> {
    /// No domain adapter was invoked; the exact request may receive a terminal error.
    BeforeEffect {
        /// The protected-currentness reason for rejecting execution.
        error: BrokerSessionSecurityError,
        /// Exact durably admitted request, still eligible for a signed error response.
        request: DormantReceivedBrokerRequestV1,
    },
    /// Domain dispatch began and the request must not be generically terminalized.
    OutcomeUnknown {
        /// The domain or protected-currentness reason for the ambiguity.
        error: DormantBrokerExecutionErrorV1<Domain>,
        /// Exact opaque request and optional sealed observation custody.
        custody: DormantBrokerOutcomeUnknownV1,
    },
}

fn current_publication_boottime(
    request: &AuthenticatedBrokerMethodRequestV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
) -> Result<u64, BrokerSessionSecurityError> {
    let boot_before = aos_sandbox_linux::boot::KernelBootId::current()
        .map_err(|_| BrokerSessionSecurityError::Currentness)?
        .into_bytes();
    let boottime = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let boot_after = aos_sandbox_linux::boot::KernelBootId::current()
        .map_err(|_| BrokerSessionSecurityError::Currentness)?
        .into_bytes();
    let seconds =
        u64::try_from(boottime.tv_sec).map_err(|_| BrokerSessionSecurityError::Currentness)?;
    let nanoseconds =
        u64::try_from(boottime.tv_nsec).map_err(|_| BrokerSessionSecurityError::Currentness)?;
    let now = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    if boot_before != context.boot_id()
        || boot_after != context.boot_id()
        || now >= request.deadline_boottime_nanoseconds()
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    Ok(now)
}

impl<Domain> DormantBrokerExecutionFailureV1<Domain> {
    /// Returns pre-effect request custody, if no domain operation was attempted.
    #[must_use]
    pub fn into_before_effect_request(self) -> Option<DormantReceivedBrokerRequestV1> {
        match self {
            Self::BeforeEffect { request, .. } => Some(request),
            Self::OutcomeUnknown { .. } => None,
        }
    }
}

impl ProtectedBrokerDomainResponseV1 {
    /// Borrows the actual domain-produced body without copying or re-encoding.
    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn from_observation(
        request: &AuthenticatedBrokerMethodRequestV1,
        body: Vec<u8>,
    ) -> Result<Self, BrokerSessionSecurityError> {
        if body.is_empty() && !is_canonical_empty_host_inventory(request.method(), &body) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(Self {
            method: request.method(),
            request_id: request.request_id(),
            signed_request_digest: request.signed_request_digest(),
            body,
        })
    }
}

fn is_canonical_empty_host_inventory(method: BrokerMethod, body: &[u8]) -> bool {
    if method != BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME || !body.is_empty() {
        return false;
    }

    // A zero-row protobuf inventory has no encoded fields. Verify the exact
    // canonical message before allowing it through the protected wrapper;
    // method-specific outcome validation still runs before terminal commit.
    let Ok(inventory) = InventoryRuntimeResponse::decode_from_slice(body) else {
        return false;
    };
    inventory.runtimes.is_empty()
        && inventory.__buffa_unknown_fields.is_empty()
        && inventory.encode_to_vec() == body
}

#[cfg(test)]
mod empty_host_inventory_tests {
    use super::*;

    #[test]
    fn canonical_zero_row_host_inventory_is_admissible() {
        let canonical = InventoryRuntimeResponse::default().encode_to_vec();

        assert!(canonical.is_empty());
        assert!(is_canonical_empty_host_inventory(
            BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
            &canonical
        ));
    }

    #[test]
    fn empty_other_method_and_noncanonical_host_body_remain_closed() {
        assert!(!is_canonical_empty_host_inventory(
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME,
            &[]
        ));
        assert!(!is_canonical_empty_host_inventory(
            BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
            &[0x08, 0x00]
        ));
    }
}

impl DormantReceivedBrokerRequestV1 {
    pub(crate) fn authenticated_original_v2(&self) -> &AuthenticatedBrokerMethodRequestV1 {
        &self.0
    }

    /// Borrows the exact signed physical request without issuing effect authority.
    pub(crate) fn storage_execution_capture_original_v1(&self)
        -> Option<&AuthenticatedBrokerMethodRequestV1>
    {
        if self.is_storage_execution_capture_request_v1() { Some(&self.0) } else { None }
    }

    /// Recognizes only server-admitted physical Capture requests.
    pub(crate) fn is_storage_execution_capture_request_v1(&self) -> bool {
        self.0.direction() == aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1::ServerReceive
            && matches!(self.method(),
                BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1
                | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1)
    }

    pub(crate) const fn original_storage_prepare_deadline(&self) -> u64 {
        self.0.deadline_boottime_nanoseconds()
    }

    pub(crate) const fn original_capture_candidate_deadline(&self) -> u64 {
        self.0.deadline_boottime_nanoseconds()
    }

    /// Retires source custody only after this same receipt admitted its successor.
    pub(crate) fn retire_original_storage_capture_candidate(
        &self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
    ) -> Result<(), aos_sandbox_storage::DormantStorageBrokerCallErrorV1> {
        storage.retire_original_capture_candidate_v1(&self.0)
    }

    pub(crate) const fn original_nix_generation_deadline(&self) -> u64 {
        self.0.deadline_boottime_nanoseconds()
    }

    pub(crate) fn is_original_mount_release_successor(&self, previous: &Self) -> bool {
        self.0.direction() == aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1::ServerReceive
            && previous.method() == BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS
            && self.method() == BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION
            && self.authorization_artifacts().is_some()
            && self.0.session_binding() == previous.0.session_binding()
            && previous.0.client_sequence().checked_add(1) == Some(self.0.client_sequence())
    }

    pub(crate) fn is_original_mount_inventory_successor(
        &self,
        original: &Self,
        method: BrokerMethod,
    ) -> bool {
        self.0.direction() == aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1::ServerReceive
            && self.method() == method && self.authorization_artifacts().is_none()
            && self.0.session_binding() == original.0.session_binding()
            && original.0.client_sequence().checked_add(1) == Some(self.0.client_sequence())
    }

    /// Compares an already admitted successor; the journal authenticated its
    /// signed predecessor link before this DATA comparison can be reached.
    pub(crate) fn is_original_output_successor(
        &self,
        original: &AuthenticatedBrokerMethodRequestV1,
    ) -> bool {
        self.0.direction() == aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1::ServerReceive
            && self.0.session_binding() == original.session_binding()
            && original.client_sequence().checked_add(1) == Some(self.0.client_sequence())
    }

    /// Moves this admitted original directly into its genuine Storage attempt.
    pub(crate) fn into_original_output_registration(
        self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
    ) -> aos_sandbox_storage::execution_output_credential::OriginalExecutionOutputRegistrationV1 {
        storage.begin_original_execution_output_registration(self.0)
    }

    pub(crate) fn decode_host_runtime_argument_request(
        &self,
        now_boottime_nanoseconds: u64,
    ) -> Result<
        aos_sandbox_protocol::host_argument_source::ValidatedHostRuntimeArgumentRequestV1,
        aos_sandbox_protocol::ProtocolValidationError,
    > {
        aos_sandbox_protocol::host_argument_source::decode_host_runtime_argument_request_v1(
            self.0.exact_body(),
            self.0.peer(),
            self.0.peer_policy(),
            now_boottime_nanoseconds,
        )
    }

    /// Returns the authenticated method selected by the signed request.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.0.method()
    }

    /// Returns the exact semantically validated method body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.0.exact_body()
    }

    /// Returns the exact authenticated request identifier.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.0.request_id()
    }

    /// Returns the exact structurally validated authorization artifacts, if present.
    ///
    /// These bytes remain explicitly untrusted. Only the sealed broker-domain
    /// adapters can authenticate and consume them as operation authority.
    #[must_use]
    pub const fn authorization_artifacts(
        &self,
    ) -> Option<&aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts> {
        self.0.authorization()
    }
}

impl DormantReceivedBrokerDescriptorRequestV1 {
    /// Returns the authenticated method selected by the signed request.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.request.method()
    }

    /// Returns the exact structurally validated authorization artifacts, if present.
    ///
    /// These remain untrusted until the sealed Host adapter authenticates the
    /// complete signed plan and live protected authority.
    #[must_use]
    pub const fn authorization_artifacts(
        &self,
    ) -> Option<&aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts> {
        self.request.authorization()
    }

    /// Converts a descriptor-free request into ordinary broker custody.
    ///
    /// # Errors
    ///
    /// Returns the unchanged request and its descriptors when any descriptor
    /// was transferred. Callers must route that custody through the exact
    /// descriptor-bearing method instead.
    pub fn into_descriptor_free_request(self) -> Result<DormantReceivedBrokerRequestV1, Self> {
        if self.descriptors.is_empty() {
            Ok(DormantReceivedBrokerRequestV1(self.request))
        } else {
            Err(self)
        }
    }

    /// Clones the authenticated Apply request while retaining its sole descriptor.
    pub(crate) fn clone_host_execution_spec_request(
        &self,
    ) -> Option<(DormantReceivedBrokerRequestV1, &OwnedFd)> {
        if self.request.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION
            || self.descriptors.len() != 1
        {
            return None;
        }
        Some((
            DormantReceivedBrokerRequestV1(self.request.clone()),
            &self.descriptors[0],
        ))
    }

    /// Clones the signed argument request while retaining its sole source descriptor.
    pub(crate) fn clone_host_argument_source_request(
        &self,
    ) -> Option<(DormantReceivedBrokerRequestV1, &OwnedFd)> {
        if self.request.method() != BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME_ARGUMENT
            || self.descriptors.len() != 1
        {
            return None;
        }
        Some((
            DormantReceivedBrokerRequestV1(self.request.clone()),
            &self.descriptors[0],
        ))
    }
}

/// Classifies protected request preparation and durable ambiguity.
#[must_use = "recover ambiguous durable state before sending"]
pub enum DormantBrokerRequestPreparationV1 {
    /// The exact signed request is durably current and may be sent.
    Prepared(DormantPreparedBrokerRequestV1),
    /// Initial installation needs exact reopen/readback recovery.
    InitializationRecoveryRequired {
        /// Redacted durable failure.
        error: BrokerSessionSecurityError,
        /// Exact protected recovery target.
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        /// The request retained without send authority until recovery succeeds.
        request: DormantUnconfirmedBrokerRequestV1,
    },
    /// Successor installation needs exact reopen/readback recovery.
    SuccessorRecoveryRequired {
        /// Redacted durable failure.
        error: BrokerSessionSecurityError,
        /// Exact protected recovery target.
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        /// The request retained without send authority until recovery succeeds.
        request: DormantUnconfirmedBrokerRequestV1,
    },
}

impl DormantBrokerRequestPreparationV1 {
    /// Borrows the exact signed request retained across protected preparation ambiguity.
    pub const fn signed_request(&self) -> &AuthenticatedBrokerMethodRequestV1 {
        match self {
            Self::Prepared(request) => &request.0,
            Self::InitializationRecoveryRequired { request, .. }
            | Self::SuccessorRecoveryRequired { request, .. } => &request.0,
        }
    }
}

/// Classifies descriptor-request preparation without losing FD custody.
#[must_use = "recover ambiguity before sending any descriptor"]
pub enum DormantBrokerDescriptorRequestPreparationV1 {
    /// The signed request and every descriptor are durably current.
    Prepared(DormantPreparedBrokerDescriptorRequestV1),
    /// Initial installation needs exact protected readback.
    InitializationRecoveryRequired {
        error: BrokerSessionSecurityError,
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        request: DormantUnconfirmedBrokerDescriptorRequestV1,
    },
    /// Successor installation needs exact protected readback.
    SuccessorRecoveryRequired {
        error: BrokerSessionSecurityError,
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        request: DormantUnconfirmedBrokerDescriptorRequestV1,
    },
}

/// Reports an atomic request send or retryable backpressure.
#[must_use = "retry pending transport without rebuilding the request"]
pub enum DormantBrokerRequestSendProgressV1 {
    /// No bytes were sent; retry the identical protected packet.
    Pending(DormantPreparedBrokerRequestV1),
    /// The exact packet was atomically sent and awaits its response.
    Sent(DormantOutstandingBrokerRequestV1),
}

/// Reports atomic descriptor-request transport or retryable backpressure.
#[must_use = "retry pending transport without rebuilding request or FD custody"]
pub enum DormantBrokerDescriptorRequestSendProgressV1 {
    /// No packet or descriptor was sent.
    Pending(DormantPreparedBrokerDescriptorRequestV1),
    /// The atomic packet/descriptor send completed and the response is outstanding.
    Sent(DormantOutstandingBrokerRequestV1),
    /// Transport or protected currentness failed with inseparable custody retained.
    RecoveryRequired(DormantBrokerDescriptorRequestSendRecoveryV1),
}

/// Retains one exact signed descriptor request across send ambiguity.
#[must_use = "retry without replacing the protected packet or any descriptor"]
pub struct DormantBrokerDescriptorRequestSendRecoveryV1 {
    error: DormantBrokerSessionHandshakeErrorV1,
    prepared: DormantPreparedBrokerDescriptorRequestV1,
}

impl DormantBrokerDescriptorRequestSendRecoveryV1 {
    /// Returns the redacted transport or protected-currentness failure.
    #[must_use]
    pub const fn error(&self) -> &DormantBrokerSessionHandshakeErrorV1 {
        &self.error
    }
}

/// Reports response backpressure or protected terminal commit disposition.
#[must_use = "retain pending transport or resolve durable commit ambiguity"]
pub enum DormantBrokerResponseProgressV1 {
    /// No response was available; retain the outstanding request.
    Pending(DormantOutstandingBrokerRequestV1),
    /// The authenticated response entered protected terminal history.
    Committed(ProtectedBrokerOutcomeCommitResultV1),
}

/// Classifies broker-side request receipt and protected commit ambiguity.
#[must_use = "recover ambiguous request custody before producing a response"]
pub enum DormantBrokerRequestReceiveProgressV1 {
    /// No request is currently available on the adopted socket.
    Pending,
    /// The exact authenticated request is durably current.
    Received(DormantReceivedBrokerRequestV1),
    /// The request is an exact replay of an effect whose result is still in flight.
    InFlightReplay(DormantBrokerOutcomeUnknownV1),
    /// The request is an exact replay with a protected terminal response.
    TerminalReplay(DormantBrokerTerminalReplayV1),
    /// The exact protected response requires domain-reopened ancillary descriptors.
    DescriptorTerminalReplay(DormantBrokerDescriptorTerminalReplayV1),
    /// Initial protected installation requires exact recovery.
    InitializationRecoveryRequired {
        /// Redacted durable failure.
        error: BrokerSessionSecurityError,
        /// Exact protected recovery target.
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        /// Received request retained until recovery succeeds.
        request: DormantUnconfirmedReceivedBrokerRequestV1,
    },
    /// Successor protected installation requires exact recovery.
    SuccessorRecoveryRequired {
        /// Redacted durable failure.
        error: BrokerSessionSecurityError,
        /// Exact protected recovery target.
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        /// Received request retained until recovery succeeds.
        request: DormantUnconfirmedReceivedBrokerRequestV1,
    },
}

/// Classifies one protected descriptor-bearing request receipt.
#[must_use = "recover ambiguity before consuming any received descriptor"]
pub enum DormantBrokerDescriptorRequestReceiveProgressV1 {
    /// No descriptor request is currently available.
    Pending,
    /// The request and exact descriptor table are durably admitted.
    Received(DormantReceivedBrokerDescriptorRequestV1),
    /// The request exactly replays an in-flight effect with its FD table retained.
    InFlightReplay(DormantBrokerDescriptorInFlightReplayV1),
    /// The request exactly replays a protected terminal response; duplicate FDs were closed.
    TerminalReplay(DormantBrokerTerminalReplayV1),
    /// The protected response requires domain-reopened ancillary descriptors.
    DescriptorTerminalReplay(DormantBrokerDescriptorTerminalReplayV1),
    /// Initial protected installation requires exact recovery.
    InitializationRecoveryRequired {
        /// Redacted durable error.
        error: BrokerSessionSecurityError,
        /// Exact protected recovery token.
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        /// Request and descriptors withheld until recovery succeeds.
        request: DormantUnconfirmedBrokerDescriptorRequestV1,
    },
    /// Successor installation requires exact recovery.
    SuccessorRecoveryRequired {
        /// Redacted durable error.
        error: BrokerSessionSecurityError,
        /// Exact protected recovery token.
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        /// Request and descriptors withheld until recovery succeeds.
        request: DormantUnconfirmedBrokerDescriptorRequestV1,
    },
}

/// Reports atomic response transport while retaining committed authority.
#[must_use = "retry pending transport or retain the sent terminal authority"]
pub enum DormantBrokerResponseSendProgressV1 {
    /// No bytes were sent; retry the identical committed response.
    Pending(ProtectedBrokerOutcomeCommittedAdvancementV1),
    /// The exact committed response was atomically sent.
    Sent(ProtectedBrokerOutcomeCommittedAdvancementV1),
    /// Protected currentness or transport failed with terminal authority retained.
    RecoveryRequired {
        /// Currentness or transport failure observed around the send.
        error: DormantBrokerSessionHandshakeErrorV1,
        /// Exact committed terminal authority retained for recovery.
        committed: ProtectedBrokerOutcomeCommittedAdvancementV1,
    },
}

/// Reports transport progress for one protected no-write terminal replay.
#[must_use = "retry pending transport without recreating replay authority"]
pub enum DormantBrokerTerminalReplaySendProgressV1 {
    /// No bytes were sent; the exact protected replay remains owned.
    Pending(DormantBrokerTerminalReplayV1),
    /// The exact protected terminal packet was atomically resent.
    Sent(DormantBrokerTerminalReplayV1),
    /// The protected head or transport became ambiguous; replay authority is retained.
    RecoveryRequired {
        /// Currentness or transport failure observed around the resend.
        error: DormantBrokerSessionHandshakeErrorV1,
        /// Exact no-write replay authority retained for recovery.
        replay: DormantBrokerTerminalReplayV1,
    },
    /// The signed response requires ancillary descriptors and cannot use this path.
    DescriptorRecoveryRequired(DormantBrokerDescriptorTerminalReplayV1),
}

/// Selects a closed, non-sensitive terminal failure generated by security.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DormantBrokerFailureV1 {
    /// The authenticated request is semantically invalid for the domain owner.
    InvalidRequest,
    /// The peer failed fixed endpoint authentication.
    UnauthenticatedPeer,
    /// The authenticated peer selected another broker audience.
    WrongAudience,
    /// The request's assignment epoch is no longer current.
    StaleAssignment,
    /// The request's desired or resource generation is no longer current.
    StaleGeneration,
    /// The authenticated opaque handle is absent from protected state.
    UnknownHandle,
    /// The request conflicts with another current protected operation.
    Conflict,
    /// A bounded protected resource ceiling was reached.
    ResourceExhausted,
    /// A registered semantic feature required by the request is unavailable.
    RequiredFeatureUnavailable(aos_sandbox_core::FeatureRef),
    /// The protected BOOTTIME deadline expired before admission or effect.
    DeadlineExpired,
    /// The domain owner could not complete its backend operation.
    BackendFailure,
    /// Exact domain bytes or protected readback failed an integrity check.
    IntegrityFailure,
}

impl DormantBrokerFailureV1 {
    fn error(self) -> Result<BrokerError, BrokerSessionSecurityError> {
        let (code, safe_message, retryable, missing_feature) = match self {
            Self::InvalidRequest => (
                BrokerErrorCode::BROKER_ERROR_CODE_INVALID_REQUEST,
                "broker request rejected",
                false,
                None,
            ),
            Self::UnauthenticatedPeer => (
                BrokerErrorCode::BROKER_ERROR_CODE_UNAUTHENTICATED_PEER,
                "broker peer authentication failed",
                false,
                None,
            ),
            Self::WrongAudience => (
                BrokerErrorCode::BROKER_ERROR_CODE_WRONG_AUDIENCE,
                "broker audience rejected",
                false,
                None,
            ),
            Self::StaleAssignment => (
                BrokerErrorCode::BROKER_ERROR_CODE_STALE_ASSIGNMENT,
                "broker assignment is stale",
                true,
                None,
            ),
            Self::StaleGeneration => (
                BrokerErrorCode::BROKER_ERROR_CODE_STALE_GENERATION,
                "broker generation is stale",
                true,
                None,
            ),
            Self::UnknownHandle => (
                BrokerErrorCode::BROKER_ERROR_CODE_UNKNOWN_HANDLE,
                "broker handle is unknown",
                false,
                None,
            ),
            Self::Conflict => (
                BrokerErrorCode::BROKER_ERROR_CODE_CONFLICT,
                "broker operation conflicts",
                true,
                None,
            ),
            Self::ResourceExhausted => (
                BrokerErrorCode::BROKER_ERROR_CODE_RESOURCE_EXHAUSTED,
                "broker resource limit reached",
                true,
                None,
            ),
            Self::RequiredFeatureUnavailable(feature) => {
                aos_sandbox_core::validate_required_features(core::slice::from_ref(&feature))
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                (
                    BrokerErrorCode::BROKER_ERROR_CODE_REQUIRED_FEATURE_UNAVAILABLE,
                    "required broker feature unavailable",
                    false,
                    Some(feature),
                )
            }
            Self::DeadlineExpired => (
                BrokerErrorCode::BROKER_ERROR_CODE_DEADLINE_EXPIRED,
                "broker request deadline expired",
                true,
                None,
            ),
            Self::BackendFailure => (
                BrokerErrorCode::BROKER_ERROR_CODE_BACKEND_FAILURE,
                "broker backend failed",
                true,
                None,
            ),
            Self::IntegrityFailure => (
                BrokerErrorCode::BROKER_ERROR_CODE_INTEGRITY_FAILURE,
                "broker integrity check failed",
                false,
                None,
            ),
        };
        Ok(BrokerError {
            code: code.into(),
            safe_message: safe_message.to_owned(),
            retryable,
            missing_feature: missing_feature
                .map(|feature| aos_proto::aos::sandbox::local::v1::Feature {
                    namespace: feature.namespace().to_owned(),
                    major: feature.major(),
                    minor: feature.minor(),
                    ..Default::default()
                })
                .into(),
            ..Default::default()
        })
    }
}

/// Couples one protected outcome gate to its authenticated adopted session.
///
/// This type has no public constructor. Only a completed handshake session can
/// reopen it from the co-owned fixed journal and kernel-observed socket peer.
#[must_use = "consume this exact protected outcome admission"]
pub struct DormantBrokerOutcomeVerificationV1 {
    gate: ProtectedBrokerOutcomeAdmissionGateV1,
    context: ProtectedBrokerSessionVerificationContextV1,
}

impl DormantBrokerOutcomeVerificationV1 {
    /// Consumes the scoped verification into its non-forgeable gate and context.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ProtectedBrokerOutcomeAdmissionGateV1,
        ProtectedBrokerSessionVerificationContextV1,
    ) {
        (self.gate, self.context)
    }
}

enum OriginalMountLiveDestinationV1<'slot> {
    Acquire(&'slot mut Option<Result<aos_sandbox_protocol::LiveValidatedAcquireMountSourceRequest, aos_sandbox_protocol::ProtocolValidationError>>),
    Release(&'slot mut Option<Result<aos_sandbox_protocol::LiveValidatedReleaseMountSourceAcquisitionRequest, aos_sandbox_protocol::ProtocolValidationError>>),
}

impl DormantAuthenticatedBrokerSessionV1 {
    pub(crate) fn captured_journal_failure_for_v1(&self, returned: &BrokerSessionSecurityError)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        self.0.captured_journal_failure_for_v1(returned)
    }

    pub(crate) fn require_initial_storage_socket_current_v1(
        &self,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), aos_sandbox::StorageReceivingClosedV1> {
        self.0.require_initial_storage_socket_current_v1(receiving)
    }

    pub(crate) fn from_retained_storage_inner_v1(inner: handshake::DormantAuthenticatedBrokerSessionV1) -> Self {
        Self(inner, Vec::new())
    }

    pub(crate) fn dispose_initial_storage_hello_v1(
        &mut self,
        cold: handshake::RetainedStorageColdOpenV1,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
        prefix: handshake::StorageInitialSessionHandshakeV1,
    ) -> Result<(), (handshake::RetainedStorageColdOpenV1, handshake::StorageInitialSessionHandshakeV1)> {
        cold.dispose_initial_storage_hello_v1(&mut self.0, receiving, prefix)
    }

    pub(crate) fn storage_prepare_native_failure_v1(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.storage_prepare_native_failure_v1()
    }

    /// Reports the exact signed two-method Create preparation profile.
    ///
    /// This inspects the already verified transcript. It does not authorize a
    /// request, borrow a receiving loan, or change the advertised method set.
    #[must_use]
    pub fn is_original_storage_preparation_profile_v1(&self) -> bool {
        self.0.is_original_storage_preparation_profile_v1()
    }

    /// Shares the original request/current-clock/Live decoder without taking it.
    ///
    /// Each returned gate, clock and decoded owner is parked before the next
    /// fallible operation. The caller retains the actual request and session;
    /// neither this BSA readback nor Live replaces independent domain admission.
    pub(crate) fn park_original_mount_live(
        &mut self,
        request: &DormantReceivedBrokerRequestV1,
        verification: &mut Option<Result<DormantBrokerOutcomeVerificationV1, BrokerSessionSecurityError>>,
        clock: &mut Option<Result<u64, BrokerSessionSecurityError>>,
        live: &mut Option<Result<aos_sandbox_protocol::LiveValidatedAcquireMountSourceRequest, aos_sandbox_protocol::ProtocolValidationError>>,
    ) -> bool {
        self.park_original_mount_live_recipe(
            request, verification, clock, OriginalMountLiveDestinationV1::Acquire(live),
        )
    }

    pub(crate) fn park_original_mount_release_live(
        &mut self,
        request: &DormantReceivedBrokerRequestV1,
        verification: &mut Option<Result<DormantBrokerOutcomeVerificationV1, BrokerSessionSecurityError>>,
        clock: &mut Option<Result<u64, BrokerSessionSecurityError>>,
        live: &mut Option<Result<aos_sandbox_protocol::LiveValidatedReleaseMountSourceAcquisitionRequest, aos_sandbox_protocol::ProtocolValidationError>>,
    ) -> bool {
        self.park_original_mount_live_recipe(
            request, verification, clock, OriginalMountLiveDestinationV1::Release(live),
        )
    }

    fn park_original_mount_live_recipe(
        &mut self,
        request: &DormantReceivedBrokerRequestV1,
        verification: &mut Option<Result<DormantBrokerOutcomeVerificationV1, BrokerSessionSecurityError>>,
        clock: &mut Option<Result<u64, BrokerSessionSecurityError>>,
        destination: OriginalMountLiveDestinationV1<'_>,
    ) -> bool {
        let (method, occupied) = match &destination {
            OriginalMountLiveDestinationV1::Acquire(live) =>
                (BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE, live.is_some()),
            OriginalMountLiveDestinationV1::Release(live) =>
                (BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION, live.is_some()),
        };
        if request.0.method() != method
            || request.0.authorization().is_none()
            || verification.is_some() || clock.is_some() || occupied
        {
            return false;
        }
        if !self.recheck_original_mount_request(request, verification, clock) {
            return false;
        }
        let Some(Ok(now)) = clock.as_ref() else {
            return false;
        };
        match destination {
            OriginalMountLiveDestinationV1::Acquire(live) => {
                *live = Some(aos_sandbox_protocol::decode_acquire_mount_source_request(
                    request.0.exact_body(), request.0.peer(), request.0.peer_policy(), *now,
                ));
                matches!(live, Some(Ok(decoded)) if decoded.header().request_id() == &request.0.request_id())
            }
            OriginalMountLiveDestinationV1::Release(live) => {
                *live = Some(aos_sandbox_protocol::decode_release_mount_source_acquisition_request(
                    request.0.exact_body(), request.0.peer(), request.0.peer_policy(), *now,
                ));
                matches!(live, Some(Ok(decoded)) if decoded.header().request_id() == &request.0.request_id())
            }
        }
    }

    /// Rechecks the same resident signed request through the sole BSA owner.
    pub(crate) fn recheck_original_mount_request(
        &mut self,
        request: &DormantReceivedBrokerRequestV1,
        verification: &mut Option<Result<DormantBrokerOutcomeVerificationV1, BrokerSessionSecurityError>>,
        clock: &mut Option<Result<u64, BrokerSessionSecurityError>>,
    ) -> bool {
        *verification = Some(self.reopen_broker_outcome(&request.0));
        let Some(Ok(verification)) = verification.as_ref() else { return false; };
        *clock = Some(current_publication_boottime(&request.0, &verification.context));
        matches!(clock, Some(Ok(_)))
    }

    pub(crate) fn observe_original_mount_terminal_prefix(
        &mut self,
        request: &DormantReceivedBrokerRequestV1,
        initial: &DormantBrokerOutcomeVerificationV1,
        owner: &mut Option<Result<DormantBrokerOutcomeVerificationV1, BrokerSessionSecurityError>>,
        clock: &mut Option<Result<u64, BrokerSessionSecurityError>>,
    ) -> bool {
        if owner.as_ref().is_some_and(Result::is_err)
            || clock.as_ref().is_some_and(Result::is_err)
        {
            return false;
        }
        *owner = Some(self.reopen_broker_outcome(&request.0));
        // The original boot binding is borrowed independently of the fresh
        // owner Result, so an owner failure does not suppress the clock post.
        *clock = Some(current_publication_boottime(&request.0, &initial.context));
        matches!(owner, Some(Ok(_))) && matches!(clock, Some(Ok(_)))
    }

    pub(crate) fn hold_fuse_intent_transport<'session>(
        &'session mut self,
        request: &'session AuthenticatedBrokerMethodRequestV1,
    ) -> Result<
        crate::handshake::fuse_intent_continuation::HeldFuseIntentTransportV1<'session>,
        BrokerSessionSecurityError,
    > {
        self.0.hold_fuse_intent_transport(request)
    }
    /// Lends live pending-request custody to the sealed effect composition.
    ///
    /// The token proves only the exact current authenticated request/head. It
    /// does not admit its authorization artifacts or confer consumer authority.
    pub(crate) fn hold_pending_request<'session>(
        &'session mut self,
        request: &'session DormantReceivedBrokerRequestV1,
    ) -> Result<
        crate::recovery::ProtectedPendingBrokerRequestCutV1<'session>,
        BrokerSessionSecurityError,
    > {
        self.0.hold_pending_request(&request.0)
    }

    /// Checks the method against the original authenticated client transcript.
    ///
    /// # Errors
    /// Rejects an unnegotiated method or changed protected endpoint, journal, or peer custody.
    pub fn require_negotiated_client_method(
        &mut self,
        method: BrokerMethod,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.require_negotiated_client_method(method)
    }

    /// Reauthenticates the original immutable Host no-apply archive.
    ///
    /// # Errors
    /// Rejects missing or inconsistent H/T archive evidence, or changed live Host-session custody.
    pub fn historical_host_terminal_no_apply_archive(
        &mut self,
        source: &aos_sandbox::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1,
    ) -> Result<crate::recovery::AuthenticatedOriginalHostNoApplyJoinV1, BrokerSessionSecurityError>
    {
        self.0.historical_host_terminal_no_apply_archive(source)
    }

    /// Captures bounded complete originals without reserving another request.
    ///
    /// # Errors
    /// Rejects incomplete or invalid failed-Create originals, or changed protected Host-session custody.
    pub fn capture_failed_create_originals_v3(
        &mut self,
        source: &aos_sandbox::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1,
    ) -> Result<crate::recovery::RetainedFailedCreateOriginalsDataV3, BrokerSessionSecurityError> {
        self.0.capture_failed_create_originals_v3(source)
    }

    /// Returns the current verified Storage transcript binding for this socket.
    ///
    /// # Errors
    ///
    /// Rejects a non-Storage session or changed protected owner, transcript,
    /// or live peer.
    pub fn current_storage_session_binding(
        &mut self,
    ) -> Result<ProtectedStorageSessionBindingV1, BrokerSessionSecurityError> {
        Ok(ProtectedStorageSessionBindingV1(
            self.0.current_storage_session_binding()?,
        ))
    }

    /// Retains the original authenticated peer pidfd after its existing checks.
    ///
    /// # Errors
    /// Rejects changed authenticated peer evidence or a failed pidfd retention.
    pub fn retain_authenticated_peer_pidfd(
        &mut self,
    ) -> Result<OwnedFd, DormantBrokerSessionHandshakeErrorV1> {
        Ok(self.0.retain_authenticated_peer_pidfd()?)
    }

    /// Reauthenticates immutable original Repair Inventory, never a live hold.
    ///
    /// # Errors
    /// Rejects an unavailable or invalid original Repair inventory in the protected history.
    pub fn operator_repair_inventory_history(
        &mut self,
        request_id: [u8; 16],
        packet: Option<&[u8]>,
    ) -> Result<
        aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        BrokerSessionSecurityError,
    > {
        self.0.operator_repair_inventory_history(request_id, packet)
    }

    /// Recovers only the archived original Storage inventory coordinates.
    ///
    /// # Errors
    /// Rejects inconsistent group/archive bindings or failed protected history verification.
    pub fn original_storage_inventory_coordinates(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
    ) -> Result<Option<crate::recovery::ArchivedStorageInventoryHeadV1>, BrokerSessionSecurityError>
    {
        self.0
            .original_storage_inventory_coordinates(group_request_id, group_request_digest)
    }

    /// Selects the original fresh status coordinates for the archived Storage group.
    ///
    /// # Errors
    /// Rejects inconsistent group/status bindings or failed protected history verification.
    pub fn fresh_storage_inventory_coordinates(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
    ) -> Result<Option<crate::recovery::ArchivedStorageInventoryHeadV1>, BrokerSessionSecurityError>
    {
        self.0
            .fresh_storage_inventory_coordinates(group_request_id, group_request_digest)
    }

    /// Archives the exact original Storage inventory request and predecessor.
    ///
    /// # Errors
    /// Rejects mismatched group/request history or a failed durable inventory archive.
    pub fn archive_original_storage_inventory(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
        inventory_request_id: [u8; 16],
        inventory_request_digest: [u8; 32],
    ) -> Result<crate::recovery::ArchivedStorageInventoryHeadV1, BrokerSessionSecurityError> {
        self.0.archive_original_storage_inventory(
            group_request_id,
            group_request_digest,
            inventory_request_id,
            inventory_request_digest,
        )
    }

    /// Checks the original protected Storage inventory abandonment commitment.
    ///
    /// # Errors
    /// Rejects inconsistent group/request/head bindings or invalid abandonment history.
    pub fn client_storage_inventory_abandonment_committed(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
        inventory_request_id: [u8; 16],
        inventory_request_digest: [u8; 32],
        client_original_head: [u8; 32],
    ) -> Result<bool, BrokerSessionSecurityError> {
        self.0.client_storage_inventory_abandonment_committed(
            group_request_id,
            group_request_digest,
            inventory_request_id,
            inventory_request_digest,
            client_original_head,
        )
    }

    /// Reauthenticates the exact original archived Storage inventory terminal.
    ///
    /// # Errors
    /// Rejects a terminal packet that fails authentication or its archived group/request binding.
    pub fn verify_original_storage_inventory_terminal(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
        inventory_request_id: [u8; 16],
        inventory_request_digest: [u8; 32],
        packet: &[u8],
    ) -> Result<
        aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        BrokerSessionSecurityError,
    >{
        self.0.verify_original_storage_inventory_terminal(
            group_request_id,
            group_request_digest,
            inventory_request_id,
            inventory_request_digest,
            packet,
        )
    }

    /// Commits only the original protected Storage inventory abandonment.
    ///
    /// # Errors
    /// Rejects changed group/request custody or a failed native abandonment commitment.
    pub fn client_confirm_storage_inventory_abandonment(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
        inventory_request_id: [u8; 16],
        inventory_request_digest: [u8; 32],
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.client_confirm_storage_inventory_abandonment(
            group_request_id,
            group_request_digest,
            inventory_request_id,
            inventory_request_digest,
        )
    }

    /// Observes the original retained historical checkpoint digest.
    ///
    /// # Errors
    /// Returns Currentness if the retained checkpoint cannot be canonically verified or encoded.
    pub fn historical_checkpoint_digest(
        &self,
    ) -> Result<[u8; 32], BrokerSessionSecurityError> {
        self.0.historical_checkpoint_digest()
    }

    /// Reconstructs the exact authenticated historical trio as nonauthorizing DATA.
    ///
    /// # Errors
    /// Rejects mismatched request, predecessor, session, or checkpoint commitments in the protected history.
    pub fn prior_verified_atomic_storage_history(
        &mut self,
        request_id: [u8; 16],
        request_packet: [u8; 32],
        predecessor_packet: [u8; 32],
        session_binding: [u8; 32],
        checkpoint_digest: [u8; 32],
    ) -> Result<crate::controller_composition::HistoricalAtomicStorageHistoryV1, BrokerSessionSecurityError>
    {
        self.0.prior_verified_atomic_storage_history(
            request_id,
            request_packet,
            predecessor_packet,
            session_binding,
            checkpoint_digest,
        )
        .map(crate::controller_composition::HistoricalAtomicStorageHistoryV1)
    }

    /// Archives the original verified atomic Storage history without replacement.
    ///
    /// # Errors
    /// Rejects invalid historical commitments or a failed native archive of the verified history.
    pub fn archive_verified_atomic_storage_history(
        &mut self,
        request_id: [u8; 16],
        request_packet: [u8; 32],
        predecessor_packet: [u8; 32],
        session_binding: [u8; 32],
        checkpoint_digest: [u8; 32],
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.archive_verified_atomic_storage_history(
            request_id,
            request_packet,
            predecessor_packet,
            session_binding,
            checkpoint_digest,
        )
    }

    /// Retires only the named original temporary Storage archive.
    ///
    /// # Errors
    /// Rejects changed protected custody, an invalid retirement chain, or a failed native retirement.
    pub fn retire_atomic_storage_archive(
        &mut self,
        request_id: [u8; 16],
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.retire_atomic_storage_archive(request_id)
    }

    pub(crate) fn prior_atomic_storage_history(
        &mut self,
        request_id: [u8; 16],
        request_packet: [u8; 32],
        predecessor_packet: [u8; 32],
        session_binding: [u8; 32],
    ) -> Result<crate::recovery::ProtectedPriorAtomicStorageHistoryV1, BrokerSessionSecurityError>
    {
        self.0.prior_atomic_storage_history(
            request_id,
            request_packet,
            predecessor_packet,
            session_binding,
        )
    }

    /// Recovers this exact Apply from protected terminal session history.
    ///
    /// The lookup happens before a new initial request can roll over the prior
    /// process history. A nonmatching or pending history returns absence; a
    /// matching terminal broker rejection remains a permanent effect failure.
    ///
    /// # Errors
    /// Rejects a malformed effect or mismatched terminal receipt permanently; unavailable protected history is retryable.
    pub fn recover_terminal_authority_effect(
        &mut self,
        effect: &PreparedAuthorityEffectV1,
    ) -> Result<Option<ValidatedAuthorityEffectReceiptV1>, EffectFailure> {
        let request = effect.broker_request().map_err(|_| {
            EffectFailure::Permanent("durable authority effect is malformed".to_owned())
        })?;
        let recovered = self
            .0
            .prior_terminal_exchange(
                request.method(),
                request.request_id(),
                effect.attempt().body(),
            )
            .map_err(|_| {
                EffectFailure::Retryable(
                    "protected terminal session history is unavailable".to_owned(),
                )
            })?;
        let Some(recovered) = recovered else {
            return Ok(None);
        };
        let receipt = recovered.result.map_err(|message| {
            let diagnostic = if message.is_empty() {
                "broker rejected the durable authority effect".to_owned()
            } else {
                format!("broker rejected the durable authority effect: {message}")
            };
            EffectFailure::Permanent(diagnostic)
        })?;
        effect
            .validate_protected_terminal_receipt(
                recovered.method,
                recovered.request_id,
                &recovered.request_body,
                receipt,
            )
            .map(Some)
            .map_err(|_| {
                EffectFailure::Permanent(
                    "protected session history contains a contradictory authority receipt"
                        .to_owned(),
                )
            })
    }

    /// Checks the fixed protected session against the controller's bound node.
    ///
    /// No identity is inferred from a socket path or an inventory response.
    ///
    /// # Errors
    /// Rejects a different node or changed protected endpoint, transcript, journal, or peer custody.
    pub fn require_current_node(
        &mut self,
        expected_node: [u8; 16],
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.require_current_node(expected_node)
    }

    /// Borrows the authenticated session socket for readiness polling.
    ///
    /// The descriptor is observation-only. All traffic must continue through
    /// the protected session methods so record-subject, transcript, sequence,
    /// and durable-currentness checks remain inseparable.
    ///
    /// # Errors
    ///
    /// Returns an error after a fatal transport failure closes the socket.
    pub fn as_fd(&self) -> Result<BorrowedFd<'_>, DormantBrokerSessionHandshakeErrorV1> {
        self.0.as_fd().map_err(Into::into)
    }

    pub(crate) fn sign_lifecycle_bootstrap_attestation(
        &mut self,
        message: &[u8; 32],
    ) -> Result<[u8; 64], BrokerSessionSecurityError> {
        self.0.sign_lifecycle_bootstrap_attestation(message)
    }

    fn begin_execution<Domain>(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        method_matches: bool,
    ) -> Result<
        (
            DormantReceivedBrokerRequestV1,
            ProtectedBrokerSessionVerificationContextV1,
        ),
        DormantBrokerExecutionFailureV1<Domain>,
    > {
        self.begin_execution_with_storage_receiving_v3(request, method_matches, None)
    }

    fn begin_execution_with_storage_receiving_v3<Domain>(&mut self,
        request: DormantReceivedBrokerRequestV1,
        method_matches: bool,
        receiving: Option<&mut dyn crate::recovery::StorageFloorFinancialSourceV2>,
    ) -> Result<(DormantReceivedBrokerRequestV1, ProtectedBrokerSessionVerificationContextV1),
        DormantBrokerExecutionFailureV1<Domain>> {
        if !method_matches {
            return Err(DormantBrokerExecutionFailureV1::BeforeEffect {
                error: BrokerSessionSecurityError::Currentness,
                request,
            });
        }
        let context = match self.0.reopen_broker_outcome_with_storage_receiving_v3(&request.0, receiving) {
            Ok((gate, context)) => {
                drop(gate);
                context
            }
            Err(error) => {
                return Err(DormantBrokerExecutionFailureV1::BeforeEffect { error, request });
            }
        };
        Ok((request, context))
    }

    fn unknown_domain<Domain>(
        request: DormantReceivedBrokerRequestV1,
        error: Domain,
    ) -> DormantBrokerExecutionFailureV1<Domain> {
        DormantBrokerExecutionFailureV1::OutcomeUnknown {
            error: DormantBrokerExecutionErrorV1::Domain(error),
            custody: DormantBrokerOutcomeUnknownV1 {
                request,
                observation: None,
            },
        }
    }

    fn finish_observed_success<Domain>(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        body: Vec<u8>,
    ) -> Result<ProtectedBrokerOutcomeCommitResultV1, DormantBrokerExecutionFailureV1<Domain>> {
        self.finish_observed_success_with_storage_receiving_v1(request, body, None)
    }

    fn finish_observed_success_with_storage_receiving_v1<Domain>(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        body: Vec<u8>,
        receiving: Option<&mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>>,
    ) -> Result<ProtectedBrokerOutcomeCommitResultV1, DormantBrokerExecutionFailureV1<Domain>> {
        self.finish_observed_success_with_storage_payer_v1(
            request, body, receiving.map(StorageOutcomeReceivingV1::Prepare),
        )
    }

    fn finish_observed_success_with_storage_payer_v1<Domain>(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        body: Vec<u8>,
        receiving: Option<StorageOutcomeReceivingV1<'_, '_, '_>>,
    ) -> Result<ProtectedBrokerOutcomeCommitResultV1, DormantBrokerExecutionFailureV1<Domain>> {
        match receiving {
            Some(StorageOutcomeReceivingV1::Lifecycle(receiving)) => {
                if let Err(_) = self.0.arm_storage_operation_post_v1(receiving) {
                    let observation = ProtectedBrokerDomainResponseV1::from_observation(&request.0, body).ok();
                    return Err(DormantBrokerExecutionFailureV1::OutcomeUnknown {
                        error: DormantBrokerExecutionErrorV1::Currentness(BrokerSessionSecurityError::Currentness),
                        custody: DormantBrokerOutcomeUnknownV1 { request, observation },
                    });
                }
                let result = self.finish_observed_success_storage_inner_v1(
                    request, body, Some(StorageOutcomeReceivingV1::Lifecycle(receiving)),
                ).map(|(committed, _request)| committed);
                let post = self.0.finish_storage_operation_post_v1(receiving);
                match result {
                    Err(failure) => Err(failure),
                    Ok(result) if post.is_ok() => Ok(result),
                    Ok(result) => Ok(result),
                }
            }
            other => self.finish_observed_success_storage_inner_v1(request, body, other)
                .map(|(committed, _request)| committed),
        }
    }

    // Host keeps its SAME received request through actual Committed/Sent.
    // All outcomes still use the one generic Prepare/Lifecycle/ordinary engine.
    fn finish_observed_success_retaining_request_v2<Domain>(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        body: Vec<u8>,
    ) -> Result<(ProtectedBrokerOutcomeCommitResultV1, DormantReceivedBrokerRequestV1),
        DormantBrokerExecutionFailureV1<Domain>>
    {
        self.finish_observed_success_storage_inner_v1(request, body, None)
    }

    fn finish_observed_success_storage_inner_v1<Domain>(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        body: Vec<u8>,
        mut receiving: Option<StorageOutcomeReceivingV1<'_, '_, '_>>,
    ) -> Result<(ProtectedBrokerOutcomeCommitResultV1, DormantReceivedBrokerRequestV1), DormantBrokerExecutionFailureV1<Domain>> {
        let observation = match ProtectedBrokerDomainResponseV1::from_observation(&request.0, body)
        {
            Ok(observation) => observation,
            Err(error) => {
                return Err(DormantBrokerExecutionFailureV1::OutcomeUnknown {
                    error: DormantBrokerExecutionErrorV1::Currentness(error),
                    custody: DormantBrokerOutcomeUnknownV1 {
                        request,
                        observation: None,
                    },
                });
            }
        };
        if let Some(receiving) = receiving.as_mut() {
            let current = match receiving {
                StorageOutcomeReceivingV1::Prepare(receiving) => {
                    let demand = self.storage_prepare_outcome_demand_v1(&request.0, &observation);
                    let reserved = match demand {
                        Ok(demand) => match request.method() {
                            BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES => receiving
                                .reserve_inventory_outcome_once_v1(demand)
                                .map_err(|_| BrokerSessionSecurityError::Currentness),
                            BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG => receiving
                                .reserve_prepare_outcome_once_v1(demand)
                                .map_err(|_| BrokerSessionSecurityError::Currentness),
                            _ => Err(BrokerSessionSecurityError::Currentness),
                        },
                        Err(error) => Err(error),
                    };
                    let current = match reserved {
                        Ok(()) => receiving.require_prepare_retention_v1()
                            .map_err(|_| BrokerSessionSecurityError::Currentness),
                        Err(error) => Err(error),
                    };
                    current
                }
                StorageOutcomeReceivingV1::Lifecycle(receiving) => self.0.reserve_storage_lifecycle_outcome_v1(
                    &request.0, &observation, receiving,
                ),
            };
            if let Err(error) = current {
                // The real observed response stays with uncertain request
                // custody if the genuine receiving owner changed before CAS.
                return Err(DormantBrokerExecutionFailureV1::OutcomeUnknown {
                    error: DormantBrokerExecutionErrorV1::Currentness(error),
                    custody: DormantBrokerOutcomeUnknownV1 {
                        request,
                        observation: Some(observation),
                    },
                });
            }
        }
        if let Err(error) = self.0.reopen_broker_outcome_with_storage_receiving_v3(&request.0,
            receiving.as_mut().map(|payer| payer.source_v3())) {
            return Err(DormantBrokerExecutionFailureV1::OutcomeUnknown {
                error: DormantBrokerExecutionErrorV1::Currentness(error),
                custody: DormantBrokerOutcomeUnknownV1 {
                    request,
                    observation: Some(observation),
                },
            });
        }
        match self.commit_authenticated_observation_with_storage_receiving_v3(
            DormantReceivedBrokerRequestV1(request.0.clone()),
            observation.clone(),
            receiving.as_mut().map(|payer| payer.source_v3()),
        ) {
            Ok(result) => Ok((result, request)),
            Err(error) => Err(DormantBrokerExecutionFailureV1::OutcomeUnknown {
                error: DormantBrokerExecutionErrorV1::Currentness(error),
                custody: DormantBrokerOutcomeUnknownV1 {
                    request,
                    observation: Some(observation),
                },
            }),
        }
    }

    /// Retries only protected currentness/readback and commit for a sealed observation.
    ///
    /// # Errors
    ///
    /// Returns the exact unchanged custody if no observation is available or
    /// if protected currentness still cannot be established.
    pub fn retry_observed_success_and_commit(
        &mut self,
        custody: DormantBrokerOutcomeUnknownV1,
    ) -> Result<ProtectedBrokerOutcomeCommitResultV1, DormantBrokerOutcomeUnknownV1> {
        let Some(observation) = custody.observation.clone() else {
            return Err(custody);
        };
        if self.0.reopen_broker_outcome(&custody.request.0).is_err() {
            return Err(custody);
        }
        match self.commit_authenticated_observation(
            DormantReceivedBrokerRequestV1(custody.request.0.clone()),
            observation,
        ) {
            Ok(result) => Ok(result),
            Err(_) => Err(custody),
        }
    }

    /// Executes Host ApplyRuntime before signing its exact successful body.
    ///
    /// # Errors
    ///
    /// Returns a domain or protected-currentness error without minting a
    /// terminal success when the effect or either currentness sandwich fails.
    pub async fn execute_host_apply_and_commit(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        adapter: crate::DormantHostBrokerEffectAdapterV1<'_>,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_host::DormantHostBrokerCallErrorV1>,
    > {
        self.execute_host_apply_and_commit_retaining_v2(request, adapter, None).await
            .map(|(committed, _)| committed)
    }

    /// Preserves the actual Host Runtime request through protected Sent.
    ///
    /// # Errors
    /// Retains the same unknown/before-effect request on admission, native,
    /// domain or terminal ambiguity; it creates no fresh Host permission.
    pub async fn execute_host_apply_and_commit_retaining_v2(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        adapter: crate::DormantHostBrokerEffectAdapterV1<'_>,
        retained_agent: Option<&aos_sandbox_host::live_agent::HostAgentLiveSessionV1>,
    ) -> Result<
        (ProtectedBrokerOutcomeCommitResultV1, DormantReceivedBrokerRequestV1),
        DormantBrokerExecutionFailureV1<aos_sandbox_host::DormantHostBrokerCallErrorV1>,
    > {
        let method_matches = request.0.method() == BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
            && adapter.matches_request(&request.0);
        let (request, context) = self.begin_execution(request, method_matches)?;
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());
        let observation = match adapter
            .execute_before_outcome(&request.0, retained_agent, version, context.boot_id())
            .await
        {
            Ok(observation) => observation,
            Err(error) => return Err(Self::unknown_domain(request, error)),
        };
        self.finish_observed_success_retaining_request_v2(request, observation.response().to_vec())
    }

    /// Applies or reads one controller-authenticated Host execution intent.
    ///
    /// The fixed Host execution owner reopens protected currentness and exact
    /// operation history. A new intent may reach Pending only; guest dispatch
    /// requires the separately authenticated agent session and route permit.
    /// Apply content remains borrowed from the sealed mapping through admission.
    ///
    /// # Errors
    ///
    /// Returns protected request custody for a pre-effect mismatch or for an
    /// unresolved owner, effect, or terminal-commit ambiguity.
    pub fn execute_host_execution_and_commit(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        execution_spec_content: Option<&[u8]>,
        host: &mut dyn aos_sandbox_host::DormantHostBrokerCallsiteV1,
        agent: Option<&mut aos_sandbox_host::live_agent::HostAgentLiveSessionV1>,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<crate::HostExecutionHandoffErrorV1>,
    > {
        let method = request.0.method();
        let method_matches = if matches!(
            method,
            BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
                | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2
        ) {
            request.0.authorization().is_none()
        } else {
            matches!(
                method,
                BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION
                    | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION
                    | BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT
                    | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_OUTPUT
                    | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT
                    | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_ARGUMENT
                    | BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
                    | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY
            ) && request.0.authorization().is_some()
        };
        let (request, context) = self.begin_execution(request, method_matches)?;
        let body = match crate::host_execution_handoff::dispatch_host_execution_handoff_v1(
            host,
            &request.0,
            execution_spec_content,
            context.boot_id(),
            agent,
            deadline_boottime_nanoseconds,
        ) {
            Ok(body) => body,
            Err(error) => return Err(Self::unknown_domain(request, error)),
        };
        self.finish_observed_success(request, body)
    }

    /// Reads a fresh QueryExecution27 scope using Host's actual held resident.
    ///
    /// The existing protected response pipeline owns CAS/readback, Sent and
    /// final currentness before the sealed Host resource-disposal callback.
    /// This cannot renew execution permission or reopen the held journals.
    ///
    /// # Errors
    /// Retains the real received request and all native/financial originals on
    /// method/scope mismatch, read refusal or authenticated outcome ambiguity.
    pub async fn execute_host_resident_query_and_commit_v3(
        &mut self, request: DormantReceivedBrokerRequestV1,
        host: &mut dyn aos_sandbox_host::DormantHostBrokerCallsiteV1,
        deadline: u64,
    ) -> Result<(ProtectedBrokerOutcomeCommitResultV1, DormantReceivedBrokerRequestV1),
        DormantBrokerExecutionFailureV1<crate::HostExecutionHandoffErrorV1>> {
        let matches = request.0.method() == BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION
            && request.0.authorization().is_some()
            && request.0.host_execution_query_data_v3().and_then(|query| query.monitor_v3()).is_some();
        let (request, context) = self.begin_execution(request, matches)?;
        let body = match host.query_resident_execution(&request.0, context.boot_id(), deadline).await {
            Ok(body) => body,
            Err(cause) => return Err(Self::unknown_domain(request, cause.into())),
        };
        self.finish_observed_success_retaining_request_v2(request, body)
    }

    /// Executes the existing Apply descriptor on Host's actual held59 owner.
    ///
    /// # Errors
    /// Keeps the actual request and original Host debt on every refusal. Only
    /// real protected outcome CAS/readback and Sent can complete the interval.
    pub async fn execute_host_accepted_execution_and_commit_v2(
        &mut self, request: DormantReceivedBrokerRequestV1,
        descriptor: &std::os::fd::OwnedFd,
        host: &mut dyn aos_sandbox_host::DormantHostBrokerCallsiteV1,
        agent: Option<&mut aos_sandbox_host::live_agent::HostAgentLiveSessionV1>,
        deadline: u64,
    ) -> Result<(ProtectedBrokerOutcomeCommitResultV1, DormantReceivedBrokerRequestV1),
        DormantBrokerExecutionFailureV1<crate::HostExecutionHandoffErrorV1>>
    {
        let matches = request.0.method() == BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION
            && request.0.authorization().is_some();
        let (request, context) = match self.begin_execution(request, matches) {
            Ok(entered) => entered,
            Err(failure) => {
                let actual = match &failure {
                    DormantBrokerExecutionFailureV1::BeforeEffect { request, .. } => &request.0,
                    DormantBrokerExecutionFailureV1::OutcomeUnknown { custody, .. } => &custody.request.0,
                };
                let _ = host.abort_pending_accepted_execution(actual);
                return Err(failure);
            }
        };
        let Some(agent) = agent else {
            let _ = host.abort_pending_accepted_execution(&request.0);
            return Err(Self::unknown_domain(request, crate::HostExecutionHandoffErrorV1::RecoveryRequired));
        };
        let body = match host.execute_accepted_execution(&request.0, descriptor,
            context.boot_id(), agent, deadline).await {
            Ok(body) => body,
            Err(error) => {
                let _ = host.abort_accepted_execution(request.0.request_id(),
                    request.0.session_binding(), request.0.signed_request_digest());
                return Err(Self::unknown_domain(request, error.into()));
            }
        };
        let result = self.finish_observed_success_retaining_request_v2(request, body);
        if let Err(failure) = &result {
            let original = match failure {
                DormantBrokerExecutionFailureV1::BeforeEffect { request, .. } => &request.0,
                DormantBrokerExecutionFailureV1::OutcomeUnknown { custody, .. } => &custody.request.0,
            };
            // Preserve the original Session failure and custody; the Host
            // retains its independently owed terminal/Ack result separately.
            let _ = host.abort_accepted_execution(original.request_id(),
                original.session_binding(), original.signed_request_digest());
        }
        result
    }

    /// Executes the paid Host Prepare/Accept flight before its signed outcome.
    ///
    /// # Errors
    /// Keeps the original received request on native/financial/currentness or
    /// terminal ambiguity. No failed flight becomes an applied or terminal
    /// success, and no one-shot method37 compatibility path is invoked.
    pub async fn execute_host_argument_and_commit_v2(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        host: &mut dyn aos_sandbox_host::DormantHostBrokerCallsiteV1,
        agent: Option<&mut aos_sandbox_host::live_agent::HostAgentLiveSessionV1>,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<(ProtectedBrokerOutcomeCommitResultV1, DormantReceivedBrokerRequestV1),
        DormantBrokerExecutionFailureV1<crate::HostExecutionHandoffErrorV1>>
    {
        let method_matches = matches!(request.0.method(),
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2
                | BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2)
            && request.0.authorization().is_some();
        let (request, context) = self.begin_execution(request, method_matches)?;
        let Some(agent) = agent else {
            return Err(Self::unknown_domain(request, crate::HostExecutionHandoffErrorV1::RecoveryRequired));
        };
        let body = match host.execute_prepared_argument(&request.0, context.boot_id(), agent,
            deadline_boottime_nanoseconds).await
        {
            Ok(body) => body,
            Err(error) => return Err(Self::unknown_domain(request, error.into())),
        };
        self.finish_observed_success_retaining_request_v2(request, body)
    }

    /// Executes a Host observe, inventory, or effect query before signing it.
    ///
    /// # Errors
    ///
    /// Returns a domain or protected-currentness error without minting a
    /// terminal success when the real Host observation or either currentness
    /// sandwich fails.
    pub async fn execute_host_observation_and_commit(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        adapter: crate::DormantHostBrokerObservationAdapterV1<'_>,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_host::DormantHostBrokerCallErrorV1>,
    > {
        let method_matches = matches!(
            request.0.method(),
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME
                | BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME
                | BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT
        ) && adapter.matches_request(&request.0);
        let (request, context) = self.begin_execution(request, method_matches)?;
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());
        let observation = match adapter
            .execute_before_outcome(&request.0, version, context.boot_id())
            .await
        {
            Ok(observation) => observation,
            Err(error) => return Err(Self::unknown_domain(request, error)),
        };
        self.finish_observed_success(request, observation.response().to_vec())
    }

    /// Executes Mount Apply before signing its exact successful body.
    ///
    /// # Errors
    ///
    /// Returns a domain or protected-currentness error without minting a
    /// terminal success when the effect or either currentness sandwich fails.
    pub fn execute_mount_apply_and_commit(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        adapter: crate::DormantMountBrokerEffectAdapterV1<'_>,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_mount::DormantMountBrokerCallErrorV1>,
    > {
        let method_matches = request.0.method() == BrokerMethod::BROKER_METHOD_MOUNT_APPLY
            && adapter.matches_request(&request.0);
        let (request, context) = self.begin_execution(request, method_matches)?;
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());
        let observation =
            match adapter.execute_before_outcome(&request.0, version, context.boot_id()) {
                Ok(observation) => observation,
                Err(error) => return Err(Self::unknown_domain(request, error)),
            };
        self.finish_observed_success(request, observation.response().to_vec())
    }

    /// Reads authoritative Mount inventory before signing its exact body.
    ///
    /// # Errors
    ///
    /// Returns a domain or protected-currentness error without minting a
    /// terminal success when inventory or either currentness sandwich fails.
    pub fn execute_mount_inventory_and_commit(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        adapter: crate::DormantMountBrokerInventoryAdapterV1<'_>,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_mount::DormantMountBrokerCallErrorV1>,
    > {
        let method_matches = matches!(
            request.0.method(),
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES
                | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS
        ) && adapter.matches_request(&request.0);
        let (request, context) = self.begin_execution(request, method_matches)?;
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());
        let observation =
            match adapter.execute_before_outcome(&request.0, version, context.boot_id()) {
                Ok(observation) => observation,
                Err(error) => return Err(Self::unknown_domain(request, error)),
            };
        self.finish_observed_success(request, observation.response().to_vec())
    }

    /// Executes Mount destination-slot mutation before signing its result.
    ///
    /// # Errors
    ///
    /// Returns a domain or protected-currentness error without minting a
    /// terminal success when the effect or either currentness sandwich fails.
    pub fn execute_mount_destination_slot_and_commit(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        adapter: crate::DormantMountBrokerEffectAdapterV1<'_>,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_mount::DormantMountBrokerCallErrorV1>,
    > {
        let method_matches = request.0.method()
            == BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT
            && adapter.matches_request(&request.0);
        let (request, context) = self.begin_execution(request, method_matches)?;
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());
        let observation = match adapter.execute_destination_slot_before_outcome(
            &request.0,
            version,
            context.boot_id(),
        ) {
            Ok(observation) => observation,
            Err(error) => return Err(Self::unknown_domain(request, error)),
        };
        self.finish_observed_success(request, observation.response().to_vec())
    }

    /// Reads the fixed Mount source-acquisition owner before signing inventory.
    ///
    /// # Errors
    ///
    /// Returns a domain or protected-currentness error unless the fixed
    /// namespace-40 graph and both session currentness checks remain exact.
    pub fn execute_mount_source_inventory_and_commit<Transport>(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        owner: &mut aos_sandbox_mount::source_acquisition::FixedMountSourceAcquisitionOwnerV2,
        root_session: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
        provider: &mut aos_sandbox_source_provider::FixedProviderOwnerV1,
        backend: &mut Transport,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_mount::MountError>,
    >
    where
        Transport: aos_sandbox_source_provider::SourceProviderBackendTransportV1 + ?Sized,
    {
        let method_matches = request.0.method()
            == BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS
            && request.0.authorization().is_none();
        let (request, _) = self.begin_execution(request, method_matches)?;
        if !provider.backend_recovery_active()
            && !owner.has_cold_provider_recovery()
            && !owner.has_pending_provider_response()
            && !owner.has_inventory_recovery_replacement()
        {
            let response = match owner.encode_current_inventory() {
                Ok(response) => response,
                Err(error) => return Err(Self::unknown_domain(request, error)),
            };
            return self.finish_observed_success(request, response);
        }

        if provider.backend_recovery_requires_successor_handshake() {
            if let Err(error) = root_session.begin_successor_handshake() {
                return Err(Self::unknown_domain(
                    request,
                    aos_sandbox_mount::MountError::State(error.to_string()),
                ));
            }
            if let Err(error) = provider.begin_recovery_successor_handshake() {
                return Err(Self::unknown_domain(
                    request,
                    aos_sandbox_mount::MountError::State(error.to_string()),
                ));
            }
            return Err(Self::unknown_domain(
                request,
                aos_sandbox_mount::MountError::State(
                    "Inventory recovery successor handshake began".to_owned(),
                ),
            ));
        }
        if provider.recovery_successor_handshake_pending()
            || provider.backend_recovery_awaits_fresh_request()
        {
            if provider.recovery_successor_handshake_pending() {
                let root_progress = match root_session.advance_handshake() {
                    Ok(progress) => progress,
                    Err(error) => {
                        return Err(Self::unknown_domain(
                            request,
                            aos_sandbox_mount::MountError::State(error.to_string()),
                        ));
                    }
                };
                let provider_progress = match provider.advance_recovery_successor_handshake() {
                    Ok(progress) => progress,
                    Err(error) => {
                        return Err(Self::unknown_domain(
                            request,
                            aos_sandbox_mount::MountError::State(error.to_string()),
                        ));
                    }
                };
                if root_progress
                    == aos_sandbox_source_provider_security::RootMountSourceProviderHandshakeStatusV1::Pending
                    || provider_progress
                        == aos_sandbox_source_provider::FixedProviderOwnerStatusV1::HandshakePending
                {
                    return Err(Self::unknown_domain(
                        request,
                        aos_sandbox_mount::MountError::State(
                            "Inventory recovery successor handshake is pending".to_owned(),
                        ),
                    ));
                }
            }
            let retry_authority = match provider.backend_recovery_mount_retry_authority() {
                Ok(authority) => authority,
                Err(error) => {
                    return Err(Self::unknown_domain(
                        request,
                        aos_sandbox_mount::MountError::State(error.to_string()),
                    ));
                }
            };
            if let Err(error) =
                owner.replace_and_send_inventory_backend_recovery(root_session, retry_authority)
            {
                return Err(Self::unknown_domain(request, error));
            }
            if let Err(error) = provider.mark_backend_recovery_request_in_flight() {
                return Err(Self::unknown_domain(
                    request,
                    aos_sandbox_mount::MountError::State(error.to_string()),
                ));
            }
        }

        let mut historical_inventory_recovered = false;
        if owner.cold_provider_recovery_has_reserved_request()
            && !provider.backend_recovery_active()
        {
            let signed_request = match owner.cold_reserved_provider_request() {
                Ok(signed) => signed,
                Err(error) => return Err(Self::unknown_domain(request, error)),
            };
            match provider.readback_mount_request(signed_request) {
                Ok(
                    aos_sandbox_source_provider::FixedProviderRequestReadbackV1::RetryAuthorized(
                        retry_authority,
                    ),
                ) => {
                    if let Err(error) = owner
                        .replace_and_send_inventory_backend_recovery(root_session, retry_authority)
                    {
                        return Err(Self::unknown_domain(request, error));
                    }
                }
                Ok(
                    aos_sandbox_source_provider::FixedProviderRequestReadbackV1::HistoricalOutcome(
                        historical,
                    ),
                ) => {
                    let recovered = provider.with_catalog_authority(|catalog_journal| {
                        owner
                            .recover_persisted_cold_provider_outcome(
                                root_session,
                                catalog_journal,
                                historical,
                            )
                            .map_err(|_| {
                                aos_sandbox_source_provider::ProviderLedgerError::InvalidTransition(
                                    "historical Inventory outcome recovery failed",
                                )
                            })
                    });
                    if let Err(error) = recovered {
                        return Err(Self::unknown_domain(
                            request,
                            aos_sandbox_mount::MountError::State(error.to_string()),
                        ));
                    }
                    historical_inventory_recovered = true;
                }
                Ok(aos_sandbox_source_provider::FixedProviderRequestReadbackV1::AcquireReopen(
                    _,
                )) => {
                    return Err(Self::unknown_domain(
                        request,
                        aos_sandbox_mount::MountError::State(
                            "Inventory readback selected an Acquire reopen".to_owned(),
                        ),
                    ));
                }
                Ok(
                    aos_sandbox_source_provider::FixedProviderRequestReadbackV1::RecoveryPending,
                ) => {
                    return Err(Self::unknown_domain(
                        request,
                        aos_sandbox_mount::MountError::State(
                            "durable Inventory recovery was not rehydrated".to_owned(),
                        ),
                    ));
                }
                Err(error) => {
                    return Err(Self::unknown_domain(
                        request,
                        aos_sandbox_mount::MountError::State(error.to_string()),
                    ));
                }
            }
        }
        if !historical_inventory_recovered
            && owner.has_inventory_recovery_replacement()
            && !provider.backend_recovery_active()
        {
            let signed_request = match owner.inventory_replaced_provider_request() {
                Ok(signed) => signed,
                Err(error) => return Err(Self::unknown_domain(request, error)),
            };
            match provider.readback_mount_request(signed_request) {
                Ok(
                    aos_sandbox_source_provider::FixedProviderRequestReadbackV1::RetryAuthorized(
                        retry_authority,
                    ),
                ) => {
                    if let Err(error) = owner
                        .replace_and_send_inventory_backend_recovery(root_session, retry_authority)
                    {
                        return Err(Self::unknown_domain(request, error));
                    }
                }
                Ok(
                    aos_sandbox_source_provider::FixedProviderRequestReadbackV1::HistoricalOutcome(
                        _,
                    )
                    | aos_sandbox_source_provider::FixedProviderRequestReadbackV1::AcquireReopen(_),
                ) => {
                    return Err(Self::unknown_domain(
                        request,
                        aos_sandbox_mount::MountError::State(
                            "Inventory replacement readback changed disposition".to_owned(),
                        ),
                    ));
                }
                Ok(
                    aos_sandbox_source_provider::FixedProviderRequestReadbackV1::RecoveryPending,
                ) => {
                    return Err(Self::unknown_domain(
                        request,
                        aos_sandbox_mount::MountError::State(
                            "durable Inventory replacement awaits Provider recovery".to_owned(),
                        ),
                    ));
                }
                Err(error) => {
                    return Err(Self::unknown_domain(
                        request,
                        aos_sandbox_mount::MountError::State(error.to_string()),
                    ));
                }
            }
        }

        if historical_inventory_recovered {
            let response = match owner.encode_current_inventory() {
                Ok(response) => response,
                Err(error) => return Err(Self::unknown_domain(request, error)),
            };
            return self.finish_observed_success(request, response);
        }

        let mut provider_session = provider.backend_session(backend);
        let outcome = match provider_session.receive_and_execute_request() {
            Ok(aos_sandbox_source_provider::FixedProviderReceivedRequestProgressV1::Pending) => {
                return Err(Self::unknown_domain(
                    request,
                    aos_sandbox_mount::MountError::State(
                        "authenticated Inventory receive is pending".to_owned(),
                    ),
                ));
            }
            Ok(aos_sandbox_source_provider::FixedProviderReceivedRequestProgressV1::Outcome(
                outcome,
            )) => outcome,
            Err(error) => {
                if provider.failed_ingress_reopen_required() {
                    let signed_request = match owner.pending_provider_request() {
                        Ok(request) => request,
                        Err(mount_error) => return Err(Self::unknown_domain(request, mount_error)),
                    };
                    if let Err(rearm_error) =
                        provider.arm_mount_retry_after_failed_ingress(signed_request)
                    {
                        return Err(Self::unknown_domain(
                            request,
                            aos_sandbox_mount::MountError::State(rearm_error.to_string()),
                        ));
                    }
                }
                return Err(Self::unknown_domain(
                    request,
                    aos_sandbox_mount::MountError::State(error.to_string()),
                ));
            }
        };
        match outcome {
            aos_sandbox_source_provider::FixedProviderBackendRequestOutcomeV1::Reply(reply)
            | aos_sandbox_source_provider::FixedProviderBackendRequestOutcomeV1::Released {
                reply,
                ..
            }
            | aos_sandbox_source_provider::FixedProviderBackendRequestOutcomeV1::CachedRecovery {
                reply,
            } => {
                if let Err(error) = provider_session.send_reply(reply) {
                    return Err(Self::unknown_domain(
                        request,
                        aos_sandbox_mount::MountError::State(error.to_string()),
                    ));
                }
            }
            aos_sandbox_source_provider::FixedProviderBackendRequestOutcomeV1::RecoveryPending => {
                drop(provider_session);
                if let Err(error) = root_session.begin_successor_handshake() {
                    return Err(Self::unknown_domain(
                        request,
                        aos_sandbox_mount::MountError::State(error.to_string()),
                    ));
                }
                if let Err(error) = provider.begin_recovery_successor_handshake() {
                    return Err(Self::unknown_domain(
                        request,
                        aos_sandbox_mount::MountError::State(error.to_string()),
                    ));
                }
                return Err(Self::unknown_domain(
                    request,
                    aos_sandbox_mount::MountError::State(
                        "Inventory backend recovery successor handshake began".to_owned(),
                    ),
                ));
            }
        }
        drop(provider_session);
        let consumed = provider.with_catalog_authority(|catalog_journal| {
            owner
                .consume_sent_provider_outcome(root_session, catalog_journal)
                .map_err(|_| {
                    aos_sandbox_source_provider::ProviderLedgerError::InvalidTransition(
                        "Mount Inventory outcome consumption failed",
                    )
                })
        });
        if let Err(error) = consumed {
            return Err(Self::unknown_domain(
                request,
                aos_sandbox_mount::MountError::State(error.to_string()),
            ));
        }
        let response = match owner.encode_current_inventory() {
            Ok(response) => response,
            Err(error) => return Err(Self::unknown_domain(request, error)),
        };
        self.finish_observed_success(request, response)
    }

    /// Executes or reads back one Mount source operation before signing its result.
    ///
    /// Fresh requests traverse the fixed Root-Mount and provider session,
    /// namespace-40 reservation, protected catalog floor, real backend adapter,
    /// authenticated response carrier, and Mount outcome reducer. An exact
    /// terminal row remains the idempotent retry path.
    ///
    /// # Errors
    ///
    /// Returns a domain or protected-currentness error unless the method is
    /// Acquire/Release, its signed authority remains present, and the fixed
    /// source graph contains the exact terminal result between currentness
    /// checks.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_mount_source_operation_and_commit<Transport>(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        owner: &mut aos_sandbox_mount::source_acquisition::FixedMountSourceAcquisitionOwnerV2,
        root_session: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
        provider: &mut aos_sandbox_source_provider::FixedProviderOwnerV1,
        backend: &mut Transport,
        canonical_catalog_publication: &[u8],
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_mount::MountError>,
    >
    where
        Transport: aos_sandbox_source_provider::SourceProviderBackendTransportV1 + ?Sized,
    {
        let method_matches = matches!(
            request.0.method(),
            BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE
                | BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION
        ) && request.0.authorization().is_some();
        let (request, context) = self.begin_execution(request, method_matches)?;
        if !owner.has_cold_provider_recovery()
            && !owner.has_postcommit_recovery()
            && !provider.backend_recovery_active()
            && let Ok(response) = owner.encode_current_operation_response(
                request.0.method(),
                request.0.exact_body(),
                request.0.peer(),
                request.0.peer_policy(),
                context.boot_id(),
            )
        {
            return self.finish_observed_success(request, response);
        }
        let authorization = match request.0.authorization() {
            Some(authorization) => authorization,
            None => {
                return Err(DormantBrokerExecutionFailureV1::BeforeEffect {
                    error: BrokerSessionSecurityError::Currentness,
                    request,
                });
            }
        };
        let mount_plan_digest: [u8; 32] = Sha256::digest(authorization.broker_plan()).into();
        let ownership_lease_digest: [u8; 32] =
            Sha256::digest(authorization.ownership_lease()).into();
        let resume_pending = match owner.pending_provider_request_matches(
            request.0.method(),
            request.0.request_id(),
            request.0.exact_body(),
            request.0.peer(),
            request.0.peer_policy(),
            context.boot_id(),
        ) {
            Ok(value) => value,
            Err(error) => return Err(Self::unknown_domain(request, error)),
        };
        if !resume_pending
            && (provider.backend_recovery_active()
                || owner.has_cold_provider_recovery()
                || owner.has_pending_provider_response()
                || owner.has_pending_provider_send())
        {
            return Err(DormantBrokerExecutionFailureV1::BeforeEffect {
                error: BrokerSessionSecurityError::Currentness,
                request,
            });
        }
        if owner.has_startup_manager_recovery() {
            if let Err(error) = owner.resume_next_startup_manager_custody(root_session) {
                return Err(Self::unknown_domain(request, error));
            }
            if !provider.backend_recovery_active()
                && let Ok(response) = owner.encode_current_operation_response(
                    request.0.method(),
                    request.0.exact_body(),
                    request.0.peer(),
                    request.0.peer_policy(),
                    context.boot_id(),
                )
            {
                return self.finish_observed_success(request, response);
            }
            if owner.has_startup_manager_recovery() {
                return Err(Self::unknown_domain(
                    request,
                    aos_sandbox_mount::MountError::State(
                        "protected startup manager custody remains pending".to_owned(),
                    ),
                ));
            }
        }
        if owner.has_postcommit_recovery() {
            if let Err(error) = owner.resolve_next_postcommit_recovery(root_session) {
                return Err(Self::unknown_domain(request, error));
            }
            if !owner.has_cold_provider_recovery()
                && !provider.backend_recovery_active()
                && let Ok(response) = owner.encode_current_operation_response(
                    request.0.method(),
                    request.0.exact_body(),
                    request.0.peer(),
                    request.0.peer_policy(),
                    context.boot_id(),
                )
            {
                return self.finish_observed_success(request, response);
            }
        }
        if owner.has_negative_custody_recovery() {
            if let Err(error) = owner.resolve_next_negative_custody_recovery(root_session) {
                return Err(Self::unknown_domain(request, error));
            }
            if !provider.backend_recovery_active()
                && let Ok(response) = owner.encode_current_operation_response(
                    request.0.method(),
                    request.0.exact_body(),
                    request.0.peer(),
                    request.0.peer_policy(),
                    context.boot_id(),
                )
            {
                return self.finish_observed_success(request, response);
            }
        }
        if owner.has_pending_manager_operation() {
            return Err(Self::unknown_domain(
                request,
                aos_sandbox_mount::MountError::State(
                    "Mount manager source custody must be resumed before terminal signing"
                        .to_owned(),
                ),
            ));
        }
        if owner.has_cold_provider_recovery()
            && !owner.has_pending_provider_response()
            && !owner.has_pending_provider_send()
        {
            let signed_request = match owner.cold_provider_request() {
                Ok(signed_request) => signed_request,
                Err(error) => return Err(Self::unknown_domain(request, error)),
            };
            let readback = match provider.readback_mount_request(signed_request.clone()) {
                Ok(readback) => readback,
                Err(error) => {
                    return Err(Self::unknown_domain(
                        request,
                        aos_sandbox_mount::MountError::State(error.to_string()),
                    ));
                }
            };
            match readback {
                aos_sandbox_source_provider::FixedProviderRequestReadbackV1::RecoveryPending => {
                    match provider.align_backend_recovery_with_mount_request(&signed_request) {
                        Ok(true) => {}
                        Ok(false) => {
                            return Err(Self::unknown_domain(
                                request,
                                aos_sandbox_mount::MountError::State(
                                    "oldest Mount recovery has no matching Provider work"
                                        .to_owned(),
                                ),
                            ));
                        }
                        Err(error) => {
                            return Err(Self::unknown_domain(
                                request,
                                aos_sandbox_mount::MountError::State(error.to_string()),
                            ));
                        }
                    }
                }
                aos_sandbox_source_provider::FixedProviderRequestReadbackV1::RetryAuthorized(
                    retry_authority,
                ) => {
                    let current_catalog = match provider
                        .authorize_current_catalog_publication(canonical_catalog_publication)
                    {
                        Ok(current) => current,
                        Err(error) => {
                            return Err(Self::unknown_domain(
                                request,
                                aos_sandbox_mount::MountError::State(error.to_string()),
                            ));
                        }
                    };
                    let resent = provider.with_catalog_authority(|catalog_journal| {
                        owner
                            .replace_and_send_backend_recovery(
                                root_session,
                                catalog_journal,
                                retry_authority,
                                Some(current_catalog),
                            )
                            .map_err(|_| {
                                aos_sandbox_source_provider::ProviderLedgerError::InvalidTransition(
                                    "oldest Mount retry reservation failed",
                                )
                            })
                    });
                    if let Err(error) = resent {
                        return Err(Self::unknown_domain(
                            request,
                            aos_sandbox_mount::MountError::State(error.to_string()),
                        ));
                    }
                }
                aos_sandbox_source_provider::FixedProviderRequestReadbackV1::HistoricalOutcome(
                    historical,
                ) => {
                    let recovered = provider.with_catalog_authority(|catalog_journal| {
                        owner
                            .recover_persisted_cold_provider_outcome(
                                root_session,
                                catalog_journal,
                                historical,
                            )
                            .map_err(|_| {
                                aos_sandbox_source_provider::ProviderLedgerError::InvalidTransition(
                                    "oldest historical Mount outcome recovery failed",
                                )
                            })
                    });
                    if let Err(error) = recovered {
                        return Err(Self::unknown_domain(
                            request,
                            aos_sandbox_mount::MountError::State(error.to_string()),
                        ));
                    }
                    let response = match owner.encode_current_operation_response(
                        request.0.method(),
                        request.0.exact_body(),
                        request.0.peer(),
                        request.0.peer_policy(),
                        context.boot_id(),
                    ) {
                        Ok(response) => response,
                        Err(error) => return Err(Self::unknown_domain(request, error)),
                    };
                    return self.finish_observed_success(request, response);
                }
                aos_sandbox_source_provider::FixedProviderRequestReadbackV1::AcquireReopen(
                    reopen,
                ) => {
                    let historical = {
                        let mut provider_session = provider.backend_session(backend);
                        match provider_session.reopen_historical_acquire(reopen) {
                            Ok(historical) => historical,
                            Err(error) => {
                                return Err(Self::unknown_domain(
                                    request,
                                    aos_sandbox_mount::MountError::State(error.to_string()),
                                ));
                            }
                        }
                    };
                    let recovered = provider.with_catalog_authority(|catalog_journal| {
                        owner
                            .recover_persisted_cold_provider_outcome(
                                root_session,
                                catalog_journal,
                                historical,
                            )
                            .map_err(|_| {
                                aos_sandbox_source_provider::ProviderLedgerError::InvalidTransition(
                                    "oldest reopened Acquire recovery failed",
                                )
                            })
                    });
                    if let Err(error) = recovered {
                        return Err(Self::unknown_domain(
                            request,
                            aos_sandbox_mount::MountError::State(error.to_string()),
                        ));
                    }
                    let response = match owner.encode_current_operation_response(
                        request.0.method(),
                        request.0.exact_body(),
                        request.0.peer(),
                        request.0.peer_policy(),
                        context.boot_id(),
                    ) {
                        Ok(response) => response,
                        Err(error) => return Err(Self::unknown_domain(request, error)),
                    };
                    return self.finish_observed_success(request, response);
                }
            }
        }
        if provider.failed_ingress_reopen_required() {
            return Err(Self::unknown_domain(
                request,
                aos_sandbox_mount::MountError::State(
                    "fatal Provider ingress requires an explicit authenticated reopen".to_owned(),
                ),
            ));
        }
        if provider.mount_retry_rearm_required() && !provider.recovery_successor_handshake_pending()
        {
            if let Err(error) = root_session.begin_successor_handshake() {
                return Err(Self::unknown_domain(
                    request,
                    aos_sandbox_mount::MountError::State(error.to_string()),
                ));
            }
            if let Err(error) = provider.begin_recovery_successor_handshake() {
                return Err(Self::unknown_domain(
                    request,
                    aos_sandbox_mount::MountError::State(error.to_string()),
                ));
            }
            return Err(Self::unknown_domain(
                request,
                aos_sandbox_mount::MountError::State(
                    "priority Mount retry successor handshake began".to_owned(),
                ),
            ));
        }
        if provider.backend_recovery_requires_successor_handshake()
            && !provider.mount_retry_priority_active()
        {
            if let Err(error) = root_session.begin_successor_handshake() {
                return Err(Self::unknown_domain(
                    request,
                    aos_sandbox_mount::MountError::State(error.to_string()),
                ));
            }
            if let Err(error) = provider.begin_recovery_successor_handshake() {
                return Err(Self::unknown_domain(
                    request,
                    aos_sandbox_mount::MountError::State(error.to_string()),
                ));
            }
            return Err(Self::unknown_domain(
                request,
                aos_sandbox_mount::MountError::State(
                    "backend recovery successor handshake began".to_owned(),
                ),
            ));
        }
        let backend_recovery_active = provider.backend_recovery_active();
        let current_catalog = if !backend_recovery_active
            && !resume_pending
            && request.0.method() == BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE
        {
            match provider.authorize_current_catalog_publication(canonical_catalog_publication) {
                Ok(current) => Some(current),
                Err(error) => {
                    return Err(Self::unknown_domain(
                        request,
                        aos_sandbox_mount::MountError::State(error.to_string()),
                    ));
                }
            }
        } else {
            None
        };
        let prepared = if backend_recovery_active {
            Ok(())
        } else {
            provider.with_catalog_authority(|catalog_journal| {
                if resume_pending && !owner.has_pending_release_preparation() {
                    return Ok(());
                }
                match request.0.method() {
                    BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE => match current_catalog {
                        Some(current_catalog) => owner.prepare_and_send_fresh_acquire(
                            root_session,
                            catalog_journal,
                            current_catalog,
                            request.0.exact_body(),
                            request.0.peer(),
                            request.0.peer_policy(),
                            context.boot_id(),
                            mount_plan_digest,
                            ownership_lease_digest,
                        ),
                        None => Err(aos_sandbox_mount::MountError::State(
                            "Mount Acquire lacks protected catalog authority".to_owned(),
                        )),
                    },
                    BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION => owner
                        .prepare_and_send_fresh_release(
                            root_session,
                            request.0.exact_body(),
                            request.0.peer(),
                            request.0.peer_policy(),
                            context.boot_id(),
                        ),
                    _ => Err(aos_sandbox_mount::MountError::State(
                        "unsupported source operation".to_owned(),
                    )),
                }
                .map_err(|_error| {
                    aos_sandbox_source_provider::ProviderLedgerError::InvalidTransition(
                        if matches!(
                            request.0.method(),
                            BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE
                        ) {
                            "Mount Acquire reservation failed"
                        } else {
                            "Mount Release reservation failed"
                        },
                    )
                })
            })
        };
        if let Err(error) = prepared {
            return Err(Self::unknown_domain(
                request,
                aos_sandbox_mount::MountError::State(error.to_string()),
            ));
        }
        if (!backend_recovery_active || provider.mount_retry_priority_active())
            && resume_pending
            && owner.has_pending_provider_send()
            && let Err(error) = owner.retry_pending_provider_send(root_session)
        {
            return Err(Self::unknown_domain(request, error));
        }
        if !provider.mount_retry_priority_active()
            && (provider.recovery_successor_handshake_pending()
                || provider.backend_recovery_awaits_fresh_request())
        {
            let recovery_progress = (|| -> Result<bool, aos_sandbox_mount::MountError> {
                if provider.recovery_successor_handshake_pending() {
                    let root_progress = root_session
                        .advance_handshake()
                        .map_err(|error| aos_sandbox_mount::MountError::State(error.to_string()))?;
                    let provider_progress = provider
                        .advance_recovery_successor_handshake()
                        .map_err(|error| aos_sandbox_mount::MountError::State(error.to_string()))?;
                    if root_progress
                        == aos_sandbox_source_provider_security::RootMountSourceProviderHandshakeStatusV1::Pending
                        || provider_progress
                            == aos_sandbox_source_provider::FixedProviderOwnerStatusV1::HandshakePending
                    {
                        return Ok(false);
                    }
                }
                if provider.mount_retry_rearm_required() {
                    let signed_request = owner.pending_provider_request()?;
                    let method = signed_request.method();
                    let retry_authority = match provider.readback_mount_request(signed_request) {
                        Ok(
                            aos_sandbox_source_provider::FixedProviderRequestReadbackV1::RetryAuthorized(
                                retry_authority,
                            ),
                        ) => retry_authority,
                        Ok(_) => {
                            return Err(aos_sandbox_mount::MountError::State(
                                "priority Mount retry readback changed disposition".to_owned(),
                            ));
                        }
                        Err(error) => {
                            return Err(aos_sandbox_mount::MountError::State(error.to_string()));
                        }
                    };
                    let current_catalog = if method
                        == aos_sandbox_source_provider_protocol::SourceProviderMethod::Acquire
                    {
                        Some(
                            provider
                                .authorize_current_catalog_publication(
                                    canonical_catalog_publication,
                                )
                                .map_err(|error| {
                                    aos_sandbox_mount::MountError::State(error.to_string())
                                })?,
                        )
                    } else {
                        None
                    };
                    provider
                        .with_catalog_authority(|catalog_journal| {
                            owner
                                .replace_and_send_backend_recovery(
                                    root_session,
                                    catalog_journal,
                                    retry_authority,
                                    current_catalog,
                                )
                                .map_err(|_| {
                                    aos_sandbox_source_provider::ProviderLedgerError::InvalidTransition(
                                        "priority Mount retry replacement failed",
                                    )
                                })
                        })
                        .map_err(|error| {
                            aos_sandbox_mount::MountError::State(error.to_string())
                        })?;
                    return Ok(true);
                }
                let current_catalog = provider
                    .authorize_current_catalog_publication(canonical_catalog_publication)
                    .map_err(|error| aos_sandbox_mount::MountError::State(error.to_string()))?;
                let retry_authority = provider
                    .backend_recovery_mount_retry_authority()
                    .map_err(|error| aos_sandbox_mount::MountError::State(error.to_string()))?;
                provider
                    .with_catalog_authority(|catalog_journal| {
                        owner
                            .replace_and_send_backend_recovery(
                                root_session,
                                catalog_journal,
                                retry_authority,
                                Some(current_catalog),
                            )
                            .map_err(|_| {
                                aos_sandbox_source_provider::ProviderLedgerError::InvalidTransition(
                                    "Mount backend recovery retry reservation failed",
                                )
                            })
                    })
                    .map_err(|error| aos_sandbox_mount::MountError::State(error.to_string()))?;
                provider
                    .mark_backend_recovery_request_in_flight()
                    .map_err(|error| aos_sandbox_mount::MountError::State(error.to_string()))?;
                Ok(true)
            })();
            match recovery_progress {
                Ok(true) => {}
                Ok(false) => {
                    return Err(Self::unknown_domain(
                        request,
                        aos_sandbox_mount::MountError::State(
                            "SourceProvider recovery successor handshake is pending".to_owned(),
                        ),
                    ));
                }
                Err(error) => return Err(Self::unknown_domain(request, error)),
            }
        }
        let cold_reply_replayed =
            if owner.has_cold_provider_recovery() && !provider.backend_recovery_active() {
                let signed_request = match owner.cold_provider_request() {
                    Ok(request) => request,
                    Err(error) => return Err(Self::unknown_domain(request, error)),
                };
                match provider.readback_mount_request(signed_request) {
                Ok(aos_sandbox_source_provider::FixedProviderRequestReadbackV1::RetryAuthorized(
                    retry_authority,
                )) => {
                    let current_catalog = match provider
                        .authorize_current_catalog_publication(canonical_catalog_publication)
                    {
                        Ok(current) => current,
                        Err(error) => {
                            return Err(Self::unknown_domain(
                                request,
                                aos_sandbox_mount::MountError::State(error.to_string()),
                            ));
                        }
                    };
                    let resent = provider.with_catalog_authority(|catalog_journal| {
                        owner
                            .replace_and_send_backend_recovery(
                                root_session,
                                catalog_journal,
                                retry_authority,
                                Some(current_catalog),
                            )
                            .map_err(|_| {
                                aos_sandbox_source_provider::ProviderLedgerError::InvalidTransition(
                                    "cold Mount request retry reservation failed",
                                )
                            })
                    });
                    if let Err(error) = resent {
                        return Err(Self::unknown_domain(
                            request,
                            aos_sandbox_mount::MountError::State(error.to_string()),
                        ));
                    }
                    false
                }
                Ok(
                    aos_sandbox_source_provider::FixedProviderRequestReadbackV1::HistoricalOutcome(
                        historical,
                    ),
                ) => {
                    let recovered = provider.with_catalog_authority(|catalog_journal| {
                        owner
                            .recover_persisted_cold_provider_outcome(
                                root_session,
                                catalog_journal,
                                historical,
                            )
                            .map_err(|_| {
                                aos_sandbox_source_provider::ProviderLedgerError::InvalidTransition(
                                    "historical Mount outcome recovery failed",
                                )
                            })
                    });
                    if let Err(error) = recovered {
                        return Err(Self::unknown_domain(
                            request,
                            aos_sandbox_mount::MountError::State(error.to_string()),
                        ));
                    }
                    true
                }
                Ok(
                    aos_sandbox_source_provider::FixedProviderRequestReadbackV1::AcquireReopen(
                        reopen,
                    ),
                ) => {
                    let historical = {
                        let mut provider_session = provider.backend_session(backend);
                        match provider_session.reopen_historical_acquire(reopen) {
                            Ok(historical) => historical,
                            Err(error) => {
                                return Err(Self::unknown_domain(
                                    request,
                                    aos_sandbox_mount::MountError::State(error.to_string()),
                                ));
                            }
                        }
                    };
                    let recovered = provider.with_catalog_authority(|catalog_journal| {
                        owner
                            .recover_persisted_cold_provider_outcome(
                                root_session,
                                catalog_journal,
                                historical,
                            )
                            .map_err(|_| {
                                aos_sandbox_source_provider::ProviderLedgerError::InvalidTransition(
                                    "reopened historical Acquire recovery failed",
                                )
                            })
                    });
                    if let Err(error) = recovered {
                        return Err(Self::unknown_domain(
                            request,
                            aos_sandbox_mount::MountError::State(error.to_string()),
                        ));
                    }
                    true
                }
                Ok(
                    aos_sandbox_source_provider::FixedProviderRequestReadbackV1::RecoveryPending,
                ) => {
                    return Err(Self::unknown_domain(
                        request,
                        aos_sandbox_mount::MountError::State(
                            "durable Provider recovery work was not rehydrated".to_owned(),
                        ),
                    ));
                }
                Err(error) => {
                    return Err(Self::unknown_domain(
                        request,
                        aos_sandbox_mount::MountError::State(error.to_string()),
                    ));
                }
            }
            } else {
                false
            };
        let live_response_pending = owner.has_pending_provider_response();
        let recover_consumed =
            !live_response_pending && owner.cold_provider_recovery_has_consumed_disposition();
        let provider_result = if recover_consumed || cold_reply_replayed {
            Ok(false)
        } else {
            let mut provider_session = provider.backend_session(backend);
            match provider_session.receive_and_execute_request() {
                Ok(aos_sandbox_source_provider::FixedProviderReceivedRequestProgressV1::Pending) => {
                    return Err(Self::unknown_domain(
                        request,
                        aos_sandbox_mount::MountError::State(
                            "authenticated SourceProvider receive is pending".to_owned(),
                        ),
                    ));
                }
                Ok(aos_sandbox_source_provider::FixedProviderReceivedRequestProgressV1::Outcome(
                    outcome,
                )) => match outcome {
                    aos_sandbox_source_provider::FixedProviderBackendRequestOutcomeV1::Reply(
                        reply,
                    )
                    | aos_sandbox_source_provider::FixedProviderBackendRequestOutcomeV1::Released {
                        reply,
                        ..
                    } => provider_session.send_reply(reply).map(|()| false),
                    aos_sandbox_source_provider::FixedProviderBackendRequestOutcomeV1::CachedRecovery {
                        reply,
                    } => provider_session.send_reply(reply).map(|()| false),
                    aos_sandbox_source_provider::FixedProviderBackendRequestOutcomeV1::RecoveryPending => {
                        Ok(true)
                    }
                },
                Err(error) => Err(error),
            }
        };
        match provider_result {
            Ok(true) => {
                if let Err(error) = root_session.begin_successor_handshake() {
                    return Err(Self::unknown_domain(
                        request,
                        aos_sandbox_mount::MountError::State(error.to_string()),
                    ));
                }
                if let Err(error) = provider.begin_recovery_successor_handshake() {
                    return Err(Self::unknown_domain(
                        request,
                        aos_sandbox_mount::MountError::State(error.to_string()),
                    ));
                }
                return Err(Self::unknown_domain(
                    request,
                    aos_sandbox_mount::MountError::State(
                        "backend recovery successor handshake began".to_owned(),
                    ),
                ));
            }
            Ok(false) => {}
            Err(error) => {
                if provider.failed_ingress_reopen_required() {
                    let signed_request = match owner.pending_provider_request() {
                        Ok(request) => request,
                        Err(mount_error) => return Err(Self::unknown_domain(request, mount_error)),
                    };
                    if let Err(rearm_error) =
                        provider.arm_mount_retry_after_failed_ingress(signed_request)
                    {
                        return Err(Self::unknown_domain(
                            request,
                            aos_sandbox_mount::MountError::State(rearm_error.to_string()),
                        ));
                    }
                }
                return Err(Self::unknown_domain(
                    request,
                    aos_sandbox_mount::MountError::State(error.to_string()),
                ));
            }
        }
        if !cold_reply_replayed {
            let consumed = provider.with_catalog_authority(|catalog_journal| {
                let result = if owner.has_pending_provider_response() {
                    owner.consume_sent_provider_outcome(root_session, catalog_journal)
                } else {
                    owner.recover_cold_provider_outcome(root_session, catalog_journal)
                };
                result.map_err(|_| {
                    aos_sandbox_source_provider::ProviderLedgerError::InvalidTransition(
                        "Mount outcome consumption failed",
                    )
                })
            });
            if let Err(error) = consumed {
                return Err(Self::unknown_domain(
                    request,
                    aos_sandbox_mount::MountError::State(error.to_string()),
                ));
            }
        }
        let response = match owner.encode_current_operation_response(
            request.0.method(),
            request.0.exact_body(),
            request.0.peer(),
            request.0.peer_policy(),
            context.boot_id(),
        ) {
            Ok(response) => response,
            Err(error) => return Err(Self::unknown_domain(request, error)),
        };
        self.finish_observed_success(request, response)
    }

    /// Seals an ambiguous Mount Acquire/Release failure into resumable custody.
    ///
    /// This is the only public conversion from the generic unknown result to a
    /// source-operation recovery value. Failures before effect remain ordinary
    /// signed-error/retry candidates and cannot enter this path.
    ///
    /// # Errors
    ///
    /// Returns the original failure unless it owns an unknown exact Mount
    /// Acquire or Release request.
    pub fn retain_mount_source_operation_recovery(
        failure: DormantBrokerExecutionFailureV1<aos_sandbox_mount::MountError>,
    ) -> Result<
        DormantMountSourceBrokerRecoveryV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_mount::MountError>,
    > {
        match failure {
            DormantBrokerExecutionFailureV1::OutcomeUnknown { custody, .. }
                if matches!(
                    custody.request.0.method(),
                    BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE
                        | BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION
                ) =>
            {
                Ok(DormantMountSourceBrokerRecoveryV1(custody))
            }
            failure => Err(failure),
        }
    }

    /// Resumes one exact ambiguous Mount Acquire/Release operation.
    ///
    /// A sealed domain observation retries only protected response commit. An
    /// unobserved request re-enters the source owner, which resumes retained
    /// send, provider-response, cold-reopen, or postcommit custody before the
    /// exact protected operation response is encoded and committed. The
    /// authenticated request is never exposed or rebuilt.
    #[allow(clippy::too_many_arguments)]
    pub fn resume_mount_source_operation_and_commit<Transport>(
        &mut self,
        recovery: DormantMountSourceBrokerRecoveryV1,
        owner: &mut aos_sandbox_mount::source_acquisition::FixedMountSourceAcquisitionOwnerV2,
        root_session: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
        provider: &mut aos_sandbox_source_provider::FixedProviderOwnerV1,
        backend: &mut Transport,
        canonical_catalog_publication: &[u8],
    ) -> DormantMountSourceBrokerRecoveryProgressV1
    where
        Transport: aos_sandbox_source_provider::SourceProviderBackendTransportV1 + ?Sized,
    {
        let request = match recovery.0 {
            custody @ DormantBrokerOutcomeUnknownV1 {
                observation: Some(_),
                ..
            } => {
                return match self.retry_observed_success_and_commit(custody) {
                    Ok(committed) => {
                        DormantMountSourceBrokerRecoveryProgressV1::Committed(committed)
                    }
                    Err(custody) => DormantMountSourceBrokerRecoveryProgressV1::RecoveryRequired(
                        DormantMountSourceBrokerRecoveryV1(custody),
                    ),
                };
            }
            DormantBrokerOutcomeUnknownV1 {
                request,
                observation: None,
            } => request,
        };
        match self.execute_mount_source_operation_and_commit(
            request,
            owner,
            root_session,
            provider,
            backend,
            canonical_catalog_publication,
        ) {
            Ok(committed) => DormantMountSourceBrokerRecoveryProgressV1::Committed(committed),
            Err(DormantBrokerExecutionFailureV1::OutcomeUnknown { custody, .. }) => {
                DormantMountSourceBrokerRecoveryProgressV1::RecoveryRequired(
                    DormantMountSourceBrokerRecoveryV1(custody),
                )
            }
            Err(DormantBrokerExecutionFailureV1::BeforeEffect { request, .. }) => {
                DormantMountSourceBrokerRecoveryProgressV1::RecoveryRequired(
                    DormantMountSourceBrokerRecoveryV1(DormantBrokerOutcomeUnknownV1 {
                        request,
                        observation: None,
                    }),
                )
            }
        }
    }

    /// Resolves Mount catalog preparation before signing its exact result.
    ///
    /// # Errors
    ///
    /// Returns a domain or protected-currentness error unless the Host-sealed
    /// scope, Mount catalog, request, and session remain mutually current.
    pub fn execute_mount_catalog_preparation_and_commit(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        adapter: crate::DormantMountCatalogPreparationAdapterV1<'_>,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_mount::DormantMountBrokerCallErrorV1>,
    > {
        let method_matches = request.0.method()
            == BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG
            && request.0.authorization().is_none();
        let (request, context) = self.begin_execution(request, method_matches)?;
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());
        let observation =
            match adapter.execute_before_outcome(&request.0, version, context.boot_id()) {
                Ok(observation) => observation,
                Err(error) => return Err(Self::unknown_domain(request, error)),
            };
        self.finish_observed_success(request, observation.response().to_vec())
    }

    fn begin_storage_lifecycle_execution_v1<Domain>(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        method_matches: bool,
        receiving: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        native_admission: &mut Option<aos_sandbox::StorageReceivingClosedV1>,
    ) -> Result<(DormantReceivedBrokerRequestV1, ProtectedBrokerSessionVerificationContextV1),
        DormantBrokerExecutionFailureV1<Domain>>
    {
        if let Err(cause) = self.0.arm_storage_request_post_v1(receiving) {
            *native_admission = Some(cause);
            return Err(DormantBrokerExecutionFailureV1::BeforeEffect {
                error: BrokerSessionSecurityError::Currentness, request,
            });
        }
        // The independent observation was armed before the actual
        // Domain reservation can poison admission. It still executes
        // directly on refusal, while this same request stays resident.
        if let Err(cause) = self.0.reserve_storage_lifecycle_domain_v1(receiving) {
            *native_admission = Some(cause);
            let _post = self.0.finish_storage_operation_post_v1(receiving);
            return Err(DormantBrokerExecutionFailureV1::BeforeEffect {
                error: BrokerSessionSecurityError::Currentness, request,
            });
        }
        let began = self.begin_execution_with_storage_receiving_v3(request, method_matches, Some(receiving));
        let post = self.0.finish_storage_operation_post_v1(receiving);
        match (began, post) {
            (Err(failure), _) => return Err(failure),
            (Ok((request, context)), Ok(())) => Ok((request, context)),
            (Ok((request, _)), Err(cause)) => {
                *native_admission = Some(cause);
                return Err(DormantBrokerExecutionFailureV1::BeforeEffect {
                    error: BrokerSessionSecurityError::Currentness, request,
                });
            }
        }
    }

    /// Executes Storage Apply before signing a committed physical result.
    ///
    /// # Errors
    ///
    /// Returns a domain or protected-currentness error when Storage remains
    /// observation-only, or when either currentness sandwich fails.
    pub fn execute_storage_apply_and_commit(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        adapter: crate::DormantStorageBrokerEffectAdapterV1<'_>,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_storage::DormantStorageBrokerCallErrorV1>,
    > {
        self.execute_storage_apply_inner_v1(request, StorageApplyDispatchV1::Ordinary(adapter))
    }

    pub(crate) fn execute_storage_apply_receiving_and_commit_v1(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        receiving: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        native_admission: &mut Option<aos_sandbox::StorageReceivingClosedV1>,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_storage::DormantStorageBrokerCallErrorV1>,
    > {
        self.execute_storage_apply_inner_v1(request, StorageApplyDispatchV1::Receiving { storage, receiving, native_admission })
    }

    fn execute_storage_apply_inner_v1(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        mut dispatch: StorageApplyDispatchV1<'_, '_, '_>,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_storage::DormantStorageBrokerCallErrorV1>,
    > {
        let method_matches = request.0.method() == BrokerMethod::BROKER_METHOD_STORAGE_APPLY
            && match &dispatch {
                StorageApplyDispatchV1::Ordinary(adapter) => adapter.matches_request(&request.0),
                StorageApplyDispatchV1::Receiving { .. } => request.authorization_artifacts().is_some(),
            };
        let (request, context) = match &mut dispatch {
            StorageApplyDispatchV1::Receiving { receiving, native_admission, .. } if method_matches => {
                self.begin_storage_lifecycle_execution_v1(request, method_matches, receiving, native_admission)?
            }
            _ => self.begin_execution(request, method_matches)?,
        };
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());
        let (response, receiving) = match dispatch {
            StorageApplyDispatchV1::Ordinary(adapter) => {
                let observation = match adapter.execute_before_outcome(&request.0, version, context.boot_id()) {
                    Ok(observation) => observation,
                    Err(error) => return Err(Self::unknown_domain(request, error)),
                };
                let response = match observation.response() {
                    Ok(response) => response,
                    Err(error) => return Err(Self::unknown_domain(request, error)),
                };
                (response, None)
            }
            StorageApplyDispatchV1::Receiving { storage, receiving, .. } => {
                let response = match self.0.consume_storage_apply_receiving_v1(
                    &request.0, version, context.boot_id(), storage, receiving,
                ) {
                    Ok(response) => response,
                    Err(error) => return Err(Self::unknown_domain(request, error)),
                };
                (response, Some(StorageOutcomeReceivingV1::Lifecycle(receiving)))
            }
        };
        self.finish_observed_success_with_storage_payer_v1(request, response, receiving)
    }

    pub(crate) fn execute_storage_prepare_receiving_and_commit_v1(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_storage::DormantStorageBrokerCallErrorV1>,
    > {
        let method_matches = request.method() == BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
            && request.authorization_artifacts().is_some();
        let (request, context) = self.begin_execution_with_storage_receiving_v3(
            request, method_matches, Some(receiving),
        )?;
        let Some(artifacts) = request.authorization_artifacts() else {
            return Err(DormantBrokerExecutionFailureV1::BeforeEffect {
                error: BrokerSessionSecurityError::Currentness,
                request,
            });
        };
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());
        let response = match storage.consume_authenticated_prepare_catalog_receiving_v1(
            request.0.exact_body(),
            request.0.request_id(),
            aos_sandbox_core::ObjectDigest::from_bytes(Sha256::digest(request.0.exact_body()).into()),
            artifacts,
            request.0.peer(),
            request.0.peer_policy(),
            version,
            context.boot_id(),
            receiving,
        ) {
            Ok(response) => response,
            Err(error) => return Err(Self::unknown_domain(request, error)),
        };
        self.finish_observed_success_with_storage_receiving_v1(request, response, Some(receiving))
    }

    /// Executes Storage catalog preparation, repair, grouped snapshot, or
    /// guest-root publication
    /// before signing success.
    ///
    /// # Errors
    ///
    /// Returns a domain or protected-currentness error without minting a
    /// success for pending recovery or a failed exact-domain operation.
    pub fn execute_storage_operation_and_commit(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        adapter: crate::DormantStorageBrokerEffectAdapterV1<'_>,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_storage::DormantStorageBrokerCallErrorV1>,
    > {
        self.execute_storage_operation_inner_v1(request, StorageOperationDispatchV1::Ordinary(adapter))
    }

    pub(crate) fn execute_storage_operation_lifecycle_and_commit_v1(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        receiving: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        native_admission: &mut Option<aos_sandbox::StorageReceivingClosedV1>,
    ) -> Result<ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_storage::DormantStorageBrokerCallErrorV1>>
    {
        self.execute_storage_operation_inner_v1(request,
            StorageOperationDispatchV1::Lifecycle { storage, receiving, native_admission })
    }

    fn execute_storage_operation_inner_v1(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        mut dispatch: StorageOperationDispatchV1<'_, '_, '_>,
    ) -> Result<ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_storage::DormantStorageBrokerCallErrorV1>>
    {
        let method_matches = match &dispatch {
            StorageOperationDispatchV1::Ordinary(adapter) => matches!(
                request.0.method(),
                BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
                    | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_NIX_GENERATION_V1
                    | BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN
                    | BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT
            ) && adapter.matches_request(&request.0),
            StorageOperationDispatchV1::Lifecycle { .. } =>
                matches!(request.0.method(),
                    BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
                        | BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN
                        | BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT)
                    && request.authorization_artifacts().is_some(),
        };
        let (request, context) = match &mut dispatch {
            StorageOperationDispatchV1::Lifecycle { receiving, native_admission, .. }
                if method_matches => self.begin_storage_lifecycle_execution_v1(
                    request, method_matches, receiving, native_admission,
                )?,
            _ => self.begin_execution(request, method_matches)?,
        };
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());
        let (response, receiving) = match dispatch {
            StorageOperationDispatchV1::Ordinary(adapter) => {
                let response = match adapter.execute_operation_before_outcome(
                    &request.0, version, context.boot_id(),
                ) {
                    Ok(response) => response,
                    Err(error) => return Err(Self::unknown_domain(request, error)),
                };
                (response, None)
            }
            StorageOperationDispatchV1::Lifecycle { storage, receiving, .. } => {
                let response = match self.0.consume_storage_operation_lifecycle_v1(
                    &request.0, version, context.boot_id(), storage, receiving,
                ) {
                    Ok(response) => response,
                    Err(error) => return Err(Self::unknown_domain(request, error)),
                };
                (response, Some(StorageOutcomeReceivingV1::Lifecycle(receiving)))
            }
        };
        self.finish_observed_success_with_storage_payer_v1(request, response, receiving)
    }

    /// Signs a recovery-only decision from the old protected Storage session.
    ///
    /// Broker-terminal evidence wins over pending abandonment. This method
    /// never reads current inventory or invokes a physical Storage effect.
    ///
    /// # Errors
    ///
    /// Returns retained request custody if the old signed history, protected
    /// marker commit, or current broker-session authority is indeterminate.
    pub fn execute_storage_inventory_recovery_and_commit(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<BrokerSessionSecurityError>,
    > {
        let method_matches = request.0.method()
            == BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY
            && request.0.authorization().is_none();
        let (request, _) = self.begin_execution(request, method_matches)?;
        let body = match self
            .0
            .broker_storage_inventory_recovery_response(&request.0)
        {
            Ok(body) => body,
            Err(error) => return Err(Self::unknown_domain(request, error)),
        };
        self.finish_observed_success(request, body)
    }

    /// Reads authoritative Storage inventory before signing its exact body.
    ///
    /// # Errors
    ///
    /// Returns a domain or protected-currentness error without minting a
    /// terminal success when complete inventory or currentness is unavailable.
    pub fn execute_storage_inventory_and_commit(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_storage::StorageRuntimeError>,
    > {
        self.execute_storage_inventory_with_storage_receiving_v1(request, storage, None)
    }

    pub(crate) fn execute_storage_inventory_with_storage_receiving_v1(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        receiving: Option<&mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>>,
    ) -> Result<ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_storage::StorageRuntimeError>>
    {
        let dispatch = match receiving {
            Some(receiving) => StorageInventoryDispatchV1::Prepare(receiving),
            None => StorageInventoryDispatchV1::Ordinary,
        };
        self.execute_storage_inventory_inner_v1(request, storage, dispatch)
    }

    pub(crate) fn execute_storage_inventory_lifecycle_and_commit_v1(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        receiving: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        native_admission: &mut Option<aos_sandbox::StorageReceivingClosedV1>,
    ) -> Result<ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_storage::StorageRuntimeError>>
    {
        self.execute_storage_inventory_inner_v1(request, storage,
            StorageInventoryDispatchV1::Lifecycle { receiving, native_admission })
    }

    fn execute_storage_inventory_inner_v1(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        mut dispatch: StorageInventoryDispatchV1<'_, '_, '_>,
    ) -> Result<ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_storage::StorageRuntimeError>>
    {
        let method_matches = request.0.method()
            == BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
            && request.0.authorization().is_none();
        let (request, _) = match &mut dispatch {
            StorageInventoryDispatchV1::Lifecycle { receiving, native_admission } =>
                self.begin_storage_lifecycle_execution_v1(request, method_matches, receiving, native_admission)?,
            StorageInventoryDispatchV1::Prepare(receiving) =>
                self.begin_execution_with_storage_receiving_v3(request, method_matches, Some(&mut **receiving))?,
            _ => self.begin_execution(request, method_matches)?,
        };
        let Some(worker_cutoff) = request
            .0
            .deadline_boottime_nanoseconds()
            .checked_sub(5_000_000_000)
        else {
            return Err(DormantBrokerExecutionFailureV1::BeforeEffect {
                error: BrokerSessionSecurityError::Currentness,
                request,
            });
        };
        let (observed, receiving) = match dispatch {
            StorageInventoryDispatchV1::Prepare(receiving) => (storage.lifecycle_inventory_resources_receiving_v1(
                request.0.deadline_boottime_nanoseconds(), worker_cutoff, receiving,
            ), Some(StorageOutcomeReceivingV1::Prepare(receiving))),
            StorageInventoryDispatchV1::Lifecycle { receiving, .. } => (
                self.0.consume_storage_inventory_receiving_v1(&request.0, worker_cutoff, storage, receiving),
                Some(StorageOutcomeReceivingV1::Lifecycle(receiving)),
            ),
            StorageInventoryDispatchV1::Ordinary => (storage.lifecycle_inventory_resources(
                request.0.deadline_boottime_nanoseconds(), worker_cutoff,
            ), None),
        };
        let response = match observed {
            Ok(response) => response,
            Err(error) => return Err(Self::unknown_domain(request, error)),
        };
        self.finish_observed_success_with_storage_payer_v1(request, response, receiving)
    }

    /// Reads authoritative Network inventory before signing its exact body.
    ///
    /// # Errors
    ///
    /// Returns a domain or protected-currentness error without minting a
    /// terminal success when physical catalog validation or currentness fails.
    pub fn execute_network_inventory_and_commit(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        catalog: &aos_sandbox_network::NetworkNamespaceCatalogV1,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_network::NetworkNamespaceCatalogError>,
    > {
        let method_matches = matches!(
            request.0.method(),
            BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY
                | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES
        ) && request.0.authorization().is_none();
        let (request, _) = self.begin_execution(request, method_matches)?;
        let response = match if request.0.method() == BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY
        {
            catalog.inventory_networks()
        } else {
            catalog.inventory_resources()
        } {
            Ok(response) => response,
            Err(error) => return Err(Self::unknown_domain(request, error)),
        };
        self.finish_observed_success(request, response)
    }

    /// Commits a success body minted by a sealed broker-domain observation.
    ///
    /// # Errors
    ///
    /// Returns an error unless the observation is cross-linked to this exact
    /// request and the protected owner can sign and durably read back its outcome.
    pub(crate) fn commit_authenticated_observation(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        observation: ProtectedBrokerDomainResponseV1,
    ) -> Result<ProtectedBrokerOutcomeCommitResultV1, BrokerSessionSecurityError> {
        self.commit_authenticated_observation_with_storage_receiving_v3(request, observation, None)
    }

    fn commit_authenticated_observation_with_storage_receiving_v3(&mut self,
        request: DormantReceivedBrokerRequestV1,
        observation: ProtectedBrokerDomainResponseV1,
        mut receiving: Option<&mut dyn crate::recovery::StorageFloorFinancialSourceV2>,
    ) -> Result<ProtectedBrokerOutcomeCommitResultV1, BrokerSessionSecurityError> {
        if observation.method != request.0.method()
            || observation.request_id != request.0.request_id()
            || observation.signed_request_digest != request.0.signed_request_digest()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let message = BrokerResponseEnvelope {
            request_id: observation.request_id.to_vec(),
            method: observation.method.into(),
            body: observation.body,
            ..Default::default()
        };
        let pending = self.0.prepare_broker_outcome_with_storage_receiving_v3(&request.0, message,
            receiving.as_mut().map(|source| &mut **source as &mut dyn crate::recovery::StorageFloorFinancialSourceV2))?;
        Ok(self.0.commit_outcome_with_storage_receiving_v3(pending, receiving))
    }

    /// Recovers an ambiguous client request installation without exposing bytes.
    #[must_use]
    pub fn recover_prepared_initialization(
        &mut self,
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        request: DormantUnconfirmedBrokerRequestV1,
    ) -> DormantBrokerRequestPreparationV1 {
        match self.0.recover_initialization(recovery) {
            ProtectedBrokerSessionInitializationResultV1::Initialized => {
                DormantBrokerRequestPreparationV1::Prepared(DormantPreparedBrokerRequestV1(
                    request.0,
                ))
            }
            ProtectedBrokerSessionInitializationResultV1::RecoveryRequired { error, recovery } => {
                DormantBrokerRequestPreparationV1::InitializationRecoveryRequired {
                    error,
                    recovery,
                    request,
                }
            }
        }
    }

    /// Recovers an ambiguous client successor request without exposing bytes.
    #[must_use]
    pub fn recover_prepared_successor(
        &mut self,
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        request: DormantUnconfirmedBrokerRequestV1,
    ) -> DormantBrokerRequestPreparationV1 {
        match self.0.recover_request_commit(recovery) {
            ProtectedBrokerRequestCommitResultV1::Committed => {
                DormantBrokerRequestPreparationV1::Prepared(DormantPreparedBrokerRequestV1(
                    request.0,
                ))
            }
            ProtectedBrokerRequestCommitResultV1::RecoveryRequired { error, recovery } => {
                DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired {
                    error,
                    recovery,
                    request,
                }
            }
        }
    }

    /// Recovers ambiguous client descriptor-request initialization with all FDs.
    #[must_use]
    pub fn recover_prepared_descriptor_initialization(
        &mut self,
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        request: DormantUnconfirmedBrokerDescriptorRequestV1,
    ) -> DormantBrokerDescriptorRequestPreparationV1 {
        match self.0.recover_initialization(recovery) {
            ProtectedBrokerSessionInitializationResultV1::Initialized => {
                DormantBrokerDescriptorRequestPreparationV1::Prepared(
                    DormantPreparedBrokerDescriptorRequestV1 {
                        request: request.request,
                        descriptors: request.descriptors,
                    },
                )
            }
            ProtectedBrokerSessionInitializationResultV1::RecoveryRequired { error, recovery } => {
                DormantBrokerDescriptorRequestPreparationV1::InitializationRecoveryRequired {
                    error,
                    recovery,
                    request,
                }
            }
        }
    }

    /// Recovers ambiguous client descriptor-request successor state with all FDs.
    #[must_use]
    pub fn recover_prepared_descriptor_successor(
        &mut self,
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        request: DormantUnconfirmedBrokerDescriptorRequestV1,
    ) -> DormantBrokerDescriptorRequestPreparationV1 {
        match self.0.recover_request_commit(recovery) {
            ProtectedBrokerRequestCommitResultV1::Committed => {
                DormantBrokerDescriptorRequestPreparationV1::Prepared(
                    DormantPreparedBrokerDescriptorRequestV1 {
                        request: request.request,
                        descriptors: request.descriptors,
                    },
                )
            }
            ProtectedBrokerRequestCommitResultV1::RecoveryRequired { error, recovery } => {
                DormantBrokerDescriptorRequestPreparationV1::SuccessorRecoveryRequired {
                    error,
                    recovery,
                    request,
                }
            }
        }
    }

    /// Recovers an ambiguous broker-side initial request admission.
    #[must_use]
    pub fn recover_received_initialization(
        &mut self,
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        request: DormantUnconfirmedReceivedBrokerRequestV1,
    ) -> DormantBrokerRequestReceiveProgressV1 {
        match self.0.recover_initialization(recovery) {
            ProtectedBrokerSessionInitializationResultV1::Initialized => {
                DormantBrokerRequestReceiveProgressV1::Received(DormantReceivedBrokerRequestV1(
                    request.0,
                ))
            }
            ProtectedBrokerSessionInitializationResultV1::RecoveryRequired { error, recovery } => {
                DormantBrokerRequestReceiveProgressV1::InitializationRecoveryRequired {
                    error,
                    recovery,
                    request,
                }
            }
        }
    }

    /// Recovers an ambiguous broker-side successor request admission.
    #[must_use]
    pub fn recover_received_successor(
        &mut self,
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        request: DormantUnconfirmedReceivedBrokerRequestV1,
    ) -> DormantBrokerRequestReceiveProgressV1 {
        match self.0.recover_request_commit(recovery) {
            ProtectedBrokerRequestCommitResultV1::Committed => {
                DormantBrokerRequestReceiveProgressV1::Received(DormantReceivedBrokerRequestV1(
                    request.0,
                ))
            }
            ProtectedBrokerRequestCommitResultV1::RecoveryRequired { error, recovery } => {
                DormantBrokerRequestReceiveProgressV1::SuccessorRecoveryRequired {
                    error,
                    recovery,
                    request,
                }
            }
        }
    }

    /// Receives, authenticates, and durably reserves one broker-side request.
    ///
    /// # Errors
    ///
    /// Returns an error for a changed record subject, socket peer, protected
    /// endpoint, clock, transcript, or malformed signed method packet.
    pub fn receive_authenticated_request(
        &mut self,
    ) -> Result<DormantBrokerRequestReceiveProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        let admission = match self.0.receive_authenticated_request() {
            Ok(value) => value,
            Err(handshake::DormantBrokerSessionHandshakeErrorV1::Transport) => {
                return Ok(DormantBrokerRequestReceiveProgressV1::Pending);
            }
            Err(error) => return Err(error.into()),
        };
        let (request, initialize) = match admission {
            crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::New {
                request,
                requires_initialization,
            } => (request, requires_initialization),
            crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::InFlightReplay {
                request,
            } => {
                return Ok(DormantBrokerRequestReceiveProgressV1::InFlightReplay(
                    DormantBrokerOutcomeUnknownV1 {
                        request: DormantReceivedBrokerRequestV1(request),
                        observation: None,
                    },
                ));
            }
            crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::TerminalReplay {
                replay,
            } => {
                let replay = DormantBrokerTerminalReplayV1(replay);
                return Ok(if replay.0.response_descriptor_roles()?.is_empty() {
                    DormantBrokerRequestReceiveProgressV1::TerminalReplay(replay)
                } else {
                    DormantBrokerRequestReceiveProgressV1::DescriptorTerminalReplay(
                        DormantBrokerDescriptorTerminalReplayV1(replay),
                    )
                });
            }
        };
        let received = DormantReceivedBrokerRequestV1(request.clone());
        if initialize {
            return Ok(match self.0.initialize_authenticated_request(&request)? {
                ProtectedBrokerSessionInitializationResultV1::Initialized => {
                    DormantBrokerRequestReceiveProgressV1::Received(received)
                }
                ProtectedBrokerSessionInitializationResultV1::RecoveryRequired {
                    error,
                    recovery,
                } => DormantBrokerRequestReceiveProgressV1::InitializationRecoveryRequired {
                    error,
                    recovery,
                    request: DormantUnconfirmedReceivedBrokerRequestV1(request),
                },
            });
        }
        Ok(match self.0.append_authenticated_request(&request)? {
            ProtectedBrokerRequestCommitResultV1::Committed => {
                DormantBrokerRequestReceiveProgressV1::Received(received)
            }
            ProtectedBrokerRequestCommitResultV1::RecoveryRequired { error, recovery } => {
                DormantBrokerRequestReceiveProgressV1::SuccessorRecoveryRequired {
                    error,
                    recovery,
                    request: DormantUnconfirmedReceivedBrokerRequestV1(request),
                }
            }
        })
    }

    /// Rejects one ordinary request while original Repair settlement is unresolved.
    ///
    /// This method never borrows a Storage runtime or domain dispatcher. It
    /// reuses actual authenticated request admission and the independently
    /// held namespace-47 session writer to commit only an exact signed Conflict.
    /// No inventory, physical effect, owner hold, or public ledger row changes.
    /// Prior in-flight or terminal work is not overwritten or called absent;
    /// the consumed socket closes promptly and its original durable history
    /// remains the sole recovery authority.
    ///
    /// # Errors
    ///
    /// Consumes the session on prior replay, unavailable current custody,
    /// malformed authenticated request, uncertain error commit/readback or
    /// response delivery beyond the original bounded request deadline.
    pub fn serve_operator_repair_unresolved_rejection(
        self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, crate::ProductionBrokerServiceErrorV1> {
        let (mut session, event) =
            self.receive_production_request(deadline_boottime_nanoseconds)?;
        let request = match event {
            crate::ProductionBrokerRequestEventV1::Request(request) => request,
            crate::ProductionBrokerRequestEventV1::InFlightReplay(_)
            | crate::ProductionBrokerRequestEventV1::TerminalReplay(_)
            | crate::ProductionBrokerRequestEventV1::DescriptorTerminalReplay(_) => {
                return Err(crate::ProductionBrokerResponseErrorV1::OutcomeRecovery.into());
            }
        };
        let deadline = deadline_boottime_nanoseconds
            .min(request.0.deadline_boottime_nanoseconds());
        check_production_deadline(deadline)
            .map_err(crate::ProductionBrokerResponseErrorV1::from)?;
        let committed = session
            .commit_authenticated_error_response(request, DormantBrokerFailureV1::Conflict)
            .map_err(crate::ProductionBrokerResponseErrorV1::from)?;
        session
            .finish_authenticated_response(committed, deadline)
            .map_err(Into::into)
    }

    /// Receives any authenticated Host request with its method-selected FD table.
    ///
    /// Ordinary Host methods carry no descriptors; `PublishCatalog` and
    /// `ApplyExecution` each carry one. The protected method decoder validates
    /// that relationship before this method returns descriptor custody. This
    /// avoids selecting a transport profile from unauthenticated packet bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, subject, descriptor-role, semantic, or
    /// protected-currentness failure. Descriptors never escape ambiguous state.
    pub fn receive_authenticated_host_request(
        &mut self,
    ) -> Result<DormantBrokerDescriptorRequestReceiveProgressV1, DormantBrokerSessionHandshakeErrorV1>
    {
        let (admission, descriptors) =
            match self.0.receive_authenticated_optional_descriptor_request() {
                Ok(value) => value,
                Err(handshake::DormantBrokerSessionHandshakeErrorV1::Transport) => {
                    return Ok(DormantBrokerDescriptorRequestReceiveProgressV1::Pending);
                }
                Err(error) => return Err(error.into()),
            };
        let (request, initialize) = match admission {
            crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::New {
                request,
                requires_initialization,
            } => (request, requires_initialization),
            crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::InFlightReplay {
                request,
            } => {
                return Ok(
                    DormantBrokerDescriptorRequestReceiveProgressV1::InFlightReplay(
                        DormantBrokerDescriptorInFlightReplayV1 {
                            custody: DormantBrokerOutcomeUnknownV1 {
                                request: DormantReceivedBrokerRequestV1(request),
                                observation: None,
                            },
                            descriptors,
                        },
                    ),
                );
            }
            crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::TerminalReplay {
                replay,
            } => {
                drop(descriptors);
                let replay = DormantBrokerTerminalReplayV1(replay);
                return Ok(if replay.0.response_descriptor_roles()?.is_empty() {
                    DormantBrokerDescriptorRequestReceiveProgressV1::TerminalReplay(replay)
                } else {
                    DormantBrokerDescriptorRequestReceiveProgressV1::DescriptorTerminalReplay(
                        DormantBrokerDescriptorTerminalReplayV1(replay),
                    )
                });
            }
        };
        let retained = DormantUnconfirmedBrokerDescriptorRequestV1 {
            request: request.clone(),
            descriptors,
        };
        if initialize {
            return Ok(match self.0.initialize_authenticated_request(&request)? {
                ProtectedBrokerSessionInitializationResultV1::Initialized => {
                    DormantBrokerDescriptorRequestReceiveProgressV1::Received(
                        DormantReceivedBrokerDescriptorRequestV1 {
                            request,
                            descriptors: retained.descriptors,
                        },
                    )
                }
                ProtectedBrokerSessionInitializationResultV1::RecoveryRequired {
                    error,
                    recovery,
                } => DormantBrokerDescriptorRequestReceiveProgressV1::InitializationRecoveryRequired {
                    error,
                    recovery,
                    request: retained,
                },
            });
        }
        Ok(match self.0.append_authenticated_request(&request)? {
            ProtectedBrokerRequestCommitResultV1::Committed => {
                DormantBrokerDescriptorRequestReceiveProgressV1::Received(
                    DormantReceivedBrokerDescriptorRequestV1 {
                        request,
                        descriptors: retained.descriptors,
                    },
                )
            }
            ProtectedBrokerRequestCommitResultV1::RecoveryRequired { error, recovery } => {
                DormantBrokerDescriptorRequestReceiveProgressV1::SuccessorRecoveryRequired {
                    error,
                    recovery,
                    request: retained,
                }
            }
        })
    }

    /// Recovers ambiguous initial descriptor-request custody.
    #[must_use]
    pub fn recover_received_descriptor_initialization(
        &mut self,
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        request: DormantUnconfirmedBrokerDescriptorRequestV1,
    ) -> DormantBrokerDescriptorRequestReceiveProgressV1 {
        match self.0.recover_initialization(recovery) {
            ProtectedBrokerSessionInitializationResultV1::Initialized => {
                DormantBrokerDescriptorRequestReceiveProgressV1::Received(
                    DormantReceivedBrokerDescriptorRequestV1 {
                        request: request.request,
                        descriptors: request.descriptors,
                    },
                )
            }
            ProtectedBrokerSessionInitializationResultV1::RecoveryRequired { error, recovery } => {
                DormantBrokerDescriptorRequestReceiveProgressV1::InitializationRecoveryRequired {
                    error,
                    recovery,
                    request,
                }
            }
        }
    }

    /// Recovers ambiguous successor descriptor-request custody.
    #[must_use]
    pub fn recover_received_descriptor_successor(
        &mut self,
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        request: DormantUnconfirmedBrokerDescriptorRequestV1,
    ) -> DormantBrokerDescriptorRequestReceiveProgressV1 {
        match self.0.recover_request_commit(recovery) {
            ProtectedBrokerRequestCommitResultV1::Committed => {
                DormantBrokerDescriptorRequestReceiveProgressV1::Received(
                    DormantReceivedBrokerDescriptorRequestV1 {
                        request: request.request,
                        descriptors: request.descriptors,
                    },
                )
            }
            ProtectedBrokerRequestCommitResultV1::RecoveryRequired { error, recovery } => {
                DormantBrokerDescriptorRequestReceiveProgressV1::SuccessorRecoveryRequired {
                    error,
                    recovery,
                    request,
                }
            }
        }
    }

    /// Signs and durably commits a terminal error for a received request.
    ///
    /// Success is deliberately excluded: it must be derived from a sealed
    /// domain observation, never from a caller-built response. Signed error
    /// bytes remain protected until the exact terminal CAS and readback complete.
    ///
    /// # Errors
    ///
    /// Returns an error for a changed request/session binding, invalid response
    /// body, noncanonical envelope, stale peer, or protected signing failure.
    pub fn commit_authenticated_error_response(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        failure: DormantBrokerFailureV1,
    ) -> Result<ProtectedBrokerOutcomeCommitResultV1, BrokerSessionSecurityError> {
        let message = BrokerResponseEnvelope {
            request_id: request.0.request_id().to_vec(),
            method: request.0.method().into(),
            error: Some(failure.error()?).into(),
            ..Default::default()
        };
        let pending = self.0.prepare_broker_outcome(&request.0, message)?;
        Ok(self.0.commit_broker_outcome(pending))
    }

    pub(crate) fn prepare_original_nonadmitting_terminal(
        &mut self,
        request: &DormantReceivedBrokerRequestV1,
        retained: &mut crate::endpoint::RetainedOriginalBrokerOutcomeV1,
    ) -> Result<bool, BrokerSessionSecurityError> {
        if request.method() != BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let message = BrokerResponseEnvelope {
            request_id: request.0.request_id().to_vec(),
            method: request.0.method().into(),
            error: Some(DormantBrokerFailureV1::Conflict.error()?).into(),
            ..Default::default()
        };
        Ok(self.0.prepare_original_nonadmitting_outcome(
            retained, crate::endpoint::OriginalBrokerOutcomePurposeV1::NonadmittingAcquire,
            &request.0, message,
        ))
    }

    pub(crate) fn prepare_original_inventory_outcome(
        &mut self,
        request: &DormantReceivedBrokerRequestV1,
        retained: &mut crate::endpoint::RetainedOriginalBrokerOutcomeV1,
        body: &mut Option<Vec<u8>>,
    ) -> Result<bool, BrokerSessionSecurityError> {
        let purpose = match request.method() {
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES => crate::endpoint::OriginalBrokerOutcomePurposeV1::ResourceInventory,
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS => crate::endpoint::OriginalBrokerOutcomePurposeV1::SourceInventory,
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        if request.authorization_artifacts().is_some() || body.is_none()
            || retained.setup.is_some() || retained.gate.is_some() || retained.signed
            || retained.endpoint.message.is_some()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let mut message = BrokerResponseEnvelope {
            request_id: request.0.request_id().to_vec(),
            method: request.method().into(),
            ..Default::default()
        };
        let Some(actual_body) = body.take() else { return Err(BrokerSessionSecurityError::Currentness); };
        message.body = actual_body;
        Ok(self.0.prepare_original_nonadmitting_outcome(retained, purpose, &request.0, message))
    }

    pub(crate) fn sign_original_nonadmitting_terminal(
        &mut self,
        request: &DormantReceivedBrokerRequestV1,
        retained: &mut crate::endpoint::RetainedOriginalBrokerOutcomeV1,
    ) -> bool {
        self.0.sign_original_nonadmitting_outcome(retained, &request.0)
    }

    pub(crate) fn compare_original_nonadmitting_outcome(
        &mut self,
        committed: &ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.compare_original_nonadmitting_outcome(committed)
    }

    pub(crate) fn original_nonadmitting_clock(
        committed: &ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<u64, BrokerSessionSecurityError> {
        let (request, context) = committed.original_nonadmitting_request_context()?;
        current_publication_boottime(request, context)
    }

    pub(crate) fn send_original_nonadmitting_packet(
        &mut self,
        committed: &ProtectedBrokerOutcomeCommittedAdvancementV1,
        returned: &mut Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    ) -> bool {
        self.0.send_original_nonadmitting_packet(committed, returned)
    }

    pub(crate) fn borrow_prepared_session_retirement_v1<'cut, 'original>(
        &self,
        receiving: &'cut mut aos_sandbox::StoragePrepareReceivingLoanV1<'original>,
    ) -> Result<aos_sandbox::StorageLifecycleSessionLoanV1<'cut, 'original>, aos_sandbox::StorageReceivingClosedV1> {
        self.0.borrow_prepared_session_retirement_v1(receiving)
    }

    pub(crate) fn reserve_storage_lifecycle_replay_v1(
        &self,
        replay: &DormantBrokerTerminalReplayV1,
        receiving: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        native_error: &mut Option<aos_sandbox::StorageReceivingClosedV1>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.reserve_storage_lifecycle_replay_v1(&replay.0, receiving, native_error)
    }

    pub(crate) fn compare_retained_storage_replay_v1(
        &mut self,
        replay: &DormantBrokerTerminalReplayV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.compare_retained_storage_replay_v1(&replay.0)
    }

    pub(crate) fn compare_retained_storage_terminal_owner_v1(
        &mut self,
        terminal: &crate::recovery::RetainedStorageTerminalV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.compare_retained_storage_terminal_owner_v1(terminal)
    }

    pub(crate) fn into_retained_storage_terminal_owner_v1(
        self,
        terminal: crate::recovery::RetainedStorageTerminalV1,
    ) -> crate::recovery::ProtectedBrokerSessionOwnerV1 {
        self.0.into_retained_storage_terminal_owner_v1(terminal)
    }

    pub(crate) fn compare_retained_storage_terminal_v1(
        &mut self,
        terminal: &ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.compare_retained_storage_terminal_v1(terminal)
    }

    pub(crate) fn end_storage_session_transport_v1(&mut self) -> aos_sandbox_linux::seqpacket::StorageSeqpacketEndAttemptV1 {
        self.0.end_storage_session_transport_v1()
    }

    pub(crate) fn require_storage_lifecycle_current_v1(
        &self,
        receiving: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<(), aos_sandbox::StorageReceivingClosedV1> {
        self.0.require_storage_lifecycle_current_v1(receiving)
    }

    pub(crate) fn resume_storage_lifecycle_v1<'cut, 'original>(
        &self,
        receiving: &'cut mut aos_sandbox::StoragePrepareReceivingLoanV1<'original>,
    ) -> Result<aos_sandbox::StorageLifecycleSessionLoanV1<'cut, 'original>, aos_sandbox::StorageReceivingClosedV1> {
        self.0.resume_storage_lifecycle_v1(receiving)
    }

    pub(crate) fn begin_initial_storage_lifecycle_v1<'cut, 'original>(
        &self,
        receiving: &'cut mut aos_sandbox::StoragePrepareReceivingLoanV1<'original>,
    ) -> Result<aos_sandbox::StorageLifecycleSessionLoanV1<'cut, 'original>, aos_sandbox::StorageReceivingClosedV1> {
        self.0.begin_initial_storage_lifecycle_v1(receiving)
    }

    pub(crate) fn arm_storage_request_post_v1(
        &self,
        receiving: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<(), aos_sandbox::StorageReceivingClosedV1> {
        self.0.arm_storage_request_post_v1(receiving)
    }

    pub(crate) fn arm_storage_operation_post_v1(
        &self,
        receiving: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<(), aos_sandbox::StorageReceivingClosedV1> {
        self.0.arm_storage_operation_post_v1(receiving)
    }

    pub(crate) fn finish_storage_operation_post_v1(
        &self,
        receiving: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<(), aos_sandbox::StorageReceivingClosedV1> {
        self.0.finish_storage_operation_post_v1(receiving)
    }

    pub(crate) fn prepare_storage_operation_disposal_v1<'phase, 'cut, 'original>(
        &self,
        receiving: &'phase mut aos_sandbox::StorageLifecycleSessionLoanV1<'cut, 'original>,
        sent: aos_sandbox_linux::seqpacket::StorageSeqpacketSendAttemptV1,
    ) -> Result<
        aos_sandbox::StorageLifecyclePositiveDisposalV1<'phase, 'cut, 'original>,
        aos_sandbox::StorageLifecycleDisposalErrorV1,
    > {
        self.0.prepare_storage_operation_disposal_v1(receiving, sent)
    }

    pub(crate) fn prepare_storage_transport_disposal_v1<'phase, 'cut, 'original>(
        &self,
        receiving: &'phase mut aos_sandbox::StorageLifecycleSessionLoanV1<'cut, 'original>,
        ended: aos_sandbox_linux::seqpacket::StorageSeqpacketEndAttemptV1,
    ) -> Result<
        aos_sandbox::StorageLifecyclePositiveDisposalV1<'phase, 'cut, 'original>,
        aos_sandbox::StorageLifecycleDisposalErrorV1,
    > {
        self.0.prepare_storage_transport_disposal_v1(receiving, ended)
    }

    pub(crate) fn into_retained_storage_owner_v1(
        self,
        terminal: crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> crate::recovery::ProtectedBrokerSessionOwnerV1 {
        self.0.into_retained_storage_owner_v1(terminal)
    }

    /// Sends only a terminal response already confirmed by protected readback.
    ///
    /// # Errors
    ///
    /// Returns an error for fatal transport failure or changed protected
    /// endpoint, peer, transcript, or journal currentness.
    pub fn send_authenticated_response(
        &mut self,
        committed: ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<DormantBrokerResponseSendProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        self.send_authenticated_response_inner(committed, None, None)
    }

    pub(crate) fn send_authenticated_response_storage_v1(
        &mut self,
        committed: ProtectedBrokerOutcomeCommittedAdvancementV1,
        returned: &mut Option<handshake::StorageResponseSendAttemptV1>,
    ) -> Result<DormantBrokerResponseSendProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        self.send_authenticated_response_inner(committed, Some(returned), None)
    }

    pub(crate) fn send_storage_response_receiving_v3(&mut self,
        committed: ProtectedBrokerOutcomeCommittedAdvancementV1,
        returned: &mut Option<handshake::StorageResponseSendAttemptV1>,
        receiving: &mut dyn crate::recovery::StorageFloorFinancialSourceV2,
    ) -> Result<DormantBrokerResponseSendProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        self.send_authenticated_response_inner(committed, Some(returned), Some(receiving))
    }

    pub(crate) fn compare_storage_terminal_receiving_v3(&mut self,
        terminal: &ProtectedBrokerOutcomeCommittedAdvancementV1,
        receiving: &mut dyn crate::recovery::StorageFloorFinancialSourceV2,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.compare_storage_terminal_receiving_v3(terminal, receiving)
    }

    pub(crate) fn dispose_storage_positive_replays_v3(&mut self) {
        self.0.dispose_storage_positive_replays_v3();
    }

    pub(crate) fn recheck_storage_receiving_v3(&mut self,
        receiving: Option<&mut dyn crate::recovery::StorageFloorFinancialSourceV2>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.recheck_storage_receiving_v3(receiving)
    }

    pub(crate) fn compare_storage_terminal_owner_receiving_v3(&mut self,
        terminal: &crate::recovery::RetainedStorageTerminalV1,
        receiving: &mut dyn crate::recovery::StorageFloorFinancialSourceV2,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.compare_storage_terminal_owner_receiving_v3(terminal, receiving)
    }

    pub(crate) fn compare_storage_replay_receiving_v3(&mut self,
        replay: &DormantBrokerTerminalReplayV1,
        receiving: &mut dyn crate::recovery::StorageFloorFinancialSourceV2,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.compare_storage_replay_receiving_v3(&replay.0, receiving)
    }

    fn send_authenticated_response_inner(
        &mut self,
        committed: ProtectedBrokerOutcomeCommittedAdvancementV1,
        returned: Option<&mut Option<handshake::StorageResponseSendAttemptV1>>,
        mut receiving: Option<&mut dyn crate::recovery::StorageFloorFinancialSourceV2>,
    ) -> Result<DormantBrokerResponseSendProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        let committed = match self.0.revalidate_storage_committed_receiving_v3(committed, receiving.as_mut()
            .map(|source| &mut **source as &mut dyn crate::recovery::StorageFloorFinancialSourceV2)) {
            Ok(committed) => committed,
            Err((error, committed)) => {
                return Ok(DormantBrokerResponseSendProgressV1::RecoveryRequired {
                    error: error.into(),
                    committed,
                });
            }
        };
        let send = match returned {
            Some(returned) => self.0.send_storage_response_receiving_v3(committed.exact_packet(), returned,
                receiving.as_mut().map(|source| &mut **source as &mut dyn crate::recovery::StorageFloorFinancialSourceV2)),
            None => self.0.send_response_packet(committed.exact_packet()),
        };
        let committed = match self.0.revalidate_storage_committed_receiving_v3(committed, receiving) {
            Ok(committed) => committed,
            Err((error, committed)) => {
                return Ok(DormantBrokerResponseSendProgressV1::RecoveryRequired {
                    error: error.into(),
                    committed,
                });
            }
        };
        Ok(match send {
            Ok(()) => DormantBrokerResponseSendProgressV1::Sent(committed),
            Err(handshake::DormantBrokerSessionHandshakeErrorV1::Transport) => {
                DormantBrokerResponseSendProgressV1::Pending(committed)
            }
            Err(error) => DormantBrokerResponseSendProgressV1::RecoveryRequired {
                error: error.into(),
                committed,
            },
        })
    }

    /// Resends one byte-exact protected terminal response without a new write.
    ///
    /// # Errors
    ///
    /// Returns an error for fatal transport failure or changed protected
    /// endpoint, peer, or transcript currentness.
    pub fn send_authenticated_terminal_replay(
        &mut self,
        replay: DormantBrokerTerminalReplayV1,
    ) -> Result<DormantBrokerTerminalReplaySendProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        self.send_authenticated_terminal_replay_inner(replay, None, None)
    }

    pub(crate) fn send_authenticated_terminal_replay_storage_v1(
        &mut self,
        replay: DormantBrokerTerminalReplayV1,
        returned: &mut Option<handshake::StorageResponseSendAttemptV1>,
    ) -> Result<DormantBrokerTerminalReplaySendProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        self.send_authenticated_terminal_replay_inner(replay, Some(returned), None)
    }

    pub(crate) fn send_storage_terminal_replay_receiving_v3(&mut self,
        replay: DormantBrokerTerminalReplayV1,
        returned: &mut Option<handshake::StorageResponseSendAttemptV1>,
        receiving: &mut dyn crate::recovery::StorageFloorFinancialSourceV2,
    ) -> Result<DormantBrokerTerminalReplaySendProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        self.send_authenticated_terminal_replay_inner(replay, Some(returned), Some(receiving))
    }

    fn send_authenticated_terminal_replay_inner(
        &mut self,
        replay: DormantBrokerTerminalReplayV1,
        returned: Option<&mut Option<handshake::StorageResponseSendAttemptV1>>,
        mut receiving: Option<&mut dyn crate::recovery::StorageFloorFinancialSourceV2>,
    ) -> Result<DormantBrokerTerminalReplaySendProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        let descriptor_roles = match replay.0.response_descriptor_roles() {
            Ok(descriptor_roles) => descriptor_roles,
            Err(error) => {
                return Ok(
                    DormantBrokerTerminalReplaySendProgressV1::RecoveryRequired {
                        error: error.into(),
                        replay,
                    },
                );
            }
        };
        if !descriptor_roles.is_empty() {
            return Ok(
                DormantBrokerTerminalReplaySendProgressV1::DescriptorRecoveryRequired(
                    DormantBrokerDescriptorTerminalReplayV1(replay),
                ),
            );
        }
        let replay = match self.0.revalidate_storage_replay_receiving_v3(replay.0, receiving.as_mut()
            .map(|source| &mut **source as &mut dyn crate::recovery::StorageFloorFinancialSourceV2)) {
            Ok(replay) => DormantBrokerTerminalReplayV1(replay),
            Err((error, replay)) => {
                return Ok(
                    DormantBrokerTerminalReplaySendProgressV1::RecoveryRequired {
                        error: error.into(),
                        replay: DormantBrokerTerminalReplayV1(replay),
                    },
                );
            }
        };
        let send = match returned {
            Some(returned) => self.0.send_storage_response_receiving_v3(replay.0.exact_packet(), returned,
                receiving.as_mut().map(|source| &mut **source as &mut dyn crate::recovery::StorageFloorFinancialSourceV2)),
            None => self.0.send_response_packet(replay.0.exact_packet()),
        };
        let replay = match self.0.revalidate_storage_replay_receiving_v3(replay.0, receiving) {
            Ok(replay) => DormantBrokerTerminalReplayV1(replay),
            Err((error, replay)) => {
                return Ok(
                    DormantBrokerTerminalReplaySendProgressV1::RecoveryRequired {
                        error: error.into(),
                        replay: DormantBrokerTerminalReplayV1(replay),
                    },
                );
            }
        };
        Ok(match send {
            Ok(()) => DormantBrokerTerminalReplaySendProgressV1::Sent(replay),
            Err(handshake::DormantBrokerSessionHandshakeErrorV1::Transport) => {
                DormantBrokerTerminalReplaySendProgressV1::Pending(replay)
            }
            Err(error) => DormantBrokerTerminalReplaySendProgressV1::RecoveryRequired {
                error: error.into(),
                replay,
            },
        })
    }

    /// Builds, signs, semantically validates, and durably reserves one request.
    ///
    /// The callback receives only protected identity/deadline coordinates. Its
    /// returned envelope must leave the signature field empty and reproduce
    /// every coordinate exactly; signed bytes remain unavailable until the
    /// protected journal commit and exact readback complete.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong role, stale peer or clock, invalid method
    /// body, changed protected context, or noncanonical envelope.
    pub fn prepare_authenticated_request(
        &mut self,
        method: BrokerMethod,
        build: impl FnOnce(DormantBrokerRequestCoordinatesV1) -> BrokerRequestEnvelope,
    ) -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError> {
        self.prepare_authenticated_request_checked(method, build, |_| true)
    }

    /// Reserves the complete selected wrapper on this same Session request ID.
    /// No nested field is passed through the ordinary deadline injector.
    ///
    /// # Errors
    /// Rejects an unavailable method57, mismatched draft/plan/lease/deadline, or failed protected request preparation.
    pub fn prepare_nix_generation_request(
        &mut self,
        draft: &aos_sandbox::production_operation_compiler::StorageGenerationPreparationDraftV1,
        signed: &aos_sandbox_protocol::authorization_artifact::SignedBrokerPlan,
        request_id: [u8; 16],
        original_deadline: u64,
    ) -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError> {
        let method = BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_NIX_GENERATION_V1;
        self.0.require_negotiated_client_method(method)?;
        draft.validate_signed_plan(signed)
            .map_err(|_| BrokerSessionSecurityError::manifest("generation whole signed plan"))?;
        let total = [draft.request_bytes(), signed.canonical_plan(), signed.canonical_signature(),
            draft.lease().canonical_lease(), draft.lease().canonical_signature()]
            .iter().try_fold(0_usize, |size, part| size.checked_add(part.len()))
            .ok_or_else(|| BrokerSessionSecurityError::manifest("generation quartet bound"))?;
        if total > 1_048_576 {
            return Err(BrokerSessionSecurityError::manifest("generation quartet bound"));
        }
        let message = BrokerRequestEnvelope {
            method: method.into(),
            body: draft.request_bytes().to_vec(),
            authorization: Some(aos_proto::aos::sandbox::local::v1::BrokerAuthorizationArtifactsV1 {
                broker_plan: signed.canonical_plan().to_vec(),
                broker_plan_signature: signed.canonical_signature().to_vec(),
                ownership_lease: draft.lease().canonical_lease().to_vec(),
                ownership_lease_signature: draft.lease().canonical_signature().to_vec(),
                ..Default::default()
            }).into(),
            ..Default::default()
        };
        let (request, initialize) = self.0.prepare_client_request(
            message, method, 0, request_id, original_deadline, 65_536,
        )?;
        if request.exact_body() != draft.request_bytes() {
            return Err(BrokerSessionSecurityError::manifest("generation original body"));
        }
        self.reserve_exact_authenticated_request(request, initialize)
    }

    /// Checks the named method before any selected grant is signed.
    ///
    /// # Errors
    /// Rejects missing method57, incompatible version/audience/response limits, or failed protected coordinate acquisition.
    pub fn nix_generation_request_id(&mut self) -> Result<[u8; 16], BrokerSessionSecurityError> {
        self.0.require_negotiated_client_method(BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_NIX_GENERATION_V1)?;
        let (request_id, _, maximum, version, audience) = self.0.client_request_coordinates()?;
        if maximum < 65_536 || version != aos_sandbox_core::ProtocolVersion::new(1, 0)
            || audience != Audience::AUDIENCE_NODE_CONTROLLER
        {
            return Err(BrokerSessionSecurityError::manifest("generation Session coordinates"));
        }
        Ok(request_id)
    }

    /// Builds, validates, signs, and durably reserves one request.
    ///
    /// `validate` runs after cryptographic and method-specific decoding but
    /// before either the initial session record or its successor is written.
    /// This lets a higher-level protected protocol bind the exact canonical
    /// body before the lower-domain effect becomes dispatchable.
    ///
    /// # Errors
    ///
    /// Returns an error for the ordinary authenticated-request failures or
    /// when `validate` rejects the fully authenticated request.
    pub fn prepare_authenticated_request_checked(
        &mut self,
        method: BrokerMethod,
        build: impl FnOnce(DormantBrokerRequestCoordinatesV1) -> BrokerRequestEnvelope,
        validate: impl FnOnce(&AuthenticatedBrokerMethodRequestV1) -> bool,
    ) -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError> {
        self.prepare_authenticated_request_checked_fallible(
            method,
            |coordinates| Ok(build(coordinates)),
            validate,
        )
    }

    /// Allows a Controller grant issuer to fail before request journal custody.
    ///
    /// The issuer sees the session-selected request ID before signing its
    /// exact broker plan. An issuer error leaves no request to send or replay.
    ///
    /// # Errors
    ///
    /// Returns the issuer error before any request append, or an ordinary
    /// authenticated-session preparation error after envelope construction.
    pub fn prepare_authenticated_request_checked_fallible(
        &mut self,
        method: BrokerMethod,
        build: impl FnOnce(
            DormantBrokerRequestCoordinatesV1,
        ) -> Result<BrokerRequestEnvelope, BrokerSessionSecurityError>,
        validate: impl FnOnce(&AuthenticatedBrokerMethodRequestV1) -> bool,
    ) -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError> {
        self.prepare_authenticated_request_with_original_cut(
            method, build, validate, None,
        )
    }

    /// Quotes only the actual same-Session adjacent Host Inventory stage.
    ///
    /// # Errors
    /// Retains forecast refusal and rejects another protocol or negotiated method.
    pub fn host_stop_inventory_demand_v5(&self,
        original: &mut crate::HostExecutionSessionReceivingOriginalV1,
    ) -> Result<aos_sandbox_core::ResourceVector, BrokerSessionSecurityError> {
        self.0.host_stop_inventory_demand_v5(original)
    }

    /// Prepares only the adjacent Inventory under the exact signed Stop cutoff.
    ///
    /// Coordinates attenuate the actual Stop; they cannot extend its lifetime
    /// or authorize another effect. The existing retained request engine owns
    /// native checks, strict semantic decoding, signing and exact reservation.
    ///
    /// # Errors
    /// Retains request/native refusal, rejecting foreign method, cutoff, Source
    /// selector, negotiated coordinates or exact protected append ambiguity.
    pub fn prepare_host_stop_inventory_retaining_v5(&mut self,
        effect: &PreparedAuthorityEffectV1,
        original: &mut crate::HostStopRequestPreparationOriginalV5,
        build: impl FnOnce(DormantBrokerRequestCoordinatesV1) -> BrokerRequestEnvelope,
    ) -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError> {
        let coordinates = self.0.host_stop_inventory_coordinates_v5(effect)?;
        let envelope = build(coordinates);
        let method = BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME;
        if envelope.method.as_known() != Some(method) || !envelope.descriptors.is_empty()
            || envelope.authorization.as_option().is_some()
        { return Err(BrokerSessionSecurityError::Currentness); }
        let (authenticated, initialize) = self.0.prepare_client_request_retaining_v1(
            envelope, method, 0, coordinates.request_id(), coordinates.deadline_boottime_nanoseconds(),
            coordinates.maximum_response_bytes(), &mut original.request)?;
        self.reserve_exact_authenticated_request(authenticated, initialize)
    }

    /// Prepares explicit ongoing Capture under its first candidate acquisition cut.
    ///
    /// Historical46 is verified as exact signed DATA by the common request
    /// decoder. Its completed delivery deadline is not an ongoing permit.
    ///
    /// # Errors
    /// Refuses unavailable methods, expired candidate acquisition or any failure
    /// of the existing authenticated request and native currentness engine.
    pub fn prepare_storage_capture_reserve_ongoing_v3(
        &mut self,
        candidate: &aos_sandbox_protocol::storage_capture_candidate::ValidatedStorageCaptureCandidateV1,
        build: impl FnOnce(DormantBrokerRequestCoordinatesV1)
            -> Result<BrokerRequestEnvelope, BrokerSessionSecurityError>,
        validate: impl FnOnce(&AuthenticatedBrokerMethodRequestV1) -> bool,
    ) -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError> {
        self.prepare_authenticated_request_with_original_cut(
            BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1,
            build, validate, Some(candidate.expiry_boottime_nanoseconds()),
        )
    }

    /// Prepares a fresh read-only Query61 under the actual current assignment cut.
    ///
    /// # Errors
    /// Rejects unavailable methods/currentness or unchanged native preparation
    /// failures. This method never enters Reserve or renews its original source.
    pub fn prepare_storage_capture_query_v2(
        &mut self,
        assignment: &aos_sandbox::runtime_scope::CurrentAssignmentTarget,
        build: impl FnOnce(DormantBrokerRequestCoordinatesV1)
            -> Result<BrokerRequestEnvelope, BrokerSessionSecurityError>,
        validate: impl FnOnce(&AuthenticatedBrokerMethodRequestV1) -> bool,
    ) -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError> {
        self.prepare_authenticated_request_with_original_cut(
            BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1,
            build, validate, Some(assignment.deadline_boottime_nanoseconds()),
        )
    }

    /// Prepares only Accept under the original nonrenewable proposal cutoff.
    ///
    /// This DATA restricts a request window. It does not establish a completed
    /// Prepare or same-Session authority; the closed execution caller must
    /// rejoin its actual predecessor owner before invoking this method.
    ///
    /// # Errors
    /// Rejects malformed preparation DATA or any failure of the existing
    /// negotiated request, signer, protected journal and currentness engine.
    pub fn prepare_host_execution_argument_accept_v2(
        &mut self,
        preparation: &aos_sandbox_protocol::host_execution_argument::preparation::HostArgumentPreparationV2,
        build: impl FnOnce(DormantBrokerRequestCoordinatesV1)
            -> Result<BrokerRequestEnvelope, BrokerSessionSecurityError>,
        validate: impl FnOnce(&AuthenticatedBrokerMethodRequestV1) -> bool,
    ) -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError> {
        let source = preparation.proposed_source();
        let mut deadline = [0; 8];
        deadline.copy_from_slice(&source[296..304]);
        self.prepare_authenticated_request_with_original_cut(
            BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2,
            build, validate, Some(u64::from_be_bytes(deadline)),
        )
    }

    // Ordinary callers retain their original coordinates. Only the closed
    // coverage and prepared execution adapters supply an earlier original
    // flight cutoff; this never
    // renews the session's own request window or skips its admission engine.
    fn prepare_authenticated_request_with_original_cut(
        &mut self,
        method: BrokerMethod,
        build: impl FnOnce(
            DormantBrokerRequestCoordinatesV1,
        ) -> Result<BrokerRequestEnvelope, BrokerSessionSecurityError>,
        validate: impl FnOnce(&AuthenticatedBrokerMethodRequestV1) -> bool,
        original_cut: Option<u64>,
    ) -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError> {
        // One-shot issuers may durably record authority inside `build`.
        // Reject an unnegotiated method before invoking that callback.
        self.0.require_negotiated_client_method(method)?;
        let (request_id, deadline, maximum_response_bytes, protocol_version, audience) =
            self.0.client_request_coordinates()?;
        let deadline = match original_cut {
            // The same live header engine below rejects an expired cutoff
            // before signing/reserving; no second clock or cause mapper is
            // introduced here. The retaining flight also bookends its cut.
            Some(cut) => deadline.min(cut),
            None => deadline,
        };
        let coordinates = DormantBrokerRequestCoordinatesV1 {
            request_id,
            deadline_boottime_nanoseconds: deadline,
            maximum_response_bytes,
            protocol_version,
            audience,
        };
        let message = build(coordinates)?;
        let (request, initialize) = self.0.prepare_client_request(
            message,
            method,
            0,
            request_id,
            deadline,
            maximum_response_bytes,
        )?;
        if !validate(&request) {
            return Err(BrokerSessionSecurityError::manifest(
                "protected lifecycle request binding",
            ));
        }
        self.reserve_exact_authenticated_request(request, initialize)
    }

    /// Signs and durably reserves one exact reconciler-prepared authority effect.
    ///
    /// Unlike the ordinary builder API, this path preserves the request ID and
    /// deadline already committed to the reconciler ledger. It accepts only an
    /// opaque [`PreparedAuthorityEffectV1`], bounds its deadline by the fixed
    /// production request window, and requires its body coordinates to match
    /// the negotiated authenticated session before journal admission.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable effect is malformed, expired, outside
    /// the negotiated session bounds, semantically invalid for this endpoint,
    /// or cannot be committed to protected session history.
    pub fn prepare_authenticated_authority_effect(
        &mut self,
        effect: &PreparedAuthorityEffectV1,
    ) -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError> {
        self.prepare_authenticated_authority_effect_checked(effect, |_| true)
    }

    /// Signs and reserves one exact durable authority request after validation.
    ///
    /// `validate` receives the fully decoded and authenticated request before
    /// either the initial session record or its successor is written. This
    /// allows a protected higher-level protocol to bind the authority-bearing
    /// body to its own exact operation cursor without rebuilding the request.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable request exceeds negotiated session
    /// limits, differs from its authority attempt, fails `validate`, or cannot
    /// be committed to protected session history.
    pub fn prepare_authenticated_authority_effect_checked(
        &mut self,
        effect: &PreparedAuthorityEffectV1,
        validate: impl FnOnce(&AuthenticatedBrokerMethodRequestV1) -> bool,
    ) -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError> {
        self.prepare_authority_effect_engine_v5(effect, validate, None)
    }

    /// Retains one genuine Stop preparation using the actual paid Source pair.
    ///
    /// The pair only attenuates Session limits. The canonical request and its
    /// signed artifacts still pass the unchanged sole admission/signing engine.
    ///
    /// # Errors
    /// Retains native/parser refusal and rejects a different method, request,
    /// signed scope, negotiated limit, currentness or caller comparison.
    pub fn prepare_host_stop_retaining_v5(
        &mut self,
        effect: &PreparedAuthorityEffectV1,
        clock: aos_sandbox_core::RawPairedClockSample,
        original: &mut crate::HostStopRequestPreparationOriginalV5,
        validate: impl FnOnce(&AuthenticatedBrokerMethodRequestV1) -> bool,
    ) -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError> {
        self.prepare_authority_effect_engine_v5(effect, validate, Some((clock, original)))
    }

    fn prepare_authority_effect_engine_v5(
        &mut self,
        effect: &PreparedAuthorityEffectV1,
        validate: impl FnOnce(&AuthenticatedBrokerMethodRequestV1) -> bool,
        retained: Option<(aos_sandbox_core::RawPairedClockSample,
            &mut crate::HostStopRequestPreparationOriginalV5)>,
    ) -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError> {
        let request = effect.broker_request().map_err(|_| {
            BrokerSessionSecurityError::manifest("durable authority effect request")
        })?;
        if retained.is_some() && request.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let (maximum_deadline, negotiated_response_bytes, protocol_version, audience) =
            match retained.as_ref() {
                Some((clock, _)) => self.0.host_stop_limits_data_v5(*clock)?,
                None => self.0.client_request_limits()?,
            };
        if request.deadline_boottime_nanoseconds() > maximum_deadline
            || request.maximum_response_bytes() > negotiated_response_bytes
            || request.protocol_version() != protocol_version
            || request.audience() != audience
        {
            return Err(BrokerSessionSecurityError::manifest(
                "durable authority effect session coordinates",
            ));
        }

        let method = request.method();
        let request_id = request.request_id();
        let deadline = request.deadline_boottime_nanoseconds();
        let maximum_response_bytes = request.maximum_response_bytes();
        let expected_body = effect.attempt().body();
        let envelope = request.into_envelope();
        let (authenticated, initialize) = match retained {
            Some((_, original)) => self.0.prepare_client_request_retaining_v1(
                envelope, method, 0, request_id, deadline, maximum_response_bytes,
                &mut original.request),
            None => self.0.prepare_client_request(envelope, method, 0, request_id,
                deadline, maximum_response_bytes),
        }?;
        if authenticated.exact_body() != expected_body {
            return Err(BrokerSessionSecurityError::manifest(
                "durable authority effect body binding",
            ));
        }
        if !validate(&authenticated) {
            return Err(BrokerSessionSecurityError::manifest(
                "protected authority effect binding",
            ));
        }

        self.reserve_exact_authenticated_request(authenticated, initialize)
    }

    /// Signs and reserves one exact durable destination-slot attempt on Mount.
    ///
    /// The session may add only its authenticated record carrier. The Mount
    /// method body, authorization quartet, operation ID, and deadline must be
    /// byte-identical to the controller's durable-before-I/O attempt.
    ///
    /// # Errors
    ///
    /// Rejects a malformed or substituted attempt, expired or incompatible
    /// session coordinates, failed semantic validation, or protected custody.
    pub fn prepare_authenticated_destination_slot_effect(
        &mut self,
        attempt: &DurableCurrentDestinationSlotAttemptV1,
    ) -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError> {
        let dispatch = attempt.dispatch_attempt();
        let envelope = BrokerRequestEnvelope::decode_from_slice(dispatch.packet())
            .map_err(|_| BrokerSessionSecurityError::manifest("durable slot packet"))?;
        let request = ApplyDestinationSlotRequest::decode_from_slice(dispatch.body())
            .map_err(|_| BrokerSessionSecurityError::manifest("durable slot body"))?;
        let header = request
            .header
            .as_option()
            .ok_or_else(|| BrokerSessionSecurityError::manifest("durable slot header"))?;
        let request_id: [u8; 16] = header
            .request_id
            .as_slice()
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::manifest("durable slot request ID"))?;
        let method = BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT;
        if !envelope.__buffa_unknown_fields.is_empty()
            || envelope.encode_to_vec() != dispatch.packet()
            || envelope.method.as_known() != Some(method)
            || envelope.body != dispatch.body()
            || envelope.authorization.as_option().is_none()
            || !envelope.descriptors.is_empty()
            || !envelope.signed_session_request.is_empty()
            || request_id != attempt.request_id()
            || header.deadline_boottime_nanoseconds != dispatch.deadline_boottime_nanoseconds()
        {
            return Err(BrokerSessionSecurityError::manifest(
                "durable slot request binding",
            ));
        }
        let (maximum_deadline, maximum_response_bytes, protocol_version, audience) =
            self.0.client_request_limits()?;
        if header.deadline_boottime_nanoseconds > maximum_deadline
            || header.maximum_response_bytes > maximum_response_bytes
            || header.protocol_major != u32::from(protocol_version.major())
            || header.protocol_minor != u32::from(protocol_version.minor())
            || header.audience.as_known() != Some(audience)
        {
            return Err(BrokerSessionSecurityError::manifest(
                "durable slot session coordinates",
            ));
        }
        let (authenticated, initialize) = self.0.prepare_client_request(
            envelope,
            method,
            0,
            request_id,
            header.deadline_boottime_nanoseconds,
            header.maximum_response_bytes,
        )?;
        if authenticated.canonical_packet() != dispatch.packet()
            || authenticated.exact_body() != dispatch.body()
            || authenticated.authorization().is_none()
        {
            return Err(BrokerSessionSecurityError::manifest(
                "authenticated slot attempt binding",
            ));
        }

        self.reserve_exact_authenticated_request(authenticated, initialize)
    }

    /// Selects exact unadvertised FUSE coordinates before owner-issued signing.
    ///
    /// Coordinates are data only. The Controller owner must still join its
    /// current desired/runtime cut, sign purpose 57, and retain its borrow
    /// through durable preparation and dispatch.
    pub(crate) fn fuse_intent_request_coordinates(
        &mut self,
    ) -> Result<DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
        self.0.require_negotiated_client_method(
            BrokerMethod::BROKER_METHOD_MOUNT_FUSE_RESERVE_INTENT_V1,
        )?;
        let (request_id, deadline, maximum_response_bytes, protocol_version, audience) =
            self.0.client_request_coordinates()?;
        if protocol_version != ProtocolVersion::new(3, 0)
            || audience != Audience::AUDIENCE_NODE_CONTROLLER
        {
            return Err(BrokerSessionSecurityError::manifest(
                "FUSE session coordinates",
            ));
        }
        Ok(DormantBrokerRequestCoordinatesV1 {
            request_id,
            deadline_boottime_nanoseconds: deadline,
            maximum_response_bytes,
            protocol_version,
            audience,
        })
    }

    /// Installs only the exact original FUSE packet in authenticated RequestPrepared.
    ///
    /// The upper composition retains genuine Controller custody. This lower
    /// method validates/signs the packet and preserves commit ambiguity; it
    /// does not adopt a Mount reservation, worker, or read authority.
    pub(crate) fn prepare_authenticated_fuse_intent_request(
        &mut self,
        packet: &[u8],
        request: &aos_sandbox_protocol::mount_fuse_reserve_intent::ValidatedFuseReserveIntentRequestV1,
    ) -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError> {
        let method = BrokerMethod::BROKER_METHOD_MOUNT_FUSE_RESERVE_INTENT_V1;
        self.0.require_negotiated_client_method(method)?;
        let envelope = BrokerRequestEnvelope::decode_from_slice(packet)
            .map_err(|_| BrokerSessionSecurityError::manifest("FUSE signed envelope"))?;
        let (maximum_deadline, maximum_response_bytes, protocol_version, audience) =
            self.0.client_request_limits()?;
        if protocol_version != ProtocolVersion::new(3, 0)
            || audience != Audience::AUDIENCE_NODE_CONTROLLER
            || request.header().deadline_boottime_nanoseconds() > maximum_deadline
            || request.header().maximum_response_bytes() > maximum_response_bytes
            || envelope.method.as_known() != Some(method)
            || !envelope.__buffa_unknown_fields.is_empty()
            || envelope.encode_to_vec() != packet
            || !envelope.descriptors.is_empty()
            || !envelope.signed_session_request.is_empty()
            || aos_sandbox_core::BrokerArgumentCommitment::for_canonical_bytes(&envelope.body)
                .digest()
                .as_bytes()
                != request.request_commitment()
        {
            return Err(BrokerSessionSecurityError::manifest(
                "FUSE original session binding",
            ));
        }
        let semantics = aos_sandbox_protocol::semantics::mount_fuse_reserve_intent::canonical_mount_fuse_reserve_intent_semantics_v1(request)
            .map_err(|_| BrokerSessionSecurityError::manifest("FUSE complete original semantics"))?;
        let (authenticated, initialize) = self.0.prepare_client_request(
            envelope,
            method,
            0,
            *request.header().request_id(),
            request.header().deadline_boottime_nanoseconds(),
            request.header().maximum_response_bytes(),
        )?;
        if authenticated.semantic_commitment() != *semantics.commitment().digest().as_bytes()
            || aos_sandbox_core::BrokerArgumentCommitment::for_canonical_bytes(
                authenticated.exact_body(),
            )
            .digest()
            .as_bytes()
                != request.request_commitment()
        {
            return Err(BrokerSessionSecurityError::manifest(
                "FUSE authenticated original semantics",
            ));
        }
        self.reserve_exact_authenticated_request(authenticated, initialize)
    }

    /// Selects original Mount request coordinates from the same protected session.
    ///
    /// # Errors
    /// Rejects incompatible Mount version/audience/response limits or failed protected coordinate acquisition.
    pub fn mount_request_coordinates(
        &mut self,
    ) -> Result<DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
        let (request_id, deadline, maximum_response_bytes, protocol_version, audience) =
            self.0.client_request_coordinates()?;
        if protocol_version != ProtocolVersion::new(2, 0)
            || audience != Audience::AUDIENCE_NODE_CONTROLLER
            || maximum_response_bytes < 16 * 1024
        {
            return Err(BrokerSessionSecurityError::manifest(
                "Mount session coordinates",
            ));
        }
        Ok(DormantBrokerRequestCoordinatesV1 {
            request_id,
            deadline_boottime_nanoseconds: deadline,
            maximum_response_bytes,
            protocol_version,
            audience,
        })
    }

    /// Prepares the original sealed Mount catalog query on this session.
    ///
    /// # Errors
    /// Rejects incompatible Mount coordinates, a mismatched catalog-query scope, or failed protected preparation.
    pub fn prepare_authenticated_mount_catalog_query(
        &mut self,
        query: &PreparedCurrentMountCatalogQueryV1,
    ) -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError> {
        let envelope = BrokerRequestEnvelope::decode_from_slice(query.packet())
            .map_err(|_| BrokerSessionSecurityError::manifest("Mount catalog packet"))?;
        let method = BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG;
        if !envelope.__buffa_unknown_fields.is_empty()
            || envelope.encode_to_vec() != query.packet()
            || envelope.method.as_known() != Some(method)
            || envelope.body != query.body()
            || envelope.authorization.as_option().is_some()
            || !envelope.descriptors.is_empty()
            || !envelope.signed_session_request.is_empty()
        {
            return Err(BrokerSessionSecurityError::manifest(
                "Mount catalog packet binding",
            ));
        }
        let (maximum_deadline, maximum_response_bytes, protocol_version, audience) =
            self.0.client_request_limits()?;
        if query.deadline_boottime_nanoseconds() > maximum_deadline
            || query.maximum_response_bytes() > maximum_response_bytes
            || protocol_version != ProtocolVersion::new(2, 0)
            || audience != Audience::AUDIENCE_NODE_CONTROLLER
        {
            return Err(BrokerSessionSecurityError::manifest(
                "Mount catalog session bounds",
            ));
        }
        let (authenticated, initialize) = self.0.prepare_client_request(
            envelope,
            method,
            0,
            query.request_id(),
            query.deadline_boottime_nanoseconds(),
            query.maximum_response_bytes(),
        )?;
        if authenticated.canonical_packet() != query.packet()
            || authenticated.exact_body() != query.body()
            || authenticated.authorization().is_some()
        {
            return Err(BrokerSessionSecurityError::manifest(
                "authenticated Mount catalog query binding",
            ));
        }
        self.reserve_exact_authenticated_request(authenticated, initialize)
    }

    /// Prepares the original durably custodied Mount attempt on this session.
    ///
    /// # Errors
    /// Rejects incompatible Mount coordinates or a request that differs from the retained durable attempt.
    pub fn prepare_authenticated_mount_apply(
        &mut self,
        attempt: &DurableCurrentMountAttemptV1,
    ) -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError> {
        let dispatch = attempt.dispatch_attempt();
        let envelope = BrokerRequestEnvelope::decode_from_slice(dispatch.packet())
            .map_err(|_| BrokerSessionSecurityError::manifest("durable Mount Apply packet"))?;
        let request = ApplyMountRequest::decode_from_slice(dispatch.body())
            .map_err(|_| BrokerSessionSecurityError::manifest("durable Mount Apply body"))?;
        let header = request
            .header
            .as_option()
            .ok_or_else(|| BrokerSessionSecurityError::manifest("durable Mount Apply header"))?;
        let request_id: [u8; 16] =
            header.request_id.as_slice().try_into().map_err(|_| {
                BrokerSessionSecurityError::manifest("durable Mount Apply request ID")
            })?;
        let method = BrokerMethod::BROKER_METHOD_MOUNT_APPLY;
        if !envelope.__buffa_unknown_fields.is_empty()
            || envelope.encode_to_vec() != dispatch.packet()
            || envelope.method.as_known() != Some(method)
            || envelope.body != dispatch.body()
            || envelope.authorization.as_option().is_none()
            || !envelope.descriptors.is_empty()
            || !envelope.signed_session_request.is_empty()
            || request_id != attempt.request_id()
            || header.deadline_boottime_nanoseconds != dispatch.deadline_boottime_nanoseconds()
        {
            return Err(BrokerSessionSecurityError::manifest(
                "durable Mount Apply request binding",
            ));
        }
        let (maximum_deadline, maximum_response_bytes, protocol_version, audience) =
            self.0.client_request_limits()?;
        if header.deadline_boottime_nanoseconds > maximum_deadline
            || header.maximum_response_bytes > maximum_response_bytes
            || header.protocol_major != u32::from(protocol_version.major())
            || header.protocol_minor != u32::from(protocol_version.minor())
            || header.audience.as_known() != Some(audience)
        {
            return Err(BrokerSessionSecurityError::manifest(
                "durable Mount Apply session coordinates",
            ));
        }
        let (authenticated, initialize) = self.0.prepare_client_request(
            envelope,
            method,
            0,
            request_id,
            header.deadline_boottime_nanoseconds,
            header.maximum_response_bytes,
        )?;
        if authenticated.canonical_packet() != dispatch.packet()
            || authenticated.exact_body() != dispatch.body()
            || authenticated.authorization().is_none()
        {
            return Err(BrokerSessionSecurityError::manifest(
                "authenticated Mount Apply attempt binding",
            ));
        }
        self.reserve_exact_authenticated_request(authenticated, initialize)
    }

    /// Reserves one exact durably custodied Mount source effect packet.
    ///
    /// # Errors
    /// Rejects a request that differs from the retained Mount source effect or fails protected preparation.
    pub fn prepare_authenticated_mount_source_effect(
        &mut self,
        attempt: &DurableCurrentAttachmentSourceDispatchV1,
    ) -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError> {
        let dispatch = attempt.dispatch_attempt();
        let envelope = BrokerRequestEnvelope::decode_from_slice(dispatch.packet())
            .map_err(|_| BrokerSessionSecurityError::manifest("durable Mount source packet"))?;
        let (method, header) = match attempt.kind() {
            AttachmentSourceAttemptKindV1::Acquire => {
                let request = AcquireMountSourceRequest::decode_from_slice(dispatch.body())
                    .map_err(|_| {
                        BrokerSessionSecurityError::manifest("durable Mount Acquire body")
                    })?;
                (
                    BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE,
                    request.header.as_option().cloned(),
                )
            }
            AttachmentSourceAttemptKindV1::Release => {
                let request =
                    ReleaseMountSourceAcquisitionRequest::decode_from_slice(dispatch.body())
                        .map_err(|_| {
                            BrokerSessionSecurityError::manifest("durable Mount Release body")
                        })?;
                (
                    BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION,
                    request.header.as_option().cloned(),
                )
            }
            AttachmentSourceAttemptKindV1::Consume => {
                return Err(BrokerSessionSecurityError::manifest(
                    "Consume has no Mount source effect packet",
                ));
            }
        };
        let header = header
            .ok_or_else(|| BrokerSessionSecurityError::manifest("durable Mount source header"))?;
        let request_id: [u8; 16] =
            header.request_id.as_slice().try_into().map_err(|_| {
                BrokerSessionSecurityError::manifest("durable Mount source request ID")
            })?;
        if !envelope.__buffa_unknown_fields.is_empty()
            || envelope.encode_to_vec() != dispatch.packet()
            || envelope.method.as_known() != Some(method)
            || envelope.body != dispatch.body()
            || envelope.authorization.as_option().is_none()
            || !envelope.descriptors.is_empty()
            || !envelope.signed_session_request.is_empty()
            || envelope.semantic_bindings.as_option().is_some()
            || request_id != *attempt.source_attempt().operation_id().as_bytes()
            || header.deadline_boottime_nanoseconds != dispatch.deadline_boottime_nanoseconds()
        {
            return Err(BrokerSessionSecurityError::manifest(
                "durable Mount source request binding",
            ));
        }
        let (maximum_deadline, maximum_response_bytes, protocol_version, audience) =
            self.0.client_request_limits()?;
        if header.deadline_boottime_nanoseconds > maximum_deadline
            || header.maximum_response_bytes > maximum_response_bytes
            || header.protocol_major != u32::from(protocol_version.major())
            || header.protocol_minor != u32::from(protocol_version.minor())
            || header.audience.as_known() != Some(audience)
        {
            return Err(BrokerSessionSecurityError::manifest(
                "durable Mount source session coordinates",
            ));
        }
        let (authenticated, initialize) = self.0.prepare_client_request(
            envelope,
            method,
            0,
            request_id,
            header.deadline_boottime_nanoseconds,
            header.maximum_response_bytes,
        )?;
        if authenticated.canonical_packet() != dispatch.packet()
            || authenticated.exact_body() != dispatch.body()
            || authenticated.authorization().is_none()
        {
            return Err(BrokerSessionSecurityError::manifest(
                "authenticated Mount source attempt binding",
            ));
        }
        self.reserve_exact_authenticated_request(authenticated, initialize)
    }

    fn reserve_exact_authenticated_request(
        &mut self,
        authenticated: AuthenticatedBrokerMethodRequestV1,
        initialize: bool,
    ) -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError> {
        if initialize {
            return Ok(
                match self.0.initialize_authenticated_request(&authenticated)? {
                    ProtectedBrokerSessionInitializationResultV1::Initialized => {
                        DormantBrokerRequestPreparationV1::Prepared(
                            DormantPreparedBrokerRequestV1(authenticated),
                        )
                    }
                    ProtectedBrokerSessionInitializationResultV1::RecoveryRequired {
                        error,
                        recovery,
                    } => DormantBrokerRequestPreparationV1::InitializationRecoveryRequired {
                        error,
                        recovery,
                        request: DormantUnconfirmedBrokerRequestV1(authenticated),
                    },
                },
            );
        }
        Ok(match self.0.append_authenticated_request(&authenticated)? {
            ProtectedBrokerRequestCommitResultV1::Committed => {
                DormantBrokerRequestPreparationV1::Prepared(
                    DormantPreparedBrokerRequestV1(authenticated),
                )
            }
            ProtectedBrokerRequestCommitResultV1::RecoveryRequired { error, recovery } => {
                DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired {
                    error,
                    recovery,
                    request: DormantUnconfirmedBrokerRequestV1(authenticated),
                }
            }
        })
    }

    /// Signs and reserves a fresh Host query for one exact durable Apply.
    ///
    /// The query runs on the current authenticated session, retains the
    /// original Apply request ID and body required by Host 1.0, and uses a new
    /// bounded deadline. Its authorization artifacts are copied from the exact
    /// durable Apply rather than reconstructed by the controller.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-Host Apply, malformed durable authority,
    /// missing artifacts, invalid session coordinates, or protected journal
    /// admission failure.
    pub fn prepare_authenticated_host_effect_query(
        &mut self,
        effect: &PreparedAuthorityEffectV1,
    ) -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError> {
        let original = effect.broker_request().map_err(|_| {
            BrokerSessionSecurityError::manifest("durable Host authority effect request")
        })?;
        if original.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME {
            return Err(BrokerSessionSecurityError::manifest(
                "durable Host authority effect method",
            ));
        }
        let original_request_id = original.request_id();
        let original_envelope = original.into_envelope();
        let authorization = original_envelope
            .authorization
            .as_option()
            .cloned()
            .ok_or_else(|| {
                BrokerSessionSecurityError::manifest("durable Host authority effect authorization")
            })?;
        let (deadline, maximum_response_bytes, protocol_version, audience) =
            self.0.client_request_limits()?;
        let body = QueryRuntimeEffectRequest {
            header: Some(RequestHeader {
                protocol_major: u32::from(protocol_version.major()),
                protocol_minor: u32::from(protocol_version.minor()),
                request_id: original_request_id.to_vec(),
                audience: audience.into(),
                deadline_boottime_nanoseconds: deadline,
                maximum_response_bytes,
                ..Default::default()
            })
            .into(),
            original_apply_request: effect.attempt().body().to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let envelope = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT.into(),
            body,
            authorization: Some(authorization).into(),
            ..Default::default()
        };
        let (authenticated, initialize) = self.0.prepare_client_request(
            envelope,
            BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT,
            0,
            original_request_id,
            deadline,
            maximum_response_bytes,
        )?;
        self.reserve_exact_authenticated_request(authenticated, initialize)
    }

    /// Builds and durably reserves one authenticated descriptor-bearing request.
    ///
    /// The fixed V1 profile derives the required role count from `method`; the
    /// exact supplied FD count and signed descriptor table must both match it.
    /// Host PublishCatalog, Host ApplyExecution, and the closed argument-source
    /// transport each carry one descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error for another method, inexact descriptor count/roles,
    /// stale fixed peer or clock evidence, or invalid signed request semantics.
    pub fn prepare_authenticated_descriptor_request(
        &mut self,
        method: BrokerMethod,
        descriptors: Vec<OwnedFd>,
        build: impl FnOnce(DormantBrokerRequestCoordinatesV1) -> BrokerRequestEnvelope,
    ) -> Result<DormantBrokerDescriptorRequestPreparationV1, BrokerSessionSecurityError> {
        if !matches!(
            method,
            BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG
                | BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION
                | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME_ARGUMENT
        ) || descriptors.len() != 1
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.0.require_negotiated_client_method(method)?;
        let (request_id, deadline, maximum_response_bytes, protocol_version, audience) =
            self.0.client_request_coordinates()?;
        let coordinates = DormantBrokerRequestCoordinatesV1 {
            request_id,
            deadline_boottime_nanoseconds: deadline,
            maximum_response_bytes,
            protocol_version,
            audience,
        };
        let message = build(coordinates);
        let actual_descriptor_count = descriptors.len();
        let (request, initialize) = self.0.prepare_client_request(
            message,
            method,
            actual_descriptor_count,
            request_id,
            deadline,
            maximum_response_bytes,
        )?;
        Ok(
            match self.reserve_exact_authenticated_request(request, initialize)? {
                DormantBrokerRequestPreparationV1::Prepared(request) => {
                    DormantBrokerDescriptorRequestPreparationV1::Prepared(
                        DormantPreparedBrokerDescriptorRequestV1 {
                            request: request.0,
                            descriptors,
                        },
                    )
                }
                DormantBrokerRequestPreparationV1::InitializationRecoveryRequired {
                    error,
                    recovery,
                    request,
                } => DormantBrokerDescriptorRequestPreparationV1::InitializationRecoveryRequired {
                    error,
                    recovery,
                    request: DormantUnconfirmedBrokerDescriptorRequestV1 {
                        request: request.0,
                        descriptors,
                    },
                },
                DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired {
                    error,
                    recovery,
                    request,
                } => DormantBrokerDescriptorRequestPreparationV1::SuccessorRecoveryRequired {
                    error,
                    recovery,
                    request: DormantUnconfirmedBrokerDescriptorRequestV1 {
                        request: request.0,
                        descriptors,
                    },
                },
            },
        )
    }

    /// Atomically sends one committed signed request and its exact descriptors.
    ///
    /// # Errors
    ///
    /// Returns an error for fatal ancillary transport or changed protected
    /// session currentness; retryable backpressure retains every FD.
    pub fn send_authenticated_descriptor_request(
        &mut self,
        prepared: DormantPreparedBrokerDescriptorRequestV1,
    ) -> DormantBrokerDescriptorRequestSendProgressV1 {
        let send = self.0.send_request_packet_with_descriptors(
            prepared.request.canonical_packet(),
            &prepared.descriptors,
        );
        match send {
            Ok(()) => DormantBrokerDescriptorRequestSendProgressV1::Sent(
                DormantOutstandingBrokerRequestV1(prepared.request),
            ),
            Err(handshake::DormantBrokerSessionHandshakeErrorV1::Transport) => {
                DormantBrokerDescriptorRequestSendProgressV1::Pending(prepared)
            }
            Err(error) => DormantBrokerDescriptorRequestSendProgressV1::RecoveryRequired(
                DormantBrokerDescriptorRequestSendRecoveryV1 {
                    error: error.into(),
                    prepared,
                },
            ),
        }
    }

    /// Retries an exact descriptor request after transport/currentness ambiguity.
    #[must_use]
    pub fn retry_authenticated_descriptor_request(
        &mut self,
        recovery: DormantBrokerDescriptorRequestSendRecoveryV1,
    ) -> DormantBrokerDescriptorRequestSendProgressV1 {
        self.send_authenticated_descriptor_request(recovery.prepared)
    }

    /// Sends only a request already committed by this protected session.
    ///
    /// # Errors
    ///
    /// Returns an error for fatal transport failure or changed protected peer,
    /// endpoint, transcript, or journal authority.
    pub fn send_authenticated_request(
        &mut self,
        request: DormantPreparedBrokerRequestV1,
    ) -> Result<DormantBrokerRequestSendProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        match self.send_authenticated_request_borrowed(&request) {
            Ok(true) => Ok(DormantBrokerRequestSendProgressV1::Sent(
                DormantOutstandingBrokerRequestV1(request.0),
            )),
            Ok(false) => {
                Ok(DormantBrokerRequestSendProgressV1::Pending(request))
            }
            Err(error) => Err(error),
        }
    }

    /// Sends the original execution query without dropping it on failure.
    ///
    /// # Errors
    ///
    /// Returns the exact prepared request with the actual send error. No
    /// replacement request, retry, or recovery is performed.
    pub fn send_execution_publication_request(
        &mut self,
        request: DormantPreparedBrokerRequestV1,
    ) -> Result<DormantBrokerRequestSendProgressV1,
        (DormantPreparedBrokerRequestV1, DormantBrokerSessionHandshakeErrorV1)>
    {
        if !matches!(request.0.method(), BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION
            | BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2
            | BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2
            | BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1
            | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1)
        {
            return Err((request, DormantBrokerSessionHandshakeErrorV1::RemoteInvalid));
        }
        match self.send_authenticated_request_borrowed(&request) {
            Ok(true) => Ok(DormantBrokerRequestSendProgressV1::Sent(DormantOutstandingBrokerRequestV1(request.0))),
            Ok(false) => Ok(DormantBrokerRequestSendProgressV1::Pending(request)),
            Err(error) => Err((request, error)),
        }
    }

    // Both wrappers enter the same packet send, preserving Legacy's consuming
    // error disposition while the execution wrapper returns original custody.
    fn send_authenticated_request_borrowed(
        &mut self,
        request: &DormantPreparedBrokerRequestV1,
    ) -> Result<bool, DormantBrokerSessionHandshakeErrorV1> {
        if matches!(request.0.method(), BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT
            | BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2)
        {
            self.0.confirm_original_host_argument_archive(&request.0)?;
        }
        match self.0.send_request_packet(request.0.canonical_packet()) {
            Ok(()) => Ok(true),
            Err(handshake::DormantBrokerSessionHandshakeErrorV1::Transport) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// Receives, authenticates, cross-links, and durably commits one response.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid response bytes, wrong method/session/
    /// sequence/request identity, changed peer evidence, or protected failure.
    pub fn receive_authenticated_response(
        &mut self,
        outstanding: DormantOutstandingBrokerRequestV1,
    ) -> Result<DormantBrokerResponseProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        self.receive_authenticated_response_borrowed(&outstanding, None).map(|committed| {
            match committed {
                Some(committed) => DormantBrokerResponseProgressV1::Committed(committed),
                None => DormantBrokerResponseProgressV1::Pending(outstanding),
            }
        })
    }

    /// Receives one execution response while retaining failed request custody.
    ///
    /// # Errors
    ///
    /// Returns the exact outstanding request with the actual transport error.
    /// Returned packet, decode failure and native admission error remain in the
    /// supplied DATA custody; ambiguous native commits retain their recovery.
    pub fn receive_execution_publication_response(
        &mut self,
        outstanding: DormantOutstandingBrokerRequestV1,
        custody: &mut ExecutionPublicationReceiveCustodyV1,
    ) -> Result<DormantBrokerResponseProgressV1,
        (DormantOutstandingBrokerRequestV1, DormantBrokerSessionHandshakeErrorV1)>
    {
        if !matches!(outstanding.0.method(), BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION
            | BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2
            | BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2
            | BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1
            | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1)
        {
            return Err((outstanding, DormantBrokerSessionHandshakeErrorV1::RemoteInvalid));
        }
        let Some(profile) = aos_sandbox_broker_session_protocol::authenticated_broker_method_profile_v1(outstanding.0.method()) else {
            return Err((outstanding, DormantBrokerSessionHandshakeErrorV1::RemoteInvalid));
        };
        if !profile.success_response_descriptor_roles().is_empty() {
            return Err((outstanding, DormantBrokerSessionHandshakeErrorV1::RemoteInvalid));
        }
        match self.receive_authenticated_response_borrowed(&outstanding, Some(custody)) {
            Ok(Some(committed)) => Ok(DormantBrokerResponseProgressV1::Committed(committed)),
            Ok(None) => Ok(DormantBrokerResponseProgressV1::Pending(outstanding)),
            Err(error) => Err((outstanding, error)),
        }
    }

    // Sole receive/decode/admission/commit algorithm. Legacy passes no resident
    // DATA destination and preserves its exact consuming failure semantics.
    fn receive_authenticated_response_borrowed(
        &mut self,
        outstanding: &DormantOutstandingBrokerRequestV1,
        mut custody: Option<&mut ExecutionPublicationReceiveCustodyV1>,
    ) -> Result<Option<ProtectedBrokerOutcomeCommitResultV1>, DormantBrokerSessionHandshakeErrorV1> {
        let maximum = usize::try_from(outstanding.0.maximum_response_bytes())
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        let packet = match self.0.receive_response_packet_retaining_v1(
            maximum, custody.as_deref_mut().map(|retained| &mut retained.raw),
        ) {
            Ok(packet) => packet,
            Err(handshake::DormantBrokerSessionHandshakeErrorV1::Transport) => {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        let local_decoded;
        let decoded = if let Some(retained) = custody.as_deref_mut() {
            retained.packet = Some(packet);
            retained.decoded = retained.packet.as_ref().map(|bytes| decode_canonical_response_v1(bytes));
            &retained.decoded
        } else {
            local_decoded = Some(decode_canonical_response_v1(&packet));
            &local_decoded
        };
        let Some(Ok(outcome)) = decoded else {
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        };
        let reopened = self.0.reopen_broker_outcome(&outstanding.0);
        let gate = match reopened {
            Ok((gate, _)) => gate,
            Err(error) => {
                if let Some(retained) = custody.as_deref_mut() {
                    retained.native_error = Some(error);
                    return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
                }
                return Err(error.into());
            }
        };
        let admitted = gate.admit_outcome(outcome);
        let pending = match admitted {
            Err(error) => {
                if let Some(retained) = custody.as_deref_mut() {
                    retained.native_error = Some(error);
                    return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
                }
                return Err(error.into());
            }
            Ok(admission) => match admission {
            crate::ProtectedBrokerOutcomeAdmissionV1::New { advancement } => advancement,
            crate::ProtectedBrokerOutcomeAdmissionV1::ExactReplay { replay } => {
                if let Some(retained) = custody.as_deref_mut() {
                    retained.rejected_replay = Some(replay);
                }
                return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
            }
            },
        };
        Ok(Some(self.0.commit_broker_outcome(pending)))
    }

    /// Installs the first authenticated request for this adopted session.
    ///
    /// # Errors
    ///
    /// Returns an error unless fixed custody, the empty or rollover journal
    /// predecessor, signed request, transcript, and live peer all agree.
    pub(crate) fn initialize_authenticated_request(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<ProtectedBrokerSessionInitializationResultV1, BrokerSessionSecurityError> {
        self.0.initialize_authenticated_request(request)
    }

    /// Appends one authenticated successor request for this adopted session.
    ///
    /// # Errors
    ///
    /// Returns an error unless the request is the exact signed successor of the
    /// current terminal head and every session observation remains current.
    pub(crate) fn append_authenticated_request(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<ProtectedBrokerRequestCommitResultV1, BrokerSessionSecurityError> {
        self.0.append_authenticated_request(request)
    }

    /// Recovers an ambiguous initial or rollover request installation.
    #[must_use]
    pub fn recover_initialization(
        &mut self,
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
    ) -> ProtectedBrokerSessionInitializationResultV1 {
        self.0.recover_initialization(recovery)
    }

    /// Recovers an ambiguous authenticated successor-request commit.
    #[must_use]
    pub fn recover_request_commit(
        &mut self,
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
    ) -> ProtectedBrokerRequestCommitResultV1 {
        self.0.recover_request_commit(recovery)
    }

    /// Reopens one request from the session's co-owned fixed journal and peer.
    ///
    /// # Errors
    ///
    /// Returns an error unless the request, transcript, endpoint, journal head,
    /// and live adopted-socket peer remain mutually current.
    pub(crate) fn reopen_broker_outcome(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<DormantBrokerOutcomeVerificationV1, BrokerSessionSecurityError> {
        let (gate, context) = self.0.reopen_broker_outcome(request)?;
        Ok(DormantBrokerOutcomeVerificationV1 { gate, context })
    }

    /// Commits one pending outcome through the authenticated adopted session.
    #[must_use]
    pub fn commit_broker_outcome(
        &mut self,
        pending: ProtectedBrokerOutcomePendingAdvancementV1,
    ) -> ProtectedBrokerOutcomeCommitResultV1 {
        self.0.commit_broker_outcome(pending)
    }

    /// Recovers one ambiguous outcome commit through the same authority path.
    #[must_use]
    pub fn recover_broker_outcome_commit(
        &mut self,
        recovery: ProtectedBrokerOutcomeCommitRecoveryV1,
    ) -> ProtectedBrokerOutcomeCommitResultV1 {
        self.0.recover_broker_outcome_commit(recovery)
    }

    /// Revalidates an exact terminal head while retaining this session borrow.
    ///
    /// # Errors
    ///
    /// Returns an error unless fixed custody, journal, transcript, live socket
    /// peer, and the exact terminal outcome remain current.
    pub fn revalidate_broker_outcome<'session>(
        &'session mut self,
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<ProtectedBrokerOutcomeCurrentV1<'session>, BrokerSessionSecurityError> {
        self.0.revalidate_broker_outcome(currentness)
    }

    /// Arms one paid same-writer execution post before any selected growth.
    ///
    /// # Errors
    /// Rejects another fixed endpoint, closed socket or already-used original.
    pub fn arm_execution_client_post_v1(&self,
        original: &mut crate::ExecutionClientPostOriginalV1) -> Result<(), BrokerSessionSecurityError>
    {
        self.0.arm_execution_client_post_v1(original)
    }

    /// Runs the prearmed independent after even after an earlier refusal.
    ///
    /// A reached complete terminal validator already owns its native after;
    /// this call then finishes comparison without entering a duplicate probe.
    ///
    /// # Errors
    /// Rejects changed custody or any original native or comparison failure.
    pub fn finish_execution_client_post_v1(&mut self,
        original: &mut crate::ExecutionClientPostOriginalV1) -> Result<(), BrokerSessionSecurityError>
    {
        self.0.finish_execution_client_post_v1(original)
    }

    /// Retains the same terminal and transfers its owed after to that validator.
    ///
    /// # Errors
    /// Returns the original owner on changed custody or failed validation.
    pub fn retain_execution_outcome_current_with_post_v1<'authority>(
        &'authority mut self, owner: ProtectedBrokerOutcomeCurrentnessOwnerV1,
        original: &mut crate::ExecutionClientPostOriginalV1,
    ) -> Result<ProtectedBrokerOutcomeCurrentV1<'authority>,
        (ProtectedBrokerOutcomeCurrentnessOwnerV1, BrokerSessionSecurityError)>
    {
        self.0.retain_execution_outcome_current_with_post_v1(owner, original)
    }

    /// Loans the original execution terminal, returning failed ownership intact.
    ///
    /// # Errors
    ///
    /// Returns the original owner and actual error when the fixed execution
    /// endpoint, protected terminal, floor, or live peer is no longer current.
    pub fn retain_execution_outcome_current<'session>(
        &'session mut self,
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<
        ProtectedBrokerOutcomeCurrentV1<'session>,
        (ProtectedBrokerOutcomeCurrentnessOwnerV1, BrokerSessionSecurityError),
    > {
        self.0.retain_execution_outcome_current(currentness)
    }

    /// Rechecks the exact borrowed Inventory predecessor without consuming it.
    ///
    /// # Errors
    /// Rejects changed predecessor/session bindings or a stale protected journal and peer.
    pub fn compare_atomic_snapshot_predecessor_v3(
        &mut self,
        currentness: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.compare_atomic_snapshot_predecessor_v3(currentness)
    }

    /// Rechecks the borrowed original Host48 terminal without consuming its owner.
    pub(crate) fn compare_host_storage_output_outcome_v1(
        &mut self,
        currentness: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.compare_host_storage_output_outcome_v1(currentness)
    }

    /// Compares the original Storage output outcome against this protected session.
    ///
    /// # Errors
    /// Rejects changed Storage output/session bindings or a stale protected journal and peer.
    pub fn compare_original_storage_output_outcome_v1(
        &mut self,
        currentness: &crate::ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.compare_original_storage_output_outcome_v1(currentness)
    }

    /// Prearms a short exclusive preparation loan before any observation.
    pub fn output_registration_transport<'session>(
        &'session mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        state: &'session mut crate::handshake::output_registration_continuation::OutputPreparationCustodyV1,
    ) -> crate::handshake::output_registration_continuation::HeldOutputPreparationV1<'session> {
        self.0.output_registration_transport(request, state)
    }

    pub(crate) fn receive_original_output_request(
        &mut self,
        receipt: &mut crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1,
        deadline: u64,
    ) -> Option<crate::ProductionBrokerRequestEventV1> {
        receipt.receive_once(&mut self.0, deadline);
        Self::take_original_storage_request_event_v1(receipt)
    }

    pub(crate) fn receive_original_storage_lifecycle_request_v1(
        &mut self,
        original: &mut crate::handshake::storage_lifecycle_request::StorageLifecycleRequestOriginalV1,
        receiving: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        deadline: u64,
        terminal: Option<&crate::recovery::RetainedStorageTerminalV1>,
    ) -> Option<crate::ProductionBrokerRequestEventV1> {
        original.receive(&mut self.0, receiving, deadline, terminal);
        Self::take_original_storage_request_event_v1(original.completed_receipt()?)
    }

    pub(crate) fn receive_original_storage_prepare_request_v1(
        &mut self,
        receipt: &mut crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1,
        deadline: u64,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
    ) -> Option<crate::ProductionBrokerRequestEventV1> {
        receipt.receive_storage_prepare_once_v1(&mut self.0, deadline, receiving);
        Self::take_original_storage_request_event_v1(receipt)
    }

    pub(crate) fn receive_original_storage_prepare_replay_v1(
        &mut self,
        receipt: &mut crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1,
        deadline: u64,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
        terminal: &ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Option<crate::ProductionBrokerRequestEventV1> {
        receipt.receive_storage_prepare_replay_once_v1(&mut self.0, deadline, receiving, terminal);
        Self::take_original_storage_request_event_v1(receipt)
    }

    pub(crate) fn recheck_storage_prepare_replay_transport_v1(
        &mut self,
        receipt: &mut crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1,
    ) -> bool {
        receipt.recheck_replay_transport_v1(&mut self.0)
    }

    fn take_original_storage_request_event_v1(
        receipt: &mut crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1,
    ) -> Option<crate::ProductionBrokerRequestEventV1> {
        match receipt.into_admitted_original()? {
            crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::New { request, .. } => {
                Some(crate::ProductionBrokerRequestEventV1::Request(DormantReceivedBrokerRequestV1(request)))
            }
            crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::InFlightReplay { request } => {
                Some(crate::ProductionBrokerRequestEventV1::InFlightReplay(DormantBrokerOutcomeUnknownV1 {
                    request: DormantReceivedBrokerRequestV1(request), observation: None,
                }))
            }
            crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::TerminalReplay { replay } => {
                Some(crate::ProductionBrokerRequestEventV1::TerminalReplay(DormantBrokerTerminalReplayV1(replay)))
            }
        }
    }

    /// Lends one Host58/59 forecast from this same live Session and held writer.
    ///
    /// The genuine C18 caller prepays the fixed original, then checks the
    /// returned complete demand before request/response growth. This performs
    /// no signing, request allocation, payment, admission or Session advance.
    ///
    /// # Errors
    /// Rejects a foreign method/endpoint, repeated original, unavailable held
    /// writer, original metadata failure or checked representation overflow.
    pub fn host_execution_argument_demand_v1(
        &self,
        method: BrokerMethod,
        original: &mut HostExecutionSessionReceivingOriginalV1,
    ) -> Result<aos_sandbox_core::ResourceVector, BrokerSessionSecurityError> {
        self.0.host_execution_argument_demand_v1(method, original)
    }

    pub fn execution_output_demand_v1(
        &self,
        method: BrokerMethod,
        original: &mut HostExecutionSessionReceivingOriginalV1,
    ) -> Result<aos_sandbox_core::ResourceVector, BrokerSessionSecurityError> {
        self.0.execution_output_demand_v1(method, original)
    }

    /// Borrows the existing Session transport ceiling at a retained paired sample.
    ///
    /// This comparison DATA grants no effect. The selected Stop must also
    /// intersect its original signed plan, lease and actual Source association.
    /// No clock is read and no receiving or request slot is acquired here.
    ///
    /// # Errors
    /// Refuses another protocol, unnegotiated ApplyRuntime, invalid Session
    /// context or checked transport-bound overflow.
    pub fn host_stop_request_bound_data_v4(
        &mut self,
        clock: aos_sandbox_core::RawPairedClockSample,
    ) -> Result<u64, BrokerSessionSecurityError> {
        self.0.host_stop_request_bound_data_v4(clock)
    }

    /// Quotes a closed Stop from this same retained Host Client writer.
    ///
    /// The original retains the held metadata/append forecast and every error.
    /// This returns requirement DATA only; the actual Stop owner must pay it
    /// before model growth, and every signed effect check remains independent.
    ///
    /// # Errors
    /// Refuses another protocol, missing ApplyRuntime negotiation, reused
    /// forecast destinations, unhealthy writer or invalid checked geometry.
    pub fn host_stop_demand_v4(
        &self,
        original: &mut HostExecutionSessionReceivingOriginalV1,
    ) -> Result<aos_sandbox_core::ResourceVector, BrokerSessionSecurityError> {
        self.0.host_stop_demand_v4(original)
    }

    /// Borrows the actual captured Host Client's complete historical DATA.
    ///
    /// This performs no IO, encoding, copying or currentness observation. The
    /// caller retains its genuine completed outcome/currentness owners and
    /// separately prepays any copied companion or historical replay models.
    ///
    /// # Errors
    /// Rejects an unhealthy or uncaptured writer, a foreign endpoint, absent
    /// history or a Session that did not negotiate the actual Apply method.
    pub fn host_execution_history_data_v1(&self) -> Result<&[u8], BrokerSessionSecurityError> {
        self.0.host_execution_history_data_v1()
    }

    /// Borrows exact protected Storage Client history from its existing writer.
    ///
    /// # Errors
    /// Rejects another endpoint/protocol, absent original60 negotiation, an
    /// unhealthy writer or an uncaptured native append owner. No IO occurs.
    pub fn storage_capture_history_data_v2(&self) -> Result<&[u8], BrokerSessionSecurityError> {
        self.0.storage_capture_history_data_v2()
    }


    /// Lends Authorize and first-Observe requirements from this same Session.
    ///
    /// The caller pays the fixed receiving original before this metadata read,
    /// then checks the returned complete representation before materializing
    /// content, descriptors or requests. This is requirement DATA only.
    ///
    /// # Errors
    /// Refuses a foreign endpoint, unnegotiated Apply, repeated original,
    /// native metadata failure or unrepresentable complete demand.
    pub fn host_execution_authorize_observe_demand_v2(
        &self,
        original: &mut HostExecutionSessionReceivingOriginalV1,
    ) -> Result<aos_sandbox_core::ResourceVector, BrokerSessionSecurityError> {
        self.0.host_execution_authorize_observe_demand_v2(original)
    }

    pub(crate) fn storage_prepare_outcome_demand_v1(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
        observation: &ProtectedBrokerDomainResponseV1,
    ) -> Result<aos_sandbox_core::ResourceVector, BrokerSessionSecurityError> {
        self.0.storage_prepare_outcome_demand_v1(request, observation)
    }

    pub(crate) fn storage_prepare_replay_demand_v1(
        &self,
        terminal: &ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<aos_sandbox_core::ResourceVector, BrokerSessionSecurityError> {
        self.0.storage_prepare_replay_demand_v1(terminal)
    }

    pub(crate) fn storage_prepare_request_demand_v1(
        &self,
    ) -> Result<aos_sandbox_core::ResourceVector, BrokerSessionSecurityError> {
        self.0.storage_prepare_request_demand_v1()
    }

    pub(crate) fn recheck_original_nix_generation_session(
        &mut self,
    ) -> Result<(), BrokerSessionSecurityError> {
        // This existing fixed Storage/NodeController check has no Output
        // operation semantics. It validates the original named journal,
        // transcript and actual peer through the sole currentness engine.
        self.0.recheck_original_nix_generation_session()
    }

    /// Parks the selected coordinates under the same original nonrenewable cutoff.
    pub fn park_output_client_coordinates(
        &mut self,
        method: BrokerMethod,
        original_cutoff: u64,
        flight: &mut crate::handshake::output_registration_continuation::OriginalOutputClientFlightV1,
    ) {
        self.0.park_output_client_coordinates_v1(method, original_cutoff, flight);
    }

    /// Reports only the method list of the actual completed transcript.
    pub fn has_selected_capture_candidate_profile(&self) -> bool {
        self.0.has_selected_capture_candidate_profile()
    }

    /// Parks method-41 coordinates once from the same actual fixed Session.
    pub fn park_capture_candidate_client_coordinates(
        &mut self,
        assignment: &aos_sandbox::runtime_scope::CurrentAssignmentTarget,
        flight: &mut crate::handshake::output_registration_continuation::OriginalOutputClientFlightV1,
    ) {
        if flight.coordinates.is_some() { return; }
        flight.coordinates = Some((|| {
            self.0.recheck_original_capture_candidate_client()?;
            self.0.require_negotiated_client_method(
                BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE,
            )?;
            let (request_id, deadline, maximum_response_bytes, protocol_version, audience) =
                self.0.client_request_coordinates()?;
            Ok(DormantBrokerRequestCoordinatesV1 {
                request_id,
                deadline_boottime_nanoseconds: deadline.min(assignment.deadline_boottime_nanoseconds()),
                maximum_response_bytes,
                protocol_version,
                audience,
            })
        })());
    }

    /// Rechecks the original selected capture-candidate client custody.
    ///
    /// # Errors
    /// Rejects a nonselected capture-candidate client or changed protected session and peer custody.
    pub fn recheck_original_capture_candidate_client(
        &mut self,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.recheck_original_capture_candidate_client()
    }

    /// Compares the original capture-candidate outcome without replacing custody.
    ///
    /// # Errors
    /// Rejects changed capture-candidate/session bindings or a stale protected journal and peer.
    pub fn compare_original_capture_candidate_outcome(
        &mut self,
        currentness: &crate::ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.compare_original_capture_candidate_outcome(currentness)
    }

    /// Parks the original Output Client request in its same retained flight.
    pub fn park_output_client_request(
        &mut self,
        flight: &mut crate::handshake::output_registration_continuation::OriginalOutputClientFlightV1,
        envelope: BrokerRequestEnvelope,
    ) -> bool {
        flight.prepare(&mut self.0, envelope)
    }

    /// Borrows the actual witness cause at this flight's recorded primary site.
    pub fn output_client_flight_failure<'a>(
        &'a self,
        flight: &'a crate::handshake::output_registration_continuation::OriginalOutputClientFlightV1,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        flight.failure_with_session(&self.0)
    }

    /// Borrows this flight's original postcheck debt through the same Session.
    pub fn output_client_flight_postcheck_debt<'a>(
        &'a self,
        flight: &'a crate::handshake::output_registration_continuation::OriginalOutputClientFlightV1,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        flight.postcheck_debt_with_session(&self.0)
    }

    /// Borrows the original preparation failure through its same Session.
    pub fn output_preparation_failure<'a>(
        &'a self,
        preparation: &'a crate::handshake::output_registration_continuation::OutputPreparationCustodyV1,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        preparation.failure_with_session(&self.0)
    }

    /// Borrows the original preparation postcheck debt through its same Session.
    pub fn output_preparation_postcheck_debt<'a>(
        &'a self,
        preparation: &'a crate::handshake::output_registration_continuation::OutputPreparationCustodyV1,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        preparation.postcheck_debt_with_session(&self.0)
    }

    /// Borrows the original terminal witness failure without consuming it.
    pub fn output_terminal_witness_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.output_terminal_witness_failure()
    }

    /// Borrows the original terminal witness debt without consuming it.
    pub fn output_terminal_witness_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.output_terminal_witness_debt()
    }

    pub(crate) fn output_terminal_witness_debt_before_protected(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.output_terminal_witness_debt_before_protected()
    }

    /// Performs the original witness bookend at the named diagnostic frontier.
    pub fn bookend_output_terminal_witnesses(&mut self, boundary: handshake::OutputCurrentnessBoundaryV1) -> bool {
        self.0.bookend_output_terminal_witnesses(boundary)
    }

    /// Attempts the original retained Output Client send once.
    pub fn send_original_output_client_request(
        &mut self,
        flight: &mut crate::handshake::output_registration_continuation::OriginalOutputClientFlightV1,
    ) -> bool {
        flight.send_once(&mut self.0)
    }

    /// Receives the original terminal into its same retained Output Client flight.
    pub fn receive_original_output_client_terminal(
        &mut self,
        flight: &mut crate::handshake::output_registration_continuation::OriginalOutputClientFlightV1,
    ) -> bool {
        flight.receive_terminal_once(&mut self.0)
    }

    pub(crate) fn commit_original_output_server_terminal(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        body: &[u8],
        terminal: &mut crate::handshake::output_registration_continuation::OriginalOutputServerTerminalV1,
    ) {
        terminal.prepare_and_commit(&mut self.0, request, body);
    }

    pub(crate) fn send_original_output_server_terminal(
        &mut self,
        terminal: &mut crate::handshake::output_registration_continuation::OriginalOutputServerTerminalV1,
    ) {
        terminal.send_once(&mut self.0);
    }

    /// Keeps the genuine Host Session exclusively borrowed across the real
    /// Storage writer and its bookends, including an atomic-write error.
    pub(crate) fn register_original_storage_output_with_host(
        &mut self,
        committed: &crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        attempt: &mut aos_sandbox_storage::execution_output_credential::OriginalExecutionOutputRegistrationV1,
        checks: &mut [Option<Result<(), BrokerSessionSecurityError>>; 2],
    ) {
        self.register_original_storage_output_with_host_inner_v1(committed, storage, output, StorageOutputDomainOperationV1::Logical(attempt), checks,
            StorageOutputDomainReceivingV1::Ordinary);
    }

    /// Holds the same Host native/currentness witnesses across funded logical46.
    pub(crate) fn register_original_storage_output_with_host_receiving_v1(
        &mut self,
        committed: &crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        attempt: &mut aos_sandbox_storage::execution_output_credential::OriginalExecutionOutputRegistrationV1,
        checks: &mut [Option<Result<(), BrokerSessionSecurityError>>; 2],
        lifecycle: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) {
        self.register_original_storage_output_with_host_inner_v1(committed, storage, output, StorageOutputDomainOperationV1::Logical(attempt), checks,
            StorageOutputDomainReceivingV1::Lifecycle { lifecycle, session, socket });
    }

    pub(crate) fn finish_original_capture_with_host_receiving_v3(
        &mut self, committed: &crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        checks: &mut [Option<Result<(), BrokerSessionSecurityError>>; 2],
        lifecycle: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox::Journal, socket: &SeqpacketSocket,
    ) {
        self.register_original_storage_output_with_host_inner_v1(committed, storage, output,
            StorageOutputDomainOperationV1::Capture(request), checks,
            StorageOutputDomainReceivingV1::Lifecycle { lifecycle, session, socket });
    }

    fn register_original_storage_output_with_host_inner_v1(
        &mut self,
        committed: &crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        mut operation: StorageOutputDomainOperationV1<'_>,
        checks: &mut [Option<Result<(), BrokerSessionSecurityError>>; 2],
        mut receiving: StorageOutputDomainReceivingV1<'_, '_, '_>,
    ) {
        let projection = committed.host_storage_output_originals_v1();
        let (outcome, currentness) = match projection {
            Ok(originals) => originals,
            Err(error) => { checks[0] = Some(Err(error)); return; }
        };
        let witness_before = self.0.bookend_output_terminal_witnesses(
            handshake::OutputCurrentnessBoundaryV1::BeforeAction,
        );
        checks[0] = Some(self.0.compare_host_storage_output_outcome_v1(currentness));
        let witness_after_check = self.0.bookend_output_terminal_witnesses(
            handshake::OutputCurrentnessBoundaryV1::PostAction,
        );
        if witness_before && witness_after_check && matches!(&checks[0], Some(Ok(()))) {
            match (&mut receiving, &mut operation) {
                (StorageOutputDomainReceivingV1::Ordinary, StorageOutputDomainOperationV1::Logical(attempt)) =>
                    storage.register_original_execution_output(output, attempt, outcome),
                (StorageOutputDomainReceivingV1::Lifecycle { lifecycle, session, socket }, StorageOutputDomainOperationV1::Logical(attempt)) =>
                    storage.register_original_execution_output_receiving_v1(output, attempt, outcome, lifecycle, session, socket),
                (StorageOutputDomainReceivingV1::Lifecycle { lifecycle, session, socket }, StorageOutputDomainOperationV1::Capture(request)) =>
                    storage.finish_original_capture_with_host_ongoing_v3(request, outcome, output, lifecycle, session, socket),
                (StorageOutputDomainReceivingV1::Ordinary, StorageOutputDomainOperationV1::Capture(_)) => {
                    checks[0] = Some(Err(BrokerSessionSecurityError::Currentness));
                }
            }
        }
        // Keep the actual writer Result in its original attempt before BOTH
        // independent terminal checks, even when either earlier check failed.
        checks[1] = Some(self.0.compare_host_storage_output_outcome_v1(currentness));
        let boundary = if matches!(&checks[1], Some(Err(_))) {
            handshake::OutputCurrentnessBoundaryV1::PostProtectedFailure
        } else {
            handshake::OutputCurrentnessBoundaryV1::PostAction
        };
        self.0.bookend_output_terminal_witnesses(boundary);
    }

    /// Produces one broker-specific effect handoff under this session borrow.
    ///
    /// # Errors
    ///
    /// Returns an error unless the exact terminal protected outcome remains
    /// current against the co-owned endpoint, transcript, journal, and peer.
    pub(crate) fn prepare_effect_handoff<'session>(
        &'session mut self,
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<ProtectedBrokerEffectHandoffV1<'session>, BrokerSessionSecurityError> {
        self.0.prepare_effect_handoff(currentness)
    }
}

#[derive(Clone, Copy)]
enum ClientWitnessRetentionV1 {
    Legacy,
    Output,
}

#[derive(Clone, Copy)]
enum StorageHelloPurposeV1 {
    Ordinary,
    Preparation,
    NixGeneration,
    OutputCapture,
}

impl ProtectedBrokerSessionFixedCustodyV1 {
    /// Drives the same fixed ControllerStorage flight, parking its actual
    /// final HELLO return before the first cold context/main/floor gate.
    ///
    /// # Errors
    /// Preserves raw-flight failures; post-verified failure keeps its first
    /// typed cause and every returned owner in the original cold slot.
    pub(crate) fn connect_retained_storage_session(
        self,
        deadline: handshake::OriginalBrokerColdDeadlineV1,
        slot: &mut Option<handshake::RetainedStorageColdOpenV1>,
        node: [u8; 16],
    ) -> Result<DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1> {
        self.connect_retained_storage_with_coverage_v1(deadline, slot, node, None)
    }

    // The selected coordinator uses the same verified-cold destination and
    // handshake engine before any inventory request on this original session.
    /// Connects the fixed Git-coverage Storage session through its original cold slot.
    ///
    /// # Errors
    /// Rejects the fixed Storage role, HELLO, cold journal/floor, peer, or original cutoff; failures remain in the cold slot.
    pub fn connect_retained_git_coverage_storage_session_v1(
        self,
        deadline: handshake::OriginalBrokerColdDeadlineV1,
        slot: &mut Option<handshake::RetainedStorageColdOpenV1>,
        node: [u8; 16],
    ) -> Result<DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1> {
        self.connect_retained_storage_with_coverage_v1(
            deadline, slot, node,
            Some(aos_sandbox_core::format::git_upload_enrollment::GitCoverageBrokerRoleV1::Storage),
        )
    }

    fn connect_retained_storage_with_coverage_v1(
        self,
        deadline: handshake::OriginalBrokerColdDeadlineV1,
        slot: &mut Option<handshake::RetainedStorageColdOpenV1>,
        node: [u8; 16],
        coverage: Option<aos_sandbox_core::format::git_upload_enrollment::GitCoverageBrokerRoleV1>,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1> {
        self.connect_retained_storage_session_inner(
            deadline, slot, node, ClientWitnessRetentionV1::Legacy, coverage,
            StorageHelloPurposeV1::Ordinary,
        )
    }

    /// Connects the closed Create Inventory/Prepare profile through its real cold slot.
    ///
    /// This signs the fixed two-method client requirement using the same
    /// protected endpoint, context, original cutoff and retained journal flow.
    ///
    /// # Errors
    /// Refuses another endpoint role, HELLO/context mismatch, expired original
    /// cutoff, changed kernel/protected custody, or cold journal/floor failure.
    pub fn connect_retained_storage_preparation_session_v1(
        self,
        deadline: handshake::OriginalBrokerColdDeadlineV1,
        slot: &mut Option<handshake::RetainedStorageColdOpenV1>,
        node: [u8; 16],
    ) -> Result<DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1> {
        self.connect_retained_storage_session_inner(
            deadline, slot, node, ClientWitnessRetentionV1::Legacy, None,
            StorageHelloPurposeV1::Preparation,
        )
    }

    /// Connects the fixed Output Storage session through its original cold slot.
    ///
    /// # Errors
    /// Rejects the fixed Output Storage role, HELLO witnesses, cold journal/floor, peer, or original cutoff.
    pub fn connect_retained_output_storage_session(
        self,
        deadline: handshake::OriginalBrokerColdDeadlineV1,
        slot: &mut Option<handshake::RetainedStorageColdOpenV1>,
        node: [u8; 16],
    ) -> Result<DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1> {
        self.require_output_client_endpoint()?;
        self.connect_retained_storage_session_inner(
            deadline, slot, node, ClientWitnessRetentionV1::Output, None,
            StorageHelloPurposeV1::OutputCapture,
        )
    }

    /// Selects only method57 in the same original fixed Storage flight.
    ///
    /// # Errors
    /// Rejects the fixed method57 Storage role, HELLO, cold journal/floor, peer, or original cutoff.
    pub fn connect_retained_nix_generation_storage_session(
        self,
        deadline: handshake::OriginalBrokerColdDeadlineV1,
        slot: &mut Option<handshake::RetainedStorageColdOpenV1>,
        node: [u8; 16],
    ) -> Result<DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1> {
        self.require_output_client_endpoint()?;
        self.connect_retained_storage_session_inner(
            deadline, slot, node, ClientWitnessRetentionV1::Output, None,
            StorageHelloPurposeV1::NixGeneration,
        )
    }

    fn connect_retained_storage_session_inner(
        self,
        deadline: handshake::OriginalBrokerColdDeadlineV1,
        slot: &mut Option<handshake::RetainedStorageColdOpenV1>,
        node: [u8; 16],
        retention: ClientWitnessRetentionV1,
        coverage: Option<aos_sandbox_core::format::git_upload_enrollment::GitCoverageBrokerRoleV1>,
        purpose: StorageHelloPurposeV1,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1> {
        if slot.is_some()
            || self.production_protocol()
                != aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage
        {
            return Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole);
        }
        deadline.check()?;
        let socket = SeqpacketSocket::connect(Path::new(self.production_socket_path()))
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::Transport)?;
        let mut handshake = self.begin_production_client_handshake_with_storage_purpose_v1(
            socket, coverage, purpose,
        )?.0;
        loop {
            deadline.check()?;
            match handshake.advance_retaining_storage()? {
                handshake::ColdClientHandshakeProgressV1::Pending(pending) => {
                    wait_for_handshake_readiness(
                        pending.as_fd()?,
                        pending.wants_write(),
                        deadline.value(),
                    )?;
                    handshake = pending;
                }
                handshake::ColdClientHandshakeProgressV1::Verified(verified) => {
                    *slot = Some(if matches!(retention, ClientWitnessRetentionV1::Output) {
                        handshake::RetainedStorageColdOpenV1::retain_output(verified, deadline)
                    } else {
                        handshake::RetainedStorageColdOpenV1::retain(verified, deadline)
                    });
                    let session = slot
                        .as_mut()
                        .ok_or(DormantBrokerSessionHandshakeErrorV1::EndpointRole)?
                        .finish(Some(node))?;
                    let session = DormantAuthenticatedBrokerSessionV1(session, Vec::new());
                    // Only the completed, empty shell drops after pure handoff.
                    *slot = None;
                    return Ok(session);
                }
                handshake::ColdClientHandshakeProgressV1::Complete(_) => std::process::abort(),
            }
        }
    }

    /// Drives the fixed Storage broker flight under its original accept D.
    ///
    /// # Errors
    /// Preserves raw-flight failures; a post-verified rejection retains its
    /// originals and permanently closes this activation's cold slot.
    pub(crate) fn complete_retained_storage_handshake(
        self,
        socket: SeqpacketSocket,
        deadline: handshake::OriginalBrokerColdDeadlineV1,
        slot: &mut Option<handshake::RetainedStorageColdOpenV1>,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1> {
        self.complete_retained_storage_handshake_with_coverage_v1(socket, deadline, slot, None)
    }

    pub(crate) fn complete_retained_storage_handshake_with_coverage_v1(
        self,
        socket: SeqpacketSocket,
        deadline: handshake::OriginalBrokerColdDeadlineV1,
        slot: &mut Option<handshake::RetainedStorageColdOpenV1>,
        coverage: Option<aos_sandbox_core::format::git_upload_enrollment::GitCoverageBrokerRoleV1>,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1> {
        self.complete_retained_storage_handshake_with_purpose_v1(
            socket, deadline, slot, coverage, StorageHelloPurposeV1::Ordinary,
        )
    }

    pub(crate) fn complete_retained_nix_generation_storage_handshake(
        self,
        socket: SeqpacketSocket,
        deadline: handshake::OriginalBrokerColdDeadlineV1,
        slot: &mut Option<handshake::RetainedStorageColdOpenV1>,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1> {
        self.complete_retained_storage_handshake_with_purpose_v1(
            socket, deadline, slot, None, StorageHelloPurposeV1::NixGeneration,
        )
    }

    pub(crate) fn complete_retained_output_capture_storage_handshake(
        self,
        socket: SeqpacketSocket,
        deadline: handshake::OriginalBrokerColdDeadlineV1,
        slot: &mut Option<handshake::RetainedStorageColdOpenV1>,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1> {
        self.complete_retained_storage_handshake_with_purpose_v1(
            socket, deadline, slot, None, StorageHelloPurposeV1::OutputCapture,
        )
    }

    fn complete_retained_storage_handshake_with_purpose_v1(
        self,
        socket: SeqpacketSocket,
        deadline: handshake::OriginalBrokerColdDeadlineV1,
        slot: &mut Option<handshake::RetainedStorageColdOpenV1>,
        coverage: Option<aos_sandbox_core::format::git_upload_enrollment::GitCoverageBrokerRoleV1>,
        purpose: StorageHelloPurposeV1,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1> {
        if slot.is_some() || self.production_protocol()
            != aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage
        {
            return Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole);
        }
        deadline.check()?;
        let handshake = self.begin_production_broker_handshake_with_storage_purpose_v1(
            socket, coverage, purpose,
        )?.0;
        complete_retained_storage_from_prepared_v1(handshake, deadline, slot, None, None)
    }

    /// Connects a fixed client endpoint and completes its production handshake.
    ///
    /// The socket path, protocol, audience, complete method profile, and
    /// protected custody root are selected by the same fixed endpoint variant.
    /// Callers supply only the boot-time deadline and cannot substitute any
    /// deployment coordinate.
    ///
    /// # Errors
    ///
    /// Returns an error when the selected endpoint is not a client, connection
    /// or protected custody fails, the peer rejects the fixed profile, or the
    /// handshake deadline expires.
    pub fn connect_production_client_session(
        self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1> {
        remaining_handshake_nanoseconds(deadline_boottime_nanoseconds)?;
        let socket = SeqpacketSocket::connect(Path::new(self.production_socket_path()))
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::Transport)?;
        self.complete_production_client_handshake(socket, deadline_boottime_nanoseconds)
    }

    /// Keeps the original HELLO writer for the two fixed Output Clients.
    ///
    /// # Errors
    /// Rejects a non-Output Client endpoint, failed HELLO witnesses, transport, or protected cold admission.
    pub fn connect_output_client_session(
        self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1> {
        self.require_output_client_endpoint()?;
        remaining_handshake_nanoseconds(deadline_boottime_nanoseconds)?;
        let socket = SeqpacketSocket::connect(Path::new(self.production_socket_path()))
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::Transport)?;
        self.complete_client_handshake_inner(
            socket, deadline_boottime_nanoseconds, ClientWitnessRetentionV1::Output, None,
        )
    }

    /// Completes a controller-side production handshake before a boot-time deadline.
    ///
    /// This is the bounded activation path for a fixed client endpoint. It
    /// derives the complete hello from the registry, advances only the retained
    /// protected typestate, and polls the same adopted socket between retryable
    /// flights. The deadline uses `CLOCK_BOOTTIME`, so host suspension cannot
    /// extend activation indefinitely.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported role profile, wrong fixed endpoint
    /// role, expired deadline, changed kernel or protected custody, invalid
    /// remote flight, or transport failure.
    pub fn complete_production_client_handshake(
        self,
        socket: SeqpacketSocket,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1> {
        self.complete_client_handshake_inner(
            socket, deadline_boottime_nanoseconds, ClientWitnessRetentionV1::Legacy, None,
        )
    }

    /// Connects only the fixed original Git-coverage Mount client session.
    ///
    /// # Errors
    /// Rejects the fixed Mount role, Git-coverage HELLO, peer, journal, or original handshake cutoff.
    pub fn connect_git_coverage_mount_session_v1(
        self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1> {
        remaining_handshake_nanoseconds(deadline_boottime_nanoseconds)?;
        let socket = SeqpacketSocket::connect(Path::new(self.production_socket_path()))
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::Transport)?;
        self.complete_client_handshake_inner(
            socket, deadline_boottime_nanoseconds, ClientWitnessRetentionV1::Legacy,
            Some(aos_sandbox_core::format::git_upload_enrollment::GitCoverageBrokerRoleV1::Mount),
        )
    }

    fn complete_client_handshake_inner(
        self,
        socket: SeqpacketSocket,
        deadline_boottime_nanoseconds: u64,
        retention: ClientWitnessRetentionV1,
        coverage: Option<aos_sandbox_core::format::git_upload_enrollment::GitCoverageBrokerRoleV1>,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1> {
        remaining_handshake_nanoseconds(deadline_boottime_nanoseconds)?;
        let mut handshake = self.begin_production_client_handshake_with_coverage_v1(socket, coverage)?;

        loop {
            // Ready sockets bypass polling, but never bypass the activation deadline.
            remaining_handshake_nanoseconds(deadline_boottime_nanoseconds)?;
            let progress = if matches!(retention, ClientWitnessRetentionV1::Output) {
                match handshake.0.advance_output_client()? {
                    handshake::ColdClientHandshakeProgressV1::Pending(pending) => {
                        DormantControllerClientHandshakeProgressV1::Pending(DormantControllerClientHandshakeV1(pending))
                    }
                    handshake::ColdClientHandshakeProgressV1::Complete(session) => {
                        DormantControllerClientHandshakeProgressV1::Complete(DormantAuthenticatedBrokerSessionV1(session, Vec::new()))
                    }
                    handshake::ColdClientHandshakeProgressV1::Verified(_) => {
                        return Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole);
                    }
                }
            } else {
                handshake.advance()?
            };
            match progress {
                DormantControllerClientHandshakeProgressV1::Complete(session) => {
                    remaining_handshake_nanoseconds(deadline_boottime_nanoseconds)?;
                    return Ok(session);
                }
                DormantControllerClientHandshakeProgressV1::Pending(pending) => {
                    wait_for_handshake_readiness(
                        pending.as_fd()?,
                        pending.wants_write(),
                        deadline_boottime_nanoseconds,
                    )?;
                    handshake = pending;
                }
            }
        }
    }

    /// Completes a service-side production handshake before a boot-time deadline.
    ///
    /// This is the bounded activation path for a fixed broker endpoint. It
    /// derives the complete hello from the registry, advances only the retained
    /// protected typestate, and polls the same adopted socket between retryable
    /// flights. The deadline uses `CLOCK_BOOTTIME`, so host suspension cannot
    /// extend activation indefinitely.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported role profile, wrong fixed endpoint
    /// role, expired deadline, changed kernel or protected custody, invalid
    /// remote flight, or transport failure.
    pub fn complete_production_broker_handshake(
        self,
        socket: SeqpacketSocket,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1> {
        self.complete_production_broker_handshake_with_coverage_v1(
            socket, deadline_boottime_nanoseconds, None,
        )
    }

    pub(crate) fn complete_production_broker_handshake_with_coverage_v1(
        self,
        socket: SeqpacketSocket,
        deadline_boottime_nanoseconds: u64,
        coverage: Option<aos_sandbox_core::format::git_upload_enrollment::GitCoverageBrokerRoleV1>,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1> {
        remaining_handshake_nanoseconds(deadline_boottime_nanoseconds)?;
        let mut handshake = self.begin_production_broker_handshake_with_coverage_v1(socket, coverage)?;

        loop {
            remaining_handshake_nanoseconds(deadline_boottime_nanoseconds)?;
            match handshake.advance()? {
                DormantBrokerEndpointHandshakeProgressV1::Complete(session) => {
                    remaining_handshake_nanoseconds(deadline_boottime_nanoseconds)?;
                    return Ok(session);
                }
                DormantBrokerEndpointHandshakeProgressV1::Pending(pending) => {
                    wait_for_handshake_readiness(
                        pending.as_fd()?,
                        pending.wants_write(),
                        deadline_boottime_nanoseconds,
                    )?;
                    handshake = pending;
                }
            }
        }
    }

    /// Adopts a controller-side socket using the complete production profile.
    ///
    /// The protocol, audience, method set, features, version, and ceilings come
    /// only from the fixed endpoint and authenticated broker registry. Callers
    /// cannot supply a partial, substituted, or downgraded hello.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported role profile, wrong fixed endpoint
    /// role, stale kernel or protected custody, or handshake construction
    /// failure.
    pub fn begin_production_client_handshake(
        self,
        socket: SeqpacketSocket,
    ) -> Result<DormantControllerClientHandshakeV1, DormantBrokerSessionHandshakeErrorV1> {
        self.begin_production_client_handshake_with_coverage_v1(socket, None)
    }

    fn begin_production_client_handshake_with_coverage_v1(
        self,
        socket: SeqpacketSocket,
        coverage: Option<aos_sandbox_core::format::git_upload_enrollment::GitCoverageBrokerRoleV1>,
    ) -> Result<DormantControllerClientHandshakeV1, DormantBrokerSessionHandshakeErrorV1> {
        self.begin_production_client_handshake_with_storage_purpose_v1(
            socket, coverage, StorageHelloPurposeV1::Ordinary,
        )
    }

    fn begin_production_client_handshake_with_storage_purpose_v1(
        self,
        socket: SeqpacketSocket,
        coverage: Option<aos_sandbox_core::format::git_upload_enrollment::GitCoverageBrokerRoleV1>,
        purpose: StorageHelloPurposeV1,
    ) -> Result<DormantControllerClientHandshakeV1, DormantBrokerSessionHandshakeErrorV1> {
        let protocol = self.production_protocol();
        let audience = self.production_audience();
        let maximum_response_bytes = u32::try_from(AUTHENTICATED_RESPONSE_MAXIMUM_BYTES)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        let hello = match coverage {
            None if matches!(purpose, StorageHelloPurposeV1::Preparation) => {
                if protocol != aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage
                    || audience != Audience::AUDIENCE_NODE_CONTROLLER
                {
                    return Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole);
                }
                aos_sandbox_broker_session_protocol::profile::storage_preparation_client_hello_v1()
            }
            None if matches!(purpose, StorageHelloPurposeV1::OutputCapture) => {
                if protocol != aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage
                    || audience != Audience::AUDIENCE_NODE_CONTROLLER
                {
                    return Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole);
                }
                aos_sandbox_broker_session_protocol::profile::execution_capture_storage_client_hello_v1()
            }
            None if matches!(purpose, StorageHelloPurposeV1::NixGeneration) => {
                if protocol != aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage
                    || audience != Audience::AUDIENCE_NODE_CONTROLLER
                {
                    return Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole);
                }
                aos_sandbox_broker_session_protocol::profile::nix_generation_storage_client_hello_v1()
            }
            None => production_broker_client_hello_v1(protocol, audience, maximum_response_bytes),
            Some(role) => {
                use aos_sandbox_core::format::git_upload_enrollment::GitCoverageBrokerRoleV1;
                use aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1;
                if audience != Audience::AUDIENCE_NODE_CONTROLLER {
                    return Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole);
                }
                match (role, protocol) {
                    (GitCoverageBrokerRoleV1::Mount, BrokerSessionProtocolV1::Mount) =>
                        aos_sandbox_broker_session_protocol::profile::git_coverage_mount_client_hello_v1(),
                    (GitCoverageBrokerRoleV1::Storage, BrokerSessionProtocolV1::Storage) =>
                        aos_sandbox_broker_session_protocol::profile::git_coverage_storage_client_hello_v1(),
                    _ => return Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole),
                }
            }
        }.map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        self.begin_client_handshake(socket, hello)
    }

    /// Adopts a service-side socket using the complete production profile.
    ///
    /// The method set, features, protocol version, and ceilings come only from
    /// the authenticated broker registry. Callers cannot advertise a partial
    /// implementation while using this production constructor.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported role profile, wrong fixed endpoint
    /// role, stale kernel or protected custody, or handshake construction
    /// failure.
    pub fn begin_production_broker_handshake(
        self,
        socket: SeqpacketSocket,
    ) -> Result<DormantBrokerEndpointHandshakeV1, DormantBrokerSessionHandshakeErrorV1> {
        self.begin_production_broker_handshake_with_coverage_v1(socket, None)
    }

    fn begin_production_broker_handshake_with_coverage_v1(
        self,
        socket: SeqpacketSocket,
        coverage: Option<aos_sandbox_core::format::git_upload_enrollment::GitCoverageBrokerRoleV1>,
    ) -> Result<DormantBrokerEndpointHandshakeV1, DormantBrokerSessionHandshakeErrorV1> {
        self.begin_production_broker_handshake_with_storage_purpose_v1(
            socket, coverage, StorageHelloPurposeV1::Ordinary,
        )
    }

    fn begin_production_broker_handshake_with_storage_purpose_v1(
        self,
        socket: SeqpacketSocket,
        coverage: Option<aos_sandbox_core::format::git_upload_enrollment::GitCoverageBrokerRoleV1>,
        purpose: StorageHelloPurposeV1,
    ) -> Result<DormantBrokerEndpointHandshakeV1, DormantBrokerSessionHandshakeErrorV1> {
        let protocol = self.production_protocol();
        let audience = self.production_audience();
        let maximum_response_bytes = u32::try_from(AUTHENTICATED_RESPONSE_MAXIMUM_BYTES)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        let hello = match coverage {
            None if matches!(purpose, StorageHelloPurposeV1::OutputCapture) => {
                if protocol != aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage
                    || audience != Audience::AUDIENCE_NODE_CONTROLLER
                {
                    return Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole);
                }
                aos_sandbox_broker_session_protocol::profile::execution_capture_storage_server_hello_v1()
            }
            None if matches!(purpose, StorageHelloPurposeV1::NixGeneration) => {
                if protocol != aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage
                    || audience != Audience::AUDIENCE_NODE_CONTROLLER
                {
                    return Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole);
                }
                aos_sandbox_broker_session_protocol::profile::nix_generation_storage_server_hello_v1()
            }
            None => production_broker_server_hello_v1(protocol, audience, maximum_response_bytes),
            Some(role) => {
                use aos_sandbox_core::format::git_upload_enrollment::GitCoverageBrokerRoleV1;
                use aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1;
                if audience != Audience::AUDIENCE_NODE_CONTROLLER {
                    return Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole);
                }
                match (role, protocol) {
                    (GitCoverageBrokerRoleV1::Mount, BrokerSessionProtocolV1::Mount) =>
                        aos_sandbox_broker_session_protocol::profile::git_coverage_mount_server_hello_v1(),
                    (GitCoverageBrokerRoleV1::Storage, BrokerSessionProtocolV1::Storage) =>
                        aos_sandbox_broker_session_protocol::profile::git_coverage_storage_server_hello_v1(),
                    _ => return Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole),
                }
            }
        }.map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        self.begin_broker_handshake(socket, hello)
    }

    /// Adopts an already-connected socket into the fixed client hello flight.
    ///
    /// This performs no connect, listener, registration, routing, descriptor,
    /// or broker effect operation.
    ///
    /// # Errors
    ///
    /// Returns an error unless this is a controller-client endpoint and the
    /// retained kernel peer and protected custody are current.
    pub fn begin_client_handshake(
        self,
        socket: SeqpacketSocket,
        hello: BrokerClientHello,
    ) -> Result<DormantControllerClientHandshakeV1, DormantBrokerSessionHandshakeErrorV1> {
        self.begin_client_handshake_inner(socket, hello)
            .map(DormantControllerClientHandshakeV1)
            .map_err(Into::into)
    }

    /// Adopts an already-connected socket into the fixed broker hello flight.
    ///
    /// This performs no accept, listener, registration, routing, descriptor,
    /// or broker effect operation.
    ///
    /// # Errors
    ///
    /// Returns an error unless this is a service-broker endpoint and the
    /// retained kernel peer and protected custody are current.
    pub fn begin_broker_handshake(
        self,
        socket: SeqpacketSocket,
        hello: BrokerServerHello,
    ) -> Result<DormantBrokerEndpointHandshakeV1, DormantBrokerSessionHandshakeErrorV1> {
        self.begin_broker_handshake_inner(socket, hello)
            .map(DormantBrokerEndpointHandshakeV1)
            .map_err(Into::into)
    }
}

// The only selected Inventory builder derives its exact method and original
// cutoff from the genuine Native borrower, then uses these actual Session
// coordinates. This helper has no caller method, request ID or deadline source.
pub(crate) fn original_create_storage_inventory_coordinates_v1(
    session: &mut crate::handshake::DormantAuthenticatedBrokerSessionV1,
    original_cutoff: u64,
) -> Result<DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
    if original_cutoff == 0 || !session.is_original_storage_preparation_profile_v1() {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    session.require_negotiated_client_method(BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES)?;
    let (request_id, deadline, maximum_response_bytes, protocol_version, audience) =
        session.client_request_coordinates()?;
    // The authenticated response codec already rejects every larger packet.
    // Match its existing actual ceiling before the retaining native receive;
    // a broader generic header limit cannot create an unpaid malformed buffer.
    let authenticated_maximum = u32::try_from(
        aos_sandbox_broker_session_protocol::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES)
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    let maximum_response_bytes = maximum_response_bytes.min(authenticated_maximum);
    Ok(DormantBrokerRequestCoordinatesV1 {
        request_id,
        deadline_boottime_nanoseconds: deadline.min(original_cutoff),
        maximum_response_bytes,
        protocol_version,
        audience,
    })
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Prepares only the actual joined Create operation's signed Inventory.
    ///
    /// The actual Native borrower funds the fixed footprint and same Session
    /// history before request construction. This entry accepts no method,
    /// request identifier, envelope, caller deadline or Prepare permission.
    #[doc(hidden)]
    pub fn prepare_original_create_storage_inventory_once(
        &mut self,
        flight: &mut crate::handshake::output_registration_continuation::OriginalStorageInventoryClientFlightV1,
        original: &mut aos_sandbox::OriginalCreateStorageInventoryV1<'_, '_, '_>,
    ) -> bool {
        flight.prepare_once(&mut self.0, original)
    }

    /// Sends the exact original Inventory request through the retaining engine.
    ///
    /// Nonconsuming EAGAIN/EINTR remains Pending only after both actual upper and
    /// Native posts and actual receipt disposal. Fatal or partial IO stays held.
    #[doc(hidden)]
    pub fn send_original_create_storage_inventory_once(
        &mut self,
        flight: &mut crate::handshake::output_registration_continuation::OriginalStorageInventoryClientFlightV1,
        original: &mut aos_sandbox::OriginalCreateStorageInventoryV1<'_, '_, '_>,
    ) -> crate::handshake::output_registration_continuation::StoragePreparationClientProgressV1 {
        flight.send_once(&mut self.0, original)
    }

    /// Waits for readiness of the actual retained pending Inventory direction.
    ///
    /// The same genuine operation supplies its original cutoff and both native
    /// posts. Failed poll originals stay on the flight; successful originals
    /// dispose before the exclusive pending phase becomes reusable.
    #[doc(hidden)]
    pub fn wait_original_create_storage_inventory_once(
        &mut self,
        flight: &mut crate::handshake::output_registration_continuation::OriginalStorageInventoryClientFlightV1,
        original: &mut aos_sandbox::OriginalCreateStorageInventoryV1<'_, '_, '_>,
    ) -> bool {
        flight.wait_once(&mut self.0, original)
    }

    /// Receives and commits the exact authenticated Inventory with paid decoding.
    ///
    /// The same real Session, peer, signed request, committed outcome, validated
    /// model and predecessor owner remain resident. This grants no Prepare or B
    /// acceptance; the later original stage must recheck its current cut.
    #[doc(hidden)]
    pub fn receive_original_create_storage_inventory_once(
        &mut self,
        flight: &mut crate::handshake::output_registration_continuation::OriginalStorageInventoryClientFlightV1,
        original: &mut aos_sandbox::OriginalCreateStorageInventoryV1<'_, '_, '_>,
    ) -> crate::handshake::output_registration_continuation::StoragePreparationClientProgressV1 {
        flight.receive_once(&mut self.0, original)
    }

    /// Borrows the chronological Inventory cause beside the same joined Ready.
    ///
    /// This preserves the concrete flight selector after its short Native loan
    /// ends. A later abandonment marker cannot replace an earlier upper cause.
    #[doc(hidden)]
    #[must_use]
    pub fn original_create_storage_inventory_failure_with_ready<'a>(
        &'a self,
        flight: &'a crate::handshake::output_registration_continuation::OriginalStorageInventoryClientFlightV1,
        ready: &'a aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        flight.failure_with_native(&self.0, ready.inventory_original_failure_v1())
    }

    /// Borrows the actual chronological Inventory cause across both owners.
    ///
    /// The caller keeps this Session, flight and genuine borrower resident
    /// through its service fence; no copied status substitutes for native debt.
    #[doc(hidden)]
    #[must_use]
    pub fn original_create_storage_inventory_failure<'a>(
        &'a self,
        flight: &'a crate::handshake::output_registration_continuation::OriginalStorageInventoryClientFlightV1,
        original: &'a aos_sandbox::OriginalCreateStorageInventoryV1<'_, '_, '_>,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        flight.failure_with_original(&self.0, original)
    }
}


impl DormantAuthenticatedBrokerSessionV1 {
    /// Encodes complete B beside this actual Session and completed Inventory.
    ///
    /// This purpose-fixed composition accepts no field list, account, budget,
    /// method, deadline or verification context from the caller. Its successful
    /// bytes remain proposal DATA for the real Root exchange.
    ///
    /// # Errors
    /// Retains actual fixed-funding, native, endpoint/floor, authenticated
    /// predecessor, allocation, framing and independent post failures on the
    /// same flight and genuine original. The caller must retain them through
    /// its failure fence while the held Source/Cache writers remain borrowed.
    #[doc(hidden)]
    pub fn encode_original_create_storage_ready_bundle_once(
        &mut self,
        flight: &mut crate::handshake::output_registration_continuation::OriginalStorageReadyBundleFlightV1,
        inventory: &crate::handshake::output_registration_continuation::OriginalStorageInventoryClientFlightV1,
        original: &mut aos_sandbox::OriginalCreateStorageBundleV1<'_, '_, '_>,
    ) -> Result<(), crate::handshake::output_registration_continuation::CreateStorageReadyBundleClosedV1> {
        flight.encode_once(&mut self.0, inventory, original)
    }

    /// Borrows the chronological complete-B cause beside the same joined Ready.
    ///
    /// The exact B stage selector chooses its retained native or upper cause;
    /// this does not open another borrower or perform a new currentness check.
    #[doc(hidden)]
    #[must_use]
    pub fn original_create_storage_ready_bundle_failure_with_ready<'a>(
        &'a self,
        flight: &'a crate::handshake::output_registration_continuation::OriginalStorageReadyBundleFlightV1,
        ready: &'a aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        flight.failure_with_native(&self.0, ready.bundle_original_failure_v1())
    }

    /// Borrows the actual chronological complete-B cause without moving custody.
    #[doc(hidden)]
    #[must_use]
    pub fn original_create_storage_ready_bundle_failure<'a>(
        &'a self,
        flight: &'a crate::handshake::output_registration_continuation::OriginalStorageReadyBundleFlightV1,
        original: &'a aos_sandbox::OriginalCreateStorageBundleV1<'_, '_, '_>,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        flight.failure_with_original(&self.0, original)
    }
}


/// Drives the existing three-flight reducer from actual fully owned preparation.
///
/// Ordinary purposes retain their old polling/disposal behavior. The selected
/// initial caller supplies its actual Native loan and native-poll Result slot;
/// every failed/pending raw owner remains in the existing selected error type.
pub(crate) fn complete_retained_storage_from_prepared_v1(
    mut handshake: handshake::DormantBrokerEndpointHandshakeV1,
    deadline: handshake::OriginalBrokerColdDeadlineV1,
    slot: &mut Option<handshake::RetainedStorageColdOpenV1>,
    mut receiving: Option<&mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>>,
    mut retained_poll: Option<&mut Option<Result<usize, rustix::io::Errno>>>,
) -> Result<DormantAuthenticatedBrokerSessionV1, DormantBrokerSessionHandshakeErrorV1> {
    loop {
        if let Err(error) = deadline.check() {
            return Err(handshake.retain_storage_preparation_failure_v1(error));
        }
        if let Some(receiving) = receiving.as_deref_mut() {
            if handshake.require_initial_storage_hello_current_v1(receiving).is_err() {
                return Err(handshake.retain_storage_preparation_failure_v1(
                    BrokerSessionSecurityError::Currentness.into(),
                ));
            }
        }
        match handshake.advance_retaining_storage()? {
            handshake::ColdBrokerHandshakeProgressV1::Pending(pending) => {
                let readiness = (|| {
                    match retained_poll.as_deref_mut() {
                        Some(native) => wait_for_handshake_readiness_retaining_v1(
                            pending.as_fd()?, pending.wants_write(), deadline.value(), native,
                        ),
                        None => wait_for_handshake_readiness(
                            pending.as_fd()?, pending.wants_write(), deadline.value(),
                        ),
                    }
                })();
                if let Err(error) = readiness {
                    return Err(pending.retain_storage_preparation_failure_v1(error));
                }
                handshake = pending;
            }
            handshake::ColdBrokerHandshakeProgressV1::Verified(verified) => {
                *slot = Some(handshake::RetainedStorageColdOpenV1::retain(
                    verified, deadline,
                ));
                let cold = slot.as_mut()
                    .ok_or(DormantBrokerSessionHandshakeErrorV1::EndpointRole)?;
                let session = match receiving.as_deref_mut() {
                    Some(receiving) => cold.finish_storage_prepare_v1(receiving)?,
                    None => cold.finish(None)?,
                };
                let session = DormantAuthenticatedBrokerSessionV1(session, Vec::new());
                if receiving.is_none() {
                    *slot = None;
                }
                return Ok(session);
            }
            handshake::ColdBrokerHandshakeProgressV1::Complete(_) => std::process::abort(),
        }
    }
}

/// Owns one original Controller boot Client acquisition under its genuine B.
///
/// The actual Runtime parks and enters its Native receiver before allocating
/// this owner. It supplies no path, UID, node tuple, vector or replacement
/// deadline. Failed captures and their independent posts remain resident.
#[must_use = "retain the complete original on failure; move only a positive Session"]
pub struct DormantControllerInitialSessionOpenV1(handshake::ControllerInitialSessionOpenV1);

/// Continuously borrows the complete completed initial Session and same B.
///
/// Construction requires the actual successful native disposition, original
/// transport and same endpoint/main/Storage native pair. This is custody only;
/// it grants no currentness, new operation, transition or financial admission.
#[doc(hidden)]
pub struct DormantControllerInitialSessionCompletedBorrowV1<'held>(
    handshake::ControllerInitialSessionCompletedBorrowV1<'held>,
);

impl DormantControllerInitialSessionCompletedBorrowV1<'_> {
    /// Requires this same completed Session and all four new recovered roles.
    ///
    /// The actual capture's endpoint and main native custody are borrowed
    /// internally. No journal, descriptor, account or replacement Session is
    /// exposed, and no read-only recovery Session can satisfy the comparison.
    ///
    /// # Errors
    /// Refuses unfinished native roles, changed C/Bank/profile or another
    /// recovered receiver, endpoint, Session or native main journal.
    #[doc(hidden)]
    pub fn require_recovered_ordinary_context_v2(
        &self,
        context: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerRecoveredOrdinarySessionsOriginalV2,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        controller: &aos_sandbox::Journal,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.require_recovered_ordinary_context_v2(context, bank, controller, profile)
    }

    /// Requires actual all-four recovered custody against the Node's same private C.
    ///
    /// # Errors
    /// Refuses a changed native receiver, Session, context, Bank or profile.
    #[doc(hidden)]
    pub fn require_recovered_ordinary_context_with_node_v2<C, E>(
        &mut self, node: &aos_sandbox::NodeController<C, E>,
        context: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerRecoveredOrdinarySessionsOriginalV2,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), BrokerSessionSecurityError>
    where C: aos_sandbox::ActivatedOperationCompiler, E: aos_sandbox::SingleNodeEffectExecutor {
        let (receiving, session) = self.reborrow_v1();
        let native = session.completed_initial_native_borrow_for_maintenance_v2(receiving)?;
        node.require_recovered_ordinary_session_for_maintenance_v2(&native, context, bank, profile)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn reborrow_v1(&mut self)
        -> (&aos_sandbox::ControllerInitialBrokerSessionReceivingV1,
            &mut handshake::DormantAuthenticatedBrokerSessionV1)
    {
        self.0.reborrow_v1()
    }
}

impl DormantControllerInitialSessionOpenV1 {
    /// Describes the fixed concrete Security owners before original B admission.
    ///
    /// Returns `None` when checked representation geometry is unrepresentable.
    #[must_use]
    pub fn receiving_shape_v1(
        role: aos_sandbox::ControllerInitialBrokerSessionRoleV1,
    ) -> Option<aos_sandbox::ControllerInitialBrokerSessionShapeV1> {
        handshake::ControllerInitialSessionOpenV1::receiving_shape_v1(role)
    }

    /// Parks a genuine fixed-paid receiver without observations or allocation.
    ///
    /// The Runtime calls the receiver's fixed entry while it is already in a
    /// resident slot, then moves that same owner here. An unentered receiver
    /// cannot borrow a capture loan or enter native work through this wrapper.
    #[must_use]
    pub fn new(
        receiving: aos_sandbox::ControllerInitialBrokerSessionReceivingV1,
        launch_image: Option<crate::production_startup::Pid1LaunchImageV1>,
    ) -> Self {
        Self(handshake::ControllerInitialSessionOpenV1::new(receiving, launch_image))
    }

    /// Advances only this original's fixed endpoint, HELLO and cold admission.
    ///
    /// # Errors
    /// Retains the actual acquisition failure, first native causes and owed post.
    pub fn open_once(&mut self) -> Result<(), BrokerSessionSecurityError> {
        self.0.open_once().map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    /// Acquires the same fixed Mount/Storage Client for its actual Root account.
    ///
    /// This retains the established coverage HELLO roster and Root-bounded
    /// cold cutoff through the same original capture; caller bytes or a cutoff
    /// scalar cannot select this purpose.
    ///
    /// # Errors
    /// Retains context, acquisition and independent original post failures.
    pub fn open_git_coverage_once_v1(
        &mut self,
        account: &mut aos_sandbox::policy_compiler::GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.open_git_coverage_once_v1(account)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    /// Moves the actual Session only after all observations and the original post.
    #[must_use]
    pub fn take_completed(&mut self) -> Option<DormantAuthenticatedBrokerSessionV1> {
        self.0.take_completed().map(|session| DormantAuthenticatedBrokerSessionV1(session, Vec::new()))
    }

    /// Borrows the whole same completed Session for a closed native transition.
    ///
    /// The borrow retains every actual native survivor and permits only the
    /// Security transition kernel to reborrow its Session mutably. No mutable
    /// Journal, raw descriptor or replacement Session escapes this type.
    ///
    /// # Errors
    /// Refuses unfinished, failed, replaced or still-ambiguous native custody.
    #[doc(hidden)]
    pub fn borrow_completed_session_v1<'held>(
        &'held self,
        session: &'held mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<DormantControllerInitialSessionCompletedBorrowV1<'held>, BrokerSessionSecurityError> {
        self.borrow_completed_kernel_session_v1(&mut session.0)
    }

    pub(crate) fn original_after_completed_preparation_v1<'capture>(
        &'capture self,
        rollover: &handshake::client_storage_continuation::CompletedStorageClientRolloverV1,
        session: &mut handshake::DormantAuthenticatedBrokerSessionV1,
    ) -> Result<&'capture aos_sandbox::ControllerInitialBrokerSessionReceivingV1, BrokerSessionSecurityError> {
        self.0.original_after_completed_preparation_v1(rollover, session)
    }

    pub(crate) fn borrow_completed_preparation_kernel_session_v1<'held>(
        &'held self,
        rollover: &handshake::client_storage_continuation::CompletedStorageClientRolloverV1,
        session: &'held mut handshake::DormantAuthenticatedBrokerSessionV1,
    ) -> Result<DormantControllerInitialSessionCompletedBorrowV1<'held>, BrokerSessionSecurityError> {
        self.0.borrow_completed_preparation_session_v1(rollover, session)
            .map(DormantControllerInitialSessionCompletedBorrowV1)
    }

    // The retained transition owns the inner Session before any fallible work.
    // It borrows the same completed capture through this private adapter rather
    // than reconstructing a public Session or exposing its Journal.
    pub(crate) fn borrow_completed_kernel_session_v1<'held>(
        &'held self,
        session: &'held mut handshake::DormantAuthenticatedBrokerSessionV1,
    ) -> Result<DormantControllerInitialSessionCompletedBorrowV1<'held>, BrokerSessionSecurityError> {
        self.0.borrow_completed_session_v1(session)
            .map(DormantControllerInitialSessionCompletedBorrowV1)
    }

    /// Borrows the earliest actual retained cause without releasing its owners.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.failure()
    }
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Reserves the genuine Create U and records its native C successor.
    ///
    /// The same Session and completed B remain held. The supplied public signer
    /// inputs come from the installed Controller signer; no key, account or
    /// resource vector is accepted here. This does not sign or dispatch Prepare.
    #[doc(hidden)]
    pub fn reserve_original_create_storage_use_once(&mut self,
        flight: &mut crate::handshake::output_registration_continuation::OriginalStorageCreatePreparationFlightV1,
        ready: &mut aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>,
        bundle: &crate::handshake::output_registration_continuation::OriginalStorageReadyBundleFlightV1,
        authority: &aos_sandbox_protocol::authorization_artifact::SigningAuthority,
        scope: aos_sandbox_core::RevocationScopeId,
    ) -> bool {
        flight.reserve_use_once(&mut self.0, ready, bundle, authority, scope)
    }

    /// Borrows the actual first U acquisition cause while all originals stay held.
    #[doc(hidden)]
    #[must_use]
    pub fn original_create_storage_use_failure_with_ready<'a>(&'a self,
        flight: &'a crate::handshake::output_registration_continuation::OriginalStorageCreatePreparationFlightV1,
        ready: &'a aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        flight.use_failure_with_ready(&self.0, ready)
    }
}


impl DormantAuthenticatedBrokerSessionV1 {
    /// Prepares Root's exact admitted Create plan under its genuine U loan.
    ///
    /// The complete actual Inventory predecessor, same Session and original
    /// Root8 inputs remain resident. This returns unsigned DATA only; it reads
    /// no key and cannot dispatch or complete Create.
    #[doc(hidden)]
    pub fn prepare_original_create_storage_signing_once(&mut self,
        flight: &mut crate::handshake::output_registration_continuation::OriginalStorageCreatePreparationFlightV1,
        original: &mut aos_sandbox::OriginalCreateStorageUseSigningV1<'_, '_, '_>,
        bundle: &crate::handshake::output_registration_continuation::OriginalStorageReadyBundleFlightV1,
        inventory: &crate::handshake::output_registration_continuation::OriginalStorageInventoryClientFlightV1,
        authority: &aos_sandbox_protocol::authorization_artifact::SigningAuthority,
        scope: aos_sandbox_core::RevocationScopeId,
    ) -> Option<aos_sandbox_protocol::authorization_artifact::BrokerPlanPreparation> {
        flight.prepare_admitted_plan_once(&mut self.0, original, bundle, inventory, authority, scope)
    }

    /// Signs only the exact admitted Create preparation on its genuine U loan.
    ///
    /// The private Controller signer supplies the already-admitted mechanical
    /// carrier. The flight retains its actual constructor/key/completion cause,
    /// raw signature and signed plan through same-Session witness posts. The
    /// caller still owes the long Native loan's independent full Root post.
    #[doc(hidden)]
    pub fn sign_original_create_storage_plan_once(&mut self,
        flight: &mut crate::handshake::output_registration_continuation::OriginalStorageCreatePreparationFlightV1,
        original: &mut aos_sandbox::OriginalCreateStorageUseSigningV1<'_, '_, '_>,
        carrier: Result<aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1,
            Box<dyn std::error::Error + Send + Sync>>,
    ) -> bool {
        flight.sign_admitted_plan_once(&mut self.0, original, carrier)
    }

    /// Checks the actual signing flight after its native original post ended.
    ///
    /// This borrows the same Ready's completed native signing state. It does
    /// not append Signed, dispatch Prepare, release originals or finish Create.
    #[doc(hidden)]
    pub fn finish_original_create_storage_signing_once(&mut self,
        flight: &mut crate::handshake::output_registration_continuation::OriginalStorageCreatePreparationFlightV1,
        ready: &aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>,
    ) -> bool {
        flight.finish_native_signing_once(ready)
    }
}


impl DormantAuthenticatedBrokerSessionV1 {
    /// Appends actual C6 Signed from this retained completed signing flight.
    ///
    /// The same completed B proposal, verified signed artifact, native U and
    /// Root8 scope determine the exact record. This issues neither a Root11
    /// binding nor Prepare dispatch and cannot complete the Create Effect.
    #[doc(hidden)]
    pub fn record_original_create_storage_signed_once(&mut self,
        flight: &mut crate::handshake::output_registration_continuation::OriginalStorageCreatePreparationFlightV1,
        ready: &mut aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>,
        bundle: &crate::handshake::output_registration_continuation::OriginalStorageReadyBundleFlightV1,
    ) -> bool {
        flight.record_signed_once(ready, bundle)
    }
}

// The sole selected Prepare caller uses its exact C6 header and stable request
// identity. Session limits can refuse it; they never renew or rewrite it.
pub(crate) fn original_create_storage_prepare_coordinates_v1(
    session: &mut crate::handshake::DormantAuthenticatedBrokerSessionV1,
    request_id: [u8; 16], cutoff: u64, header: &RequestHeader,
) -> Result<DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
    if !session.is_original_storage_preparation_profile_v1() || cutoff == 0 || request_id == [0; 16] {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    session.require_negotiated_client_method(BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG)?;
    let (deadline, maximum_response_bytes, protocol_version, audience) = session.client_request_limits()?;
    if header.request_id.as_slice() != request_id || header.deadline_boottime_nanoseconds != cutoff
        || cutoff > deadline || header.maximum_response_bytes > maximum_response_bytes
        || header.maximum_response_bytes == 0
        || header.maximum_response_bytes as usize > aos_sandbox_broker_session_protocol::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES
        || header.protocol_major != u32::from(protocol_version.major())
        || header.protocol_minor != u32::from(protocol_version.minor())
        || header.audience.as_known() != Some(audience) {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    Ok(DormantBrokerRequestCoordinatesV1 { request_id,
        deadline_boottime_nanoseconds: cutoff, maximum_response_bytes: header.maximum_response_bytes,
        protocol_version, audience })
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Reserves the actual C6 Prepare request and records its native C8 readback.
    ///
    /// This fixed wrapper admits the same U, compares the retained Inventory
    /// predecessor, and delegates the existing Session signer/CAS. Every entered
    /// outcome runs the independently owed Native C8/Root after path.
    ///
    /// # Errors
    /// Returns false while retaining the original admission, replay, envelope,
    /// signed request/CAS, C8/native/cutoff or independently owed post failure.
    #[doc(hidden)]
    pub fn prepare_original_create_storage_request_once(&mut self,
        flight: &mut crate::handshake::output_registration_continuation::OriginalStorageCreatePreparationFlightV1,
        ready: &mut aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>,
        bundle: &crate::handshake::output_registration_continuation::OriginalStorageReadyBundleFlightV1,
        inventory: &crate::handshake::output_registration_continuation::OriginalStorageInventoryClientFlightV1,
    ) -> bool {
        flight.prepare_request_once(&mut self.0, ready, bundle, inventory)
    }
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Sends only the actual same-U C8-reserved Create Prepare request.
    ///
    /// The flight and Ready retain every native/error result through all posts.
    #[doc(hidden)]
    pub fn send_original_create_storage_request_once(&mut self,
        flight: &mut OriginalStorageCreatePreparationFlightV1,
        ready: &mut aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>,
    ) -> StoragePreparationClientProgressV1 {
        flight.send_request_once(&mut self.0, ready)
    }

    /// Waits only for the same actual Prepare flight's pending native turn.
    #[doc(hidden)]
    pub fn wait_original_create_storage_request_once(&mut self,
        flight: &mut OriginalStorageCreatePreparationFlightV1,
        ready: &mut aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>,
    ) -> bool {
        flight.wait_request_once(&mut self.0, ready)
    }

    /// Authenticates and commits only that same actual Prepare request's result.
    ///
    /// Committed retains the complete signed terminal and original currentness;
    /// it is not Create/Apply/U-settlement completion.
    #[doc(hidden)]
    pub fn receive_original_create_storage_request_once(&mut self,
        flight: &mut OriginalStorageCreatePreparationFlightV1,
        ready: &mut aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>,
    ) -> StoragePreparationClientProgressV1 {
        flight.receive_request_once(&mut self.0, ready)
    }
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Records C9 from the same actual committed Prepare terminal and U.
    ///
    /// Packet bytes remain borrowed from the retained flight. Every entered
    /// native refusal runs the original prepaid Root post before returning.
    ///
    /// # Errors
    /// Returns false while retaining the first Session, terminal/readback,
    /// financial, C9 crossing or independently owed post failure.
    #[doc(hidden)]
    pub fn record_original_create_storage_outcome_once(&mut self,
        flight: &mut crate::handshake::output_registration_continuation::OriginalStorageCreatePreparationFlightV1,
        ready: &mut aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>,
    ) -> bool {
        flight.record_outcome_once(&mut self.0, ready)
    }
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Transfers this flight's genuine C9 outcome and verifies Root5's reply.
    ///
    /// The actual authenticated request and outcome packets stay borrowed from
    /// the same completed preparation flight. Native requires its own actual
    /// C9 owner and returned U; this wrapper supplies no parsed authority.
    #[doc(hidden)]
    pub fn exchange_original_create_storage_outcome_once(&mut self,
        flight: &mut crate::handshake::output_registration_continuation::OriginalStorageCreatePreparationFlightV1,
        ready: &mut aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>,
    ) -> bool {
        flight.exchange_outcome_once(ready)
    }
}

// Only the genuine query original supplies the nonce/cutoff. This constructs
// DATA after its native before; it samples no new entropy or clock itself.
pub(crate) fn delete_inventory_coordinates_v1(
    session: &crate::handshake::DormantAuthenticatedBrokerSessionV1,
    original: &aos_sandbox::DeleteInventorySessionAppendOriginalV1<'_, '_, '_, '_, '_, '_>,
) -> Result<DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
    let (request_id, deadline_boottime_nanoseconds, maximum_response_bytes,
        protocol_version, audience) = crate::handshake::delete_inventory_coordinates_v1(session, original)?;
    Ok(DormantBrokerRequestCoordinatesV1 {
        request_id, deadline_boottime_nanoseconds, maximum_response_bytes,
        protocol_version, audience,
    })
}

pub(crate) fn storage_provisioning_inventory_coordinates_v1(
    session: &mut crate::handshake::DormantAuthenticatedBrokerSessionV1, cutoff: u64,
) -> Result<DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
    if !session.is_original_storage_lifecycle_profile_v2() || cutoff == 0 {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    session.require_negotiated_client_method(BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES)?;
    let (request_id, deadline, maximum_response_bytes, protocol_version, audience) = session.client_request_coordinates()?;
    Ok(DormantBrokerRequestCoordinatesV1 { request_id, deadline_boottime_nanoseconds: deadline.min(cutoff),
        maximum_response_bytes: maximum_response_bytes.min(aos_sandbox_broker_session_protocol::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES as u32),
        protocol_version, audience })
}

pub(crate) fn storage_provisioning_apply_coordinates_v1(
    session: &mut crate::handshake::DormantAuthenticatedBrokerSessionV1,
    request: &aos_sandbox::PreparedAuthorityBrokerRequestV1,
) -> Result<DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
    if !session.is_original_storage_lifecycle_profile_v2() {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    session.require_negotiated_client_method(BrokerMethod::BROKER_METHOD_STORAGE_APPLY)?;
    let (deadline, maximum, protocol_version, audience) = session.client_request_limits()?;
    if request.method() != BrokerMethod::BROKER_METHOD_STORAGE_APPLY
        || request.deadline_boottime_nanoseconds() > deadline || request.maximum_response_bytes() > maximum
        || request.protocol_version() != protocol_version || request.audience() != audience {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    Ok(DormantBrokerRequestCoordinatesV1 { request_id: request.request_id(),
        deadline_boottime_nanoseconds: request.deadline_boottime_nanoseconds(),
        maximum_response_bytes: request.maximum_response_bytes(), protocol_version, audience })
}

impl DormantAuthenticatedBrokerSessionV1 {
    pub(crate) fn run_storage_provisioning_apply_once_v1(&mut self,
        receiving: &mut crate::controller_composition::StorageProvisioningSessionIoOriginalV1,
        original: &mut aos_sandbox::CreateProvisioningStorageIoLoanV1<'_>, prepared: &aos_sandbox::PreparedAuthorityEffectV1,
    ) -> Result<(), crate::handshake::output_registration_continuation::OutputPreparationClosedV1> {
        receiving.run_once(&mut self.0, original, prepared, false)
    }

    pub(crate) fn run_storage_provisioning_inventory_once_v1(&mut self,
        receiving: &mut crate::controller_composition::StorageProvisioningSessionIoOriginalV1,
        original: &mut aos_sandbox::CreateProvisioningStorageIoLoanV1<'_>, prepared: &aos_sandbox::PreparedAuthorityEffectV1,
    ) -> Result<(), crate::handshake::output_registration_continuation::OutputPreparationClosedV1> {
        receiving.run_once(&mut self.0, original, prepared, true)
    }
}

impl DormantAuthenticatedBrokerSessionV1 {
    pub(crate) fn borrow_storage_provisioning_workspace_v1<'models>(&'models self,
        receiving: &'models crate::controller_composition::StorageProvisioningSessionIoOriginalV1,
        original: &mut aos_sandbox::CreateProvisioningStorageIoLoanV1<'_>, prepared: &aos_sandbox::PreparedAuthorityEffectV1,
    ) -> Result<aos_sandbox::StorageProvisioningWorkspaceOriginalV1<'models>, aos_sandbox::ResourceReservationErrorV1> {
        receiving.borrow_workspace_kernel_v1(&self.0, original, prepared)
    }
}

impl DormantAuthenticatedBrokerSessionV1 {
    pub(crate) fn borrow_storage_provisioning_source_workspace_v1<'models>(
        &'models self,
        receiving: &'models crate::controller_composition::StorageProvisioningSessionIoOriginalV1,
        context: &mut aos_sandbox::CreateProvisioningSourceWorkspaceContextV1<'_>,
    ) -> Result<aos_sandbox::StorageProvisioningWorkspaceOriginalV1<'models>, aos_sandbox::ResourceReservationErrorV1> {
        receiving.borrow_source_workspace_kernel_v1(&self.0, context)
    }
}

mod operator_recover;
pub use operator_recover::{OperatorRecoverStorageSessionOpenV1, OperatorReconciliationSessionOpenV2, ExecutionNoApplySessionOpenV2, OperatorStopCleanupSessionOpenV1, OperatorStopCleanupSourceSessionOpenV1};

mod operator_recover_inventory;
pub use operator_recover_inventory::{OperatorRecoverStorageInventoryOriginalV1, OperatorReconciliationInventoryOriginalV2, ControllerCatalogMaintenanceInventoryOriginalV2, OperatorStopCleanupInventoryOriginalV1, OperatorStopCleanupSourceInventoryOriginalV1};
pub(crate) use operator_recover_inventory::operator_recover_inventory_coordinates_v1;

impl DormantAuthenticatedBrokerSessionV1 {
    pub(crate) fn borrow_storage_host_client_receiving_v1<'loan, 'cut, 'original>(
        &'loan mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        lifecycle: &'loan mut aos_sandbox::StorageLifecycleSessionLoanV1<'cut, 'original>,
    ) -> Result<crate::recovery::StorageHostClientReceivingV1<'loan, 'cut, 'original>, BrokerSessionSecurityError> {
        self.0.borrow_storage_host_client_receiving_v1(request, lifecycle)
    }

    pub(crate) fn take_storage_host_opened_once_v1(
        original: &mut crate::handshake::StorageHostSessionOpenV1,
    ) -> Option<Self> {
        original.take_completed_v1().map(|session| Self(session, Vec::new()))
    }

    pub(crate) fn storage_host_unmodified_prefix_bound_v1(&self)
        -> Result<aos_sandbox::journal::ProtectedJournalPreopenReplayExtentV1, BrokerSessionSecurityError>
    { self.0.storage_host_unmodified_prefix_bound_v1() }

}

impl DormantAuthenticatedBrokerSessionV1 {
    pub(crate) fn storage_host_output_receiving_demand_v1(&self)
        -> Result<aos_sandbox_core::ResourceVector, crate::handshake::StorageHostExchangeDemandErrorV1>
    { self.0.storage_host_output_receiving_demand_v1() }
}

mod storage_capture_query;
mod storage_logical_output;

// Both variants hold the actual existing owners. The enum chooses no effect
// from caller DATA and never replaces the same Host witnesses or after checks.
enum StorageOutputDomainReceivingV1<'loan, 'cut, 'original> {
    Ordinary,
    Lifecycle {
        lifecycle: &'loan mut aos_sandbox::StorageLifecycleSessionLoanV1<'cut, 'original>,
        session: &'loan aos_sandbox::Journal,
        socket: &'loan aos_sandbox_linux::seqpacket::SeqpacketSocket,
    },
}


mod storage_capture_candidate;

enum StorageOutputDomainOperationV1<'operation> {
    Logical(&'operation mut aos_sandbox_storage::execution_output_credential::OriginalExecutionOutputRegistrationV1),
    Capture(&'operation AuthenticatedBrokerMethodRequestV1),
}

pub(crate) fn start_resource_provisioning_coordinates_v2(
    session: &mut crate::handshake::DormantAuthenticatedBrokerSessionV1,
    header: &aos_sandbox_protocol::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2,
    inventory: bool,
) -> Result<crate::DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
    session.start_resource_provisioning_coordinates_v2(header, inventory)
}

impl DormantAuthenticatedBrokerSessionV1 {
    pub(crate) fn rejoin_storage_session_once_v2(&mut self,
        destination: &mut crate::controller_composition::StartResourceProvisioningSessionIoOriginalV4,
        original: &mut aos_sandbox::OriginalStartHostRootLoanV1<'_, '_>,
        root: &aos_sandbox::normal_root::RootStartResourceCurrentTurnV2<'_>,
        previous: &aos_sandbox::CreateProvisioningOriginalsV1,
        controller: &aos_sandbox::Journal,
    ) -> Result<(), aos_sandbox::ResourceReservationErrorV1> {
        destination.rejoin_storage_inner_once_v2(&mut self.0, original, root, previous, controller)
    }

    pub(crate) fn prepare_storage_once_v2(&mut self,
        destination: &mut crate::controller_composition::StartResourceProvisioningSessionIoOriginalV4,
        original: &mut aos_sandbox::StartResourceProvisioningIoLoanV2<'_>,
        prepared: &aos_sandbox::PreparedStartResourceRequestOriginalV2,
    ) -> Result<(), crate::handshake::output_registration_continuation::OutputPreparationClosedV1> {
        destination.prepare_storage_inner_once_v2(&mut self.0, original, prepared)
    }

    pub(crate) fn inventory_storage_once_v2(&mut self,
        destination: &mut crate::controller_composition::StartResourceProvisioningSessionIoOriginalV4,
        original: &mut aos_sandbox::StartResourceProvisioningIoLoanV2<'_>,
        prepared: &aos_sandbox::PreparedStartResourceRequestOriginalV2,
    ) -> Result<(), crate::handshake::output_registration_continuation::OutputPreparationClosedV1> {
        destination.inventory_storage_inner_once_v2(&mut self.0, original, prepared)
    }
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Describes the actual held Session's negotiated Delete26 receiving representation.
    ///
    /// The signed request bound is DATA from the genuine Root receipt. This
    /// observes no native state, grants no loan and opens no Session or writer.
    #[doc(hidden)]
    #[must_use]
    pub fn delete_storage_preparation_shape_v3(&self, request_bound: usize)
        -> Option<aos_sandbox::StorageProvisioningSessionIoShapeDataV1> {
        self.0.delete_storage_preparation_shape_v3(request_bound)
    }

    pub(crate) fn retire_delete_storage_preparation_window_once_v3(&mut self,
        flight: &mut crate::controller_composition::DeleteStoragePreparationSessionIoOriginalV3,
        original: &mut aos_sandbox::OriginalDeleteStoragePreparationLoanV3<'_>,
    ) -> Result<(), crate::handshake::output_registration_continuation::OutputPreparationClosedV1> {
        flight.retire_inner_once_v3(&mut self.0, original)
    }

    pub(crate) fn run_delete_storage_preparation_once_v3(&mut self,
        flight: &mut crate::controller_composition::DeleteStoragePreparationSessionIoOriginalV3,
        original: &mut aos_sandbox::OriginalDeleteStoragePreparationLoanV3<'_>,
        inventory: &crate::controller_composition::DeleteInventoryAnswerOriginalsV1,
    ) -> Result<(), crate::handshake::output_registration_continuation::OutputPreparationClosedV1> {
        flight.run_inner_once_v3(&mut self.0, original, inventory)
    }

    /// Describes the actual negotiated Apply7 flight without entering a native interval.
    #[doc(hidden)]
    #[must_use]
    pub fn delete_storage_apply_shape_v3(&self, request_bound: usize)
        -> Option<aos_sandbox::StorageProvisioningSessionIoShapeDataV1> {
        self.0.delete_storage_apply_shape_v3(request_bound)
    }

    pub(crate) fn retire_delete_storage_apply_window_once_v3(&mut self,
        flight: &mut crate::controller_composition::DeleteStorageApplySessionIoOriginalV3,
        original: &mut aos_sandbox::OriginalDeleteStorageApplyLoanV3<'_>,
    ) -> Result<(), crate::handshake::output_registration_continuation::OutputPreparationClosedV1> {
        flight.retire_inner_once_v3(&mut self.0, original)
    }

    pub(crate) fn run_delete_storage_apply_once_v3(&mut self,
        flight: &mut crate::controller_composition::DeleteStorageApplySessionIoOriginalV3,
        original: &mut aos_sandbox::OriginalDeleteStorageApplyLoanV3<'_>,
        preparation: &crate::controller_composition::DeleteStoragePreparationSessionIoOriginalV3,
    ) -> Result<(), crate::handshake::output_registration_continuation::OutputPreparationClosedV1> {
        flight.run_inner_once_v3(&mut self.0, original, preparation)
    }
}

// The private Session owner evaluates the unchanged signed26 predicate.
pub(crate) fn delete_storage_preparation_coordinates_v3(
    session: &mut crate::handshake::DormantAuthenticatedBrokerSessionV1,
    header: &RequestHeader,
) -> Result<DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
    session.delete_storage_preparation_coordinates_v3(header)
}

mod catalog_maintenance;
#[doc(hidden)]
pub use catalog_maintenance::{ControllerCatalogMaintenanceCycleOriginalV2, ControllerCatalogMaintenanceColdCompletedV2, ControllerCatalogMaintenanceColdReceiptV2, ControllerCatalogMaintenanceRefreshCompletedV2, ControllerCatalogMaintenanceRefreshReceiptV2};

#[cfg(test)]
mod maintenance_readiness_tests {
    use super::*;
    use std::os::fd::AsFd as _;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    #[test]
    fn successive_inventory_waits_keep_the_same_socket_and_do_not_consume_packets() {
        let (mut socket, mut peer) = UnixStream::pair().unwrap();
        for byte in [7_u8, 9_u8] {
            let mut sender = peer.try_clone().unwrap();
            let thread = std::thread::spawn(move || sender.write_all(&[byte]).unwrap());
            let mut native = None;
            let mut events = None;

            wait_for_inventory_readiness_retaining_v5(socket.as_fd(), &mut native, &mut events).unwrap();
            thread.join().unwrap();
            assert!(matches!(native, Some(Ok(1))));
            assert!(events.unwrap().contains(PollFlags::IN));

            let mut received = [0_u8];
            socket.read_exact(&mut received).unwrap();
            assert_eq!(received, [byte]);
        }
        // The same original connection still carries traffic after both waits.
        peer.write_all(&[11]).unwrap();
        let mut received = [0_u8];
        socket.read_exact(&mut received).unwrap();
        assert_eq!(received, [11]);
    }

    #[test]
    fn closed_peer_keeps_actual_hangup_events_and_cannot_admit_an_inventory() {
        let (socket, peer) = UnixStream::pair().unwrap();
        drop(peer);
        let mut native = None;
        let mut events = None;

        assert!(wait_for_inventory_readiness_retaining_v5(
            socket.as_fd(), &mut native, &mut events).is_err());
        assert!(matches!(native, Some(Ok(1))));
        assert!(events.unwrap().contains(PollFlags::HUP));
    }
}

pub(crate) fn delete_storage_apply_coordinates_v3(
    session: &mut crate::handshake::DormantAuthenticatedBrokerSessionV1,
    header: &RequestHeader,
) -> Result<DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
    session.delete_storage_apply_coordinates_v3(header)
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Describes the negotiated Network9 flight without entering a native interval.
    #[doc(hidden)]
    #[must_use]
    pub fn delete_network_apply_shape_v4(&self, request_bound: usize)
        -> Option<aos_sandbox::StorageProvisioningSessionIoShapeDataV1> {
        self.0.delete_network_apply_shape_v4(request_bound)
    }

    pub(crate) fn retire_delete_network_apply_window_once_v4(&mut self,
        flight: &mut crate::controller_composition::DeleteNetworkApplySessionIoOriginalV4,
        original: &mut aos_sandbox::OriginalDeleteNetworkApplyLoanV4<'_>,
    ) -> Result<(), crate::handshake::output_registration_continuation::OutputPreparationClosedV1> {
        flight.retire_inner_once_v4(&mut self.0, original)
    }

    pub(crate) fn run_delete_network_apply_once_v4(&mut self,
        flight: &mut crate::controller_composition::DeleteNetworkApplySessionIoOriginalV4,
        original: &mut aos_sandbox::OriginalDeleteNetworkApplyLoanV4<'_>,
        inventory: &crate::controller_composition::DeleteInventoryAnswerOriginalsV1,
    ) -> Result<(), crate::handshake::output_registration_continuation::OutputPreparationClosedV1> {
        flight.run_inner_once_v4(&mut self.0, original, inventory)
    }
}

pub(crate) fn delete_network_apply_coordinates_v4(
    session: &mut crate::handshake::DormantAuthenticatedBrokerSessionV1,
    header: &RequestHeader,
) -> Result<DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
    session.delete_network_apply_coordinates_v4(header)
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Describes the negotiated Mount62 flight without entering a native interval.
    #[doc(hidden)]
    #[must_use]
    pub fn delete_mount_reap_shape_v4(&self, request_bound: usize)
        -> Option<aos_sandbox::StorageProvisioningSessionIoShapeDataV1> {
        self.0.delete_mount_reap_shape_v4(request_bound)
    }

    pub(crate) fn retire_delete_mount_reap_window_once_v4(&mut self,
        flight: &mut crate::controller_composition::DeleteMountReapSessionIoOriginalV4,
        original: &mut aos_sandbox::OriginalDeleteMountReapLoanV4<'_>,
    ) -> Result<(), crate::handshake::output_registration_continuation::OutputPreparationClosedV1> {
        flight.retire_inner_once_v4(&mut self.0, original)
    }

    pub(crate) fn run_delete_mount_reap_once_v4(&mut self,
        flight: &mut crate::controller_composition::DeleteMountReapSessionIoOriginalV4,
        original: &mut aos_sandbox::OriginalDeleteMountReapLoanV4<'_>,
        inventory: &crate::controller_composition::DeleteInventoryAnswerOriginalsV1,
    ) -> Result<(), crate::handshake::output_registration_continuation::OutputPreparationClosedV1> {
        flight.run_inner_once_v4(&mut self.0, original, inventory)
    }
}

pub(crate) fn delete_mount_reap_coordinates_v4(
    session: &mut crate::handshake::DormantAuthenticatedBrokerSessionV1,
    header: &RequestHeader,
) -> Result<DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
    session.delete_mount_reap_coordinates_v4(header)
}
