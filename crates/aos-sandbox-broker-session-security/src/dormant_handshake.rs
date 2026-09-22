//! Public dormant facade for the sealed protected hello-flight typestate.
//!
//! This module exposes only fixed-custody adoption of an already-connected
//! ordinary sequenced-packet socket. The actual handshake states remain sealed
//! in [`crate::handshake`], and this facade registers no listener, route,
//! service registration, background task, or broker effect.

use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::Path;

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerDescriptorDisposition, BrokerDescriptorDispositionEntry, BrokerDescriptorEntry,
    BrokerDescriptorRole, BrokerError, BrokerErrorCode, BrokerMethod, BrokerRequestEnvelope,
    BrokerResponseEnvelope, HostCatalogPublicationStatus, PublishHostCatalogResponse,
};
use aos_sandbox::PreparedAuthorityEffectV1;
use aos_sandbox_broker_session_protocol::{
    AUTHENTICATED_RESPONSE_MAXIMUM_BYTES, ProtectedBrokerSessionVerificationContextV1,
    decode_canonical_response_v1,
    hello_message::{BrokerClientHello, BrokerServerHello},
    production_broker_client_hello_v1, production_broker_server_hello_v1,
};
use aos_sandbox_core::ProtocolVersion;
use aos_sandbox_linux::immutable_file::SealedMemfdMapping;
use aos_sandbox_linux::seqpacket::SeqpacketSocket;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use aos_sandbox_protocol::host_catalog::MAXIMUM_HOST_CATALOG_BYTES;
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
        }
    }
}

fn remaining_handshake_nanoseconds(
    deadline_boottime_nanoseconds: u64,
) -> Result<u64, DormantBrokerSessionHandshakeErrorV1> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
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
pub(crate) fn check_production_deadline(
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

pub(crate) fn wait_for_handshake_readiness(
    descriptor: BorrowedFd<'_>,
    wants_write: bool,
    deadline_boottime_nanoseconds: u64,
) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
    let remaining = remaining_handshake_nanoseconds(deadline_boottime_nanoseconds)?;
    let timeout = Timespec {
        tv_sec: i64::try_from(remaining / 1_000_000_000)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::Deadline)?,
        tv_nsec: i64::try_from(remaining % 1_000_000_000)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::Deadline)?,
    };
    let readiness = if wants_write {
        PollFlags::OUT
    } else {
        PollFlags::IN
    };
    let mut descriptors = [PollFd::from_borrowed_fd(descriptor, readiness)];

    match poll(&mut descriptors, Some(&timeout)) {
        Ok(0) => Err(DormantBrokerSessionHandshakeErrorV1::Deadline),
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(_) => Err(DormantBrokerSessionHandshakeErrorV1::Transport),
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
}

/// Retains one protected, durably reserved request before atomic transport.
#[must_use = "send or retain the exact protected request"]
pub struct DormantPreparedBrokerRequestV1(AuthenticatedBrokerMethodRequestV1);

impl DormantPreparedBrokerRequestV1 {
    /// Returns the signed deadline without releasing request custody.
    pub(crate) const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.0.deadline_boottime_nanoseconds()
    }
}

/// Retains one sent request while its exact terminal response is outstanding.
#[must_use = "receive or retain the exact outstanding request"]
pub struct DormantOutstandingBrokerRequestV1(AuthenticatedBrokerMethodRequestV1);

impl DormantOutstandingBrokerRequestV1 {
    /// Returns the original signed deadline for response readiness polling.
    pub(crate) const fn deadline_boottime_nanoseconds(&self) -> u64 {
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
    pub(crate) const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.request.deadline_boottime_nanoseconds()
    }
}

/// Retains one authenticated request received and committed by the broker owner.
#[must_use = "produce its exact response or retain the committed request"]
pub struct DormantReceivedBrokerRequestV1(AuthenticatedBrokerMethodRequestV1);

/// Retains an exact protected terminal response selected by request replay.
#[must_use = "resend or retain the exact protected terminal response"]
pub struct DormantBrokerTerminalReplayV1(ProtectedBrokerOutcomeReplayV1);

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

/// Retains a revalidated terminal replay with its exact reopened descriptor order.
#[must_use = "send or retain the exact protected replay and every reopened descriptor"]
pub struct DormantReadyBrokerDescriptorTerminalReplayV1 {
    replay: DormantBrokerTerminalReplayV1,
    descriptors: Vec<OwnedFd>,
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

/// Retains a descriptor-producing observation after its domain dispatch began.
#[must_use = "retry protected response commit or retain every descriptor"]
pub enum DormantBrokerDescriptorOutcomeUnknownV1 {
    /// No exact descriptor response was produced; only opaque request custody remains.
    Unobserved(DormantBrokerOutcomeUnknownV1),
    /// Exact response bytes and descriptor order were observed but are not committed.
    Observed {
        request: DormantReceivedBrokerRequestV1,
        body: Vec<u8>,
        descriptors: Vec<OwnedFd>,
        replay_ticket: Option<aos_sandbox_host::DormantHostScopeReplayTicketV1>,
    },
}

/// Retains plain request and descriptor custody across a scope execution failure.
#[must_use = "retain or explicitly resolve the returned descriptor custody"]
pub enum DormantBrokerDescriptorExecutionFailureV1<Domain> {
    /// No domain adapter was invoked; the request remains eligible for an error.
    BeforeEffect {
        error: BrokerSessionSecurityError,
        request: DormantReceivedBrokerRequestV1,
    },
    /// Domain dispatch began and descriptors, if produced, remain exact and opaque.
    OutcomeUnknown {
        error: DormantBrokerExecutionErrorV1<Domain>,
        custody: DormantBrokerDescriptorOutcomeUnknownV1,
    },
}

/// Retains the catalog descriptor request across publication execution failure.
#[must_use = "retain or explicitly resolve the exact publication custody"]
pub enum DormantBrokerPublicationExecutionFailureV1<Domain> {
    /// No publisher was invoked; the exact request and descriptor remain owned.
    BeforeEffect {
        error: BrokerSessionSecurityError,
        request: DormantReceivedBrokerDescriptorRequestV1,
    },
    /// Publication dispatch began; only protected readback may resolve the request.
    OutcomeUnknown {
        error: DormantBrokerExecutionErrorV1<Domain>,
        recovery: DormantHostCatalogPublicationUnknownV1,
    },
}

/// Retains exact Host catalog effect custody until physical readback resolves it.
#[must_use = "resolve the exact physical publication or retain its custody"]
pub struct DormantHostCatalogPublicationUnknownV1 {
    request: DormantReceivedBrokerRequestV1,
    descriptor: OwnedFd,
    snapshot: aos_sandbox_protocol::HostCatalogSnapshot,
    intended_bytes: u64,
    intended_generation: u64,
    intended_digest: aos_sandbox_core::ObjectDigest,
    known_status: Option<HostCatalogPublicationStatus>,
}

/// Authorizes one retry only after protected readback proved the effect absent.
#[must_use = "retry the exact proven-absent publication or retain its custody"]
pub struct DormantHostCatalogPublicationRetryV1(DormantHostCatalogPublicationUnknownV1);

/// Reports physical resolution of one ambiguous Host catalog publication.
#[must_use = "commit the response, retry the exact absent effect, or retain recovery custody"]
pub enum DormantHostCatalogPublicationRecoveryProgressV1 {
    /// Physical readback proved the intended catalog committed; response commit advanced.
    ResponseCommit(ProtectedBrokerOutcomeCommitResultV1),
    /// Physical readback proved the intended effect absent and retry-safe.
    RetrySafe(DormantHostCatalogPublicationRetryV1),
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

fn validated_publication_snapshot(
    descriptor: &OwnedFd,
    expected_bytes: u64,
    expected_generation: u64,
    expected_digest: aos_sandbox_core::ObjectDigest,
) -> Result<aos_sandbox_protocol::HostCatalogSnapshot, aos_sandbox_host::DormantHostBrokerCallErrorV1>
{
    let duplicate = rustix::io::dup(descriptor)
        .map_err(|error| aos_sandbox_host::HostError::Catalog(error.to_string()))?;
    SealedMemfdMapping::run(
        duplicate,
        expected_bytes,
        u64::try_from(MAXIMUM_HOST_CATALOG_BYTES)
            .map_err(|_| aos_sandbox_host::DormantHostBrokerCallErrorV1::StaleKernel)?,
        |catalog, _identity| {
            let digest = aos_sandbox_core::ObjectDigest::from_bytes(Sha256::digest(catalog).into());
            if digest != expected_digest {
                return Err(aos_sandbox_host::HostError::Catalog(
                    "sealed host catalog digest does not match request".to_owned(),
                ));
            }
            let snapshot = aos_sandbox_protocol::HostCatalogSnapshot::decode_canonical(catalog)?;
            if snapshot.generation() != expected_generation {
                return Err(aos_sandbox_host::HostError::Catalog(
                    "sealed host catalog generation does not match request".to_owned(),
                ));
            }
            Ok(snapshot)
        },
    )
    .map_err(|error| aos_sandbox_host::HostError::Catalog(error.to_string()))?
    .map_err(Into::into)
}

fn publication_response_body(
    generation: u64,
    digest: aos_sandbox_core::ObjectDigest,
    status: HostCatalogPublicationStatus,
) -> Vec<u8> {
    PublishHostCatalogResponse {
        status: status.into(),
        generation,
        catalog_sha256: digest.as_bytes().to_vec(),
        ..Default::default()
    }
    .encode_to_vec()
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
    pub(crate) fn from_observation(
        request: &AuthenticatedBrokerMethodRequestV1,
        body: Vec<u8>,
    ) -> Result<Self, BrokerSessionSecurityError> {
        if body.is_empty() {
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

impl DormantReceivedBrokerRequestV1 {
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

/// Reports descriptor-response backpressure or protected terminal custody.
#[must_use = "retain the outstanding request or exact response descriptors"]
pub enum DormantBrokerDescriptorResponseProgressV1 {
    /// No response was available; retain the outstanding request.
    Pending(DormantOutstandingBrokerRequestV1),
    /// The signed response and exact descriptors entered protected custody.
    Committed(DormantBrokerDescriptorCommitResultV1),
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

/// Reports protected Host descriptor reopen progress for a terminal replay.
#[must_use = "send reopened descriptors or retain replay recovery custody"]
pub enum DormantBrokerDescriptorTerminalReplayRecoveryProgressV1 {
    /// The exact signed response body and descriptor count were reopened and revalidated.
    Ready(DormantReadyBrokerDescriptorTerminalReplayV1),
    /// Domain or protected currentness failed without losing replay authority.
    RecoveryRequired {
        /// Host reopen or protected-currentness failure.
        error: DormantBrokerExecutionErrorV1<aos_sandbox_host::DormantHostBrokerCallErrorV1>,
        /// Exact descriptor-bearing replay retained for another reopen attempt.
        replay: DormantBrokerDescriptorTerminalReplayV1,
    },
}

/// Reports transport progress for an exact descriptor-bearing terminal replay.
#[must_use = "retry pending transport without dropping replay or descriptor custody"]
pub enum DormantBrokerDescriptorTerminalReplaySendProgressV1 {
    /// The exact signed packet and descriptors were resent atomically.
    Sent(DormantBrokerTerminalReplayV1),
    /// No packet or descriptor was sent.
    Pending(DormantReadyBrokerDescriptorTerminalReplayV1),
    /// Transport or protected currentness became ambiguous with all custody retained.
    RecoveryRequired {
        /// Currentness or ancillary transport failure.
        error: DormantBrokerSessionHandshakeErrorV1,
        /// Exact replay and reopened descriptors retained for recovery.
        replay: DormantReadyBrokerDescriptorTerminalReplayV1,
    },
}

/// Retains a descriptor response across protected commit ambiguity.
#[must_use = "recover or send while retaining every exact descriptor"]
pub enum DormantBrokerDescriptorCommitResultV1 {
    /// The signed response is durably committed and its descriptors are sendable.
    Committed(DormantCommittedBrokerDescriptorResponseV1),
    /// The response commit is ambiguous and descriptors remain in custody.
    RecoveryRequired(DormantBrokerDescriptorCommitRecoveryV1),
    /// Terminal CAS committed, while receipt signing or Host finalization remains ambiguous.
    HostFinalizationRequired(DormantHostScopeTerminalFinalizationV1),
}

/// Retains post-CAS terminal and descriptor custody until Host receipt finalization.
#[must_use = "finalize the Host receipt before sending the descriptor response"]
pub struct DormantHostScopeTerminalFinalizationV1 {
    error: DormantBrokerExecutionErrorV1<aos_sandbox_host::DormantHostBrokerCallErrorV1>,
    committed: ProtectedBrokerOutcomeCommittedAdvancementV1,
    descriptors: Vec<OwnedFd>,
    replay_ticket: Option<aos_sandbox_host::DormantHostScopeReplayTicketV1>,
}

impl DormantHostScopeTerminalFinalizationV1 {
    /// Returns the failure observed while finalizing the protected Host receipt.
    #[must_use]
    pub const fn error(
        &self,
    ) -> &DormantBrokerExecutionErrorV1<aos_sandbox_host::DormantHostBrokerCallErrorV1> {
        &self.error
    }
}

/// Seals one committed signed descriptor response to its exact FD custody.
#[must_use = "send or retain the inseparable signed response and descriptors"]
pub struct DormantCommittedBrokerDescriptorResponseV1 {
    committed: ProtectedBrokerOutcomeCommittedAdvancementV1,
    descriptors: Vec<OwnedFd>,
    host_observed: bool,
}

/// Retains an ambiguous descriptor commit without exposing replaceable FDs.
#[must_use = "recover the inseparable protected commit and descriptor custody"]
pub struct DormantBrokerDescriptorCommitRecoveryV1 {
    error: BrokerSessionSecurityError,
    recovery: ProtectedBrokerOutcomeCommitRecoveryV1,
    descriptors: Vec<OwnedFd>,
    host_observed: bool,
    scope_replay_ticket: Option<aos_sandbox_host::DormantHostScopeReplayTicketV1>,
}

/// Retains a committed descriptor response across send ambiguity.
#[must_use = "retry with the same signed response and descriptors"]
pub struct DormantBrokerDescriptorSendRecoveryV1 {
    error: DormantBrokerSessionHandshakeErrorV1,
    response: DormantCommittedBrokerDescriptorResponseV1,
}

impl DormantCommittedBrokerDescriptorResponseV1 {
    fn seal(
        committed: ProtectedBrokerOutcomeCommittedAdvancementV1,
        descriptors: Vec<OwnedFd>,
        host_observed: bool,
    ) -> Self {
        Self {
            committed,
            descriptors,
            host_observed,
        }
    }
}

impl DormantBrokerDescriptorCommitRecoveryV1 {
    /// Returns the protected commit failure without exposing separable custody.
    #[must_use]
    pub const fn error(&self) -> &BrokerSessionSecurityError {
        &self.error
    }
}

impl DormantBrokerDescriptorSendRecoveryV1 {
    /// Returns the send/currentness failure without exposing separable custody.
    #[must_use]
    pub const fn error(&self) -> &DormantBrokerSessionHandshakeErrorV1 {
        &self.error
    }

    /// Consumes failed transport custody into its redacted error.
    ///
    /// This deliberately drops the inseparable committed response and
    /// descriptors. It is suitable only when the owning authenticated session
    /// is also consumed so recovery must proceed by reconnect and exact replay.
    #[must_use]
    pub fn into_error(self) -> DormantBrokerSessionHandshakeErrorV1 {
        self.error
    }
}

/// Retains committed descriptor transport across retryable backpressure.
#[must_use = "retry or retain the exact signed packet and descriptors"]
pub enum DormantBrokerDescriptorSendProgressV1 {
    /// No bytes or descriptors were sent.
    Pending(DormantCommittedBrokerDescriptorResponseV1),
    /// The exact packet and descriptor table were atomically sent.
    Sent(ProtectedBrokerOutcomeCommittedAdvancementV1),
    /// Currentness or transport failed with terminal and descriptor custody retained.
    RecoveryRequired(DormantBrokerDescriptorSendRecoveryV1),
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

impl DormantAuthenticatedBrokerSessionV1 {
    /// Checks the fixed protected session against the controller's bound node.
    ///
    /// No identity is inferred from a socket path or an inventory response.
    pub(crate) fn require_current_node(
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
        if !method_matches {
            return Err(DormantBrokerExecutionFailureV1::BeforeEffect {
                error: BrokerSessionSecurityError::Currentness,
                request,
            });
        }
        let context = match self.0.reopen_broker_outcome(&request.0) {
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
        if let Err(error) = self.0.reopen_broker_outcome(&request.0) {
            return Err(DormantBrokerExecutionFailureV1::OutcomeUnknown {
                error: DormantBrokerExecutionErrorV1::Currentness(error),
                custody: DormantBrokerOutcomeUnknownV1 {
                    request,
                    observation: Some(observation),
                },
            });
        }
        match self.commit_authenticated_observation(
            DormantReceivedBrokerRequestV1(request.0.clone()),
            observation.clone(),
        ) {
            Ok(result) => Ok(result),
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
        let method_matches = request.0.method() == BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
            && adapter.matches_request(&request.0);
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

    /// Produces a Host payload or mount scope before signing descriptor roles.
    ///
    /// # Errors
    ///
    /// Returns a domain or protected-currentness error without exposing the
    /// descriptors when the Host scope or either currentness sandwich fails.
    pub async fn execute_host_scope_and_commit(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        mut adapter: crate::DormantHostBrokerEffectAdapterV1<'_>,
    ) -> Result<
        DormantBrokerDescriptorCommitResultV1,
        DormantBrokerDescriptorExecutionFailureV1<aos_sandbox_host::DormantHostBrokerCallErrorV1>,
    > {
        let method_matches = matches!(
            request.0.method(),
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE
                | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
        ) && adapter.matches_request(&request.0);
        if !method_matches {
            return Err(DormantBrokerDescriptorExecutionFailureV1::BeforeEffect {
                error: BrokerSessionSecurityError::Currentness,
                request,
            });
        }
        let context = match self.0.reopen_broker_outcome(&request.0) {
            Ok((gate, context)) => {
                drop(gate);
                context
            }
            Err(error) => {
                return Err(DormantBrokerDescriptorExecutionFailureV1::BeforeEffect {
                    error,
                    request,
                });
            }
        };
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());
        let terminal_verifier = match self.0.broker_outcome_verifier() {
            Ok(verifier) => verifier,
            Err(error) => {
                return Err(DormantBrokerDescriptorExecutionFailureV1::BeforeEffect {
                    error,
                    request,
                });
            }
        };
        if !matches!(
            adapter.fixed_terminal_verifier_commitment(),
            Ok(commitment) if commitment == terminal_verifier.commitment()
        ) {
            return Err(DormantBrokerDescriptorExecutionFailureV1::BeforeEffect {
                error: BrokerSessionSecurityError::Currentness,
                request,
            });
        }
        let observation = match adapter
            .execute_scope_before_outcome(&request.0, version, context.boot_id())
            .await
        {
            Ok(observation) => observation,
            Err(error) => {
                return Err(DormantBrokerDescriptorExecutionFailureV1::OutcomeUnknown {
                    error: DormantBrokerExecutionErrorV1::Domain(error),
                    custody: DormantBrokerDescriptorOutcomeUnknownV1::Unobserved(
                        DormantBrokerOutcomeUnknownV1 {
                            request,
                            observation: None,
                        },
                    ),
                });
            }
        };
        let (body, descriptors, replay_ticket) =
            observation.into_response_descriptors_and_replay_ticket();
        let custody = DormantBrokerDescriptorOutcomeUnknownV1::Observed {
            request,
            body,
            descriptors,
            replay_ticket,
        };
        self.retry_observed_host_scope_and_commit(custody, adapter)
            .map_err(
                |custody| DormantBrokerDescriptorExecutionFailureV1::OutcomeUnknown {
                    error: DormantBrokerExecutionErrorV1::Currentness(
                        BrokerSessionSecurityError::Currentness,
                    ),
                    custody,
                },
            )
    }

    /// Retries protected commit for one exact observed Host scope response.
    ///
    /// This path never re-executes the Host effect. It retains the exact body,
    /// descriptor order, and replay ticket together until the terminal CAS and
    /// Host receipt finalization take ownership of them.
    ///
    /// # Errors
    ///
    /// Returns the unchanged custody when it is unobserved, lacks its replay
    /// ticket, has an inexact descriptor table, or protected currentness and
    /// response preparation cannot be re-established.
    pub fn retry_observed_host_scope_and_commit(
        &mut self,
        custody: DormantBrokerDescriptorOutcomeUnknownV1,
        mut adapter: crate::DormantHostBrokerEffectAdapterV1<'_>,
    ) -> Result<DormantBrokerDescriptorCommitResultV1, DormantBrokerDescriptorOutcomeUnknownV1>
    {
        let DormantBrokerDescriptorOutcomeUnknownV1::Observed {
            request,
            body,
            descriptors,
            replay_ticket,
        } = custody
        else {
            return Err(custody);
        };
        let Some(replay_ticket) = replay_ticket else {
            return Err(DormantBrokerDescriptorOutcomeUnknownV1::Observed {
                request,
                body,
                descriptors,
                replay_ticket: None,
            });
        };
        let roles = match request.0.method() {
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE => {
                aos_sandbox_protocol::payload_scope::PAYLOAD_SCOPE_DESCRIPTOR_ROLES.as_slice()
            }
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE => {
                aos_sandbox_protocol::mount_scope::MOUNT_SCOPE_DESCRIPTOR_ROLES.as_slice()
            }
            _ => {
                return Err(DormantBrokerDescriptorOutcomeUnknownV1::Observed {
                    request,
                    body,
                    descriptors,
                    replay_ticket: Some(replay_ticket),
                });
            }
        };
        if roles.len() != descriptors.len()
            || self.0.reopen_broker_outcome(&request.0).is_err()
            || !matches!(
                (adapter.fixed_terminal_verifier_commitment(), self.0.broker_outcome_verifier()),
                (Ok(adapter_commitment), Ok(verifier))
                    if adapter_commitment == verifier.commitment()
            )
        {
            return Err(DormantBrokerDescriptorOutcomeUnknownV1::Observed {
                request,
                body,
                descriptors,
                replay_ticket: Some(replay_ticket),
            });
        }

        let response_descriptors = roles
            .iter()
            .enumerate()
            .map(|(index, role)| {
                u32::try_from(index).map(|index| BrokerDescriptorEntry {
                    index,
                    role: (*role).into(),
                    ..Default::default()
                })
            })
            .collect::<Result<Vec<_>, _>>();
        let Ok(response_descriptors) = response_descriptors else {
            return Err(DormantBrokerDescriptorOutcomeUnknownV1::Observed {
                request,
                body,
                descriptors,
                replay_ticket: Some(replay_ticket),
            });
        };
        let message = BrokerResponseEnvelope {
            request_id: request.0.request_id().to_vec(),
            method: request.0.method().into(),
            body: body.clone(),
            descriptors: response_descriptors,
            ..Default::default()
        };
        let pending = match self.0.prepare_broker_outcome(&request.0, message) {
            Ok(pending) => pending,
            Err(_) => {
                return Err(DormantBrokerDescriptorOutcomeUnknownV1::Observed {
                    request,
                    body,
                    descriptors,
                    replay_ticket: Some(replay_ticket),
                });
            }
        };

        Ok(match self.0.commit_broker_outcome(pending) {
            ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => self
                .finalize_host_scope_terminal(committed, descriptors, replay_ticket, &mut adapter),
            ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, recovery } => {
                DormantBrokerDescriptorCommitResultV1::RecoveryRequired(
                    DormantBrokerDescriptorCommitRecoveryV1 {
                        error,
                        recovery,
                        descriptors,
                        host_observed: true,
                        scope_replay_ticket: Some(replay_ticket),
                    },
                )
            }
        })
    }

    fn finalize_host_scope_terminal(
        &mut self,
        committed: ProtectedBrokerOutcomeCommittedAdvancementV1,
        descriptors: Vec<OwnedFd>,
        mut replay_ticket: aos_sandbox_host::DormantHostScopeReplayTicketV1,
        adapter: &mut crate::DormantHostBrokerEffectAdapterV1<'_>,
    ) -> DormantBrokerDescriptorCommitResultV1 {
        let receipt = self
            .0
            .sign_terminal_commit_receipt_for_committed(&replay_ticket, &committed);
        let Ok(receipt) = receipt else {
            return DormantBrokerDescriptorCommitResultV1::HostFinalizationRequired(
                DormantHostScopeTerminalFinalizationV1 {
                    error: DormantBrokerExecutionErrorV1::Currentness(
                        BrokerSessionSecurityError::Currentness,
                    ),
                    committed,
                    descriptors,
                    replay_ticket: Some(replay_ticket),
                },
            );
        };
        if let Err(error) = adapter.bind_scope_terminal(Some(&mut replay_ticket), &receipt) {
            return DormantBrokerDescriptorCommitResultV1::HostFinalizationRequired(
                DormantHostScopeTerminalFinalizationV1 {
                    error: DormantBrokerExecutionErrorV1::Domain(error),
                    committed,
                    descriptors,
                    replay_ticket: Some(replay_ticket),
                },
            );
        }
        self.1.push(replay_ticket);
        DormantBrokerDescriptorCommitResultV1::Committed(
            DormantCommittedBrokerDescriptorResponseV1::seal(committed, descriptors, true),
        )
    }

    /// Retries post-CAS Host receipt signing and durable finalization.
    #[must_use]
    pub fn recover_host_scope_terminal_finalization(
        &mut self,
        retained: DormantHostScopeTerminalFinalizationV1,
        mut adapter: crate::DormantHostBrokerEffectAdapterV1<'_>,
    ) -> DormantBrokerDescriptorCommitResultV1 {
        let DormantHostScopeTerminalFinalizationV1 {
            committed,
            descriptors,
            replay_ticket,
            ..
        } = retained;
        let committed = match self.0.revalidate_broker_committed(committed) {
            Ok(committed) => committed,
            Err((error, committed)) => {
                return DormantBrokerDescriptorCommitResultV1::HostFinalizationRequired(
                    DormantHostScopeTerminalFinalizationV1 {
                        error: DormantBrokerExecutionErrorV1::Currentness(error),
                        committed,
                        descriptors,
                        replay_ticket,
                    },
                );
            }
        };
        let Some(replay_ticket) = replay_ticket else {
            return DormantBrokerDescriptorCommitResultV1::HostFinalizationRequired(
                DormantHostScopeTerminalFinalizationV1 {
                    error: DormantBrokerExecutionErrorV1::Currentness(
                        BrokerSessionSecurityError::Currentness,
                    ),
                    committed,
                    descriptors,
                    replay_ticket: None,
                },
            );
        };
        self.finalize_host_scope_terminal(committed, descriptors, replay_ticket, &mut adapter)
    }

    /// Publishes one sealed Host catalog before signing its exact result.
    ///
    /// # Errors
    ///
    /// Returns a domain or protected-currentness error without signing success
    /// unless the exact request descriptor is consumed by the fixed publisher.
    pub fn execute_host_catalog_publication_and_commit(
        &mut self,
        request: DormantReceivedBrokerDescriptorRequestV1,
        publisher: &aos_sandbox_host::catalog::FileHostCatalogPublisher,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerPublicationExecutionFailureV1<aos_sandbox_host::DormantHostBrokerCallErrorV1>,
    > {
        if request.request.method() != BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG
            || request.request.authorization().is_some()
            || request.descriptors.len() != 1
        {
            return Err(DormantBrokerPublicationExecutionFailureV1::BeforeEffect {
                error: BrokerSessionSecurityError::Currentness,
                request,
            });
        }
        let context = match self.0.reopen_broker_outcome(&request.request) {
            Ok((gate, context)) => {
                drop(gate);
                context
            }
            Err(error) => {
                return Err(DormantBrokerPublicationExecutionFailureV1::BeforeEffect {
                    error,
                    request,
                });
            }
        };
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());
        let now = match current_publication_boottime(&request.request, &context) {
            Ok(now) => now,
            Err(error) => {
                return Err(DormantBrokerPublicationExecutionFailureV1::BeforeEffect {
                    error,
                    request,
                });
            }
        };
        let publication =
            match aos_sandbox_protocol::host_catalog::decode_host_catalog_publication_request(
                request.request.exact_body(),
                request.request.peer(),
                request.request.peer_policy(),
                now,
            ) {
                Ok(publication)
                    if publication.header().request_id() == &request.request.request_id()
                        && publication.header().protocol_version() == version =>
                {
                    publication
                }
                _ => {
                    return Err(DormantBrokerPublicationExecutionFailureV1::BeforeEffect {
                        error: BrokerSessionSecurityError::Currentness,
                        request,
                    });
                }
            };
        let descriptor = &request.descriptors[0];
        let snapshot = match validated_publication_snapshot(
            descriptor,
            publication.catalog_bytes(),
            publication.catalog_generation(),
            publication.catalog_digest(),
        ) {
            Ok(snapshot) => snapshot,
            Err(_) => {
                return Err(DormantBrokerPublicationExecutionFailureV1::BeforeEffect {
                    error: BrokerSessionSecurityError::Currentness,
                    request,
                });
            }
        };
        let outcome = publisher.publish(&snapshot);
        let DormantReceivedBrokerDescriptorRequestV1 {
            request: authenticated_request,
            mut descriptors,
        } = request;
        let descriptor = descriptors.remove(0);
        let mut custody = DormantHostCatalogPublicationUnknownV1 {
            request: DormantReceivedBrokerRequestV1(authenticated_request),
            descriptor,
            snapshot,
            intended_bytes: publication.catalog_bytes(),
            intended_generation: publication.catalog_generation(),
            intended_digest: publication.catalog_digest(),
            known_status: None,
        };
        let status = match outcome {
            Ok(aos_sandbox_host::catalog::HostCatalogPublicationOutcome::Published) => {
                HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_PUBLISHED
            }
            Ok(aos_sandbox_host::catalog::HostCatalogPublicationOutcome::Replay) => {
                HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_REPLAY
            }
            Err(error) => {
                return Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                    error: DormantBrokerExecutionErrorV1::Domain(error.into()),
                    recovery: custody,
                });
            }
        };
        custody.known_status = Some(status);
        match self.commit_host_catalog_publication(&custody, status) {
            Ok(committed) => Ok(committed),
            Err(error) => Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                error: DormantBrokerExecutionErrorV1::Currentness(error),
                recovery: custody,
            }),
        }
    }

    /// Resolves an ambiguous Host catalog effect without redispatching it.
    ///
    /// # Errors
    ///
    /// Returns the unchanged recovery custody when descriptor, session,
    /// deadline, fixed-root readback, or visible catalog state is indeterminate.
    pub fn recover_host_catalog_publication(
        &mut self,
        recovery: DormantHostCatalogPublicationUnknownV1,
        publisher: &aos_sandbox_host::catalog::FileHostCatalogPublisher,
    ) -> Result<
        DormantHostCatalogPublicationRecoveryProgressV1,
        DormantBrokerPublicationExecutionFailureV1<aos_sandbox_host::DormantHostBrokerCallErrorV1>,
    > {
        if validated_publication_snapshot(
            &recovery.descriptor,
            recovery.intended_bytes,
            recovery.intended_generation,
            recovery.intended_digest,
        )
        .is_err()
        {
            return Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                error: DormantBrokerExecutionErrorV1::Currentness(
                    BrokerSessionSecurityError::Currentness,
                ),
                recovery,
            });
        }
        if let Some(status) = recovery.known_status {
            return match self.commit_host_catalog_publication(&recovery, status) {
                Ok(committed) => {
                    Ok(DormantHostCatalogPublicationRecoveryProgressV1::ResponseCommit(committed))
                }
                Err(error) => Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                    error: DormantBrokerExecutionErrorV1::Currentness(error),
                    recovery,
                }),
            };
        }
        let readback = match publisher.resolve_ambiguous_publication(&recovery.snapshot) {
            Ok(readback) => readback,
            Err(error) => {
                return Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                    error: DormantBrokerExecutionErrorV1::Domain(error.into()),
                    recovery,
                });
            }
        };
        match readback {
            aos_sandbox_host::catalog::HostCatalogPublicationReadback::Committed => {
                match self.commit_host_catalog_publication(
                    &recovery,
                    HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_PUBLISHED,
                ) {
                    Ok(committed) => Ok(
                        DormantHostCatalogPublicationRecoveryProgressV1::ResponseCommit(committed),
                    ),
                    Err(error) => Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                        error: DormantBrokerExecutionErrorV1::Currentness(error),
                        recovery,
                    }),
                }
            }
            aos_sandbox_host::catalog::HostCatalogPublicationReadback::Absent => {
                let context = match self.0.reopen_broker_outcome(&recovery.request.0) {
                    Ok((gate, context)) => {
                        drop(gate);
                        context
                    }
                    Err(error) => {
                        return Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                            error: DormantBrokerExecutionErrorV1::Currentness(error),
                            recovery,
                        });
                    }
                };
                if let Err(error) = current_publication_boottime(&recovery.request.0, &context) {
                    return Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                        error: DormantBrokerExecutionErrorV1::Currentness(error),
                        recovery,
                    });
                }
                Ok(DormantHostCatalogPublicationRecoveryProgressV1::RetrySafe(
                    DormantHostCatalogPublicationRetryV1(recovery),
                ))
            }
            aos_sandbox_host::catalog::HostCatalogPublicationReadback::Conflicting => {
                Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                    error: DormantBrokerExecutionErrorV1::Currentness(
                        BrokerSessionSecurityError::Currentness,
                    ),
                    recovery,
                })
            }
        }
    }

    /// Retries only a publication whose protected readback proved it absent.
    ///
    /// # Errors
    ///
    /// Returns pre-effect custody after lost currentness, or exact ambiguity
    /// custody if the fixed publisher begins the retry without a durable result.
    pub fn retry_absent_host_catalog_publication(
        &mut self,
        retry: DormantHostCatalogPublicationRetryV1,
        publisher: &aos_sandbox_host::catalog::FileHostCatalogPublisher,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerPublicationExecutionFailureV1<aos_sandbox_host::DormantHostBrokerCallErrorV1>,
    > {
        let custody = retry.0;
        let context = match self.0.reopen_broker_outcome(&custody.request.0) {
            Ok((gate, context)) => {
                drop(gate);
                context
            }
            Err(error) => {
                return Err(DormantBrokerPublicationExecutionFailureV1::BeforeEffect {
                    error,
                    request: DormantReceivedBrokerDescriptorRequestV1 {
                        request: custody.request.0,
                        descriptors: vec![custody.descriptor],
                    },
                });
            }
        };
        if let Err(error) = current_publication_boottime(&custody.request.0, &context) {
            return Err(DormantBrokerPublicationExecutionFailureV1::BeforeEffect {
                error,
                request: DormantReceivedBrokerDescriptorRequestV1 {
                    request: custody.request.0,
                    descriptors: vec![custody.descriptor],
                },
            });
        }
        let status = match publisher.publish(&custody.snapshot) {
            Ok(aos_sandbox_host::catalog::HostCatalogPublicationOutcome::Published) => {
                HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_PUBLISHED
            }
            Ok(aos_sandbox_host::catalog::HostCatalogPublicationOutcome::Replay) => {
                HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_REPLAY
            }
            Err(error) => {
                return Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                    error: DormantBrokerExecutionErrorV1::Domain(error.into()),
                    recovery: custody,
                });
            }
        };
        let mut custody = custody;
        custody.known_status = Some(status);
        match self.commit_host_catalog_publication(&custody, status) {
            Ok(committed) => Ok(committed),
            Err(error) => Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                error: DormantBrokerExecutionErrorV1::Currentness(error),
                recovery: custody,
            }),
        }
    }

    fn commit_host_catalog_publication(
        &mut self,
        custody: &DormantHostCatalogPublicationUnknownV1,
        status: HostCatalogPublicationStatus,
    ) -> Result<ProtectedBrokerOutcomeCommitResultV1, BrokerSessionSecurityError> {
        let (gate, context) = self.0.reopen_broker_outcome(&custody.request.0)?;
        drop(gate);
        current_publication_boottime(&custody.request.0, &context)?;
        let body =
            publication_response_body(custody.intended_generation, custody.intended_digest, status);
        let message = BrokerResponseEnvelope {
            request_id: custody.request.0.request_id().to_vec(),
            method: custody.request.0.method().into(),
            body,
            request_descriptor_dispositions: vec![BrokerDescriptorDispositionEntry {
                request_index: 0,
                role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_HOST_CATALOG.into(),
                disposition: BrokerDescriptorDisposition::BROKER_DESCRIPTOR_DISPOSITION_CLOSED
                    .into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let pending = self.0.prepare_broker_outcome(&custody.request.0, message)?;
        Ok(self.0.commit_broker_outcome(pending))
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
        let method_matches = request.0.method() == BrokerMethod::BROKER_METHOD_STORAGE_APPLY
            && adapter.matches_request(&request.0);
        let (request, context) = self.begin_execution(request, method_matches)?;
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());
        let observation =
            match adapter.execute_before_outcome(&request.0, version, context.boot_id()) {
                Ok(observation) => observation,
                Err(error) => return Err(Self::unknown_domain(request, error)),
            };
        let response = match observation.response() {
            Ok(response) => response,
            Err(error) => return Err(Self::unknown_domain(request, error)),
        };
        self.finish_observed_success(request, response)
    }

    /// Executes Storage catalog preparation or repair before signing success.
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
        let method_matches = matches!(
            request.0.method(),
            BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
                | BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN
        ) && adapter.matches_request(&request.0);
        let (request, context) = self.begin_execution(request, method_matches)?;
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());
        let response = match adapter.execute_operation_before_outcome(
            &request.0,
            version,
            context.boot_id(),
        ) {
            Ok(response) => response,
            Err(error) => return Err(Self::unknown_domain(request, error)),
        };
        self.finish_observed_success(request, response)
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
        let method_matches = request.0.method()
            == BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
            && request.0.authorization().is_none();
        let (request, _) = self.begin_execution(request, method_matches)?;
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
        let response = match storage
            .lifecycle_inventory_resources(request.0.deadline_boottime_nanoseconds(), worker_cutoff)
        {
            Ok(response) => response,
            Err(error) => return Err(Self::unknown_domain(request, error)),
        };
        self.finish_observed_success(request, response)
    }

    /// Admits Network Apply and signs success only for a committed replay observation.
    ///
    /// # Errors
    ///
    /// Returns a domain or protected-currentness error while Network work is
    /// prepared, ambiguous, or otherwise lacks a committed physical result.
    pub fn execute_network_apply_and_commit(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        adapter: crate::DormantNetworkBrokerEffectAdapterV1<'_>,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_network::DormantNetworkBrokerCallErrorV1>,
    > {
        let method_matches = request.0.method() == BrokerMethod::BROKER_METHOD_NETWORK_APPLY
            && adapter.matches_request(&request.0);
        let (request, context) = self.begin_execution(request, method_matches)?;
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());
        let observation =
            match adapter.execute_before_outcome(&request.0, version, context.boot_id()) {
                Ok(observation) => observation,
                Err(error) => return Err(Self::unknown_domain(request, error)),
            };
        let response = match observation.response() {
            Ok(response) => response,
            Err(error) => return Err(Self::unknown_domain(request, error)),
        };
        self.finish_observed_success(request, response)
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
        let pending = self.0.prepare_broker_outcome(&request.0, message)?;
        Ok(self.0.commit_broker_outcome(pending))
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

    /// Receives and reserves one exact Host catalog publication descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, subject, descriptor-role, semantic, or
    /// protected-currentness failure. Descriptors never escape ambiguous state.
    pub fn receive_authenticated_publish_request(
        &mut self,
    ) -> Result<DormantBrokerDescriptorRequestReceiveProgressV1, DormantBrokerSessionHandshakeErrorV1>
    {
        let (admission, descriptors) = match self.0.receive_authenticated_descriptor_request(1) {
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
        if request.method() != BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG {
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        }
        if initialize {
            let retained = DormantUnconfirmedBrokerDescriptorRequestV1 {
                request: request.clone(),
                descriptors,
            };
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
        let retained = DormantUnconfirmedBrokerDescriptorRequestV1 {
            request: request.clone(),
            descriptors,
        };
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

    /// Receives any authenticated Host request with its method-selected FD table.
    ///
    /// Ordinary Host methods carry no descriptors and `PublishCatalog` carries
    /// exactly one. The protected method decoder validates that relationship
    /// before this method returns descriptor custody. This avoids selecting a
    /// transport profile from unauthenticated packet bytes.
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

    /// Commits a terminal error for a rejected Host catalog descriptor request.
    ///
    /// The sole received descriptor is closed before terminal preparation, and
    /// the signed response records its exact Host-catalog role and closed
    /// disposition. This method cannot terminalize a request after publication
    /// dispatch has begun.
    ///
    /// # Errors
    ///
    /// Returns an error unless the request is exactly `Host.PublishCatalog`
    /// with one descriptor and the protected terminal error can be prepared.
    pub fn commit_authenticated_publication_error_response(
        &mut self,
        request: DormantReceivedBrokerDescriptorRequestV1,
        failure: DormantBrokerFailureV1,
    ) -> Result<ProtectedBrokerOutcomeCommitResultV1, BrokerSessionSecurityError> {
        if request.request.method() != BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG
            || request.descriptors.len() != 1
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let DormantReceivedBrokerDescriptorRequestV1 {
            request,
            descriptors,
        } = request;
        drop(descriptors);
        let message = BrokerResponseEnvelope {
            request_id: request.request_id().to_vec(),
            method: request.method().into(),
            error: Some(failure.error()?).into(),
            request_descriptor_dispositions: vec![BrokerDescriptorDispositionEntry {
                request_index: 0,
                role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_HOST_CATALOG.into(),
                disposition: BrokerDescriptorDisposition::BROKER_DESCRIPTOR_DISPOSITION_CLOSED
                    .into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let pending = self.0.prepare_broker_outcome(&request, message)?;
        Ok(self.0.commit_broker_outcome(pending))
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
        let committed = match self.0.revalidate_broker_committed(committed) {
            Ok(committed) => committed,
            Err((error, committed)) => {
                return Ok(DormantBrokerResponseSendProgressV1::RecoveryRequired {
                    error: error.into(),
                    committed,
                });
            }
        };
        let send = self.0.send_response_packet(committed.exact_packet());
        let committed = match self.0.revalidate_broker_committed(committed) {
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
    ) -> Result<DormantBrokerTerminalReplaySendProgressV1, DormantBrokerSessionHandshakeErrorV1>
    {
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
        let replay = match self.0.revalidate_broker_replay(replay.0) {
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
        let send = self.0.send_response_packet(replay.0.exact_packet());
        let replay = match self.0.revalidate_broker_replay(replay.0) {
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

    /// Reopens exact Host scope descriptors for a protected terminal replay.
    #[must_use]
    pub async fn reopen_host_scope_terminal_replay(
        &mut self,
        replay: DormantBrokerDescriptorTerminalReplayV1,
        mut adapter: crate::DormantHostBrokerEffectAdapterV1<'_>,
    ) -> DormantBrokerDescriptorTerminalReplayRecoveryProgressV1 {
        let replay = match self.0.revalidate_broker_replay(replay.0.0) {
            Ok(replay) => replay,
            Err((error, replay)) => {
                return DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::RecoveryRequired {
                    error: DormantBrokerExecutionErrorV1::Currentness(error),
                    replay: DormantBrokerDescriptorTerminalReplayV1(DormantBrokerTerminalReplayV1(
                        replay,
                    )),
                };
            }
        };
        let method = replay.method();
        let method_matches = matches!(
            method,
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE
                | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
        ) && adapter.matches_request(replay.request());
        if !method_matches {
            return DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::RecoveryRequired {
                error: DormantBrokerExecutionErrorV1::Currentness(
                    BrokerSessionSecurityError::Currentness,
                ),
                replay: DormantBrokerDescriptorTerminalReplayV1(DormantBrokerTerminalReplayV1(
                    replay,
                )),
            };
        }
        let context = replay.verification_context();
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());
        let expected_body = match replay.outcome().result() {
            aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1::Success {
                exact_body,
                ..
            } => exact_body.as_slice(),
            aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1::Error(_) => &[],
        };
        let expected_response_body_digest: [u8; 32] = Sha256::digest(expected_body).into();
        let terminal_verifier = match self.0.broker_outcome_verifier() {
            Ok(verifier) => verifier,
            Err(error) => {
                return DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::RecoveryRequired {
                    error: DormantBrokerExecutionErrorV1::Currentness(error),
                    replay: DormantBrokerDescriptorTerminalReplayV1(DormantBrokerTerminalReplayV1(
                        replay,
                    )),
                };
            }
        };
        let terminal_verifier_commitment = terminal_verifier.commitment();
        if !matches!(
            adapter.fixed_terminal_verifier_commitment(),
            Ok(commitment) if commitment == terminal_verifier_commitment
        ) {
            return DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::RecoveryRequired {
                error: DormantBrokerExecutionErrorV1::Currentness(
                    BrokerSessionSecurityError::Currentness,
                ),
                replay: DormantBrokerDescriptorTerminalReplayV1(DormantBrokerTerminalReplayV1(
                    replay,
                )),
            };
        }
        let replay_authorization = self.1.iter().find(|ticket| {
            ticket.matches_protected_replay(
                replay.method(),
                replay.request_id(),
                replay.signed_request_digest(),
                replay.session_binding(),
                expected_response_body_digest,
                replay.signed_outcome_digest(),
                replay.protected_generation(),
                replay.protected_head(),
            )
        });
        if replay_authorization.is_none() {
            if let Ok(reservation) = adapter.locate_scope_reservation(
                replay.request(),
                expected_response_body_digest,
                terminal_verifier_commitment,
                version,
                context.boot_id(),
            ) {
                let receipt = self
                    .0
                    .sign_terminal_commit_receipt_for_replay(&reservation, &replay);
                let finalized = receipt
                    .as_ref()
                    .is_ok_and(|receipt| adapter.bind_scope_terminal(None, receipt).is_ok());
                if !finalized {
                    return DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::RecoveryRequired {
                        error: DormantBrokerExecutionErrorV1::Currentness(
                            BrokerSessionSecurityError::Currentness,
                        ),
                        replay: DormantBrokerDescriptorTerminalReplayV1(
                            DormantBrokerTerminalReplayV1(replay),
                        ),
                    };
                }
            }
        }
        let observation = match adapter
            .execute_scope_replay_before_outcome(
                replay_authorization,
                replay.request(),
                expected_response_body_digest,
                replay.signed_outcome_digest(),
                replay.protected_generation(),
                replay.protected_head(),
                terminal_verifier_commitment,
                version,
                context.boot_id(),
            )
            .await
        {
            Ok(observation) => observation,
            Err(error) => {
                return DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::RecoveryRequired {
                    error: DormantBrokerExecutionErrorV1::Domain(error),
                    replay: DormantBrokerDescriptorTerminalReplayV1(DormantBrokerTerminalReplayV1(
                        replay,
                    )),
                };
            }
        };
        let (body, descriptors, _) = observation.into_response_descriptors_and_replay_ticket();
        let descriptor_count_matches = replay
            .response_descriptor_roles()
            .is_ok_and(|roles| roles.len() == descriptors.len());
        if body != expected_body || !descriptor_count_matches {
            drop(descriptors);
            return DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::RecoveryRequired {
                error: DormantBrokerExecutionErrorV1::Currentness(
                    BrokerSessionSecurityError::Currentness,
                ),
                replay: DormantBrokerDescriptorTerminalReplayV1(DormantBrokerTerminalReplayV1(
                    replay,
                )),
            };
        }
        let replay = match self.0.revalidate_broker_replay(replay) {
            Ok(replay) => replay,
            Err((error, replay)) => {
                drop(descriptors);
                return DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::RecoveryRequired {
                    error: DormantBrokerExecutionErrorV1::Currentness(error),
                    replay: DormantBrokerDescriptorTerminalReplayV1(DormantBrokerTerminalReplayV1(
                        replay,
                    )),
                };
            }
        };
        DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::Ready(
            DormantReadyBrokerDescriptorTerminalReplayV1 {
                replay: DormantBrokerTerminalReplayV1(replay),
                descriptors,
            },
        )
    }

    /// Atomically resends a protected terminal response and its reopened descriptors.
    #[must_use]
    pub fn send_authenticated_descriptor_terminal_replay(
        &mut self,
        ready: DormantReadyBrokerDescriptorTerminalReplayV1,
    ) -> DormantBrokerDescriptorTerminalReplaySendProgressV1 {
        let DormantReadyBrokerDescriptorTerminalReplayV1 {
            replay,
            descriptors,
        } = ready;
        let replay = match self.0.revalidate_broker_replay(replay.0) {
            Ok(replay) => replay,
            Err((error, replay)) => {
                return DormantBrokerDescriptorTerminalReplaySendProgressV1::RecoveryRequired {
                    error: error.into(),
                    replay: DormantReadyBrokerDescriptorTerminalReplayV1 {
                        replay: DormantBrokerTerminalReplayV1(replay),
                        descriptors,
                    },
                };
            }
        };
        if !replay
            .response_descriptor_roles()
            .is_ok_and(|roles| roles.len() == descriptors.len())
        {
            return DormantBrokerDescriptorTerminalReplaySendProgressV1::RecoveryRequired {
                error: DormantBrokerSessionHandshakeErrorV1::Protected(
                    BrokerSessionSecurityError::Currentness,
                ),
                replay: DormantReadyBrokerDescriptorTerminalReplayV1 {
                    replay: DormantBrokerTerminalReplayV1(replay),
                    descriptors,
                },
            };
        }
        let send = self
            .0
            .send_response_packet_with_descriptors(replay.exact_packet(), &descriptors);
        let replay = match self.0.revalidate_broker_replay(replay) {
            Ok(replay) => replay,
            Err((error, replay)) => {
                return DormantBrokerDescriptorTerminalReplaySendProgressV1::RecoveryRequired {
                    error: error.into(),
                    replay: DormantReadyBrokerDescriptorTerminalReplayV1 {
                        replay: DormantBrokerTerminalReplayV1(replay),
                        descriptors,
                    },
                };
            }
        };
        match send {
            Ok(()) => DormantBrokerDescriptorTerminalReplaySendProgressV1::Sent(
                DormantBrokerTerminalReplayV1(replay),
            ),
            Err(handshake::DormantBrokerSessionHandshakeErrorV1::Transport) => {
                DormantBrokerDescriptorTerminalReplaySendProgressV1::Pending(
                    DormantReadyBrokerDescriptorTerminalReplayV1 {
                        replay: DormantBrokerTerminalReplayV1(replay),
                        descriptors,
                    },
                )
            }
            Err(error) => DormantBrokerDescriptorTerminalReplaySendProgressV1::RecoveryRequired {
                error: error.into(),
                replay: DormantReadyBrokerDescriptorTerminalReplayV1 {
                    replay: DormantBrokerTerminalReplayV1(replay),
                    descriptors,
                },
            },
        }
    }

    /// Recovers an ambiguous descriptor-response commit without dropping FDs.
    #[must_use]
    pub fn recover_descriptor_response_commit(
        &mut self,
        retained: DormantBrokerDescriptorCommitRecoveryV1,
    ) -> DormantBrokerDescriptorCommitResultV1 {
        let DormantBrokerDescriptorCommitRecoveryV1 {
            recovery,
            descriptors,
            host_observed,
            scope_replay_ticket,
            ..
        } = retained;
        match self.0.recover_broker_outcome_commit(recovery) {
            ProtectedBrokerOutcomeCommitResultV1::Committed(committed) if !host_observed => {
                DormantBrokerDescriptorCommitResultV1::Committed(
                    DormantCommittedBrokerDescriptorResponseV1::seal(
                        committed,
                        descriptors,
                        host_observed,
                    ),
                )
            }
            ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => {
                DormantBrokerDescriptorCommitResultV1::HostFinalizationRequired(
                    DormantHostScopeTerminalFinalizationV1 {
                        error: DormantBrokerExecutionErrorV1::Currentness(
                            BrokerSessionSecurityError::Currentness,
                        ),
                        committed,
                        descriptors,
                        replay_ticket: scope_replay_ticket,
                    },
                )
            }
            ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, recovery } => {
                DormantBrokerDescriptorCommitResultV1::RecoveryRequired(
                    DormantBrokerDescriptorCommitRecoveryV1 {
                        error,
                        recovery,
                        descriptors,
                        host_observed,
                        scope_replay_ticket,
                    },
                )
            }
        }
    }

    /// Atomically sends one committed signed response and its exact descriptors.
    ///
    /// # Errors
    ///
    /// Returns an error for changed protected transport currentness or a fatal
    /// ancillary send; retryable backpressure retains packet and descriptor custody.
    pub fn send_authenticated_descriptor_response(
        &mut self,
        response: DormantCommittedBrokerDescriptorResponseV1,
    ) -> Result<DormantBrokerDescriptorSendProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        let DormantCommittedBrokerDescriptorResponseV1 {
            committed,
            descriptors,
            host_observed,
        } = response;
        let roles_match = committed
            .response_descriptor_roles()
            .is_ok_and(|roles| roles.len() == descriptors.len());
        if !host_observed || !roles_match {
            return Ok(DormantBrokerDescriptorSendProgressV1::RecoveryRequired(
                DormantBrokerDescriptorSendRecoveryV1 {
                    error: DormantBrokerSessionHandshakeErrorV1::Protected(
                        BrokerSessionSecurityError::Currentness,
                    ),
                    response: DormantCommittedBrokerDescriptorResponseV1::seal(
                        committed,
                        descriptors,
                        host_observed,
                    ),
                },
            ));
        }
        let committed = match self.0.revalidate_broker_committed(committed) {
            Ok(committed) => committed,
            Err((error, committed)) => {
                return Ok(DormantBrokerDescriptorSendProgressV1::RecoveryRequired(
                    DormantBrokerDescriptorSendRecoveryV1 {
                        error: error.into(),
                        response: DormantCommittedBrokerDescriptorResponseV1::seal(
                            committed,
                            descriptors,
                            host_observed,
                        ),
                    },
                ));
            }
        };
        let send = self
            .0
            .send_response_packet_with_descriptors(committed.exact_packet(), &descriptors);
        let committed = match self.0.revalidate_broker_committed(committed) {
            Ok(committed) => committed,
            Err((error, committed)) => {
                return Ok(DormantBrokerDescriptorSendProgressV1::RecoveryRequired(
                    DormantBrokerDescriptorSendRecoveryV1 {
                        error: error.into(),
                        response: DormantCommittedBrokerDescriptorResponseV1::seal(
                            committed,
                            descriptors,
                            host_observed,
                        ),
                    },
                ));
            }
        };
        Ok(match send {
            Ok(()) => DormantBrokerDescriptorSendProgressV1::Sent(committed),
            Err(handshake::DormantBrokerSessionHandshakeErrorV1::Transport) => {
                DormantBrokerDescriptorSendProgressV1::Pending(
                    DormantCommittedBrokerDescriptorResponseV1::seal(
                        committed,
                        descriptors,
                        host_observed,
                    ),
                )
            }
            Err(error) => DormantBrokerDescriptorSendProgressV1::RecoveryRequired(
                DormantBrokerDescriptorSendRecoveryV1 {
                    error: error.into(),
                    response: DormantCommittedBrokerDescriptorResponseV1::seal(
                        committed,
                        descriptors,
                        host_observed,
                    ),
                },
            ),
        })
    }

    /// Retries descriptor transport from inseparable ambiguity custody.
    ///
    /// # Errors
    ///
    /// Returns an error only for the same protected-currentness or transport
    /// failures reported by [`Self::send_authenticated_descriptor_response`].
    pub fn retry_authenticated_descriptor_response(
        &mut self,
        retained: DormantBrokerDescriptorSendRecoveryV1,
    ) -> Result<DormantBrokerDescriptorSendProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        self.send_authenticated_descriptor_response(retained.response)
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
        let prepared = DormantPreparedBrokerRequestV1(request.clone());
        if initialize {
            return Ok(match self.0.initialize_authenticated_request(&request)? {
                ProtectedBrokerSessionInitializationResultV1::Initialized => {
                    DormantBrokerRequestPreparationV1::Prepared(prepared)
                }
                ProtectedBrokerSessionInitializationResultV1::RecoveryRequired {
                    error,
                    recovery,
                } => DormantBrokerRequestPreparationV1::InitializationRecoveryRequired {
                    error,
                    recovery,
                    request: DormantUnconfirmedBrokerRequestV1(request),
                },
            });
        }
        Ok(match self.0.append_authenticated_request(&request)? {
            ProtectedBrokerRequestCommitResultV1::Committed => {
                DormantBrokerRequestPreparationV1::Prepared(prepared)
            }
            ProtectedBrokerRequestCommitResultV1::RecoveryRequired { error, recovery } => {
                DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired {
                    error,
                    recovery,
                    request: DormantUnconfirmedBrokerRequestV1(request),
                }
            }
        })
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
        let request = effect.broker_request().map_err(|_| {
            BrokerSessionSecurityError::manifest("durable authority effect request")
        })?;
        let (maximum_deadline, negotiated_response_bytes, protocol_version, audience) =
            self.0.client_request_limits()?;
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
        let (authenticated, initialize) = self.0.prepare_client_request(
            envelope,
            method,
            0,
            request_id,
            deadline,
            maximum_response_bytes,
        )?;
        if authenticated.exact_body() != expected_body {
            return Err(BrokerSessionSecurityError::manifest(
                "durable authority effect body binding",
            ));
        }

        let prepared = DormantPreparedBrokerRequestV1(authenticated.clone());
        if initialize {
            return Ok(
                match self.0.initialize_authenticated_request(&authenticated)? {
                    ProtectedBrokerSessionInitializationResultV1::Initialized => {
                        DormantBrokerRequestPreparationV1::Prepared(prepared)
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
                DormantBrokerRequestPreparationV1::Prepared(prepared)
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

    /// Builds and durably reserves one authenticated descriptor-bearing request.
    ///
    /// The fixed V1 profile derives the required role count from `method`; the
    /// exact supplied FD count and signed descriptor table must both match it.
    /// This dormant path currently admits only Host PublishCatalog, the sole V1
    /// request carrying SCM_RIGHTS descriptors.
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
        if method != BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG || descriptors.len() != 1 {
            return Err(BrokerSessionSecurityError::Currentness);
        }
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
        if initialize {
            return Ok(match self.0.initialize_authenticated_request(&request)? {
                ProtectedBrokerSessionInitializationResultV1::Initialized => {
                    DormantBrokerDescriptorRequestPreparationV1::Prepared(
                        DormantPreparedBrokerDescriptorRequestV1 {
                            request,
                            descriptors,
                        },
                    )
                }
                ProtectedBrokerSessionInitializationResultV1::RecoveryRequired {
                    error,
                    recovery,
                } => DormantBrokerDescriptorRequestPreparationV1::InitializationRecoveryRequired {
                    error,
                    recovery,
                    request: DormantUnconfirmedBrokerDescriptorRequestV1 {
                        request,
                        descriptors,
                    },
                },
            });
        }
        Ok(match self.0.append_authenticated_request(&request)? {
            ProtectedBrokerRequestCommitResultV1::Committed => {
                DormantBrokerDescriptorRequestPreparationV1::Prepared(
                    DormantPreparedBrokerDescriptorRequestV1 {
                        request,
                        descriptors,
                    },
                )
            }
            ProtectedBrokerRequestCommitResultV1::RecoveryRequired { error, recovery } => {
                DormantBrokerDescriptorRequestPreparationV1::SuccessorRecoveryRequired {
                    error,
                    recovery,
                    request: DormantUnconfirmedBrokerDescriptorRequestV1 {
                        request,
                        descriptors,
                    },
                }
            }
        })
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
        match self.0.send_request_packet(request.0.canonical_packet()) {
            Ok(()) => Ok(DormantBrokerRequestSendProgressV1::Sent(
                DormantOutstandingBrokerRequestV1(request.0),
            )),
            Err(handshake::DormantBrokerSessionHandshakeErrorV1::Transport) => {
                Ok(DormantBrokerRequestSendProgressV1::Pending(request))
            }
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
        let maximum = usize::try_from(outstanding.0.maximum_response_bytes())
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        let packet = match self.0.receive_response_packet(maximum) {
            Ok(packet) => packet,
            Err(handshake::DormantBrokerSessionHandshakeErrorV1::Transport) => {
                return Ok(DormantBrokerResponseProgressV1::Pending(outstanding));
            }
            Err(error) => return Err(error.into()),
        };
        let outcome = decode_canonical_response_v1(&packet)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        let (gate, _) = self.0.reopen_broker_outcome(&outstanding.0)?;
        let pending = match gate.admit_outcome(&outcome)? {
            crate::ProtectedBrokerOutcomeAdmissionV1::New { advancement } => advancement,
            crate::ProtectedBrokerOutcomeAdmissionV1::ExactReplay { .. } => {
                return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
            }
        };
        Ok(DormantBrokerResponseProgressV1::Committed(
            self.0.commit_broker_outcome(pending),
        ))
    }

    /// Receives and commits one Host scope response with its exact descriptors.
    ///
    /// The expected descriptor count is derived from the authenticated method,
    /// never supplied by the caller. Durable outcome ambiguity retains every
    /// received descriptor beside the exact recovery token.
    ///
    /// # Errors
    ///
    /// Returns an error for another method, invalid response bytes, an inexact
    /// descriptor table, changed peer/session evidence, or protected failure.
    pub fn receive_authenticated_scope_response(
        &mut self,
        outstanding: DormantOutstandingBrokerRequestV1,
    ) -> Result<DormantBrokerDescriptorResponseProgressV1, DormantBrokerSessionHandshakeErrorV1>
    {
        let expected_descriptors = match outstanding.0.method() {
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE => {
                aos_sandbox_protocol::payload_scope::PAYLOAD_SCOPE_DESCRIPTOR_ROLES.len()
            }
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE => {
                aos_sandbox_protocol::mount_scope::MOUNT_SCOPE_DESCRIPTOR_ROLES.len()
            }
            _ => return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid),
        };
        let maximum = usize::try_from(outstanding.0.maximum_response_bytes())
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        let (packet, descriptors) = match self
            .0
            .receive_response_packet_with_descriptors(maximum, expected_descriptors)
        {
            Ok(received) => received,
            Err(handshake::DormantBrokerSessionHandshakeErrorV1::Transport) => {
                return Ok(DormantBrokerDescriptorResponseProgressV1::Pending(
                    outstanding,
                ));
            }
            Err(error) => return Err(error.into()),
        };
        let outcome = decode_canonical_response_v1(&packet)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        let (gate, _) = self.0.reopen_broker_outcome(&outstanding.0)?;
        let pending = match gate.admit_outcome_with_descriptor_count(&outcome, descriptors.len())? {
            crate::ProtectedBrokerOutcomeAdmissionV1::New { advancement } => advancement,
            crate::ProtectedBrokerOutcomeAdmissionV1::ExactReplay { .. } => {
                return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
            }
        };
        let committed = match self.0.commit_broker_outcome(pending) {
            ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => {
                DormantBrokerDescriptorCommitResultV1::Committed(
                    DormantCommittedBrokerDescriptorResponseV1::seal(committed, descriptors, false),
                )
            }
            ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, recovery } => {
                DormantBrokerDescriptorCommitResultV1::RecoveryRequired(
                    DormantBrokerDescriptorCommitRecoveryV1 {
                        error,
                        recovery,
                        descriptors,
                        host_observed: false,
                        scope_replay_ticket: None,
                    },
                )
            }
        };
        Ok(DormantBrokerDescriptorResponseProgressV1::Committed(
            committed,
        ))
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

impl ProtectedBrokerSessionFixedCustodyV1 {
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
        remaining_handshake_nanoseconds(deadline_boottime_nanoseconds)?;
        let mut handshake = self.begin_production_client_handshake(socket)?;

        loop {
            // Ready sockets bypass polling, but never bypass the activation deadline.
            remaining_handshake_nanoseconds(deadline_boottime_nanoseconds)?;
            match handshake.advance()? {
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
        remaining_handshake_nanoseconds(deadline_boottime_nanoseconds)?;
        let mut handshake = self.begin_production_broker_handshake(socket)?;

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
        let protocol = self.production_protocol();
        let audience = self.production_audience();
        let maximum_response_bytes = u32::try_from(AUTHENTICATED_RESPONSE_MAXIMUM_BYTES)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        let hello = production_broker_client_hello_v1(protocol, audience, maximum_response_bytes)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
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
        let protocol = self.production_protocol();
        let audience = self.production_audience();
        let maximum_response_bytes = u32::try_from(AUTHENTICATED_RESPONSE_MAXIMUM_BYTES)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        let hello = production_broker_server_hello_v1(protocol, audience, maximum_response_bytes)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
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
