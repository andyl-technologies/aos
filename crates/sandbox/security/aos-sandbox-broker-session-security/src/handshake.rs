//! Dormant authenticated hello-flight composition over adopted sockets.
//!
//! This module owns the exact connected socket across publication, ClientHello,
//! and BrokerHello. Every receive is immediately bound back to that socket,
//! and every transition rechecks protected custody plus retained pidfd evidence.
//! Public fixed-role wrappers drive one bounded flight at a time and retain the
//! resulting transcript with the adopted socket and protected journal owner.
//! They register no peer, transport, descriptor, service, or effect authority.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

pub(crate) mod fuse_intent_continuation;
pub(crate) mod output_registration_continuation;
pub(super) mod client_storage_continuation;
pub(super) mod host_worker_comparison;
pub(crate) mod retained_storage_session;
mod storage_broker_start;
mod fixed_service_session;
pub use fixed_service_session::{FixedServiceSessionOpenOriginalV4, FixedServiceSessionBorrowV4, FixedServiceSessionClosedV4};
mod initial_storage_session;
mod selected_client_open;
mod start_network_client;
pub use start_network_client::{StartResourceSessionOpenOriginalV4, StartResourceSessionClosedV4, StartResourceSessionBorrowV4};
mod storage_host_client;
pub(crate) use storage_host_client::StorageHostSessionOpenV1;
mod controller_initial;
mod selected_client_hello;
use selected_client_hello::SelectedClientHelloVerificationV1;
pub(crate) use controller_initial::{ControllerInitialSessionOpenV1, ControllerInitialClientClosedV1, ControllerInitialSessionCompletedBorrowV1};
mod process_evidence;
pub(crate) use process_evidence::receiving_failure_footprint_v1 as storage_process_evidence_footprint_v1;
use process_evidence::{ProcessNativeObservationV1, RetainedProcessEvidenceFailureV1};
pub(crate) use initial_storage_session::StorageInitialSessionHandshakeV1;
pub(crate) mod storage_lifecycle_request;

use aos_sandbox_api::aos::sandbox::local::v1::{Audience, BrokerMethod};
use aos_sandbox_controller_domain::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1;
use aos_sandbox_broker_session_protocol::{
    BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES, BrokerSessionProtocolV1, CLIENT_HELLO_MAXIMUM_BYTES,
    SERVER_HELLO_MAXIMUM_BYTES, UntrustedBrokerSessionEndpointPublicationV1,
    VerifiedBrokerSessionTranscriptV1, decode_canonical_client_hello_v1,
    decode_canonical_server_hello_v1,
    hello_message::{BrokerClientHello, BrokerServerHello},
    verify_broker_session_transcript_after_client_v1, verify_broker_session_transcript_v1,
    verify_client_hello_context_v1, verify_client_hello_signature_v1,
};
use aos_linux_descriptors::pidfd::PidFd;
use aos_linux_descriptors::pidfd::PidFdCredentials;
use aos_linux_descriptors::pidfd::PidFdInfo;
use aos_sandbox_linux::pidfd::PidFdProcessIdentity;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_linux::seqpacket::{
    ConnectionPeerIdentity, KernelAuthorizedRecordSubject, SeqpacketError, SeqpacketSocket,
};
use aos_sandbox_protocol::PeerCredentials;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use aos_sandbox_protocol::authenticated_session::historical_checkpoint::{
    HistoricalSessionCheckpointConstructionCaptureV1, HistoricalSessionCheckpointV1,
};

use crate::recovery::{
    ArchivedStorageInventoryHeadV1, AuthenticatedOriginalHostNoApplyJoinV1, FixedEndpointCustodyV1,
    ProtectedBrokerSessionOwnerV1, ProtectedPriorAtomicStorageHistoryV1,
    ProtectedPriorTerminalExchangeV1, ProtectedVerifiedAtomicStorageHistoryV1,
};
use crate::{
    BrokerSessionSecurityError, ProtectedBrokerSessionBrokerV1, ProtectedBrokerSessionClientV1,
    ProtectedBrokerSessionFixedCustodyV1,
};

/// Requires a live record subject matching the receiving socket's pinned peer.
fn require_connection_record_subject(
    subject: &KernelAuthorizedRecordSubject,
    peer: &ConnectionPeerIdentity,
) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
    require_connection_record_subject_engine_v1(subject, peer, None)
}

fn require_connection_record_subject_engine_v1(
    subject: &KernelAuthorizedRecordSubject,
    peer: &ConnectionPeerIdentity,
    mut original: Option<&mut Option<aos_linux_descriptors::Result<bool>>>,
) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
    let credentials = subject.credentials();
    let peer_credentials = peer.credentials();

    let local;
    let alive = if let Some(slot) = original.as_deref_mut() {
        *slot = Some(subject.is_alive());
        slot.as_ref().ok_or(DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?
    } else {
        local = subject.is_alive();
        &local
    };
    if !*alive.as_ref().map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?
        || credentials.pid() != peer_credentials.pid()
        || credentials.uid() != peer_credentials.uid()
        || credentials.gid() != peer_credentials.gid()
        || subject.initial_info() != peer.initial_info()
    {
        return Err(DormantBrokerSessionHandshakeErrorV1::KernelEvidence);
    }

    Ok(())
}

#[derive(Clone, Copy)]
enum HandshakeReceiveProfileV1 {
    Ordinary,
    StoragePreparation,
    ControllerInitial,
    StartResource,
    StorageHost,
}

impl HandshakeReceiveProfileV1 {
    const fn retains_original(self) -> bool {
        matches!(self, Self::StoragePreparation | Self::ControllerInitial | Self::StartResource | Self::StorageHost)
    }
}

struct HandshakeCarrier {
    transport: HandshakeTransport,
    receive_profile: HandshakeReceiveProfileV1,
    selected_record: Option<aos_sandbox_linux::seqpacket::ReceivedRecord>,
    selected_send: Option<aos_sandbox_linux::seqpacket::StorageSeqpacketSendAttemptV1>,
    peer: ProcessEvidence,
    #[cfg(test)]
    io_trace: std::sync::Arc<HandshakeIoTrace>,
    #[cfg(test)]
    scripted_send_errors: std::collections::VecDeque<SeqpacketError>,
    #[cfg(test)]
    scripted_receive_errors: std::collections::VecDeque<SeqpacketError>,
    #[cfg(test)]
    corrupt_peer_after_next_send: bool,
}

enum HandshakeTransport {
    Ordinary(SeqpacketSocket),
    Descriptor(DescriptorSubjectSocket),
}

#[cfg(test)]
#[derive(Default)]
struct HandshakeIoTrace {
    sends: std::sync::atomic::AtomicUsize,
    receives: std::sync::atomic::AtomicUsize,
}

#[allow(dead_code, reason = "used by the sealed handshake typestates")]
impl HandshakeCarrier {
    fn as_fd(&self) -> Result<BorrowedFd<'_>, DormantBrokerSessionHandshakeErrorV1> {
        match &self.transport {
            HandshakeTransport::Ordinary(socket) => socket.as_fd(),
            HandshakeTransport::Descriptor(socket) => socket.as_fd(),
        }
        .map_err(|_| DormantBrokerSessionHandshakeErrorV1::Transport)
    }

    fn ordinary(socket: SeqpacketSocket) -> Result<Self, HandshakeError> {
        let peer = ProcessEvidence::capture_peer(socket.peer())?;
        Ok(Self::ordinary_from_peer_v1(socket, peer, HandshakeReceiveProfileV1::Ordinary))
    }

    fn ordinary_from_peer_v1(
        socket: SeqpacketSocket,
        peer: ProcessEvidence,
        receive_profile: HandshakeReceiveProfileV1,
    ) -> Self {
        Self {
            transport: HandshakeTransport::Ordinary(socket),
            receive_profile,
            selected_record: None,
            selected_send: None,
            peer,
            #[cfg(test)]
            io_trace: std::sync::Arc::new(HandshakeIoTrace::default()),
            #[cfg(test)]
            scripted_send_errors: std::collections::VecDeque::new(),
            #[cfg(test)]
            scripted_receive_errors: std::collections::VecDeque::new(),
            #[cfg(test)]
            corrupt_peer_after_next_send: false,
        }
    }

    fn descriptor(socket: DescriptorSubjectSocket) -> Result<Self, HandshakeError> {
        let peer = ProcessEvidence::capture_peer(socket.peer())?;
        Ok(Self {
            transport: HandshakeTransport::Descriptor(socket),
            receive_profile: HandshakeReceiveProfileV1::Ordinary,
            selected_record: None,
            selected_send: None,
            peer,
            #[cfg(test)]
            io_trace: std::sync::Arc::new(HandshakeIoTrace::default()),
            #[cfg(test)]
            scripted_send_errors: std::collections::VecDeque::new(),
            #[cfg(test)]
            scripted_receive_errors: std::collections::VecDeque::new(),
            #[cfg(test)]
            corrupt_peer_after_next_send: false,
        })
    }

    fn send(&mut self, bytes: &[u8]) -> Result<(), SeqpacketError> {
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering;

            self.io_trace.sends.fetch_add(1, Ordering::Relaxed);
            if let Some(error) = self.scripted_send_errors.pop_front() {
                return Err(error);
            }
        }
        let result = match &mut self.transport {
            HandshakeTransport::Ordinary(socket) => socket.send(bytes),
            HandshakeTransport::Descriptor(socket) => socket.send(bytes),
        };
        #[cfg(test)]
        if self.corrupt_peer_after_next_send {
            self.corrupt_peer_after_next_send = false;
            self.peer.process_id ^= 1;
        }
        result
    }

    fn send_broker_original(&mut self, bytes: &[u8]) -> Result<(), HandshakeError> {
        if self.receive_profile.retains_original() {
            let HandshakeTransport::Ordinary(socket) = &mut self.transport else {
                return Err(HandshakeError::RemoteInvalid);
            };
            // Only the preceding positively closed HELLO stage can reach a
            // later send. Its successful control receipt may be replaced;
            // negative/ambiguous sends never reenter this reducer. The same
            // lower framing engine is used by selected request/reply traffic.
            let attempt = socket.send_storage_session_retaining_v1(bytes);
            if attempt.is_sent() {
                self.selected_send = Some(attempt);
                return Ok(());
            }
            // HELLO retains its existing no-retry availability policy even for
            // a native nonconsuming EAGAIN/EINTR. The whole actual attempt and
            // carrier remain owned; no generic fatal-error clearing occurs.
            return Err(HandshakeError::SelectedSend(
                RetainedStorageHandshakeSendFailureV1 { attempt },
            ));
        }
        match self.send(bytes) {
            Ok(()) => Ok(()),
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) =>
                Err(HandshakeError::RetryableTransport),
            Err(_) => Err(HandshakeError::Transport),
        }
    }

    fn receive(&mut self, maximum: usize) -> Result<BoundFlight, HandshakeError> {
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering;

            self.io_trace.receives.fetch_add(1, Ordering::Relaxed);
            if let Some(error) = self.scripted_receive_errors.pop_front() {
                return Err(HandshakeError::transport(error));
            }
        }
        match &mut self.transport {
            HandshakeTransport::Ordinary(socket) => {
                let record = match self.receive_profile {
                    HandshakeReceiveProfileV1::Ordinary =>
                        socket.receive(maximum).map_err(HandshakeError::transport)?,
                    HandshakeReceiveProfileV1::StoragePreparation
                    | HandshakeReceiveProfileV1::ControllerInitial
                    | HandshakeReceiveProfileV1::StartResource
                    | HandshakeReceiveProfileV1::StorageHost => {
                        let record = match socket.receive_storage_preparation_retaining_v1(maximum) {
                            Ok(record) => record,
                            Err(error) if error.is_nonconsuming_would_block()
                                || error.is_nonconsuming_interrupted() => {
                                // This exact lower retry owns no captured sample.
                                return Err(HandshakeError::RetryableTransport);
                            }
                            Err(error) => return Err(HandshakeError::RetainedReceive(error)),
                        };
                        self.selected_record = Some(record);
                        let record = self.selected_record.as_ref()
                            .ok_or(HandshakeError::RemoteInvalid)?;
                        socket.compare_storage_preparation_received_original_v1(record)
                            .map_err(HandshakeError::RecordBinding)?;
                        ProcessEvidence::capture_peer_retaining(socket.peer())?;
                        let evidence = ProcessEvidence::observe_retaining(
                            record.subject().pidfd(), Some(record.subject().initial_info().into()),
                            |evidence| record.subject().credentials().pid().get() == evidence.process_id,
                        )?;
                        if record.subject().credentials().pid().get() != evidence.process_id {
                            return Err(HandshakeError::KernelEvidence);
                        }
                        let record = self.selected_record.take()
                            .ok_or(HandshakeError::RemoteInvalid)?;
                        let (payload, subject) = record.into_parts();
                        return Ok(BoundFlight {
                            payload, subject: RetainedSubject { subject, evidence },
                        });
                    }
                };
                let bound = socket
                    .bind_received(record)
                    .map_err(|_| HandshakeError::RemoteInvalid)?;
                ProcessEvidence::validate_peer(bound.peer())?;
                let (payload, subject, peer) = bound.into_parts();
                ProcessEvidence::validate_peer(peer)?;
                let subject = RetainedSubject::capture(subject)?;
                Ok(BoundFlight { payload, subject })
            }
            HandshakeTransport::Descriptor(socket) => {
                let record = socket
                    .receive(maximum, 0)
                    .map_err(HandshakeError::transport)?;
                let bound = socket
                    .bind_received(record)
                    .map_err(|_| HandshakeError::RemoteInvalid)?;
                if !bound.descriptors().is_empty() {
                    return Err(HandshakeError::RemoteInvalid);
                }
                ProcessEvidence::validate_peer(bound.peer())?;
                let (payload, subject, descriptors, peer) = bound.into_parts();
                if !descriptors.is_empty() {
                    return Err(HandshakeError::RemoteInvalid);
                }
                ProcessEvidence::validate_peer(peer)?;
                let subject = RetainedSubject::capture(subject)?;
                Ok(BoundFlight { payload, subject })
            }
        }
    }

    fn validate_peer(&self) -> Result<(), HandshakeError> {
        let peer = match &self.transport {
            HandshakeTransport::Ordinary(socket) => socket.peer(),
            HandshakeTransport::Descriptor(socket) => socket.peer(),
        };
        if self.receive_profile.retains_original() {
            self.peer.validate_connection_retaining(peer)
        } else {
            self.peer.validate_connection(peer)
        }
    }

    fn validate_subject(&self, subject: &RetainedSubject) -> Result<(), HandshakeError> {
        if self.receive_profile.retains_original() {
            subject.validate_storage_preparation()
        } else {
            subject.validate()
        }
    }

    fn close(&mut self) {
        if self.receive_profile.retains_original() {
            // The selected caller consumes this carrier into its opaque failed
            // reducer owner. Retain the actual endpoint; no retry handle escapes.
            return;
        }
        match &mut self.transport {
            HandshakeTransport::Ordinary(socket) => socket.close(),
            HandshakeTransport::Descriptor(socket) => socket.close(),
        }
    }

    fn into_ordinary(self) -> Result<SeqpacketSocket, DormantBrokerSessionHandshakeErrorV1> {
        match self.transport {
            HandshakeTransport::Ordinary(socket) => Ok(socket),
            HandshakeTransport::Descriptor(_) => {
                Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole)
            }
        }
    }

    #[cfg(test)]
    fn io_trace(&self) -> std::sync::Arc<HandshakeIoTrace> {
        std::sync::Arc::clone(&self.io_trace)
    }

    #[cfg(test)]
    fn interrupt_next_send(&mut self) {
        self.scripted_send_errors
            .push_back(SeqpacketError::Interrupted);
    }

    #[cfg(test)]
    fn would_block_next_send(&mut self) {
        self.scripted_send_errors
            .push_back(SeqpacketError::WouldBlock);
    }

    #[cfg(test)]
    fn interrupt_next_receive(&mut self) {
        self.scripted_receive_errors
            .push_back(SeqpacketError::Interrupted);
    }

    #[cfg(test)]
    fn would_block_next_receive(&mut self) {
        self.scripted_receive_errors
            .push_back(SeqpacketError::WouldBlock);
    }

    #[cfg(test)]
    fn corrupt_peer_after_next_send(&mut self) {
        self.corrupt_peer_after_next_send = true;
    }
}

struct BoundFlight {
    payload: Vec<u8>,
    subject: RetainedSubject,
}

struct RetainedSubject {
    subject: KernelAuthorizedRecordSubject,
    evidence: ProcessEvidence,
}

impl RetainedSubject {
    fn capture(subject: KernelAuthorizedRecordSubject) -> Result<Self, HandshakeError> {
        let evidence = ProcessEvidence::capture(subject.pidfd(), subject.initial_info())?;
        if subject.credentials().pid().get() != evidence.process_id {
            return Err(HandshakeError::KernelEvidence);
        }
        Ok(Self { subject, evidence })
    }

    fn validate(&self) -> Result<(), HandshakeError> {
        self.evidence.validate(self.subject.pidfd())
    }

    fn validate_storage_preparation(&self) -> Result<(), HandshakeError> {
        ProcessEvidence::observe_retaining(self.subject.pidfd(), None,
            |current| current == self.evidence).map(|_| ())
    }

    fn same_execution(&self, other: &Self) -> bool {
        self.evidence == other.evidence
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ProcessEvidence {
    process_id: u32,
    thread_group_id: u32,
    start_time_ticks: u64,
    cgroup_id: u64,
    real_user_id: u32,
    real_group_id: u32,
    effective_user_id: u32,
    effective_group_id: u32,
    saved_user_id: u32,
    saved_group_id: u32,
    filesystem_user_id: u32,
    filesystem_group_id: u32,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ProcessInformation {
    process_id: u32,
    thread_group_id: u32,
    parent_process_id: u32,
    credentials: Option<ProcessCredentials>,
    cgroup_id: Option<u64>,
}

impl From<PidFdInfo> for ProcessInformation {
    fn from(information: PidFdInfo) -> Self {
        Self {
            process_id: information.pid(),
            thread_group_id: information.thread_group_id(),
            parent_process_id: information.parent_pid(),
            credentials: information.credentials().map(ProcessCredentials::from),
            cgroup_id: information.cgroup_id(),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ProcessCredentials {
    real_user_id: u32,
    real_group_id: u32,
    effective_user_id: u32,
    effective_group_id: u32,
    saved_user_id: u32,
    saved_group_id: u32,
    filesystem_user_id: u32,
    filesystem_group_id: u32,
}

impl From<PidFdCredentials> for ProcessCredentials {
    fn from(credentials: PidFdCredentials) -> Self {
        Self {
            real_user_id: credentials.real_user_id(),
            real_group_id: credentials.real_group_id(),
            effective_user_id: credentials.effective_user_id(),
            effective_group_id: credentials.effective_group_id(),
            saved_user_id: credentials.saved_user_id(),
            saved_group_id: credentials.saved_group_id(),
            filesystem_user_id: credentials.filesystem_user_id(),
            filesystem_group_id: credentials.filesystem_group_id(),
        }
    }
}

#[derive(Clone, Copy)]
struct ProcessIdentity {
    process_id: u32,
    thread_group_id: u32,
    start_time_ticks: u64,
    cgroup_id: Option<u64>,
}

impl From<PidFdProcessIdentity> for ProcessIdentity {
    fn from(identity: PidFdProcessIdentity) -> Self {
        Self {
            process_id: identity.pid(),
            thread_group_id: identity.thread_group_id(),
            start_time_ticks: identity.start_time_ticks(),
            cgroup_id: identity.cgroup_id(),
        }
    }
}

impl ProcessEvidence {
    fn capture_peer(peer: &ConnectionPeerIdentity) -> Result<Self, HandshakeError> {
        let evidence = Self::capture(peer.pidfd(), peer.initial_info())?;
        if peer.credentials().pid().get() != evidence.process_id
            || peer.credentials().uid() != evidence.effective_user_id
            || peer.credentials().gid() != evidence.effective_group_id
        {
            return Err(HandshakeError::KernelEvidence);
        }
        Ok(evidence)
    }

    fn validate_peer(peer: &ConnectionPeerIdentity) -> Result<(), HandshakeError> {
        Self::capture_peer(peer).map(|_| ())
    }

    fn capture(pidfd: &PidFd, initial: PidFdInfo) -> Result<Self, HandshakeError> {
        Self::observe(pidfd, Some(initial.into()))
    }

    fn observe(pidfd: &PidFd, initial: Option<ProcessInformation>) -> Result<Self, HandshakeError> {
        Self::observe_with_originals(pidfd, initial, None)
    }

    fn observe_with_originals(
        pidfd: &PidFd,
        initial: Option<ProcessInformation>,
        mut originals: Option<&mut ProcessNativeObservationV1>,
    ) -> Result<Self, HandshakeError> {
        let before = match originals.as_deref_mut() {
            Some(originals) => originals.before(pidfd),
            None => pidfd.info().map_err(|_| HandshakeError::KernelEvidence),
        }?;
        let identity = match originals.as_deref_mut() {
            Some(originals) => originals.identity(pidfd),
            None => aos_sandbox_linux::pidfd::process_identity(&(pidfd)).map_err(|_| HandshakeError::KernelEvidence),
        }?;
        let after = match originals.as_deref_mut() {
            Some(originals) => originals.after(pidfd),
            None => pidfd.info().map_err(|_| HandshakeError::KernelEvidence),
        }?;
        let alive = match originals.as_deref_mut() {
            Some(originals) => originals.alive(pidfd),
            None => pidfd.is_alive().map_err(|_| HandshakeError::KernelEvidence),
        };

        Self::from_observation_sandwich(
            initial,
            before.into(),
            identity.into(),
            after.into(),
            alive,
        )
    }

    fn from_observation_sandwich(
        initial: Option<ProcessInformation>,
        before: ProcessInformation,
        identity: ProcessIdentity,
        after: ProcessInformation,
        alive: Result<bool, HandshakeError>,
    ) -> Result<Self, HandshakeError> {
        let alive = alive?;
        if !alive || before != after || initial.is_some_and(|value| value != before) {
            return Err(HandshakeError::KernelEvidence);
        }

        let credentials = before.credentials.ok_or(HandshakeError::KernelEvidence)?;
        let cgroup_id = before
            .cgroup_id
            .filter(|value| *value != 0)
            .ok_or(HandshakeError::KernelEvidence)?;
        if identity.process_id != before.process_id
            || identity.thread_group_id != before.thread_group_id
            || identity.cgroup_id != Some(cgroup_id)
        {
            return Err(HandshakeError::KernelEvidence);
        }
        Ok(Self::new(before, identity, credentials, cgroup_id))
    }

    fn new(
        information: ProcessInformation,
        identity: ProcessIdentity,
        credentials: ProcessCredentials,
        cgroup_id: u64,
    ) -> Self {
        Self {
            process_id: information.process_id,
            thread_group_id: information.thread_group_id,
            start_time_ticks: identity.start_time_ticks,
            cgroup_id,
            real_user_id: credentials.real_user_id,
            real_group_id: credentials.real_group_id,
            effective_user_id: credentials.effective_user_id,
            effective_group_id: credentials.effective_group_id,
            saved_user_id: credentials.saved_user_id,
            saved_group_id: credentials.saved_group_id,
            filesystem_user_id: credentials.filesystem_user_id,
            filesystem_group_id: credentials.filesystem_group_id,
        }
    }

    fn validate(self, pidfd: &PidFd) -> Result<(), HandshakeError> {
        let current = Self::observe(pidfd, None)?;
        self.require_current_observation(current, true)
    }

    // Shares the original handshake's connection-establishment bookend. The
    // listening PID1 and the service's later record subject are distinct.
    fn validate_connection(
        self,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), HandshakeError> {
        self.validate(peer.pidfd())?;
        if peer.credentials().pid().get() != self.process_id
            || peer.credentials().uid() != self.effective_user_id
            || peer.credentials().gid() != self.effective_group_id
        {
            return Err(HandshakeError::KernelEvidence);
        }
        Ok(())
    }

    fn require_current_observation(self, current: Self, alive: bool) -> Result<(), HandshakeError> {
        if !alive || current != self {
            return Err(HandshakeError::KernelEvidence);
        }
        Ok(())
    }
}

/// Retains the complete native result of a refused selected HELLO send.
///
/// It owns only returned transport custody. It provides no retry, admission,
/// completion or resource permission, and has no public constructor.
#[derive(Debug)]
pub struct RetainedStorageHandshakeSendFailureV1 {
    attempt: aos_sandbox_linux::seqpacket::StorageSeqpacketSendAttemptV1,
}

impl core::fmt::Display for RetainedStorageHandshakeSendFailureV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("selected HELLO send failed with its native original retained")
    }
}

impl std::error::Error for RetainedStorageHandshakeSendFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.attempt.failure()
    }
}

enum HandshakeError {
    Local(BrokerSessionSecurityError),
    RemoteInvalid,
    KernelEvidence,
    RetainedProcess(RetainedProcessEvidenceFailureV1),
    RetryableTransport,
    RetainedReceive(aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1),
    RetainedSend(aos_sandbox_linux::seqpacket::RetainedSeqpacketSendErrorV1),
    SelectedSend(RetainedStorageHandshakeSendFailureV1),
    RecordBinding(aos_sandbox_linux::seqpacket::RecordBindingError),
    SelectedPreparation(Box<RetainedStoragePreparationHandshakeFailureV1>),
    Transport,
}

impl core::fmt::Debug for HandshakeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Local(error) => formatter.debug_tuple("Local").field(error).finish(),
            Self::RemoteInvalid => formatter.write_str("RemoteInvalid"),
            Self::KernelEvidence => formatter.write_str("KernelEvidence"),
            Self::RetainedProcess(_) => formatter.write_str("KernelEvidence"),
            Self::RetryableTransport => formatter.write_str("RetryableTransport"),
            Self::RetainedReceive(error) => formatter.debug_tuple("RetainedReceive").field(error).finish(),
            Self::RetainedSend(error) => formatter.debug_tuple("RetainedSend").field(error).finish(),
            Self::SelectedSend(error) => formatter.debug_tuple("SelectedSend").field(error).finish(),
            Self::RecordBinding(error) => formatter.debug_tuple("RecordBinding").field(error).finish(),
            Self::SelectedPreparation(error) => formatter.debug_tuple("SelectedPreparation").field(error).finish(),
            Self::Transport => formatter.write_str("Transport"),
        }
    }
}

impl core::fmt::Display for HandshakeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Local(error) => core::fmt::Display::fmt(error, formatter),
            Self::RemoteInvalid => formatter.write_str("original handshake remote evidence is invalid"),
            Self::KernelEvidence => formatter.write_str("original handshake kernel evidence changed"),
            Self::RetainedProcess(error) => core::fmt::Display::fmt(error, formatter),
            Self::RetryableTransport => formatter.write_str("original handshake transport was not ready"),
            Self::RetainedReceive(_) => formatter.write_str("original selected Storage receive failed with custody retained"),
            Self::RetainedSend(_) => formatter.write_str("original selected Storage send failed with custody retained"),
            Self::SelectedSend(error) => core::fmt::Display::fmt(error, formatter),
            Self::RecordBinding(_) => formatter.write_str("original selected Storage record binding failed"),
            Self::SelectedPreparation(error) => core::fmt::Display::fmt(error, formatter),
            Self::Transport => formatter.write_str("original handshake transport failed"),
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Local(error) => Some(error),
            Self::RetainedProcess(error) => Some(error),
            Self::RetainedReceive(error) => Some(error),
            Self::RetainedSend(error) => Some(error),
            Self::SelectedSend(error) => Some(error),
            Self::RecordBinding(error) => Some(error),
            Self::SelectedPreparation(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl HandshakeError {
    fn transport(error: SeqpacketError) -> Self {
        match error {
            SeqpacketError::WouldBlock | SeqpacketError::Interrupted => Self::RetryableTransport,
            SeqpacketError::EmptyRecord
            | SeqpacketError::RecordTooLarge { .. }
            | SeqpacketError::ControlTruncated
            | SeqpacketError::PayloadTruncated
            | SeqpacketError::LengthChanged { .. }
            | SeqpacketError::Ancillary(_) => Self::RemoteInvalid,
            SeqpacketError::Kernel(_)
            | SeqpacketError::Closed
            | SeqpacketError::InvalidMaximum
            | SeqpacketError::PartialSend { .. }
            | SeqpacketError::PeerIdentity(_) => Self::Transport,
        }
    }
}

impl From<BrokerSessionSecurityError> for HandshakeError {
    fn from(error: BrokerSessionSecurityError) -> Self {
        Self::Local(error)
    }
}

enum SelectedBrokerFailureOwnerV1 {
    Publication(BrokerPublicationFlight),
    ClientHello {
        stage: BrokerAwaitClientHello,
        // A successful raw receive remains original custody even when its
        // following native/grammar/authentication observation refuses it.
        _flight: Option<BoundFlight>,
    },
    ServerHello(BrokerHelloFlight),
    ClientPublication { stage: ClientAwaitPublication, _flight: Option<BoundFlight> },
    ClientSend(ClientHelloFlight),
    ClientBrokerHello { stage: ClientAwaitBrokerHello, _flight: Option<BoundFlight> },
}

impl SelectedBrokerFailureOwnerV1 {
    fn typed_hello_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ClientBrokerHello { stage, .. } => stage.typed.as_ref()?.failure(),
            _ => None,
        }
    }

    fn endpoint_failure_for(
        &self,
        returned: &BrokerSessionSecurityError,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Publication(stage) => stage.custody.retained_revalidation_failure_for(returned),
            Self::ClientHello { stage, .. } => stage.custody.retained_revalidation_failure_for(returned),
            Self::ServerHello(stage) => stage.custody.retained_revalidation_failure_for(returned),
            Self::ClientPublication { stage, .. } => stage.custody.retained_revalidation_failure_for(returned),
            Self::ClientSend(stage) => stage.custody.retained_revalidation_failure_for(returned),
            Self::ClientBrokerHello { stage, .. } => stage.custody.retained_revalidation_failure_for(returned),
        }
    }

    fn carrier(&self) -> &HandshakeCarrier {
        match self {
            Self::Publication(stage) => &stage.carrier,
            Self::ClientHello { stage, .. } => &stage.carrier,
            Self::ServerHello(stage) => &stage.carrier,
            Self::ClientPublication { stage, .. } => &stage.carrier,
            Self::ClientSend(stage) => &stage.carrier,
            Self::ClientBrokerHello { stage, .. } => &stage.carrier,
        }
    }

    fn selected(&self) -> bool {
        self.carrier().receive_profile.retains_original()
    }
    fn retained_client_parts_mut_v1(&mut self)
        -> Option<(&mut ProtectedBrokerSessionOwnerV1, &SeqpacketSocket)>
    {
        match self {
            Self::ClientPublication { stage, .. } => client_retained_parts_v1(&mut stage.custody, &stage.carrier),
            Self::ClientSend(stage) => client_retained_parts_v1(&mut stage.custody, &stage.carrier),
            Self::ClientBrokerHello { stage, .. } => client_retained_parts_v1(&mut stage.custody, &stage.carrier),
            Self::Publication(_) | Self::ClientHello { .. } | Self::ServerHello(_) => None,
        }
    }
}

// Each selected bookend executes independently after the actual action.
// Keep all returned Results on a negative path, including positive siblings.
#[derive(Debug)]
struct SelectedBrokerHandshakePostV1 {
    protected: Result<(), BrokerSessionSecurityError>,
    peer: Result<(), HandshakeError>,
    subject: Option<Result<(), HandshakeError>>,
}

impl SelectedBrokerHandshakePostV1 {
    fn observe(
        custody: &mut ProtectedBrokerSessionBrokerV1,
        carrier: &HandshakeCarrier,
        subject: Option<&RetainedSubject>,
    ) -> Self {
        let protected = custody.revalidate_handshake_custody();
        let peer = carrier.validate_peer();
        let subject = subject.map(|subject| carrier.validate_subject(subject));
        Self { protected, peer, subject }
    }

    fn observe_client(
        custody: &mut ClientHandshakeCustodyV1,
        carrier: &HandshakeCarrier,
        subject: Option<&RetainedSubject>,
    ) -> Self {
        let protected = custody.revalidate_handshake_custody();
        let peer = carrier.validate_peer();
        let subject = subject.map(|subject| carrier.validate_subject(subject));
        Self { protected, peer, subject }
    }

    fn first_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Err(error) = &self.protected { return Some(error); }
        if let Err(error) = &self.peer { return Some(error); }
        if let Some(Err(error)) = &self.subject { return Some(error); }
        None
    }
}

enum SelectedHandshakeFailureCauseV1 {
    Flight(HandshakeError),
    Post,
    Outer(crate::DormantBrokerSessionHandshakeErrorV1),
}

/// Retains the failed selected raw handshake without exposing its originals.
///
/// The actual first error, independent postcheck and existing reducer stage
/// remain owned. This historical custody provides no retry or effect authority.
pub struct RetainedStoragePreparationHandshakeFailureV1 {
    first: SelectedHandshakeFailureCauseV1,
    post: Option<HandshakeError>,
    postchecks: Option<SelectedBrokerHandshakePostV1>,
    _owner: SelectedBrokerFailureOwnerV1,
}

impl RetainedStoragePreparationHandshakeFailureV1 {
    fn resolve_returned_endpoint_error<'cause>(
        &'cause self,
        returned: &'cause (dyn std::error::Error + 'static),
    ) -> &'cause (dyn std::error::Error + 'static) {
        let protected = returned.downcast_ref::<BrokerSessionSecurityError>()
            .or_else(|| match returned.downcast_ref::<HandshakeError>() {
                Some(HandshakeError::Local(cause)) => Some(cause),
                _ => None,
            })
            .or_else(|| match returned.downcast_ref::<crate::DormantBrokerSessionHandshakeErrorV1>() {
                Some(crate::DormantBrokerSessionHandshakeErrorV1::Protected(cause)) => Some(cause),
                _ => None,
            });
        protected.and_then(|cause| self._owner.endpoint_failure_for(cause)).unwrap_or(returned)
    }

    fn first(&self) -> &(dyn std::error::Error + 'static) {
        let returned: &(dyn std::error::Error + 'static) = match &self.first {
            SelectedHandshakeFailureCauseV1::Flight(error) => error,
            SelectedHandshakeFailureCauseV1::Post => self.postchecks.as_ref()
                .and_then(SelectedBrokerHandshakePostV1::first_failure)
                .unwrap_or(&HandshakeError::KernelEvidence),
            SelectedHandshakeFailureCauseV1::Outer(error) => error,
        };
        if matches!(self.first, SelectedHandshakeFailureCauseV1::Flight(_)) {
            if let Some(cause) = self._owner.typed_hello_failure_v1() {
                return cause;
            }
        }
        // Resolve only the exact marker returned by this actual endpoint stage.
        // A later endpoint post cannot replace an earlier semantic refusal.
        self.resolve_returned_endpoint_error(returned)
    }

    /// Borrows an independently retained later postcheck refusal.
    ///
    /// Absence does not establish that every post ran or succeeded.
    #[must_use]
    pub fn postcheck_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.postchecks.as_ref().and_then(SelectedBrokerHandshakePostV1::first_failure)
            .or_else(|| self.post.as_ref().map(|error| error as &dyn std::error::Error))
            .map(|returned| self.resolve_returned_endpoint_error(returned))
    }
}

impl core::fmt::Debug for RetainedStoragePreparationHandshakeFailureV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("RetainedStoragePreparationHandshakeFailureV1")
            .field("first", &self.first())
            .field("post", &self.post)
            .field("postchecks", &self.postchecks)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Display for RetainedStoragePreparationHandshakeFailureV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "selected Storage handshake original retained: {}", self.first())
    }
}

impl std::error::Error for RetainedStoragePreparationHandshakeFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.first())
    }
}

fn retain_selected_broker_failure_v1(
    owner: SelectedBrokerFailureOwnerV1,
    first: HandshakeError,
    post: Option<HandshakeError>,
) -> HandshakeError {
    if !owner.selected() { return post.unwrap_or(first); }
    HandshakeError::SelectedPreparation(Box::new(RetainedStoragePreparationHandshakeFailureV1 {
        first: SelectedHandshakeFailureCauseV1::Flight(first), post, postchecks: None, _owner: owner,
    }))
}

fn retain_selected_broker_post_failure_v1(
    owner: SelectedBrokerFailureOwnerV1,
    action_error: Option<HandshakeError>,
    postchecks: SelectedBrokerHandshakePostV1,
) -> HandshakeError {
    // Only the selected branch calls this after action or a post has refused.
    // A missing post failure still yields a closed negative, never authority.
    let first = action_error.map(SelectedHandshakeFailureCauseV1::Flight)
        .unwrap_or(SelectedHandshakeFailureCauseV1::Post);
    HandshakeError::SelectedPreparation(Box::new(RetainedStoragePreparationHandshakeFailureV1 {
        first, post: None, postchecks: Some(postchecks), _owner: owner,
    }))
}

fn retain_selected_client_failure_v1(
    owner: SelectedBrokerFailureOwnerV1,
    first: HandshakeError,
    post: Option<SelectedBrokerHandshakePostV1>,
) -> HandshakeError {
    match post {
        Some(post) => retain_selected_broker_post_failure_v1(owner, Some(first), post),
        None => retain_selected_broker_failure_v1(owner, first, None),
    }
}

// Fixed upper error/owner carriers only. Raw/model/payload lanes are priced
// by the same selected fixed supplier; no new admission is returned here.
pub(crate) fn storage_preparation_handshake_failure_obligations_v1() -> Option<(usize, usize)> {
    let bytes = std::mem::size_of::<RetainedStoragePreparationHandshakeFailureV1>().checked_mul(2)?
        .checked_add(std::mem::size_of::<HandshakeError>())?
        .checked_add(std::mem::size_of::<DormantBrokerSessionHandshakeErrorV1>())?
        .checked_add(std::mem::size_of::<crate::DormantBrokerSessionHandshakeErrorV1>())?;
    let (typed_bytes, typed_cells) = SelectedClientHelloVerificationV1::receiving_obligations_v1()?;
    Some((bytes.checked_add(typed_bytes)?, 2usize.checked_add(typed_cells)?))
}

enum Transition<Complete, Retry> {
    Complete(Complete),
    Retry(Retry),
    Failed(HandshakeError),
}

// Fresh endpoints and positively retired Storage Sessions share the exact
// HELLO state machine. The retained variant keeps the sole Journal, floor and
// endpoint together; no key reload or second lock can occur during rehandshake.
enum BrokerHandshakeCustodyV1 {
    Fresh(ProtectedBrokerSessionBrokerV1),
    RetainedStorage(ProtectedBrokerSessionOwnerV1),
}

impl std::ops::Deref for BrokerHandshakeCustodyV1 {
    type Target = ProtectedBrokerSessionBrokerV1;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Fresh(endpoint) => endpoint,
            Self::RetainedStorage(owner) => owner.retained_storage_broker_v1(),
        }
    }
}

impl std::ops::DerefMut for BrokerHandshakeCustodyV1 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Fresh(endpoint) => endpoint,
            Self::RetainedStorage(owner) => owner.retained_storage_broker_mut_v1(),
        }
    }
}

enum BrokerHelloSelectionV5 {
    Provided(BrokerServerHello),
    HostCleanupDeferred,
}

impl BrokerHelloSelectionV5 {
    fn after_verified_client_v1(&self, client: &aos_sandbox_broker_session_protocol::CanonicalBrokerClientHelloV1)
        -> Result<BrokerServerHello, HandshakeError> {
        let methods = &client.message().required_methods;
        match self {
            Self::Provided(hello) => Ok(hello.clone()),
            Self::HostCleanupDeferred => {
                let selected = if methods.len() == 2
                    && methods[0].as_known() == Some(BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME)
                    && methods[1].as_known() == Some(BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME) {
                    aos_sandbox_broker_session_protocol::profile::host_stop_cleanup_server_hello_v1()
                } else if methods.len() == 2
                    && methods[0].as_known() == Some(BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2)
                    && methods[1].as_known() == Some(BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2) {
                    aos_sandbox_broker_session_protocol::profile::host_no_apply_cleanup_server_hello_v1()
                } else {
                    // Preserve the original ordinary Host negotiation and its
                    // protected head gate. It supplies no cleanup-slot bypass.
                    aos_sandbox_broker_session_protocol::profile::production_broker_server_hello_v1(
                        BrokerSessionProtocolV1::Host, Audience::AUDIENCE_NODE_CONTROLLER,
                        aos_sandbox_broker_session_protocol::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES as u32,
                    )
                };
                selected.map_err(|_| HandshakeError::RemoteInvalid)
            }
        }
    }

    fn require_transcript_v1(&self, transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), HandshakeError> {
        if matches!(self, Self::HostCleanupDeferred)
            && !aos_sandbox_broker_session_protocol::profile::is_host_stop_cleanup_transcript_v1(transcript)
            && !aos_sandbox_broker_session_protocol::profile::is_host_no_apply_cleanup_transcript_v1(transcript)
        {
            let ordinary = aos_sandbox_broker_session_protocol::profile::authenticated_broker_methods_for_role_v1(
                BrokerSessionProtocolV1::Host, Audience::AUDIENCE_NODE_CONTROLLER);
            if transcript.protocol() != BrokerSessionProtocolV1::Host
                || transcript.audience() != Audience::AUDIENCE_NODE_CONTROLLER
                || transcript.negotiated_methods() != ordinary
            { return Err(HandshakeError::RemoteInvalid); }
        }
        Ok(())
    }
}

struct BrokerPublicationFlight {
    custody: BrokerHandshakeCustodyV1,
    carrier: HandshakeCarrier,
    pending: [u8; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES],
    broker_hello: BrokerHelloSelectionV5,
}

impl BrokerPublicationFlight {
    fn begin(
        mut custody: BrokerHandshakeCustodyV1,
        carrier: HandshakeCarrier,
        broker_hello: BrokerServerHello,
    ) -> Result<Self, HandshakeError> {
        carrier.validate_peer()?;
        let pending = custody.finalize_endpoint_publication()?;
        Ok(Self {
            custody,
            carrier,
            pending,
            broker_hello: BrokerHelloSelectionV5::Provided(broker_hello),
        })
    }

    fn send(mut self) -> Transition<BrokerAwaitClientHello, Self> {
        if let Err(error) = self.custody.revalidate_handshake_custody() {
            return Transition::Failed(retain_selected_broker_failure_v1(
                SelectedBrokerFailureOwnerV1::Publication(self), error.into(), None,
            ));
        }
        if let Err(error) = self.carrier.validate_peer() {
            return Transition::Failed(retain_selected_broker_failure_v1(
                SelectedBrokerFailureOwnerV1::Publication(self), error, None,
            ));
        }
        let send_result = self.carrier.send_broker_original(&self.pending);
        let selected_post = self.carrier.receive_profile.retains_original()
            .then(|| SelectedBrokerHandshakePostV1::observe(
                &mut self.custody, &self.carrier, None,
            ));
        if selected_post.as_ref().is_some_and(|post| post.first_failure().is_some()) {
            self.carrier.close();
            if let Some(post) = selected_post {
                return Transition::Failed(retain_selected_broker_post_failure_v1(
                    SelectedBrokerFailureOwnerV1::Publication(self), send_result.err(), post,
                ));
            }
        }
        let currentness = if selected_post.is_none() {
            self.custody.revalidate_handshake_custody()
                .map_err(HandshakeError::from)
                .and_then(|()| self.carrier.validate_peer())
        } else { Ok(()) };
        if let Err(post) = currentness {
            self.carrier.close();
            let (first, post) = match send_result {
                Err(error) => (error, Some(post)), Ok(()) => (post, None),
            };
            return Transition::Failed(retain_selected_broker_failure_v1(
                SelectedBrokerFailureOwnerV1::Publication(self), first, post,
            ));
        }
        match send_result {
            Ok(()) => {}
            Err(HandshakeError::RetryableTransport) => {
                return Transition::Retry(self);
            }
            Err(error) => {
                self.carrier.close();
                return Transition::Failed(match selected_post {
                    Some(post) => retain_selected_broker_post_failure_v1(
                        SelectedBrokerFailureOwnerV1::Publication(self), Some(error), post,
                    ),
                    None => retain_selected_broker_failure_v1(
                        SelectedBrokerFailureOwnerV1::Publication(self), error, None,
                    ),
                });
            }
        }
        Transition::Complete(BrokerAwaitClientHello {
            custody: self.custody,
            carrier: self.carrier,
            publication: self.pending,
            broker_hello: self.broker_hello,
        })
    }
}

struct BrokerAwaitClientHello {
    custody: BrokerHandshakeCustodyV1,
    carrier: HandshakeCarrier,
    publication: [u8; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES],
    broker_hello: BrokerHelloSelectionV5,
}

impl BrokerAwaitClientHello {
    fn receive(mut self) -> Transition<BrokerHelloFlight, Self> {
        if let Err(error) = self.custody.revalidate_handshake_custody() {
            return Transition::Failed(retain_selected_broker_failure_v1(
                SelectedBrokerFailureOwnerV1::ClientHello { stage: self, _flight: None },
                error.into(), None,
            ));
        }
        if let Err(error) = self.carrier.validate_peer() {
            self.carrier.close();
            return Transition::Failed(retain_selected_broker_failure_v1(
                SelectedBrokerFailureOwnerV1::ClientHello { stage: self, _flight: None },
                error, None,
            ));
        }
        let receive_result = self.carrier.receive(CLIENT_HELLO_MAXIMUM_BYTES);
        let selected_post = self.carrier.receive_profile.retains_original()
            .then(|| SelectedBrokerHandshakePostV1::observe(
                &mut self.custody, &self.carrier,
                receive_result.as_ref().ok().map(|flight| &flight.subject),
            ));
        if selected_post.as_ref().is_some_and(|post| post.first_failure().is_some()) {
            self.carrier.close();
            if let Some(post) = selected_post {
                let (action_error, flight) = match receive_result {
                    Err(error) => (Some(error), None), Ok(flight) => (None, Some(flight)),
                };
                return Transition::Failed(retain_selected_broker_post_failure_v1(
                    SelectedBrokerFailureOwnerV1::ClientHello { stage: self, _flight: flight },
                    action_error, post,
                ));
            }
        }
        let currentness = if selected_post.is_none() {
            self.custody.revalidate_handshake_custody()
                .map_err(HandshakeError::from)
                .and_then(|()| self.carrier.validate_peer())
        } else { Ok(()) };
        if let Err(post) = currentness {
            self.carrier.close();
            let (first, post, flight) = match receive_result {
                Err(error) => (error, Some(post), None),
                Ok(flight) => (post, None, Some(flight)),
            };
            return Transition::Failed(retain_selected_broker_failure_v1(
                SelectedBrokerFailureOwnerV1::ClientHello { stage: self, _flight: flight }, first, post,
            ));
        }
        let flight = match receive_result {
            Ok(flight) => flight,
            Err(HandshakeError::RetryableTransport) => return Transition::Retry(self),
            Err(error) => {
                self.carrier.close();
                return Transition::Failed(match selected_post {
                    Some(post) => retain_selected_broker_post_failure_v1(
                        SelectedBrokerFailureOwnerV1::ClientHello { stage: self, _flight: None }, Some(error), post,
                    ),
                    None => retain_selected_broker_failure_v1(
                        SelectedBrokerFailureOwnerV1::ClientHello { stage: self, _flight: None }, error, None,
                    ),
                });
            }
        };
        let completed = (|| {
            self.carrier.validate_subject(&flight.subject)?;
            let canonical_client = decode_canonical_client_hello_v1(&flight.payload)
                .map_err(|_| HandshakeError::RemoteInvalid)?;
            let key = self.custody.client_hello_verification_key()?;
            let signed = verify_client_hello_signature_v1(&canonical_client, &key)
                .map_err(|_| HandshakeError::RemoteInvalid)?;
            let client_process = signed.authenticated_client_process();
            if client_process == self.custody.process_execution_id_bytes() {
                return Err(HandshakeError::RemoteInvalid);
            }
            let context = self
                .custody
                .context_for_handshake(client_process)
                .map_err(|_| HandshakeError::Local(self.custody.poison_handshake_custody()))?;
            let verified_client = verify_client_hello_context_v1(signed, &context)
                .map_err(|_| HandshakeError::RemoteInvalid)?;
            // Bootstrap pays only this native prefix. Select the exact live
            // roster after the same signature, context and native peer checks.
            let hello = self.broker_hello.after_verified_client_v1(&canonical_client)?;
            let broker_packet = self
                .custody
                .finalize_broker_hello(hello, &canonical_client)?;
            let broker = decode_canonical_server_hello_v1(&broker_packet)
                .map_err(|_| HandshakeError::RemoteInvalid)?;
            let transcript = verify_broker_session_transcript_after_client_v1(
                &verified_client,
                &broker,
                &context,
            )
            .map_err(|_| HandshakeError::Local(self.custody.poison_handshake_custody()))?;
            self.broker_hello.require_transcript_v1(&transcript)?;
            self.custody.revalidate_handshake_custody()?;
            self.carrier.validate_peer()?;
            self.carrier.validate_subject(&flight.subject)?;
            Ok((broker_packet, transcript))
        })();
        let (broker_packet, transcript) = match completed {
            Ok(value) => value,
            Err(error) => {
                self.carrier.close();
                return Transition::Failed(retain_selected_broker_failure_v1(
                    SelectedBrokerFailureOwnerV1::ClientHello { stage: self, _flight: Some(flight) }, error, None,
                ));
            }
        };
        Transition::Complete(BrokerHelloFlight {
            custody: self.custody,
            carrier: self.carrier,
            publication: self.publication,
            client_packet: flight.payload,
            client_subject: flight.subject,
            broker_packet,
            transcript,
        })
    }
}

struct BrokerHelloFlight {
    custody: BrokerHandshakeCustodyV1,
    carrier: HandshakeCarrier,
    publication: [u8; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES],
    client_packet: Vec<u8>,
    client_subject: RetainedSubject,
    broker_packet: Vec<u8>,
    transcript: VerifiedBrokerSessionTranscriptV1,
}

impl BrokerHelloFlight {
    fn send(mut self) -> Transition<InertProvisionalBrokerSession, Self> {
        if let Err(error) = self.custody.revalidate_handshake_custody() {
            return Transition::Failed(retain_selected_broker_failure_v1(
                SelectedBrokerFailureOwnerV1::ServerHello(self), error.into(), None,
            ));
        }
        if let Err(error) = self.carrier.validate_peer() {
            self.carrier.close();
            return Transition::Failed(retain_selected_broker_failure_v1(
                SelectedBrokerFailureOwnerV1::ServerHello(self), error, None,
            ));
        }
        if let Err(error) = self.carrier.validate_subject(&self.client_subject) {
            self.carrier.close();
            return Transition::Failed(retain_selected_broker_failure_v1(
                SelectedBrokerFailureOwnerV1::ServerHello(self), error, None,
            ));
        }
        let send_result = self.carrier.send_broker_original(&self.broker_packet);
        let selected_post = self.carrier.receive_profile.retains_original()
            .then(|| SelectedBrokerHandshakePostV1::observe(
                &mut self.custody, &self.carrier, Some(&self.client_subject),
            ));
        if selected_post.as_ref().is_some_and(|post| post.first_failure().is_some()) {
            self.carrier.close();
            if let Some(post) = selected_post {
                return Transition::Failed(retain_selected_broker_post_failure_v1(
                    SelectedBrokerFailureOwnerV1::ServerHello(self), send_result.err(), post,
                ));
            }
        }
        let currentness = if selected_post.is_none() {
            self.custody.revalidate_handshake_custody()
                .map_err(HandshakeError::from)
                .and_then(|()| self.carrier.validate_peer())
                .and_then(|()| self.carrier.validate_subject(&self.client_subject))
        } else { Ok(()) };
        if let Err(post) = currentness {
            self.carrier.close();
            let (first, post) = match send_result {
                Err(error) => (error, Some(post)), Ok(()) => (post, None),
            };
            return Transition::Failed(retain_selected_broker_failure_v1(
                SelectedBrokerFailureOwnerV1::ServerHello(self), first, post,
            ));
        }
        match send_result {
            Ok(()) => {}
            Err(HandshakeError::RetryableTransport) => {
                return Transition::Retry(self);
            }
            Err(error) => {
                self.carrier.close();
                return Transition::Failed(match selected_post {
                    Some(post) => retain_selected_broker_post_failure_v1(
                        SelectedBrokerFailureOwnerV1::ServerHello(self), Some(error), post,
                    ),
                    None => retain_selected_broker_failure_v1(
                        SelectedBrokerFailureOwnerV1::ServerHello(self), error, None,
                    ),
                });
            }
        }
        Transition::Complete(InertProvisionalBrokerSession {
            _custody: self.custody,
            _carrier: self.carrier,
            _publication: self.publication,
            _client_packet: self.client_packet,
            _client_subject: self.client_subject,
            _broker_packet: self.broker_packet,
            _transcript: self.transcript,
        })
    }
}

struct SelectedClientUnwindFenceV1(bool);

impl SelectedClientUnwindFenceV1 {
    fn for_carrier(carrier: &HandshakeCarrier) -> Self {
        Self(carrier.receive_profile.retains_original())
    }
}

impl Drop for SelectedClientUnwindFenceV1 {
    fn drop(&mut self) {
        if self.0 && std::thread::panicking() { std::process::abort(); }
    }
}

enum ClientHandshakeCustodyV1 {
    Fresh(ProtectedBrokerSessionClientV1),
    RetainedStorage(ProtectedBrokerSessionOwnerV1),
}

fn client_retained_parts_v1<'owner, 'socket>(
    custody: &'owner mut ClientHandshakeCustodyV1,
    carrier: &'socket HandshakeCarrier,
) -> Option<(&'owner mut ProtectedBrokerSessionOwnerV1, &'socket SeqpacketSocket)> {
    let ClientHandshakeCustodyV1::RetainedStorage(owner) = custody else { return None; };
    let HandshakeTransport::Ordinary(socket) = &carrier.transport else { return None; };
    Some((owner, socket))
}

impl std::ops::Deref for ClientHandshakeCustodyV1 {
    type Target = ProtectedBrokerSessionClientV1;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Fresh(endpoint) => endpoint,
            Self::RetainedStorage(owner) => owner.retained_storage_client_endpoint_v1(),
        }
    }
}

impl std::ops::DerefMut for ClientHandshakeCustodyV1 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Fresh(endpoint) => endpoint,
            Self::RetainedStorage(owner) => owner.retained_storage_client_endpoint_mut_v1(),
        }
    }
}

struct ClientAwaitPublication {
    custody: ClientHandshakeCustodyV1,
    selected_client_packet: Option<Vec<u8>>,
    carrier: HandshakeCarrier,
    client_hello: BrokerClientHello,
}

impl ClientAwaitPublication {
    fn begin(
        custody: ClientHandshakeCustodyV1,
        carrier: HandshakeCarrier,
        client_hello: BrokerClientHello,
    ) -> Result<Self, HandshakeError> {
        carrier.validate_peer()?;
        Ok(Self {
            custody,
            selected_client_packet: None,
            carrier,
            client_hello,
        })
    }

    fn receive(mut self) -> Transition<ClientHelloFlight, Self> {
        let _stage_fence = SelectedClientUnwindFenceV1::for_carrier(&self.carrier);
        if let Err(error) = self.custody.revalidate_handshake_custody() {
            if !self.carrier.receive_profile.retains_original() {
                return Transition::Failed(error.into());
            }
            return Transition::Failed(retain_selected_broker_failure_v1(
                SelectedBrokerFailureOwnerV1::ClientPublication { stage: self, _flight: None }, error.into(), None,
            ));
        }
        if let Err(error) = self.carrier.validate_peer() {
            self.carrier.close();
            if !self.carrier.receive_profile.retains_original() {
                return Transition::Failed(error);
            }
            return Transition::Failed(retain_selected_broker_failure_v1(
                SelectedBrokerFailureOwnerV1::ClientPublication { stage: self, _flight: None }, error, None,
            ));
        }
        let receive_result = self
            .carrier
            .receive(BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES);
        // Declared after the actual action Result, so an unexpected unwind
        // cannot dispose its native sample before the resident outer fence.
        let _action_fence = SelectedClientUnwindFenceV1::for_carrier(&self.carrier);
        let selected_post = self.carrier.receive_profile.retains_original()
            .then(|| SelectedBrokerHandshakePostV1::observe_client(
                &mut self.custody, &self.carrier, None,
            ));
        let currentness = if selected_post.is_none() { self
            .custody
            .revalidate_handshake_custody()
            .map_err(HandshakeError::from)
            .and_then(|()| self.carrier.validate_peer()) } else { Ok(()) };
        if selected_post.as_ref().is_some_and(|post| post.first_failure().is_some()) {
            // Move the whole action result only after choosing its first cause.
            return Transition::Failed(match receive_result {
                Ok(flight) => retain_selected_broker_post_failure_v1(
                    SelectedBrokerFailureOwnerV1::ClientPublication { stage: self, _flight: Some(flight) }, None,
                    match selected_post { Some(post) => post, None => std::process::abort() },
                ),
                Err(error) => retain_selected_broker_post_failure_v1(
                    SelectedBrokerFailureOwnerV1::ClientPublication { stage: self, _flight: None }, Some(error.into()),
                    match selected_post { Some(post) => post, None => std::process::abort() },
                ),
            });
        }
        if let Err(error) = currentness {
            self.carrier.close();
            if !self.carrier.receive_profile.retains_original() {
                return Transition::Failed(error);
            }
            return Transition::Failed(retain_selected_client_failure_v1(
                SelectedBrokerFailureOwnerV1::ClientPublication { stage: self, _flight: None }, error, selected_post,
            ));
        }
        let flight = match receive_result {
            Ok(flight) => flight,
            Err(HandshakeError::RetryableTransport) => return Transition::Retry(self),
            Err(error) => {
                self.carrier.close();
                if !self.carrier.receive_profile.retains_original() {
                    return Transition::Failed(error);
                }
                return Transition::Failed(retain_selected_client_failure_v1(
                SelectedBrokerFailureOwnerV1::ClientPublication { stage: self, _flight: None }, error, selected_post,
            ));
            }
        };
        let _flight_fence = SelectedClientUnwindFenceV1::for_carrier(&self.carrier);
        let completed = (|| {
            self.carrier.validate_subject(&flight.subject)?;
            let publication =
                UntrustedBrokerSessionEndpointPublicationV1::decode_untrusted(&flight.payload)
                    .map_err(|_| HandshakeError::RemoteInvalid)?;
            let local_binding = self.custody.manifest_binding()?;
            if publication.untrusted_manifest_binding() != *local_binding.as_bytes() {
                return Err(HandshakeError::RemoteInvalid);
            }
            let broker_process = publication.untrusted_broker_process_execution_id();
            if broker_process == self.custody.process_execution_id_bytes() {
                return Err(HandshakeError::RemoteInvalid);
            }
            let client_packet = self
                .custody
                .finalize_client_hello(self.client_hello.clone(), broker_process)?;
            let mut ordinary_packet = None;
            let selected = self.carrier.receive_profile.retains_original();
            if selected {
                self.selected_client_packet = Some(client_packet);
            } else {
                ordinary_packet = Some(client_packet);
            }
            self.custody.revalidate_handshake_custody()?;
            self.carrier.validate_peer()?;
            self.carrier.validate_subject(&flight.subject)?;
            let packet = if selected { self.selected_client_packet.take() } else { ordinary_packet.take() }
                .ok_or(HandshakeError::RemoteInvalid)?;
            Ok((publication, packet))
        })();
        let (publication, client_packet) = match completed {
            Ok(value) => value,
            Err(error) => {
                self.carrier.close();
                if !self.carrier.receive_profile.retains_original() {
                    return Transition::Failed(error);
                }
                return Transition::Failed(retain_selected_client_failure_v1(
                SelectedBrokerFailureOwnerV1::ClientPublication { stage: self, _flight: Some(flight) }, error, selected_post,
            ));
            }
        };
        Transition::Complete(ClientHelloFlight {
            custody: self.custody,
            carrier: self.carrier,
            publication,
            publication_packet: flight.payload,
            publication_subject: flight.subject,
            client_packet,
        })
    }
}

enum ClientSendObservationV1 {
    Ordinary(Result<(), SeqpacketError>),
    Selected(Result<(), HandshakeError>),
}

struct ClientHelloFlight {
    custody: ClientHandshakeCustodyV1,
    carrier: HandshakeCarrier,
    publication: UntrustedBrokerSessionEndpointPublicationV1,
    publication_packet: Vec<u8>,
    publication_subject: RetainedSubject,
    client_packet: Vec<u8>,
}

impl ClientHelloFlight {
    fn send(mut self) -> Transition<ClientAwaitBrokerHello, Self> {
        let _stage_fence = SelectedClientUnwindFenceV1::for_carrier(&self.carrier);
        if let Err(error) = self.custody.revalidate_handshake_custody() {
            if !self.carrier.receive_profile.retains_original() {
                return Transition::Failed(error.into());
            }
            return Transition::Failed(retain_selected_broker_failure_v1(
                SelectedBrokerFailureOwnerV1::ClientSend(self), error.into(), None,
            ));
        }
        if let Err(error) = self.carrier.validate_peer() {
            self.carrier.close();
            if !self.carrier.receive_profile.retains_original() {
                return Transition::Failed(error);
            }
            return Transition::Failed(retain_selected_broker_failure_v1(
                SelectedBrokerFailureOwnerV1::ClientSend(self), error, None,
            ));
        }
        if let Err(error) = self.carrier.validate_subject(&self.publication_subject) {
            self.carrier.close();
            if !self.carrier.receive_profile.retains_original() {
                return Transition::Failed(error);
            }
            return Transition::Failed(retain_selected_broker_failure_v1(
                SelectedBrokerFailureOwnerV1::ClientSend(self), error, None,
            ));
        }
        let send_result = if self.carrier.receive_profile.retains_original() {
            ClientSendObservationV1::Selected(self.carrier.send_broker_original(&self.client_packet))
        } else {
            ClientSendObservationV1::Ordinary(self.carrier.send(&self.client_packet))
        };
        // Declared after the actual action Result, so an unexpected unwind
        // cannot dispose its native sample before the resident outer fence.
        let _action_fence = SelectedClientUnwindFenceV1::for_carrier(&self.carrier);
        let selected_post = self.carrier.receive_profile.retains_original()
            .then(|| SelectedBrokerHandshakePostV1::observe_client(
                &mut self.custody, &self.carrier, Some(&self.publication_subject),
            ));
        let currentness = if selected_post.is_none() { self
            .custody
            .revalidate_handshake_custody()
            .map_err(HandshakeError::from)
            .and_then(|()| self.carrier.validate_peer())
            .and_then(|()| self.carrier.validate_subject(&self.publication_subject)) } else { Ok(()) };
        if selected_post.as_ref().is_some_and(|post| post.first_failure().is_some()) {
            // Move the whole action result only after choosing its first cause.
            return Transition::Failed(match send_result {
                ClientSendObservationV1::Selected(Ok(())) => retain_selected_broker_post_failure_v1(
                    SelectedBrokerFailureOwnerV1::ClientSend(self), None,
                    match selected_post { Some(post) => post, None => std::process::abort() },
                ),
                ClientSendObservationV1::Selected(Err(error)) => retain_selected_broker_post_failure_v1(
                    SelectedBrokerFailureOwnerV1::ClientSend(self), Some(error.into()),
                    match selected_post { Some(post) => post, None => std::process::abort() },
                ),
                ClientSendObservationV1::Ordinary(_) => std::process::abort(),
            });
        }
        if let Err(error) = currentness {
            self.carrier.close();
            if !self.carrier.receive_profile.retains_original() {
                return Transition::Failed(error);
            }
            return Transition::Failed(retain_selected_client_failure_v1(
                SelectedBrokerFailureOwnerV1::ClientSend(self), error, selected_post,
            ));
        }
        match send_result {
            ClientSendObservationV1::Ordinary(Ok(()))
            | ClientSendObservationV1::Selected(Ok(())) => {}
            ClientSendObservationV1::Ordinary(Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted))
            | ClientSendObservationV1::Selected(Err(HandshakeError::RetryableTransport)) => {
                return Transition::Retry(self);
            }
            ClientSendObservationV1::Ordinary(Err(_)) => {
                self.carrier.close();
                return Transition::Failed(HandshakeError::Transport);
            }
            ClientSendObservationV1::Selected(Err(error)) => {
                self.carrier.close();
                return Transition::Failed(retain_selected_client_failure_v1(
                    SelectedBrokerFailureOwnerV1::ClientSend(self), error, selected_post,
                ));
            }
        }
        Transition::Complete(ClientAwaitBrokerHello {
            typed: None,
            custody: self.custody,
            carrier: self.carrier,
            publication: self.publication,
            publication_packet: self.publication_packet,
            publication_subject: self.publication_subject,
            client_packet: self.client_packet,
        })
    }
}

struct ClientAwaitBrokerHello {
    typed: Option<SelectedClientHelloVerificationV1>,
    custody: ClientHandshakeCustodyV1,
    carrier: HandshakeCarrier,
    publication: UntrustedBrokerSessionEndpointPublicationV1,
    publication_packet: Vec<u8>,
    publication_subject: RetainedSubject,
    client_packet: Vec<u8>,
}

impl ClientAwaitBrokerHello {
    fn receive(mut self) -> Transition<InertProvisionalClientSession, Self> {
        let _stage_fence = SelectedClientUnwindFenceV1::for_carrier(&self.carrier);
        if let Err(error) = self.custody.revalidate_handshake_custody() {
            if !self.carrier.receive_profile.retains_original() {
                return Transition::Failed(error.into());
            }
            return Transition::Failed(retain_selected_broker_failure_v1(
                SelectedBrokerFailureOwnerV1::ClientBrokerHello { stage: self, _flight: None }, error.into(), None,
            ));
        }
        if let Err(error) = self.carrier.validate_peer() {
            self.carrier.close();
            if !self.carrier.receive_profile.retains_original() {
                return Transition::Failed(error);
            }
            return Transition::Failed(retain_selected_broker_failure_v1(
                SelectedBrokerFailureOwnerV1::ClientBrokerHello { stage: self, _flight: None }, error, None,
            ));
        }
        if let Err(error) = self.carrier.validate_subject(&self.publication_subject) {
            self.carrier.close();
            if !self.carrier.receive_profile.retains_original() {
                return Transition::Failed(error);
            }
            return Transition::Failed(retain_selected_broker_failure_v1(
                SelectedBrokerFailureOwnerV1::ClientBrokerHello { stage: self, _flight: None }, error, None,
            ));
        }
        let receive_result = self.carrier.receive(SERVER_HELLO_MAXIMUM_BYTES);
        // Declared after the actual action Result, so an unexpected unwind
        // cannot dispose its native sample before the resident outer fence.
        let _action_fence = SelectedClientUnwindFenceV1::for_carrier(&self.carrier);
        let selected_post = self.carrier.receive_profile.retains_original()
            .then(|| SelectedBrokerHandshakePostV1::observe_client(
                &mut self.custody, &self.carrier, Some(&self.publication_subject),
            ));
        let currentness = if selected_post.is_none() { self
            .custody
            .revalidate_handshake_custody()
            .map_err(HandshakeError::from)
            .and_then(|()| self.carrier.validate_peer())
            .and_then(|()| self.carrier.validate_subject(&self.publication_subject)) } else { Ok(()) };
        if selected_post.as_ref().is_some_and(|post| post.first_failure().is_some()) {
            // Move the whole action result only after choosing its first cause.
            return Transition::Failed(match receive_result {
                Ok(flight) => retain_selected_broker_post_failure_v1(
                    SelectedBrokerFailureOwnerV1::ClientBrokerHello { stage: self, _flight: Some(flight) }, None,
                    match selected_post { Some(post) => post, None => std::process::abort() },
                ),
                Err(error) => retain_selected_broker_post_failure_v1(
                    SelectedBrokerFailureOwnerV1::ClientBrokerHello { stage: self, _flight: None }, Some(error.into()),
                    match selected_post { Some(post) => post, None => std::process::abort() },
                ),
            });
        }
        if let Err(error) = currentness {
            self.carrier.close();
            if !self.carrier.receive_profile.retains_original() {
                return Transition::Failed(error);
            }
            return Transition::Failed(retain_selected_client_failure_v1(
                SelectedBrokerFailureOwnerV1::ClientBrokerHello { stage: self, _flight: None }, error, selected_post,
            ));
        }
        let flight = match receive_result {
            Ok(flight) => flight,
            Err(HandshakeError::RetryableTransport) => return Transition::Retry(self),
            Err(error) => {
                self.carrier.close();
                if !self.carrier.receive_profile.retains_original() {
                    return Transition::Failed(error);
                }
                return Transition::Failed(retain_selected_client_failure_v1(
                SelectedBrokerFailureOwnerV1::ClientBrokerHello { stage: self, _flight: None }, error, selected_post,
            ));
            }
        };
        let _flight_fence = SelectedClientUnwindFenceV1::for_carrier(&self.carrier);
        let completed = if self.carrier.receive_profile.retains_original() {
            (|| {
                self.carrier.validate_subject(&flight.subject)?;
                if !self.publication_subject.same_execution(&flight.subject) {
                    return Err(HandshakeError::KernelEvidence);
                }
                self.typed = Some(SelectedClientHelloVerificationV1::new());
                let typed = self.typed.as_mut().ok_or(HandshakeError::RemoteInvalid)?;
                typed.verify_once(
                    &self.client_packet, &flight.payload,
                    self.publication.untrusted_broker_process_execution_id(), &mut self.custody,
                )?;
                self.custody.revalidate_handshake_custody()?;
                self.carrier.validate_peer()?;
                self.carrier.validate_subject(&self.publication_subject)?;
                self.carrier.validate_subject(&flight.subject)?;
                Ok(None)
            })()
        } else {
            let completed = (|| {
                self.carrier.validate_subject(&flight.subject)?;
                if !self.publication_subject.same_execution(&flight.subject) {
                    return Err(HandshakeError::KernelEvidence);
                }
                let client = decode_canonical_client_hello_v1(&self.client_packet)
                    .map_err(|_| HandshakeError::RemoteInvalid)?;
                let broker = decode_canonical_server_hello_v1(&flight.payload)
                    .map_err(|_| HandshakeError::RemoteInvalid)?;
                let broker_process = self.publication.untrusted_broker_process_execution_id();
                if broker.signed_artifact().subject().broker_process() != broker_process {
                    return Err(HandshakeError::RemoteInvalid);
                }
                let context = self
                    .custody
                    .context_for_handshake(broker_process)
                    .map_err(|_| HandshakeError::Local(self.custody.poison_handshake_custody()))?;
                let transcript = verify_broker_session_transcript_v1(&client, &broker, &context)
                    .map_err(|_| HandshakeError::RemoteInvalid)?;
                self.custody.revalidate_handshake_custody()?;
                self.carrier.validate_peer()?;
                self.carrier.validate_subject(&self.publication_subject)?;
                self.carrier.validate_subject(&flight.subject)?;
                Ok(transcript)
            })();
            completed.map(Some)
        };
        let transcript = match completed {
            Ok(Some(value)) => value,
            Ok(None) => match self.typed.as_mut().and_then(|typed| typed.take_transcript_positive_v1()) {
                Some(value) => value,
                None => std::process::abort(),
            },
            Err(error) => {
                self.carrier.close();
                if !self.carrier.receive_profile.retains_original() {
                    return Transition::Failed(error);
                }
                return Transition::Failed(retain_selected_client_failure_v1(
                    SelectedBrokerFailureOwnerV1::ClientBrokerHello { stage: self, _flight: Some(flight) },
                    error, selected_post,
                ));
            }
        };
        Transition::Complete(InertProvisionalClientSession {
            _custody: self.custody,
            _carrier: self.carrier,
            _publication_packet: self.publication_packet,
            _client_packet: self.client_packet,
            _broker_packet: flight.payload,
            _publication_subject: self.publication_subject,
            _broker_subject: flight.subject,
            _transcript: transcript,
        })
    }
}

struct InertProvisionalBrokerSession {
    _custody: BrokerHandshakeCustodyV1,
    _carrier: HandshakeCarrier,
    _publication: [u8; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES],
    _client_packet: Vec<u8>,
    _client_subject: RetainedSubject,
    _broker_packet: Vec<u8>,
    _transcript: VerifiedBrokerSessionTranscriptV1,
}

struct InertProvisionalClientSession {
    _custody: ClientHandshakeCustodyV1,
    _carrier: HandshakeCarrier,
    _publication_packet: Vec<u8>,
    _client_packet: Vec<u8>,
    _broker_packet: Vec<u8>,
    _publication_subject: RetainedSubject,
    _broker_subject: RetainedSubject,
    _transcript: VerifiedBrokerSessionTranscriptV1,
}

// Only the last verified HELLO edge constructs this move-only handoff. It
// keeps every original flight/subject while cold journal admission borrows it.
pub(super) struct VerifiedStorageHandshakeV1 {
    root: &'static str,
    custody: Option<FixedEndpointCustodyV1>,
    retained_owner: Option<ProtectedBrokerSessionOwnerV1>,
    carrier: Option<HandshakeCarrier>,
    transcript: Option<VerifiedBrokerSessionTranscriptV1>,
    client_packet: Vec<u8>,
    broker_packet: Vec<u8>,
    _witnesses: Option<VerifiedStorageWitnessesV1>,
}

enum VerifiedStorageWitnessesV1 {
    Client {
        _publication: Vec<u8>,
        _publication_subject: RetainedSubject,
        _broker_subject: RetainedSubject,
    },
    Broker {
        _publication: [u8; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES],
        _client_subject: RetainedSubject,
    },
}

impl VerifiedStorageWitnessesV1 {
    fn validate_client(
        &self,
        establishment: ProcessEvidence,
        peer: &ConnectionPeerIdentity,
        selection: ClientWitnessValidationV1,
    ) -> Result<(), HandshakeError> {
        let validate_establishment = || {
            if matches!(selection, ClientWitnessValidationV1::StoragePreparation) {
                establishment.validate_connection_retaining(peer)
            } else {
                establishment.validate_connection(peer)
            }
        };
        if matches!(selection, ClientWitnessValidationV1::Output | ClientWitnessValidationV1::StoragePreparation) {
            validate_establishment()?;
        }
        let Self::Client {
            _publication_subject: publication,
            _broker_subject: broker,
            ..
        } = self else {
            return Err(HandshakeError::KernelEvidence);
        };

        #[cfg(feature = "online-nix")]
        if matches!(selection, ClientWitnessValidationV1::OnlineNix) {
            establishment.validate_connection(peer)?;
        }
        if matches!(selection, ClientWitnessValidationV1::StoragePreparation) {
            publication.validate_storage_preparation()?;
            broker.validate_storage_preparation()?;
        } else {
            publication.validate()?;
            broker.validate()?;
        }
        if !publication.same_execution(broker) {
            return Err(HandshakeError::KernelEvidence);
        }
        validate_establishment()
    }

    #[cfg(feature = "online-nix")]
    fn require_online_client_subject(
        &self,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<(), OnlineTransportFailureV1> {
        let Self::Client {
            _broker_subject: broker,
            ..
        } = self else {
            return Err(OnlineTransportFailureV1::Closed);
        };

        // The actual signed HELLO subject, not SO_PEERCRED of the PID1
        // listener, supplies the response writer's original nomination.
        if !subject.is_alive()?
            || subject.credentials() != broker.subject.credentials()
            || subject.initial_info() != broker.subject.initial_info()
        {
            return Err(OnlineTransportFailureV1::Closed);
        }
        broker.evidence.validate(subject.pidfd())
            .map_err(|cause| OnlineTransportFailureV1::Witness(cause.into()))
    }
}

// Keep each selected route's original position of the establishment check
// relative to the Client shape match while sharing the observation engine.
#[derive(Clone, Copy)]
enum ClientWitnessValidationV1 {
    Output,
    StoragePreparation,
    #[cfg(feature = "online-nix")]
    OnlineNix,
}

enum ClientWitnessFailureV1 {
    Output(HandshakeError),
    #[cfg(feature = "online-nix")]
    OnlineNix(DormantBrokerSessionHandshakeErrorV1),
}

impl ClientWitnessFailureV1 {
    fn cause(&self) -> &(dyn std::error::Error + 'static) {
        match self {
            Self::Output(cause) => cause,
            #[cfg(feature = "online-nix")]
            Self::OnlineNix(cause) => cause,
        }
    }
}

/// Retains the same establishment and HELLO subjects for the closed Nix and
/// Output Client routes. Their admission and original error projections remain
/// distinct; neither route can nominate a replacement service writer.
struct AuthenticatedClientWitnessesV1 {
    // Derived from the actual selected carrier, never a caller grant.
    storage_preparation: bool,
    establishment: ProcessEvidence,
    witnesses: VerifiedStorageWitnessesV1,
    first_failure: Option<ClientWitnessFailureV1>,
}

/// Identifies the original negative witness-check frontier as diagnostic DATA.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum OutputCurrentnessBoundaryV1 {
    /// Records refusal before the original action.
    BeforeAction,
    /// Records refusal after the original action.
    PostAction,
    /// Preserves earlier debt already owned by a native protected postcheck.
    PostProtectedFailure,
}

impl AuthenticatedClientWitnessesV1 {
    #[cfg(feature = "online-nix")]
    fn revalidate_online(
        &mut self,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.first_failure.is_some() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        if let Err(cause) = self.witnesses.validate_client(
            self.establishment, peer, ClientWitnessValidationV1::OnlineNix,
        ) {
            // Preserve the first typed witness rejection before returning the
            // existing currentness projection to the resident outer attempt.
            self.first_failure = Some(ClientWitnessFailureV1::OnlineNix(cause.into()));
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    fn revalidate(&mut self, peer: &ConnectionPeerIdentity) -> bool {
        if self.first_failure.is_some() {
            return false;
        }
        match self.witnesses.validate_client(
            self.establishment, peer,
            if self.storage_preparation { ClientWitnessValidationV1::StoragePreparation }
            else { ClientWitnessValidationV1::Output },
        ) {
            Ok(()) => true,
            Err(cause) => {
                self.first_failure = Some(ClientWitnessFailureV1::Output(cause));
                false
            }
        }
    }

    fn revalidate_delete_inventory(&mut self, peer: &ConnectionPeerIdentity) -> bool {
        if self.first_failure.is_some() {
            return false;
        }
        match self.witnesses.validate_client(
            self.establishment, peer, ClientWitnessValidationV1::StoragePreparation,
        ) {
            Ok(()) => true,
            Err(cause) => {
                self.first_failure = Some(ClientWitnessFailureV1::Output(cause));
                false
            }
        }
    }

    fn require_delete_inventory_subject(&mut self, subject: &KernelAuthorizedRecordSubject) -> bool {
        if self.first_failure.is_some() {
            return false;
        }
        match self.compare_subject_engine(subject, ClientWitnessValidationV1::StoragePreparation) {
            Ok(()) => true,
            Err(cause) => {
                self.first_failure = Some(ClientWitnessFailureV1::Output(cause));
                false
            }
        }
    }

    fn observe_delete_inventory_post(&self, peer: &ConnectionPeerIdentity) -> Result<(), HandshakeError> {
        // A previously retained first failure must not suppress this separate
        // paid post. The expected original witnesses remain the same objects;
        // the returned result has its own owning destination on the D query.
        self.witnesses.validate_client(
            self.establishment, peer, ClientWitnessValidationV1::StoragePreparation,
        )
    }

    fn require_subject(&mut self, subject: &KernelAuthorizedRecordSubject) -> bool {
        if self.first_failure.is_some() {
            return false;
        }
        match self.compare_subject(subject) {
            Ok(()) => true,
            Err(cause) => {
                self.first_failure = Some(ClientWitnessFailureV1::Output(cause));
                false
            }
        }
    }

    fn compare_subject(&self, subject: &KernelAuthorizedRecordSubject) -> Result<(), HandshakeError> {
        self.compare_subject_engine(subject, if self.storage_preparation {
            ClientWitnessValidationV1::StoragePreparation
        } else {
            ClientWitnessValidationV1::Output
        })
    }

    fn compare_subject_engine(&self, subject: &KernelAuthorizedRecordSubject,
        selection: ClientWitnessValidationV1,
    ) -> Result<(), HandshakeError> {
        let VerifiedStorageWitnessesV1::Client {
            _broker_subject: broker,
            ..
        } = &self.witnesses else {
            return Err(HandshakeError::KernelEvidence);
        };
        let actual = subject.credentials();
        let expected = broker.subject.credentials();
        if actual.pid() != expected.pid()
            || actual.uid() != expected.uid()
            || actual.gid() != expected.gid()
            || subject.initial_info() != broker.subject.initial_info()
        {
            return Err(HandshakeError::KernelEvidence);
        }
        if matches!(selection, ClientWitnessValidationV1::StoragePreparation) {
            ProcessEvidence::observe_retaining(subject.pidfd(), None,
                |current| current == broker.evidence).map(|_| ())
        } else {
            broker.evidence.validate(subject.pidfd())
        }
    }
}

#[cfg(all(test, feature = "online-nix"))]
mod online_client_witness_data_tests {
    use super::ProcessEvidence;

    fn execution(process_id: u32) -> ProcessEvidence {
        ProcessEvidence {
            process_id,
            thread_group_id: process_id,
            start_time_ticks: 42,
            cgroup_id: 7,
            real_user_id: 1000,
            real_group_id: 1000,
            effective_user_id: 1000,
            effective_group_id: 1000,
            saved_user_id: 1000,
            saved_group_id: 1000,
            filesystem_user_id: 1000,
            filesystem_group_id: 1000,
        }
    }

    #[test]
    fn pid1_establishment_is_not_the_authenticated_service_execution() {
        // These are comparison DATA only; no pidfd, Session or live witness
        // is fabricated by this test.
        let establishment = execution(1);
        let service = execution(57);

        assert!(establishment
            .require_current_observation(establishment, true)
            .is_ok());
        assert!(service.require_current_observation(service, true).is_ok());
        assert!(service
            .require_current_observation(establishment, true)
            .is_err());
        assert!(establishment.require_current_observation(service, true).is_err());
    }

    #[test]
    fn service_identity_credential_change_or_exit_refuses() {
        let original = execution(57);
        let mut changed_start = original;
        changed_start.start_time_ticks += 1;
        let mut changed_cgroup = original;
        changed_cgroup.cgroup_id += 1;
        let mut changed_credentials = original;
        changed_credentials.effective_user_id += 1;

        for changed in [execution(58), changed_start, changed_cgroup, changed_credentials] {
            assert!(original.require_current_observation(changed, true).is_err());
        }
        assert!(original.require_current_observation(original, false).is_err());
    }
}

#[derive(Clone, Copy)]
enum HandshakeCompletionV1 {
    Legacy,
    RetainStorage,
    OutputClient,
}

/// Carries the original fixed cold-flight cutoff as comparison DATA only.
///
/// This does not authorize a socket, floor or operation. Installed fixed
/// callers derive it once at their old handshake boundary and retain it
/// through every cold-open phase; no lower phase manufactures a new cutoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalBrokerColdDeadlineV1(u64);

impl OriginalBrokerColdDeadlineV1 {
    /// Samples the installed Controller's original ten-second cutoff once.
    ///
    /// # Errors
    /// Returns the existing transport projection for clock/overflow failure.
    pub fn controller() -> Result<Self, crate::DormantBrokerSessionHandshakeErrorV1> {
        crate::production_deadline_after(std::time::Duration::from_secs(10))
            .map(Self)
            .map_err(|_| crate::DormantBrokerSessionHandshakeErrorV1::Transport)
    }

    // Samples the same fixed ten-second handshake bound once and intersects
    // it with the actual original Root flight. Neither cutoff is renewed.
    /// Intersects the original fixed handshake cutoff with the original Root cutoff.
    ///
    /// # Errors
    /// Returns the fixed cutoff sampling error or rejects an expired original Root cutoff.
    pub fn git_coverage(original_root_cut: u64)
        -> Result<Self, crate::DormantBrokerSessionHandshakeErrorV1>
    {
        let original = Self::controller()?;
        let bounded = Self(original.0.min(original_root_cut));
        bounded.check()?;
        Ok(bounded)
    }

    // The installed Storage accept loop already sampled its original 30s D.
    // Preserve that exact DATA rather than sampling again after acceptance.
    pub(super) const fn storage_accept(deadline: u64) -> Self {
        Self(deadline)
    }

    /// Observes the original cold-flight deadline as comparison DATA.
    pub fn value(self) -> u64 {
        self.0
    }

    #[cfg(feature = "online-nix")]
    pub(crate) fn online_request(
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        if !matches!(request.method(),
            aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2
                | aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2
                | aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2)
            || request.deadline_boottime_nanoseconds() == 0
            || request.deadline_boottime_nanoseconds() == u64::MAX
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let deadline = Self(request.deadline_boottime_nanoseconds());
        deadline.check().map_err(|_| BrokerSessionSecurityError::Currentness)?;
        Ok(deadline)
    }

    /// Samples the existing direct BOOTTIME comparator against the same D.
    ///
    /// # Errors
    /// Preserves the existing clock/encoding and expiry error cases.
    pub(crate) fn remaining(self) -> Result<u64, crate::DormantBrokerSessionHandshakeErrorV1> {
        crate::dormant_handshake::remaining_handshake_nanoseconds(self.0)
    }

    /// Rejects expiry without altering the original cutoff.
    ///
    /// # Errors
    /// Preserves direct clock/encoding failure and deadline expiry.
    pub fn check(self) -> Result<(), crate::DormantBrokerSessionHandshakeErrorV1> {
        self.remaining().map(|_| ())
    }
}

pub(super) enum ColdClientHandshakeProgressV1 {
    Pending(DormantControllerClientHandshakeV1),
    Complete(DormantAuthenticatedBrokerSessionV1),
    Verified(VerifiedStorageHandshakeV1),
}

pub(super) enum ColdBrokerHandshakeProgressV1 {
    Pending(DormantBrokerEndpointHandshakeV1),
    Complete(DormantAuthenticatedBrokerSessionV1),
    Verified(VerifiedStorageHandshakeV1),
}

/// Narrows only the method list of the sole canonical Nix HELLO producer.
#[cfg(feature = "online-nix")]
pub(crate) fn online_resolve_client_hello()
    -> Result<BrokerClientHello, aos_sandbox_broker_session_protocol::BrokerSessionNegotiationError>
{
    let mut hello = aos_sandbox_broker_session_protocol::production_broker_client_hello_v1(
        BrokerSessionProtocolV1::Nix,
        aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER,
        aos_sandbox_broker_session_protocol::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES as u32,
    )?;
    hello.required_methods = vec![
        aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2.into(),
    ];
    Ok(hello)
}

/// Keeps canonical Nix features/version/ceilings but advertises only real50.
#[cfg(feature = "online-nix")]
pub(crate) fn online_resolve_server_hello()
    -> Result<BrokerServerHello, aos_sandbox_broker_session_protocol::BrokerSessionNegotiationError>
{
    let mut hello = aos_sandbox_broker_session_protocol::production_broker_server_hello_v1(
        BrokerSessionProtocolV1::Nix,
        aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER,
        aos_sandbox_broker_session_protocol::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES as u32,
    )?;
    hello.methods = vec![
        aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2.into(),
    ];
    Ok(hello)
}

/// Advertises only the connected existing-output continuation on the client.
///
/// This selects negotiation DATA, not startup, request or floor authority.
/// The actual independently measured mode remains an installed caller check.
#[cfg(feature = "online-nix")]
pub(crate) fn online_existing_output_client_hello()
    -> Result<BrokerClientHello, aos_sandbox_broker_session_protocol::BrokerSessionNegotiationError>
{
    let mut hello = online_resolve_client_hello()?;
    hello.required_methods.extend_from_slice(&[
        aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2.into(),
        aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2.into(),
    ]);
    Ok(hello)
}

/// Advertises the same closed three-method continuation on the original owner.
#[cfg(feature = "online-nix")]
pub(crate) fn online_existing_output_server_hello()
    -> Result<BrokerServerHello, aos_sandbox_broker_session_protocol::BrokerSessionNegotiationError>
{
    let mut hello = online_resolve_server_hello()?;
    hello.methods.extend_from_slice(&[
        aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2.into(),
        aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2.into(),
    ]);
    Ok(hello)
}

/// Joins the closed online root to the unchanged client HELLO typestate.
#[cfg(feature = "online-nix")]
pub(crate) fn begin_online_resolve_client(
    custody: ProtectedBrokerSessionClientV1,
    socket: SeqpacketSocket,
    hello: BrokerClientHello,
) -> Result<DormantControllerClientHandshakeV1, DormantBrokerSessionHandshakeErrorV1> {
    if custody.protected_protocol_and_node().0 != BrokerSessionProtocolV1::Nix {
        return Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole);
    }
    DormantControllerClientHandshakeV1::begin(
        "/var/lib/aos/sandboxd/broker-session/nix", custody, socket, hello,
    )
}

/// Joins the closed online root to the unchanged broker HELLO typestate.
#[cfg(feature = "online-nix")]
pub(crate) fn begin_online_resolve_broker(
    custody: ProtectedBrokerSessionBrokerV1,
    socket: SeqpacketSocket,
    hello: BrokerServerHello,
) -> Result<DormantBrokerEndpointHandshakeV1, DormantBrokerSessionHandshakeErrorV1> {
    if custody.protected_protocol_and_node().0 != BrokerSessionProtocolV1::Nix {
        return Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole);
    }
    DormantBrokerEndpointHandshakeV1::begin(
        "/var/lib/aos/sandbox-nix/broker-session/controller", custody, socket, hello,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StorageColdPhaseV1 {
    Fresh,
    Checking,
    Complete,
    Failed,
}

impl StorageColdPhaseV1 {
    fn may_begin(self) -> bool {
        self == Self::Fresh
    }

    fn is_unfinished(self) -> bool {
        self != Self::Complete
    }
}

#[derive(Clone, Copy)]
enum OutputColdFailureSiteV1 {
    WitnessCreation,
    WitnessPrecheck,
    ProtectedOwner,
    ClientNative,
    WitnessPostcheck,
    Outer,
}

/// Owns one genuine post-VERIFIED HELLO while cold admission borrows it.
///
/// All returned owners are parked before later gates. Its first outer cause
/// is separate from native/physical causes and cleanup debt retained below.
/// An unfinished selected owner cannot be silently dropped or resumed.
pub struct RetainedStorageColdOpenV1 {
    verified: VerifiedStorageHandshakeV1,
    deadline: OriginalBrokerColdDeadlineV1,
    #[cfg(feature = "online-nix")]
    online_provision: Option<crate::nix_service::floor::OnlineProvisionV1>,
    #[cfg(feature = "online-nix")]
    online_client_establishment: Option<ProcessEvidence>,
    checkpoint: Option<HistoricalSessionCheckpointV1>,
    checkpoint_construction: Option<HistoricalSessionCheckpointConstructionCaptureV1>,
    main: Option<crate::recovery::BrokerMainOpenV1>,
    owner: Option<ProtectedBrokerSessionOwnerV1>,
    hello_controls: Option<RetainedStorageHelloControlsV1>,
    hello_disposal: Option<aos_sandbox_controller_domain::StorageSessionHelloDisposalErrorV1>,
    initial_post_preparation: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    initial_floor_disposal: Option<Result<(), BrokerSessionSecurityError>>,
    storage_required_post: Option<Result<(), BrokerSessionSecurityError>>,
    controller_required_post: Option<Result<(), BrokerSessionSecurityError>>,
    controller_rights_restore: Option<Result<(), SeqpacketError>>,
    warm_hello_disposal: Option<aos_sandbox_controller_domain::StorageLifecycleDisposalErrorV1>,
    phase: StorageColdPhaseV1,
    first_failure: Option<crate::DormantBrokerSessionHandshakeErrorV1>,
    client_witnesses: Option<Result<AuthenticatedClientWitnessesV1, HandshakeError>>,
    output_failure_site: Option<OutputColdFailureSiteV1>,
    output_witness_debt: bool,
}

struct RetainedStorageHelloControlsV1 {
    record: Option<aos_sandbox_linux::seqpacket::ReceivedRecord>,
    sent: Option<aos_sandbox_linux::seqpacket::StorageSeqpacketSendAttemptV1>,
}

impl RetainedStorageColdOpenV1 {
    fn completed_transfer_shell_v1(&self) -> bool {
        self.phase == StorageColdPhaseV1::Complete && self.first_failure.is_none()
            && self.owner.is_none() && self.checkpoint.is_none()
            && self.verified.transcript.is_none() && self.verified.carrier.is_none()
            && self.verified.custody.is_none() && self.verified.retained_owner.is_none()
            && self.client_witnesses.is_none()
            && self.main.as_ref().is_some_and(|main| main.completed_transfer_shell_v1())
            && self.hello_disposal.is_none() && self.warm_hello_disposal.is_none()
            && !self.output_witness_debt
    }

    pub(crate) fn retained_revalidation_failure_for(
        &self,
        returned: &BrokerSessionSecurityError,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.owner.as_ref().or(self.verified.retained_owner.as_ref())
            .and_then(|owner| owner.retained_revalidation_failure_for(returned))
            .or_else(|| self.main.as_ref().and_then(|main| main.retained_revalidation_failure_for(returned)))
            .or_else(|| self.verified.custody.as_ref()
                .and_then(|custody| custody.retained_revalidation_failure_for(returned)))
    }

    fn initial_socket_v1(&self) -> Option<&SeqpacketSocket> {
        match self.verified.carrier.as_ref().map(|carrier| &carrier.transport) {
            Some(HandshakeTransport::Ordinary(socket)) => Some(socket),
            _ => None,
        }
    }

    fn retained_client_parts_mut_v1(&mut self)
        -> Option<(&mut ProtectedBrokerSessionOwnerV1, &SeqpacketSocket, &VerifiedBrokerSessionTranscriptV1)>
    {
        let owner = match self.owner.as_mut() {
            Some(owner) => owner,
            None => self.verified.retained_owner.as_mut()?,
        };
        let carrier = self.verified.carrier.as_ref()?;
        let HandshakeTransport::Ordinary(socket) = &carrier.transport else { return None; };
        let transcript = self.verified.transcript.as_ref()?;
        Some((owner, socket, transcript))
    }

    /// Consumes successful initial controls only after joint Native preparation.
    pub(crate) fn dispose_initial_storage_hello_v1(
        mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
        prefix: StorageInitialSessionHandshakeV1,
    ) -> Result<(), (Self, StorageInitialSessionHandshakeV1)> {
        if !prefix.controls_may_dispose() || self.phase != StorageColdPhaseV1::Complete
            || !self.hello_controls.as_ref().is_some_and(|controls| controls.sent.is_some())
        {
            return Err((self, prefix));
        }
        // The initial physical programme spans the whole Cold/checkpoint and
        // HELLO interval, including its final floor/currentness observations.
        // Ending it at MainOpen would leave those real checks unpaid.
        self.initial_floor_disposal = Some(
            session.owner.finish_storage_initial_physical_program_v2(receiving),
        );
        if !matches!(self.initial_floor_disposal, Some(Ok(()))) {
            return Err((self, prefix));
        }
        let (journal, opening, settlement) = match session.owner.storage_prepare_hello_cleanup_parts_v1() {
            Ok(parts) => parts,
            Err(_) => return Err((self, prefix)),
        };
        self.initial_post_preparation = Some(receiving.arm_initial_observation_post_v1());
        if !matches!(self.initial_post_preparation, Some(Ok(()))) {
            return Err((self, prefix));
        }
        let sent = match self.hello_controls.as_mut().and_then(|controls| controls.sent.take()) {
            Some(sent) => sent,
            None => std::process::abort(),
        };
        let prepared = receiving.prepare_initial_session_hello_disposal_v1(
            journal, &session.socket, opening, sent,
        );
        match prepared {
            Err(cause) => {
                self.hello_disposal = Some(cause);
                Err((self, prefix))
            }
            Ok(disposal) => {
                // Every fallible cold/native/floor/endpoint check is complete.
                // The Session keeps its actual writer/socket/transcript; this
                // drops only the completed reducer's raw/control copies.
                drop(prefix);
                drop(self);
                disposal.complete_after_disposal_v1();
                *settlement = Some(Ok(()));
                Ok(())
            }
        }
    }

    fn dispose_retained_storage_hello_v1(
        mut self,
        session: &DormantAuthenticatedBrokerSessionV1,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<(), Self> {
        if self.phase != StorageColdPhaseV1::Complete
            || !self.hello_controls.as_ref().is_some_and(|controls| controls.sent.is_some())
        {
            return Err(self);
        }
        let journal = match session.owner.retained_storage_journal_v1() {
            Ok(journal) => journal,
            Err(_) => return Err(self),
        };
        let sent = match self.hello_controls.as_mut().and_then(|controls| controls.sent.take()) {
            Some(sent) => sent,
            None => std::process::abort(),
        };
        match receiving.prepare_handshake_disposal_v1(journal, &session.socket, sent) {
            Err(cause) => {
                self.warm_hello_disposal = Some(cause);
                Err(self)
            }
            Ok(disposal) => {
                // Native posts can consume time. This is the fresh transport
                // cutoff, while the original floor/native cutoff stays retired.
                if let Err(cause) = self.deadline.check() {
                    self.first_failure.get_or_insert(cause);
                    drop(disposal);
                    return Err(self);
                }
                drop(self);
                disposal.complete_after_disposal_v1();
                Ok(())
            }
        }
    }

    fn retained_storage_parts_v1(&self) -> Result<(&aos_sandbox_controller_domain::Journal, &SeqpacketSocket), BrokerSessionSecurityError> {
        let owner = self.owner.as_ref().or(self.verified.retained_owner.as_ref())
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let socket = match self.verified.carrier.as_ref().map(|carrier| &carrier.transport) {
            Some(HandshakeTransport::Ordinary(socket)) => socket,
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        Ok((owner.retained_storage_journal_v1()?, socket))
    }

    #[cfg(feature = "online-nix")]
    pub(crate) const fn original_deadline(&self) -> OriginalBrokerColdDeadlineV1 {
        self.deadline
    }
    pub(super) fn retain(
        verified: VerifiedStorageHandshakeV1,
        deadline: OriginalBrokerColdDeadlineV1,
    ) -> Self {
        Self {
            verified,
            deadline,
            #[cfg(feature = "online-nix")]
            online_provision: None,
            #[cfg(feature = "online-nix")]
            online_client_establishment: None,
            checkpoint: None,
            checkpoint_construction: None,
            main: None,
            owner: None,
            hello_controls: None,
            hello_disposal: None,
            initial_post_preparation: None,
            initial_floor_disposal: None,
            storage_required_post: None,
            controller_required_post: None,
            controller_rights_restore: None,
            warm_hello_disposal: None,
            phase: StorageColdPhaseV1::Fresh,
            first_failure: None,
            client_witnesses: None,
            output_failure_site: None,
            output_witness_debt: false,
        }
    }

    /// Parks only a genuine verified HELLO and its independently supplied floor.
    ///
    /// The closed online route uses the same cold-open/checkpoint algorithm.
    /// Its existing-only profile is not a method46 or offline provisioning grant.
    #[cfg(feature = "online-nix")]
    pub(crate) fn retain_online(
        verified: VerifiedStorageHandshakeV1,
        deadline: OriginalBrokerColdDeadlineV1,
        provision: crate::nix_service::floor::OnlineProvisionV1,
    ) -> Self {
        let mut retained = Self::retain(verified, deadline);
        if matches!(
            &retained.verified.custody,
            Some(FixedEndpointCustodyV1::Client(_))
        ) {
            let Some(carrier) = &retained.verified.carrier else {
                std::process::abort();
            };
            retained.online_client_establishment = Some(carrier.peer);
        }
        retained.online_provision = Some(provision);
        retained
    }

    pub(super) fn retain_output(
        verified: VerifiedStorageHandshakeV1,
        deadline: OriginalBrokerColdDeadlineV1,
    ) -> Self {
        let mut retained = Self::retain(verified, deadline);
        let establishment = retained.verified.carrier.as_ref().map(|carrier| carrier.peer);
        if matches!(
            retained.verified._witnesses.as_ref(),
            Some(VerifiedStorageWitnessesV1::Client { .. })
        ) {
            if let Some(establishment) = establishment {
                if let Some(witnesses) = retained.verified._witnesses.take() {
                    retained.client_witnesses = Some(Ok(AuthenticatedClientWitnessesV1 {
                        storage_preparation: retained.verified.carrier.as_ref().is_some_and(|carrier|
                            carrier.receive_profile.retains_original()),
                        establishment,
                        witnesses,
                        first_failure: None,
                    }));
                    return retained;
                }
            }
        }
        retained.client_witnesses = Some(Err(HandshakeError::KernelEvidence));
        retained.output_failure_site = Some(OutputColdFailureSiteV1::WitnessCreation);
        retained
    }

    /// Observes whether the original cold open remains unfinished.
    pub fn is_failed(&self) -> bool {
        self.phase.is_unfinished()
    }

    /// Transfers a fully checked session only after final same-D retirement.
    ///
    /// # Errors
    /// Stores the first actual outer rejection and leaves all originals
    /// resident; an unfinished/failed operation can never be started again.
    pub(crate) fn finish(
        &mut self,
        expected_node: Option<[u8; 16]>,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, crate::DormantBrokerSessionHandshakeErrorV1> {
        self.finish_with_storage_receiving(expected_node, None, None, None, None, None)
    }

    pub(crate) fn finish_storage_prepare_v1(
        &mut self,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, crate::DormantBrokerSessionHandshakeErrorV1> {
        self.finish_with_storage_receiving(None, Some(receiving), None, None, None, None)
    }

    fn finish_retained_storage_session_v1(
        &mut self,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, crate::DormantBrokerSessionHandshakeErrorV1> {
        self.finish_with_storage_receiving(None, None, Some(receiving), None, None, None)
    }

    fn finish_retained_storage_client_v1(
        &mut self,
        original: &mut aos_sandbox_controller_domain::OriginalCreateStorageClientSessionV1<'_, '_, '_>,
        actual_node: [u8; 16],
    ) -> Result<DormantAuthenticatedBrokerSessionV1, crate::DormantBrokerSessionHandshakeErrorV1> {
        self.finish_with_storage_receiving(Some(actual_node), None, None, Some(original), None, None)
    }

    fn finish_controller_initial_v1(
        &mut self,
        receiving: &mut aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingLoanV1<'_>,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, crate::DormantBrokerSessionHandshakeErrorV1> {
        let node = receiving.expected_node_v1()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        self.finish_with_storage_receiving(Some(node), None, None, None, Some(receiving), None)
    }

    pub(crate) fn finish_storage_host_v1(
        &mut self,
        receiving: &mut crate::recovery::StorageHostClientReceivingV1<'_, '_, '_>,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, crate::DormantBrokerSessionHandshakeErrorV1> {
        self.finish_with_storage_receiving(Some(receiving.node_v1()), None, None, None, None, Some(receiving))
    }

    fn finish_with_storage_receiving(
        &mut self,
        expected_node: Option<[u8; 16]>,
        receiving: Option<&mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>>,
        retained: Option<&mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>>,
        client: Option<&mut aos_sandbox_controller_domain::OriginalCreateStorageClientSessionV1<'_, '_, '_>>,
        initial: Option<&mut aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingLoanV1<'_>>,
        host: Option<&mut crate::recovery::StorageHostClientReceivingV1<'_, '_, '_>>,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, crate::DormantBrokerSessionHandshakeErrorV1> {
        self.finish_with_fixed_service_receiving_v4(expected_node, receiving, retained, client, initial, host, None)
    }

    fn finish_start_resource_v4(&mut self, receiving: &mut start_network_client::StartResourceColdReceivingV4<'_, '_>)
        -> Result<DormantAuthenticatedBrokerSessionV1, crate::DormantBrokerSessionHandshakeErrorV1> {
        let node = receiving.loan.expected_node_v2().map_err(|_| BrokerSessionSecurityError::Currentness)?;
        self.finish_with_fixed_service_receiving_v4(Some(node), None, None, None, None, None, Some(receiving))
    }

    fn finish_fixed_service_v4(&mut self, receiving: &mut dyn crate::recovery::FixedServiceColdJournalReceivingV4)
        -> Result<DormantAuthenticatedBrokerSessionV1, crate::DormantBrokerSessionHandshakeErrorV1> {
        self.finish_with_fixed_service_receiving_v4(None, None, None, None, None, None, Some(receiving))
    }

    fn finish_with_fixed_service_receiving_v4(
        &mut self, expected_node: Option<[u8; 16]>,
        receiving: Option<&mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>>,
        retained: Option<&mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>>,
        client: Option<&mut aos_sandbox_controller_domain::OriginalCreateStorageClientSessionV1<'_, '_, '_>>,
        initial: Option<&mut aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingLoanV1<'_>>,
        host: Option<&mut crate::recovery::StorageHostClientReceivingV1<'_, '_, '_>>,
        fixed: Option<&mut dyn crate::recovery::FixedServiceColdJournalReceivingV4>,
    ) -> Result<DormantAuthenticatedBrokerSessionV1, crate::DormantBrokerSessionHandshakeErrorV1> {
        if !self.phase.may_begin() {
            return Err(self.failure_projection());
        }
        self.phase = StorageColdPhaseV1::Checking;
        let controller_initial = initial.is_some();
        let storage_initial = receiving.is_some();
        if let Err(cause) = self.admit(expected_node, receiving, retained, client, initial, host, fixed) {
            if self.first_failure.is_none() {
                self.first_failure = Some(cause);
            }
            if self.client_witnesses.is_some() {
                self.output_failure_site
                    .get_or_insert(OutputColdFailureSiteV1::Outer);
            }
            if controller_initial {
                // The same initial owner, actual journals, paid physical
                // permit and first cause stay resident throughout this post.
                // It runs before the outer original's independent C post.
                self.controller_required_post = Some(match self.owner.as_mut() {
                    Some(owner) => owner.observe_controller_initial_failure_post_v1(),
                    None => match self.main.as_mut() {
                        Some(main) => main.observe_controller_initial_failure_post_v1(),
                        None => Err(BrokerSessionSecurityError::Currentness),
                    },
                });
            }
            if storage_initial {
                // This reuses only the already armed Storage failure post.
                // MainOpen may already have consumed it; no healthy reentry
                // or new policy/native allowance is created by this join.
                self.storage_required_post = Some(match self.owner.as_mut() {
                    Some(owner) => owner.observe_storage_initial_failure_post_v2(),
                    None => match self.main.as_mut() {
                        Some(main) => main.observe_storage_initial_failure_post_v2(),
                        None => Ok(()),
                    },
                });
            }
            self.phase = StorageColdPhaseV1::Failed;
            return Err(self.failure_projection());
        }

        // These shapes were checked before cutoff retirement. No allocation,
        // observation or fallible gate follows the pure owning handoff.
        let owner = match self.owner.take() {
            Some(owner) => owner,
            None => std::process::abort(),
        };
        let checkpoint = match self.checkpoint.take() {
            Some(checkpoint) => checkpoint,
            None => std::process::abort(),
        };
        let transcript = match self.verified.transcript.take() {
            Some(transcript) => transcript,
            None => std::process::abort(),
        };
        let (socket, record, sent) = match self.verified.carrier.take() {
            Some(HandshakeCarrier {
                transport: HandshakeTransport::Ordinary(socket),
                selected_record,
                selected_send,
                ..
            }) => (socket, selected_record, selected_send),
            _ => std::process::abort(),
        };
        self.hello_controls = Some(RetainedStorageHelloControlsV1 { record, sent });
        let client_witnesses = match self.client_witnesses.take() {
            Some(Ok(witnesses)) => Ok(Some(witnesses)),
            None => Ok(None),
            Some(Err(_)) => std::process::abort(),
        };
        #[cfg(feature = "online-nix")]
        let client_witnesses = match self.online_client_establishment {
            Some(establishment) => {
                let Some(witnesses @ VerifiedStorageWitnessesV1::Client { .. }) =
                    self.verified._witnesses.take()
                else {
                    std::process::abort();
                };
                Ok(Some(AuthenticatedClientWitnessesV1 {
                    storage_preparation: false,
                    establishment,
                    witnesses,
                    first_failure: None,
                }))
            }
            None => client_witnesses,
        };
        self.phase = StorageColdPhaseV1::Complete;
        Ok(DormantAuthenticatedBrokerSessionV1 {
            owner,
            socket,
            transcript,
            checkpoint,
            client_witnesses,
            terminal_witness_failure: false,
            terminal_witness_debt: None,
            execution_cold_native: None,
            recovery_session_native: None,
            stop_cleanup_source_native: None,
        })
    }

    fn admit(
        &mut self,
        expected_node: Option<[u8; 16]>,
        mut receiving: Option<&mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>>,
        mut retained: Option<&mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>>,
        mut client: Option<&mut aos_sandbox_controller_domain::OriginalCreateStorageClientSessionV1<'_, '_, '_>>,
        mut initial: Option<&mut aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingLoanV1<'_>>,
        mut host: Option<&mut crate::recovery::StorageHostClientReceivingV1<'_, '_, '_>>,
        mut fixed: Option<&mut dyn crate::recovery::FixedServiceColdJournalReceivingV4>,
    ) -> Result<(), crate::DormantBrokerSessionHandshakeErrorV1> {
        self.deadline.check()?;
        let retained_open = self.verified.retained_owner.is_some();
        if retained_open != (retained.is_some() || client.is_some())
            || (retained.is_some() && client.is_some())
            || (retained_open && (receiving.is_some() || initial.is_some()))
            || (initial.is_some() && receiving.is_some())
            || (host.is_some() && (retained_open || initial.is_some() || receiving.is_some()))
            || (fixed.is_some() && (retained_open || initial.is_some() || receiving.is_some() || host.is_some()))
        {
            return Err(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole);
        }
        if let Some(retained) = retained.as_deref_mut() {
            let (journal, socket) = self.retained_storage_parts_v1()?;
            retained.require_current_v1(journal, socket)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        }

        if let Some(receiving) = receiving.as_deref_mut() {
            receiving.require_session_fixed_current_v1()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        }
        if let Some(original) = initial.as_deref_mut() {
            original.require_fixed_capture_current_v1(original.role_v1())
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        }
        if let Some(original) = host.as_deref_mut() { original.require_current_v1()?; }
        if let Some(original) = fixed.as_deref_mut() { original.require_current_v4()?; }
        #[cfg(feature = "online-nix")]
        if let Some(establishment) = self.online_client_establishment {
            self.verified.require_online_client_witnesses(establishment)?;
        }
        if let Some(witnesses) = &mut self.client_witnesses {
            let carrier = self.verified.carrier.as_ref()
                .ok_or(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole)?;
            let peer = match &carrier.transport {
                HandshakeTransport::Ordinary(socket) => socket.peer(),
                _ => return Err(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole),
            };
            let current = match witnesses {
                Ok(witnesses) => witnesses.revalidate(peer),
                Err(_) => false,
            };
            if !current {
                self.output_failure_site
                    .get_or_insert(OutputColdFailureSiteV1::WitnessPrecheck);
                return Err(crate::DormantBrokerSessionHandshakeErrorV1::KernelEvidence);
            }
        }
        let transcript = self.verified.transcript
            .as_ref()
            .ok_or(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole)?;
        let context = if let Some(owner) = self.verified.retained_owner.as_mut() {
            if client.is_some() {
                owner.retained_storage_client_endpoint_mut_v1()
                    .context_for_handshake(transcript.broker_process())?
            } else {
                owner.retained_storage_broker_mut_v1()
                    .context_for_handshake(transcript.client_process())?
            }
        } else {
            let custody = self.verified.custody.as_mut()
                .ok_or(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole)?;
            match custody {
                FixedEndpointCustodyV1::Client(custody) => {
                    custody.context_for_handshake(transcript.broker_process())?
                }
                FixedEndpointCustodyV1::Broker(custody) => {
                    custody.context_for_handshake(transcript.client_process())?
                }
            }
        };
        self.deadline.check()?;
        let socket = match self.verified.carrier.as_ref() {
            Some(HandshakeCarrier {
                transport: HandshakeTransport::Ordinary(socket),
                ..
            }) => socket,
            _ => return Err(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole),
        };
        let credentials = socket.peer().credentials();
        let peer = PeerCredentials {
            uid: credentials.uid(),
            gid: credentials.gid(),
            pid: Some(credentials.pid().get()),
        };
        if initial.is_some() || host.is_some() || fixed.is_some() {
            self.checkpoint_construction = Some(HistoricalSessionCheckpointConstructionCaptureV1::new());
            let construction = self.checkpoint_construction.as_mut()
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            HistoricalSessionCheckpointV1::new_retaining(
                context, &self.verified.client_packet, &self.verified.broker_packet,
                peer, transcript, construction,
            ).map_err(BrokerSessionSecurityError::from)?;
            self.checkpoint = Some(construction.take_checkpoint_once()
                .map_err(BrokerSessionSecurityError::from)?);
        } else {
            self.checkpoint = Some(
                HistoricalSessionCheckpointV1::new(
                    context,
                    &self.verified.client_packet,
                    &self.verified.broker_packet,
                    peer,
                    transcript,
                )
                .map_err(BrokerSessionSecurityError::from)?,
            );
        }
        self.deadline.check()?;

        if retained_open {
            self.owner = self.verified.retained_owner.take();
        } else {
            let main = if let Some(original) = fixed.as_deref_mut() {
                crate::recovery::BrokerMainOpenV1::prepare_fixed_service_v4(
                    self.verified.root, &mut self.verified.custody, self.deadline, original,
                )?
            } else if let Some(original) = host.as_deref_mut() {
                crate::recovery::BrokerMainOpenV1::prepare_storage_host_v1(
                    self.verified.root, &mut self.verified.custody, self.deadline, original,
                )?
            } else if let Some(original) = initial.as_deref_mut() {
                crate::recovery::BrokerMainOpenV1::prepare_controller_initial_v1(
                    self.verified.root, &mut self.verified.custody, self.deadline, original,
                )?
            } else {
                #[cfg(feature = "online-nix")]
                let main = if self.online_provision.is_some() {
                    crate::recovery::BrokerMainOpenV1::prepare_online(
                        &mut self.verified.custody,
                        &mut self.online_provision,
                        self.deadline,
                    )?
                } else {
                    crate::recovery::BrokerMainOpenV1::prepare_storage(
                        self.verified.root,
                        &mut self.verified.custody,
                        self.deadline,
                    )?
                };
                #[cfg(not(feature = "online-nix"))]
                let main = crate::recovery::BrokerMainOpenV1::prepare_storage(
                    self.verified.root,
                    &mut self.verified.custody,
                    self.deadline,
                )?;
                main
            };
            self.main = Some(main);
            let main = self.main
                .as_mut()
                .ok_or(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole)?;
            self.deadline.check()?;
            if let Some(original) = fixed.as_deref_mut() {
                main.open_fixed_service_v4(original)?;
            } else if let Some(original) = host.as_deref_mut() {
                main.open_storage_host_v1(original)?;
            } else if let Some(original) = initial.as_deref_mut() {
                main.open_controller_initial_v1(original)?;
            } else {
                match receiving.as_deref_mut() {
                    Some(receiving) => main.open_storage_prepare_v1(receiving)?,
                    None => main.open()?,
                }
            }
            main.finish_into(&mut self.owner);
        }
        self.deadline.check()?;
        let owner = self.owner
            .as_mut()
            .ok_or(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole)?;
        // Only the genuine Recover receiver or real Storage F lender selects
        // the signed Inventory18-only slot. Ordinary heads remain untouched.
        owner.select_verified_storage_recover_slot_v1(
            transcript,
            initial.as_ref().is_some_and(|loan| loan.operator_recover_cutoff_data_v1().is_some()
                && loan.role_v1() == aos_sandbox_controller_domain::ControllerInitialBrokerSessionRoleV1::Storage
                && matches!(loan.is_execution_cleanup_cold_data_v2(), Ok(false))
                && matches!(loan.is_host_stop_cleanup_data_v1(), Ok(false))),
            retained.is_some(),
            initial.as_ref().is_some_and(|loan| matches!(loan.is_execution_cleanup_cold_data_v2(), Ok(true))),
            initial.as_ref().is_some_and(|loan| matches!(loan.is_host_stop_cleanup_data_v1(), Ok(true))),
            fixed.as_ref().and_then(|original| original.host_cleanup_purpose_v1()),
        )?;
        if let Some(witnesses) = &mut self.client_witnesses {
            let result = match expected_node {
                Some(node) => owner.require_current_node(node, transcript, socket.peer()),
                None => owner.revalidate_transport(transcript, socket.peer()),
            };
            if let Err(error) = result {
                self.first_failure = Some(error.into());
                self.output_failure_site
                    .get_or_insert(OutputColdFailureSiteV1::ProtectedOwner);
            }
            let witness_current = match witnesses {
                Ok(witnesses) => witnesses.revalidate(socket.peer()),
                Err(_) => false,
            };
            if !witness_current {
                if self.first_failure.is_some() {
                    self.output_witness_debt = true;
                } else {
                    self.output_failure_site
                        .get_or_insert(OutputColdFailureSiteV1::WitnessPostcheck);
                }
            }
            if self.first_failure.is_some() {
                return Err(crate::DormantBrokerSessionHandshakeErrorV1::Protected(
                    BrokerSessionSecurityError::Currentness,
                ));
            }
            if !witness_current {
                return Err(crate::DormantBrokerSessionHandshakeErrorV1::KernelEvidence);
            }
        } else {
            match expected_node {
                Some(node) => owner.require_current_node(node, transcript, socket.peer())?,
                None => owner.revalidate_transport(transcript, socket.peer())?,
            }
        }
        self.deadline.check()?;

        #[cfg(feature = "online-nix")]
        if let Some(establishment) = self.online_client_establishment {
            self.verified.require_online_client_witnesses(establishment)?;
        }

        if let Some(receiving) = receiving.as_deref_mut() {
            receiving.require_session_fixed_current_v1()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        }

        if let Some(original) = fixed.as_deref_mut() { original.require_current_v4()?; }

        // Final node/startup/currentness observations precede the final same-D
        // check inside retirement. Selected Client witnesses move once into
        // the Session; ordinary witnesses keep their original shell lifetime.
        if let Some(retained) = retained.as_deref_mut() {
            let journal = owner.retained_storage_journal_v1()?;
            retained.require_current_v1(journal, socket)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        }
        if let Some(original) = initial.as_deref_mut() {
            owner.require_controller_initial_journal_v1(original)?;
        }
        if initial.is_some() {
            let carrier = self.verified.carrier.as_mut()
                .ok_or(crate::DormantBrokerSessionHandshakeErrorV1::Transport)?;
            let HandshakeTransport::Ordinary(socket) = &mut carrier.transport else {
                return Err(crate::DormantBrokerSessionHandshakeErrorV1::Transport);
            };
            // The genuine initial socket rejected rights before connection.
            // Restore only after complete authentication/currentness, while
            // the same cold interval still owns its independent failure post.
            // The existing final retirement below checks the SAME absolute
            // cutoff after this syscall and before the Session is published.
            self.controller_rights_restore = Some(socket.restore_rights_once_v1());
            if !matches!(self.controller_rights_restore, Some(Ok(()))) {
                return Err(crate::DormantBrokerSessionHandshakeErrorV1::Transport);
            }
        }
        // Reborrow the same retained carrier after its mutable native-mode
        // transition; no socket is replaced, adopted or observed here.
        let carrier = self.verified.carrier.as_ref()
            .ok_or(crate::DormantBrokerSessionHandshakeErrorV1::Transport)?;
        let HandshakeTransport::Ordinary(socket) = &carrier.transport else {
            return Err(crate::DormantBrokerSessionHandshakeErrorV1::Transport);
        };
        if let Some(original) = host.as_deref_mut() { original.require_current_v1()?; }
        if retained_open {
            // The native floor's original cold interval is already retired.
            // Only this new HELLO transport cutoff completes here; no reset,
            // floor attachment or request rollover CAS is performed.
            self.deadline.check()?;
        } else {
            owner.retire_cold_deadline(self.deadline)?;
        }
        if let Some(client) = client.as_deref_mut() {
            let journal = owner.retained_storage_client_journal_v1()?;
            if client.complete_narrow_hello_once(journal, socket, transcript).is_err() {
                self.output_failure_site = Some(OutputColdFailureSiteV1::ClientNative);
                return Err(BrokerSessionSecurityError::Currentness.into());
            }
        }
        Ok(())
    }

    fn storage_host_native_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let first = self.first_failure.as_ref();
        if let Some(crate::DormantBrokerSessionHandshakeErrorV1::Protected(cause)) = first {
            if let Some(original) = self.retained_revalidation_failure_for(cause) { return Some(original); }
        }
        self.checkpoint_construction.as_ref().and_then(|capture| capture.failure())
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.main.as_ref().and_then(|main| main.storage_host_native_failure_v1()))
    }

    fn controller_initial_native_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(returned)) = &self.controller_rights_restore {
            return self.initial_socket_v1().and_then(SeqpacketSocket::zero_rights_failure_v1)
                .or(Some(returned));
        }
        self.checkpoint_construction.as_ref().and_then(|capture| capture.failure())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.main.as_ref().and_then(|main| main.controller_initial_native_failure_v1()))
    }

    pub(crate) fn storage_prepare_native_failure_v1(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.owner.as_ref().and_then(|owner| owner.storage_prepare_native_failure())
            .or_else(|| self.initial_floor_disposal.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.storage_required_post.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.initial_post_preparation.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.hello_disposal.as_ref().map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.warm_hello_disposal.as_ref().map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.main.as_ref().and_then(|main| main.storage_prepare_native_failure()))
    }

    pub(crate) fn storage_prepare_cold_failure_v1(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.owner.as_ref().and_then(|owner| owner.storage_prepare_cold_failure())
            .or_else(|| self.main.as_ref().and_then(|main| main.storage_prepare_cold_failure()))
    }

    // Resolves only the site latched before the next independent bookend.
    // Later witness debt cannot displace the actual earlier protected cause.
    /// Borrows the original primary cold-open failure without consuming its custody.
    pub fn output_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.output_failure_site? {
            OutputColdFailureSiteV1::WitnessCreation
            | OutputColdFailureSiteV1::WitnessPrecheck
            | OutputColdFailureSiteV1::WitnessPostcheck => self.output_witness_cause(),
            OutputColdFailureSiteV1::ProtectedOwner | OutputColdFailureSiteV1::ClientNative
            | OutputColdFailureSiteV1::Outer => {
                self.first_failure.as_ref().map(|error| error as &dyn std::error::Error)
            }
        }
    }

    pub(crate) fn output_postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.output_witness_debt.then(|| self.output_witness_cause()).flatten()
    }

    fn output_witness_cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.client_witnesses.as_ref()? {
            Ok(witnesses) => witnesses.first_failure.as_ref()
                .map(ClientWitnessFailureV1::cause),
            Err(error) => Some(error),
        }
    }

    fn failure_projection(&self) -> crate::DormantBrokerSessionHandshakeErrorV1 {
        project_cold_failure(self.first_failure.as_ref())
    }
}

fn project_cold_failure(
    cause: Option<&crate::DormantBrokerSessionHandshakeErrorV1>,
) -> crate::DormantBrokerSessionHandshakeErrorV1 {
    use crate::DormantBrokerSessionHandshakeErrorV1 as Error;
    match cause {
        Some(Error::EndpointRole) => Error::EndpointRole,
        Some(Error::Protected(error)) => Error::Protected(error.clone()),
        Some(Error::RemoteInvalid) => Error::RemoteInvalid,
        Some(Error::KernelEvidence) => Error::KernelEvidence,
        Some(Error::Transport) => Error::Transport,
        Some(Error::Deadline) => Error::Deadline,
        // The complete actual cause remains in first_failure; this existing
        // status projection must neither move it nor invent retry authority.
        Some(Error::StoragePreparation(_) | Error::RetainedReceive(_)
            | Error::RetainedSend(_) | Error::SelectedSend(_) | Error::RecordBinding(_)) =>
                Error::Protected(BrokerSessionSecurityError::Currentness),
        None => Error::Protected(BrokerSessionSecurityError::Currentness),
    }
}

impl Drop for RetainedStorageColdOpenV1 {
    fn drop(&mut self) {
        if self.phase.is_unfinished() {
            // This is a terminal safety fence, not drain or recovery of a raw
            // pre-return prefix. Originals remain until process termination.
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod storage_cold_data_tests {
    use super::{OriginalBrokerColdDeadlineV1, StorageColdPhaseV1, project_cold_failure};
    use crate::{BrokerSessionSecurityError, DormantBrokerSessionHandshakeErrorV1 as Error};

    #[test]
    fn only_fresh_phase_can_begin() {
        assert!(StorageColdPhaseV1::Fresh.may_begin());
        for phase in [
            StorageColdPhaseV1::Checking,
            StorageColdPhaseV1::Complete,
            StorageColdPhaseV1::Failed,
        ] {
            assert!(!phase.may_begin());
        }
    }

    #[test]
    fn every_unfinished_parked_phase_is_closed_to_replacement() {
        for phase in [
            StorageColdPhaseV1::Fresh,
            StorageColdPhaseV1::Checking,
            StorageColdPhaseV1::Failed,
        ] {
            assert!(phase.is_unfinished());
        }
        assert!(!StorageColdPhaseV1::Complete.is_unfinished());
    }

    #[test]
    fn storage_deadline_data_preserves_original_without_renewal() {
        for original in [0, 1, 10_000_000_000, 30_000_000_000, u64::MAX] {
            let deadline = OriginalBrokerColdDeadlineV1::storage_accept(original);
            let retained_copy = deadline;

            assert_eq!(deadline.value(), original);
            assert_eq!(retained_copy.value(), original);
        }
    }

    #[test]
    fn outer_projection_preserves_each_actual_typed_case() {
        for cause in [
            Error::EndpointRole,
            Error::Protected(BrokerSessionSecurityError::Currentness),
            Error::RemoteInvalid,
            Error::KernelEvidence,
            Error::Transport,
            Error::Deadline,
        ] {
            let projected = project_cold_failure(Some(&cause));

            assert_eq!(projected.to_string(), cause.to_string());
        }
    }

    #[test]
    fn absent_diagnostic_is_currentness_not_retry_or_drain() {
        assert!(matches!(
            project_cold_failure(None),
            Error::Protected(BrokerSessionSecurityError::Currentness),
        ));
    }
}

impl VerifiedStorageHandshakeV1 {
    #[cfg(feature = "online-nix")]
    fn require_online_client_witnesses(
        &self,
        establishment: ProcessEvidence,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        let Some(HandshakeCarrier {
            transport: HandshakeTransport::Ordinary(socket),
            ..
        }) = &self.carrier else {
            return Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole);
        };
        let witnesses = self._witnesses.as_ref()
            .ok_or(DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?;
        witnesses.validate_client(
            establishment, socket.peer(), ClientWitnessValidationV1::OnlineNix,
        )?;
        Ok(())
    }

    fn client(root: &'static str, session: InertProvisionalClientSession) -> Self {
        let InertProvisionalClientSession {
            _custody: custody,
            _carrier: carrier,
            _publication_packet: publication,
            _client_packet: client_packet,
            _broker_packet: broker_packet,
            _publication_subject: publication_subject,
            _broker_subject: broker_subject,
            _transcript: transcript,
        } = session;
        let (custody, retained_owner) = match custody {
            ClientHandshakeCustodyV1::Fresh(endpoint) => (Some(FixedEndpointCustodyV1::Client(endpoint)), None),
            ClientHandshakeCustodyV1::RetainedStorage(owner) => (None, Some(owner)),
        };
        Self {
            root,
            custody,
            retained_owner,
            carrier: Some(carrier),
            transcript: Some(transcript),
            client_packet,
            broker_packet,
            _witnesses: Some(VerifiedStorageWitnessesV1::Client {
                _publication: publication,
                _publication_subject: publication_subject,
                _broker_subject: broker_subject,
            }),
        }
    }

    fn broker(root: &'static str, session: InertProvisionalBrokerSession) -> Self {
        let InertProvisionalBrokerSession {
            _custody: custody,
            _carrier: carrier,
            _publication: publication,
            _client_packet: client_packet,
            _client_subject: client_subject,
            _broker_packet: broker_packet,
            _transcript: transcript,
        } = session;
        let (custody, retained_owner) = match custody {
            BrokerHandshakeCustodyV1::Fresh(endpoint) => (Some(FixedEndpointCustodyV1::Broker(endpoint)), None),
            BrokerHandshakeCustodyV1::RetainedStorage(owner) => (None, Some(owner)),
        };
        Self {
            root,
            custody,
            retained_owner,
            carrier: Some(carrier),
            transcript: Some(transcript),
            client_packet,
            broker_packet,
            _witnesses: Some(VerifiedStorageWitnessesV1::Broker {
                _publication: publication,
                _client_subject: client_subject,
            }),
        }
    }
}

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
    /// The selected HELLO retains its whole returned native send observation.
    #[error("selected HELLO send failed with original custody retained")]
    SelectedSend(#[source] RetainedStorageHandshakeSendFailureV1),
    /// A parked selected record failed its original carrier comparison.
    #[error("selected Storage original carrier comparison failed")]
    RecordBinding(#[source] aos_sandbox_linux::seqpacket::RecordBindingError),
    /// The selected handshake retains its actual failed raw reducer owner.
    #[error("selected Storage handshake failed with original custody retained")]
    StoragePreparation(#[source] Box<RetainedStoragePreparationHandshakeFailureV1>),
    /// The adopted socket failed outside the retryable interruption profile.
    #[error("broker-session handshake transport failed")]
    Transport,
}

impl From<HandshakeError> for DormantBrokerSessionHandshakeErrorV1 {
    fn from(error: HandshakeError) -> Self {
        match error {
            HandshakeError::Local(error) => Self::Protected(error),
            HandshakeError::RemoteInvalid => Self::RemoteInvalid,
            HandshakeError::KernelEvidence | HandshakeError::RetainedProcess(_) => Self::KernelEvidence,
            HandshakeError::RetryableTransport => Self::Transport,
            HandshakeError::Transport => Self::Transport,
            HandshakeError::SelectedPreparation(error) => Self::StoragePreparation(error),
            HandshakeError::RetainedReceive(error) => Self::RetainedReceive(error),
            HandshakeError::RetainedSend(error) => Self::RetainedSend(error),
            HandshakeError::SelectedSend(error) => Self::SelectedSend(error),
            HandshakeError::RecordBinding(error) => Self::RecordBinding(error),
        }
    }
}

enum DormantClientHandshakeStateV1 {
    AwaitPublication(ClientAwaitPublication),
    SendHello(ClientHelloFlight),
    AwaitBrokerHello(ClientAwaitBrokerHello),
}

/// Owns one explicitly adopted client socket while its hello flights advance.
#[must_use = "advance, retain, or drop the dormant client handshake"]
pub(super) struct DormantControllerClientHandshakeV1 {
    root: &'static str,
    state: DormantClientHandshakeStateV1,
}

/// Reports one bounded client-side handshake step.
#[must_use = "retry or retain the completed dormant session"]
pub(super) enum DormantControllerClientHandshakeProgressV1 {
    /// A pending or retryable flight retained the complete handshake state.
    Pending(DormantControllerClientHandshakeV1),
    /// The protected hello exchange and fixed journal open both completed.
    Complete(DormantAuthenticatedBrokerSessionV1),
}

impl DormantControllerClientHandshakeV1 {
    fn retained_client_parts_mut_v1(&mut self)
        -> Option<(&mut ProtectedBrokerSessionOwnerV1, &SeqpacketSocket)>
    {
        match &mut self.state {
            DormantClientHandshakeStateV1::AwaitPublication(stage) => client_retained_parts_v1(&mut stage.custody, &stage.carrier),
            DormantClientHandshakeStateV1::SendHello(stage) => client_retained_parts_v1(&mut stage.custody, &stage.carrier),
            DormantClientHandshakeStateV1::AwaitBrokerHello(stage) => client_retained_parts_v1(&mut stage.custody, &stage.carrier),
        }
    }

    fn begin(
        root: &'static str,
        custody: ProtectedBrokerSessionClientV1,
        socket: SeqpacketSocket,
        hello: BrokerClientHello,
    ) -> Result<Self, DormantBrokerSessionHandshakeErrorV1> {
        let carrier = HandshakeCarrier::ordinary(socket)?;
        let state = ClientAwaitPublication::begin(ClientHandshakeCustodyV1::Fresh(custody), carrier, hello)?;
        Ok(Self {
            root,
            state: DormantClientHandshakeStateV1::AwaitPublication(state),
        })
    }

    fn begin_controller_initial_v1(
        root: &'static str,
        custody: ProtectedBrokerSessionClientV1,
        socket: SeqpacketSocket,
        hello: BrokerClientHello,
        peer: ProcessEvidence,
    ) -> Self {
        Self::begin_selected_client_v1(root, custody, socket, hello, peer,
            HandshakeReceiveProfileV1::ControllerInitial)
    }

    fn begin_start_resource_v4(
        root: &'static str, custody: ProtectedBrokerSessionClientV1,
        socket: SeqpacketSocket, hello: BrokerClientHello, peer: ProcessEvidence,
    ) -> Self {
        Self::begin_selected_client_v1(root, custody, socket, hello, peer,
            HandshakeReceiveProfileV1::StartResource)
    }

    pub(super) fn begin_storage_host_v1(
        root: &'static str,
        custody: ProtectedBrokerSessionClientV1,
        socket: SeqpacketSocket,
        hello: BrokerClientHello,
        peer: ProcessEvidence,
    ) -> Self {
        Self::begin_selected_client_v1(root, custody, socket, hello, peer,
            HandshakeReceiveProfileV1::StorageHost)
    }

    fn begin_selected_client_v1(
        root: &'static str,
        custody: ProtectedBrokerSessionClientV1,
        socket: SeqpacketSocket,
        hello: BrokerClientHello,
        peer: ProcessEvidence,
        profile: HandshakeReceiveProfileV1,
    ) -> Self {
        let carrier = HandshakeCarrier::ordinary_from_peer_v1(socket, peer, profile);
        Self {
            root,
            state: DormantClientHandshakeStateV1::AwaitPublication(ClientAwaitPublication {
                custody: ClientHandshakeCustodyV1::Fresh(custody),
                selected_client_packet: None,
                carrier,
                client_hello: hello,
            }),
        }
    }

    fn begin_retained_storage(
        owner: ProtectedBrokerSessionOwnerV1,
        socket: SeqpacketSocket,
        hello: BrokerClientHello,
        peer: ProcessEvidence,
    ) -> Self {
        // The enclosing paid transition retains the actual peer capture Result.
        // Construction itself cannot drop the same owner/socket on a new error.
        let carrier = HandshakeCarrier::ordinary_from_peer_v1(
            socket, peer, HandshakeReceiveProfileV1::StoragePreparation,
        );
        let stage = ClientAwaitPublication {
            custody: ClientHandshakeCustodyV1::RetainedStorage(owner),
            selected_client_packet: None,
            carrier,
            client_hello: hello,
        };
        Self {
            root: aos_sandbox_controller_domain::journal::broker_session_receiving::CONTROLLER_STORAGE_CLIENT_JOURNAL_ROOT_V1,
            state: DormantClientHandshakeStateV1::AwaitPublication(stage),
        }
    }

    /// Advances exactly one receive or send flight on the adopted socket.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid remote bytes, changed kernel evidence,
    /// protected-custody failure, or a non-retryable transport failure.
    pub(super) fn advance(
        self,
    ) -> Result<DormantControllerClientHandshakeProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        match self.advance_with_completion(HandshakeCompletionV1::Legacy)? {
            ColdClientHandshakeProgressV1::Pending(pending) => {
                Ok(DormantControllerClientHandshakeProgressV1::Pending(pending))
            }
            ColdClientHandshakeProgressV1::Complete(session) => {
                Ok(DormantControllerClientHandshakeProgressV1::Complete(session))
            }
            ColdClientHandshakeProgressV1::Verified(_) => {
                Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole)
            }
        }
    }

    // The same three-flight reducer returns the real verified handoff before
    // context/checkpoint/main/floor work. Selected raw failures retain the same
    // reducer owner; ordinary profiles preserve their existing disposition.
    pub(super) fn advance_retaining_storage(
        self,
    ) -> Result<ColdClientHandshakeProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        self.advance_with_completion(HandshakeCompletionV1::RetainStorage)
    }

    pub(super) fn advance_output_client(
        self,
    ) -> Result<ColdClientHandshakeProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        self.advance_with_completion(HandshakeCompletionV1::OutputClient)
    }

    fn advance_with_completion(
        self,
        completion: HandshakeCompletionV1,
    ) -> Result<ColdClientHandshakeProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        match self.state {
            DormantClientHandshakeStateV1::AwaitPublication(state) => match state.receive() {
                Transition::Complete(state) => {
                    Ok(ColdClientHandshakeProgressV1::Pending(Self {
                        root: self.root,
                        state: DormantClientHandshakeStateV1::SendHello(state),
                    }))
                }
                Transition::Retry(state) => {
                    Ok(ColdClientHandshakeProgressV1::Pending(Self {
                        root: self.root,
                        state: DormantClientHandshakeStateV1::AwaitPublication(state),
                    }))
                }
                Transition::Failed(error) => Err(error.into()),
            },
            DormantClientHandshakeStateV1::SendHello(state) => match state.send() {
                Transition::Complete(state) => {
                    Ok(ColdClientHandshakeProgressV1::Pending(Self {
                        root: self.root,
                        state: DormantClientHandshakeStateV1::AwaitBrokerHello(state),
                    }))
                }
                Transition::Retry(state) => {
                    Ok(ColdClientHandshakeProgressV1::Pending(Self {
                        root: self.root,
                        state: DormantClientHandshakeStateV1::SendHello(state),
                    }))
                }
                Transition::Failed(error) => Err(error.into()),
            },
            DormantClientHandshakeStateV1::AwaitBrokerHello(state) => match state.receive() {
                Transition::Complete(session) => match completion {
                    HandshakeCompletionV1::Legacy => Ok(ColdClientHandshakeProgressV1::Complete(
                        DormantAuthenticatedBrokerSessionV1::from_client(self.root, session)?,
                    )),
                    HandshakeCompletionV1::RetainStorage => {
                        Ok(ColdClientHandshakeProgressV1::Verified(
                            VerifiedStorageHandshakeV1::client(self.root, session),
                        ))
                    }
                    HandshakeCompletionV1::OutputClient => Ok(ColdClientHandshakeProgressV1::Complete(
                        DormantAuthenticatedBrokerSessionV1::from_output_client(self.root, session)?,
                    )),
                },
                Transition::Retry(state) => {
                    Ok(ColdClientHandshakeProgressV1::Pending(Self {
                        root: self.root,
                        state: DormantClientHandshakeStateV1::AwaitBrokerHello(state),
                    }))
                }
                Transition::Failed(error) => Err(error.into()),
            },
        }
    }

    pub(super) fn as_fd(&self) -> Result<BorrowedFd<'_>, DormantBrokerSessionHandshakeErrorV1> {
        match &self.state {
            DormantClientHandshakeStateV1::AwaitPublication(state) => state.carrier.as_fd(),
            DormantClientHandshakeStateV1::SendHello(state) => state.carrier.as_fd(),
            DormantClientHandshakeStateV1::AwaitBrokerHello(state) => state.carrier.as_fd(),
        }
    }

    pub(super) const fn wants_write(&self) -> bool {
        matches!(self.state, DormantClientHandshakeStateV1::SendHello(_))
    }
}

enum DormantBrokerHandshakeStateV1 {
    SendPublication(BrokerPublicationFlight),
    AwaitClientHello(BrokerAwaitClientHello),
    SendHello(BrokerHelloFlight),
}

/// Owns one explicitly adopted broker socket while its hello flights advance.
#[must_use = "advance, retain, or drop the dormant broker handshake"]
pub(super) struct DormantBrokerEndpointHandshakeV1 {
    root: &'static str,
    state: DormantBrokerHandshakeStateV1,
}

/// Reports one bounded broker-side handshake step.
#[must_use = "retry or retain the completed dormant session"]
pub(super) enum DormantBrokerEndpointHandshakeProgressV1 {
    /// A pending or retryable flight retained the complete handshake state.
    Pending(DormantBrokerEndpointHandshakeV1),
    /// The protected hello exchange and fixed journal open both completed.
    Complete(DormantAuthenticatedBrokerSessionV1),
}

impl DormantBrokerEndpointHandshakeV1 {
    fn begin(
        root: &'static str,
        custody: ProtectedBrokerSessionBrokerV1,
        socket: SeqpacketSocket,
        hello: BrokerServerHello,
    ) -> Result<Self, DormantBrokerSessionHandshakeErrorV1> {
        let carrier = HandshakeCarrier::ordinary(socket)?;
        let state = BrokerPublicationFlight::begin(BrokerHandshakeCustodyV1::Fresh(custody), carrier, hello)?;
        Ok(Self {
            root,
            state: DormantBrokerHandshakeStateV1::SendPublication(state),
        })
    }

    // Only the genuine fixed-current receiving loan can select the bounded
    // raw profile, before this same original handshake publishes any flight.
    pub(crate) fn require_initial_storage_hello_current_v1(
        &self,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        let carrier = match &self.state {
            DormantBrokerHandshakeStateV1::SendPublication(flight) => &flight.carrier,
            DormantBrokerHandshakeStateV1::AwaitClientHello(flight) => &flight.carrier,
            DormantBrokerHandshakeStateV1::SendHello(flight) => &flight.carrier,
        };
        let HandshakeTransport::Ordinary(socket) = &carrier.transport else {
            return Err(BrokerSessionSecurityError::Currentness);
        };
        receiving.require_initial_session_hello_current_v1(socket)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    pub(super) fn advance(
        self,
    ) -> Result<DormantBrokerEndpointHandshakeProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        match self.advance_with_completion(HandshakeCompletionV1::Legacy)? {
            ColdBrokerHandshakeProgressV1::Pending(pending) => {
                Ok(DormantBrokerEndpointHandshakeProgressV1::Pending(pending))
            }
            ColdBrokerHandshakeProgressV1::Complete(session) => {
                Ok(DormantBrokerEndpointHandshakeProgressV1::Complete(session))
            }
            ColdBrokerHandshakeProgressV1::Verified(_) => {
                Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole)
            }
        }
    }

    pub(super) fn retain_storage_preparation_failure_v1(
        self,
        error: crate::DormantBrokerSessionHandshakeErrorV1,
    ) -> crate::DormantBrokerSessionHandshakeErrorV1 {
        let owner = match self.state {
            DormantBrokerHandshakeStateV1::SendPublication(stage) => SelectedBrokerFailureOwnerV1::Publication(stage),
            DormantBrokerHandshakeStateV1::AwaitClientHello(stage) =>
                SelectedBrokerFailureOwnerV1::ClientHello { stage, _flight: None },
            DormantBrokerHandshakeStateV1::SendHello(stage) => SelectedBrokerFailureOwnerV1::ServerHello(stage),
        };
        if !owner.selected() { return error; }
        crate::DormantBrokerSessionHandshakeErrorV1::StoragePreparation(Box::new(
            RetainedStoragePreparationHandshakeFailureV1 {
                first: SelectedHandshakeFailureCauseV1::Outer(error), post: None, postchecks: None, _owner: owner,
            },
        ))
    }

    // The same three-flight reducer returns the real verified handoff before
    // context/checkpoint/main/floor work. Selected raw failures retain the same
    // reducer owner; ordinary profiles preserve their existing disposition.
    pub(super) fn advance_retaining_storage(
        self,
    ) -> Result<ColdBrokerHandshakeProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        self.advance_with_completion(HandshakeCompletionV1::RetainStorage)
    }

    fn advance_with_completion(
        self,
        completion: HandshakeCompletionV1,
    ) -> Result<ColdBrokerHandshakeProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        match self.state {
            DormantBrokerHandshakeStateV1::SendPublication(state) => match state.send() {
                Transition::Complete(state) => {
                    Ok(ColdBrokerHandshakeProgressV1::Pending(Self {
                        root: self.root,
                        state: DormantBrokerHandshakeStateV1::AwaitClientHello(state),
                    }))
                }
                Transition::Retry(state) => {
                    Ok(ColdBrokerHandshakeProgressV1::Pending(Self {
                        root: self.root,
                        state: DormantBrokerHandshakeStateV1::SendPublication(state),
                    }))
                }
                Transition::Failed(error) => Err(error.into()),
            },
            DormantBrokerHandshakeStateV1::AwaitClientHello(state) => match state.receive() {
                Transition::Complete(state) => {
                    Ok(ColdBrokerHandshakeProgressV1::Pending(Self {
                        root: self.root,
                        state: DormantBrokerHandshakeStateV1::SendHello(state),
                    }))
                }
                Transition::Retry(state) => {
                    Ok(ColdBrokerHandshakeProgressV1::Pending(Self {
                        root: self.root,
                        state: DormantBrokerHandshakeStateV1::AwaitClientHello(state),
                    }))
                }
                Transition::Failed(error) => Err(error.into()),
            },
            DormantBrokerHandshakeStateV1::SendHello(state) => match state.send() {
                Transition::Complete(session) => match completion {
                    HandshakeCompletionV1::Legacy => Ok(ColdBrokerHandshakeProgressV1::Complete(
                        DormantAuthenticatedBrokerSessionV1::from_broker(self.root, session)?,
                    )),
                    HandshakeCompletionV1::RetainStorage => {
                        Ok(ColdBrokerHandshakeProgressV1::Verified(
                            VerifiedStorageHandshakeV1::broker(self.root, session),
                        ))
                    }
                    HandshakeCompletionV1::OutputClient => Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole),
                },
                Transition::Retry(state) => {
                    Ok(ColdBrokerHandshakeProgressV1::Pending(Self {
                        root: self.root,
                        state: DormantBrokerHandshakeStateV1::SendHello(state),
                    }))
                }
                Transition::Failed(error) => Err(error.into()),
            },
        }
    }

    pub(super) fn as_fd(&self) -> Result<BorrowedFd<'_>, DormantBrokerSessionHandshakeErrorV1> {
        match &self.state {
            DormantBrokerHandshakeStateV1::SendPublication(state) => state.carrier.as_fd(),
            DormantBrokerHandshakeStateV1::AwaitClientHello(state) => state.carrier.as_fd(),
            DormantBrokerHandshakeStateV1::SendHello(state) => state.carrier.as_fd(),
        }
    }

    pub(super) const fn wants_write(&self) -> bool {
        matches!(
            self.state,
            DormantBrokerHandshakeStateV1::SendPublication(_)
                | DormantBrokerHandshakeStateV1::SendHello(_)
        )
    }
}

/// Retains one selected response send through all protected transport posts.
pub(crate) struct StorageResponseSendAttemptV1 {
    before: Result<(), BrokerSessionSecurityError>,
    native: Option<aos_sandbox_linux::seqpacket::StorageSeqpacketSendAttemptV1>,
    after: Result<(), BrokerSessionSecurityError>,
}

impl StorageResponseSendAttemptV1 {
    // Two original turns plus one reusable exact-replay attempt stay resident.
    // Native syscall errors use raw errno; the sole malformed send diagnostic
    // is a fixed message shorter than this conservative byte allowance.
    pub(crate) fn retained_cycle_obligations_v1() -> Option<(usize, usize)> {
        let bytes = crate::production_service::ProductionOriginalStoragePrepareCycleV1::retained_carrier_bytes_v1()
            .max(std::mem::size_of::<crate::production_service::ProductionOriginalStorageLifecycleSessionV1>())
            .checked_add(3 * 128)?;
        Some((bytes, 3))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Err(error) = &self.before { return Some(error); }
        if let Some(error) = self.native.as_ref().and_then(|native| native.failure()) {
            return Some(error);
        }
        self.after.as_ref().err().map(|error| error as &dyn std::error::Error)
    }

    // A returned errno is not an operation refusal when the same actual lower
    // receipt proves nonconsumption and all protected/native posts are positive.
    pub(super) fn refuses_terminal_progress_v1(&self) -> bool {
        !self.is_sent() && !self.is_nonconsuming()
    }

    pub(crate) fn take_native_sent_v1(&mut self)
        -> Option<aos_sandbox_linux::seqpacket::StorageSeqpacketSendAttemptV1>
    {
        if self.is_sent() { self.native.take() } else { None }
    }

    pub(super) fn is_nonconsuming(&self) -> bool {
        self.before.is_ok() && self.after.is_ok()
            && self.native.as_ref().is_some_and(|native| native.is_nonconsuming())
    }

    pub(super) fn is_sent(&self) -> bool {
        self.before.is_ok() && self.after.is_ok()
            && self.native.as_ref().is_some_and(|native| native.is_sent())
    }
}

/// Keeps actual response-native prefixes through the enclosing paid posts.
#[derive(Default)]
pub(crate) struct ExecutionResponsePacketOriginalV1 {
    receive_error: Option<aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>,
    binding_error: Option<aos_sandbox_linux::seqpacket::RecordBindingError>,
    rejected_record: Option<aos_sandbox_linux::seqpacket::ReceivedRecord>,
    payload: Option<Vec<u8>>,
    subject: Option<aos_sandbox_linux::seqpacket::KernelAuthorizedRecordSubject>,
    alive: Option<aos_linux_descriptors::Result<bool>>,
}

impl ExecutionResponsePacketOriginalV1 {
    fn entered(&self) -> bool {
        self.receive_error.is_some() || self.binding_error.is_some()
            || self.rejected_record.is_some() || self.payload.is_some() || self.subject.is_some()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.receive_error.as_ref().map(|error| error as _)
            .or_else(|| self.binding_error.as_ref().map(|error| error as _))
            .or_else(|| self.alive.as_ref()?.as_ref().err().map(|error| error as _))
    }
}

/// Retains an authenticated adopted socket together with its fixed protected owner.
///
/// No service is registered and no request is dispatched. The callback keeps
/// the verified transcript scoped to the co-owned socket, journal, and exact
/// kernel peer observation.
#[must_use = "retain the authenticated dormant session while using protected history"]
pub(super) struct DormantAuthenticatedBrokerSessionV1 {
    owner: ProtectedBrokerSessionOwnerV1,
    socket: SeqpacketSocket,
    transcript: VerifiedBrokerSessionTranscriptV1,
    checkpoint: HistoricalSessionCheckpointV1,
    client_witnesses: Result<Option<AuthenticatedClientWitnessesV1>, HandshakeError>,
    terminal_witness_failure: bool,
    terminal_witness_debt: Option<OutputCurrentnessBoundaryV1>,
    // Declared last: the actual Session's journal, socket, checkpoint and
    // witnesses physically drop before their Source/C18 retention identity.
    execution_cold_native: Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerExecutionColdSessionRetentionV2>,
    // The same last-field rule covers Recover-funded cold Session graphs.
    recovery_session_native: Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerRecoverySessionRetentionV1>,
    // Source22 keeps its own financial native identity after the Session graph.
    stop_cleanup_source_native: Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerStopCleanupSessionRetentionV1>,
}

// The closed two-successor route has thirteen root-step returns, four reader
// returns, one output-read return and two phase returns. These are comparison
// archives, not a memory-funding or fresh-floor proof.
#[cfg(feature = "online-nix")]
pub(crate) const ONLINE_POSTFLIGHT_PASSES_V1: usize = 20;

/// Retains independent negative observations without granting currentness.
#[cfg(feature = "online-nix")]
pub(crate) struct OnlinePostflightV1 {
    pub(crate) client_before: Option<Result<(), BrokerSessionSecurityError>>,
    pub(crate) endpoint_before: Option<Result<(), BrokerSessionSecurityError>>,
    pub(crate) peer: Option<Result<(), BrokerSessionSecurityError>>,
    pub(crate) endpoint_after: Option<Result<(), BrokerSessionSecurityError>>,
    pub(crate) named: Option<Result<(), aos_sandbox_controller_domain::JournalError>>,
    pub(crate) floor: Option<Result<(), crate::tpm_nv_custody::FloorErrorV1>>,
    pub(crate) client_after: Option<Result<(), BrokerSessionSecurityError>>,
    pub(crate) clock: Option<Result<(), OnlinePostflightClockErrorV1>>,
}

#[cfg(feature = "online-nix")]
impl OnlinePostflightV1 {
    pub(crate) const fn new() -> Self {
        Self {
            client_before: None,
            endpoint_before: None,
            peer: None,
            endpoint_after: None,
            named: None,
            floor: None,
            client_after: None,
            clock: None,
        }
    }

    pub(crate) fn failed(&self) -> bool {
        self.client_before.as_ref().is_none_or(Result::is_err)
            || self.endpoint_before.as_ref().is_none_or(Result::is_err)
            || self.peer.as_ref().is_none_or(Result::is_err)
            || self.endpoint_after.as_ref().is_none_or(Result::is_err)
            || self.named.as_ref().is_none_or(Result::is_err)
            || self.floor.as_ref().is_none_or(Result::is_err)
            || self.client_after.as_ref().is_none_or(Result::is_err)
            || self.clock.as_ref().is_none_or(Result::is_err)
    }
}

#[cfg(all(test, feature = "online-nix"))]
mod online_postflight_data_tests {
    use super::{OnlinePostflightClockErrorV1, OnlinePostflightV1};
    use crate::BrokerSessionSecurityError;

    #[test]
    fn an_unobserved_report_is_not_positive() {
        assert!(OnlinePostflightV1::new().failed());
    }

    #[test]
    fn later_clock_debt_does_not_replace_an_earlier_component_cause() {
        let mut report = OnlinePostflightV1::new();
        report.endpoint_before = Some(Err(BrokerSessionSecurityError::ExecutionChanged));

        report.clock = Some(Err(OnlinePostflightClockErrorV1::Unavailable));

        assert!(matches!(report.endpoint_before.as_ref(),
            Some(Err(BrokerSessionSecurityError::ExecutionChanged))));
        assert!(matches!(report.clock.as_ref(),
            Some(Err(OnlinePostflightClockErrorV1::Unavailable))));
        assert!(report.failed());
    }
}

/// Keeps the actual final clock cause separate from an earlier action cause.
#[cfg(feature = "online-nix")]
#[derive(Debug, thiserror::Error)]
pub(crate) enum OnlinePostflightClockErrorV1 {
    #[error("the original paired clock observation failed: {0}")]
    Observation(#[from] aos_sandbox_model::OwnershipClockObservationError),
    #[error("the original admitted effect clock failed: {0}")]
    Effect(#[from] aos_sandbox_broker::BrokerAdmissionError),
    #[error("the original admitted clock context is unavailable or already fenced")]
    Unavailable,
}

/// Reports selected transport failures while originals stay in caller slots.
#[cfg(feature = "online-nix")]
#[derive(Debug, thiserror::Error)]
pub enum OnlineTransportFailureV1 {
    /// The original protected Session or currentness check refused.
    #[error("online protected Session custody failed: {0}")]
    Protected(#[from] BrokerSessionSecurityError),
    /// The returned record did not bind to the original socket.
    #[error("online original record binding failed: {0}")]
    Binding(#[from] aos_sandbox_linux::seqpacket::RecordBindingError),
    /// The original kernel record-subject observation failed.
    #[error("online original record subject failed: {0}")]
    Kernel(#[from] aos_linux_descriptors::Error),
    /// The original HELLO witness refused its currentness check.
    #[error("online original HELLO witness failed: {0}")]
    Witness(#[from] DormantBrokerSessionHandshakeErrorV1),
    /// The actual owning native receive failure remains in its resident slot.
    #[error("the actual owning receive failure is retained in this attempt")]
    Receive,
    /// The actual admission failure remains in its resident slot.
    #[error("the actual request admission error is retained in this attempt")]
    Admission,
    /// The original paired ownership-clock observation failed.
    #[error("original paired clock observation failed: {0}")]
    Clock(#[from] aos_sandbox_model::OwnershipClockObservationError),
    /// The actual selected request decoder failure remains in its slot.
    #[error("the actual selected request decoder error remains in its slot")]
    Decode,
    /// The actual selected send failure remains in its slot.
    #[error("the actual selected send error remains in its slot")]
    Send,
    /// The original transport or result destination is closed.
    #[error("online original transport or destination slot is closed")]
    Closed,
}

/// Keeps the full native target even when commit or its readback is ambiguous.
#[cfg(feature = "online-nix")]
pub(crate) enum OnlineRequestNativeResultV1 {
    Initialized(Result<crate::ProtectedBrokerSessionInitializationResultV1, BrokerSessionSecurityError>),
    Appended(Result<crate::ProtectedBrokerRequestCommitResultV1, BrokerSessionSecurityError>),
}

#[cfg(feature = "online-nix")]
impl OnlineRequestNativeResultV1 {
    pub(crate) fn is_committed(&self) -> bool {
        matches!(self,
            Self::Initialized(Ok(crate::ProtectedBrokerSessionInitializationResultV1::Initialized))
                | Self::Appended(Ok(crate::ProtectedBrokerRequestCommitResultV1::Committed))
        )
    }
}

/// Opens the sole cgroup root used by both fixed Mount worker-peer boundaries.
pub(super) fn fixed_mount_peer_verifier()
-> Result<aos_sandbox_host::peer::ControllerPeerVerifier, DormantBrokerSessionHandshakeErrorV1> {
    Ok(aos_sandbox_host::peer::ControllerPeerVerifier::new(
        fixed_worker_cgroup_root()?,
    ))
}

fn fixed_worker_cgroup_root()
-> Result<aos_sandbox_linux::cgroup::CgroupV2Root, DormantBrokerSessionHandshakeErrorV1> {
    let descriptor = rustix::fs::open(
        "/sys/fs/cgroup",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
    aos_sandbox_linux::cgroup::CgroupV2Root::from_owned(descriptor)
        .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)
}

impl DormantAuthenticatedBrokerSessionV1 {
    // Keep the actual Session association inside its owning module. The native
    // loan borrows the genuine B/C23 originals, not the Session field references.
    pub(crate) fn borrow_create_provisioning_client_once_v1<'turn, 'original, 'intake>(
        &self,
        initial: &'turn aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingV1,
        receiving: &'turn mut aos_sandbox_controller_domain::OriginalCreateProvisioningRootLoanV1<'original, 'intake>,
        controller: &'turn aos_sandbox_controller_domain::Journal,
        complete: aos_sandbox_model::ResourceVector,
    ) -> Result<
        Result<aos_sandbox_controller_domain::OriginalCreateStorageClientSessionV1<'turn, 'original, 'intake>,
            aos_sandbox_controller_domain::CreateStorageClientSessionClosedV1>,
        BrokerSessionSecurityError,
    > {
        let journal = self.owner.retained_storage_client_journal_v1()?;
        Ok(receiving.borrow_storage_apply_client_once_v1(
            initial, controller, journal, &self.socket, &self.transcript, complete,
        ))
    }

    // The actual session owns these private native fields. Keep the same
    // journal/socket/transcript association here rather than exporting them.
    pub(crate) fn require_create_provisioning_predecessor_v1(
        &self,
        initial: &aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingV1,
        receiving: &mut aos_sandbox_controller_domain::OriginalCreateProvisioningRootLoanV1<'_, '_>,
        controller: &aos_sandbox_controller_domain::Journal,
        complete: aos_sandbox_model::ResourceVector,
    ) -> Result<
        Result<(), aos_sandbox_controller_domain::CreateProvisioningClientSessionAssociationErrorV1>,
        BrokerSessionSecurityError,
    > {
        let journal = self.owner.retained_storage_client_journal_v1()?;
        Ok(receiving.require_completed_preparation_session_v1(
            initial, controller, journal, &self.socket, &self.transcript, complete,
        ))
    }

    pub(super) fn require_initial_storage_socket_current_v1(
        &self,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1> {
        receiving.require_initial_session_socket_current_v1(&self.socket)
    }

    pub(crate) fn resume_storage_lifecycle_v1<'cut, 'original>(
        &self,
        receiving: &'cut mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'original>,
    ) -> Result<aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'cut, 'original>, aos_sandbox_controller_domain::StorageReceivingClosedV1> {
        let journal = self.owner.retained_storage_journal_v1()
            .map_err(|_| aos_sandbox_controller_domain::StorageReceivingClosedV1)?;
        receiving.resume_lifecycle_session_v1(journal, &self.socket)
    }

    pub(crate) fn begin_initial_storage_lifecycle_v1<'cut, 'original>(
        &self,
        receiving: &'cut mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'original>,
    ) -> Result<aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'cut, 'original>, aos_sandbox_controller_domain::StorageReceivingClosedV1> {
        let journal = self.owner.retained_storage_journal_v1()
            .map_err(|_| aos_sandbox_controller_domain::StorageReceivingClosedV1)?;
        receiving.borrow_initial_lifecycle_session_v1(journal, &self.socket)
    }

    pub(crate) fn arm_storage_request_post_v1(
        &self,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1> {
        let journal = self.owner.retained_storage_journal_v1()
            .map_err(|_| aos_sandbox_controller_domain::StorageReceivingClosedV1)?;
        receiving.arm_request_observation_post_v1(journal, &self.socket)
    }

    pub(crate) fn arm_storage_operation_post_v1(
        &self,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1> {
        let journal = self.owner.retained_storage_journal_v1()
            .map_err(|_| aos_sandbox_controller_domain::StorageReceivingClosedV1)?;
        receiving.arm_operation_observation_post_v1(journal, &self.socket)
    }

    pub(crate) fn finish_storage_operation_post_v1(
        &self,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1> {
        // This private fixed borrower observes the same still-held Journal even
        // if its ordinary health gate now refuses after the primary action.
        let journal = self.owner.retained_storage_journal_v1()
            .map_err(|_| aos_sandbox_controller_domain::StorageReceivingClosedV1)?;
        receiving.finish_operation_observation_post_v1(journal, &self.socket)
    }

    pub(crate) fn require_storage_lifecycle_current_v1(
        &self,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1> {
        let journal = self.owner.retained_storage_journal_v1()
            .map_err(|_| aos_sandbox_controller_domain::StorageReceivingClosedV1)?;
        receiving.require_current_v1(journal, &self.socket)
    }

    pub(crate) fn prepare_storage_operation_disposal_v1<'phase, 'cut, 'original>(
        &self,
        receiving: &'phase mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'cut, 'original>,
        sent: aos_sandbox_linux::seqpacket::StorageSeqpacketSendAttemptV1,
    ) -> Result<
        aos_sandbox_controller_domain::StorageLifecyclePositiveDisposalV1<'phase, 'cut, 'original>,
        aos_sandbox_controller_domain::StorageLifecycleDisposalErrorV1,
    > {
        // The private owner, socket and exact terminal were just checked and
        // remain resident; no move or fallible operation separates that cut.
        let journal = match self.owner.retained_storage_journal_v1() {
            Ok(journal) => journal,
            Err(_) => std::process::abort(),
        };
        receiving.prepare_operation_disposal_v1(journal, &self.socket, sent)
    }

    pub(crate) fn reserve_storage_lifecycle_domain_v1(
        &self,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let journal = self.owner.retained_storage_journal_v1()
            .map_err(|_| aos_sandbox_controller_domain::StorageReceivingClosedV1)?;
        // Request/raw/artifact models are already paid by the consumed Request
        // flight. State/worker models are paid separately before their growth.
        let bytes = 3 * std::mem::size_of::<crate::dormant_handshake::ProtectedBrokerDomainResponseV1>()
            + 3 * std::mem::size_of::<crate::ProtectedBrokerOutcomeCommitResultV1>();
        receiving.reserve_domain_v1(journal, &self.socket,
            ResourceVector::ZERO.with(D::MemoryBytes, bytes as u64))
    }

    pub(crate) fn consume_storage_apply_receiving_v1(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
        protocol: aos_sandbox_model::ProtocolVersion,
        boot: [u8; 16],
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<Vec<u8>, aos_sandbox_storage::DormantStorageBrokerCallErrorV1> {
        let journal = self.owner.retained_storage_journal_v1()
            .map_err(|_| aos_sandbox_storage::StorageRuntimeError::Receiving)?;
        let artifacts = request.authorization()
            .ok_or(aos_sandbox_storage::DormantStorageBrokerCallErrorV1::StaleKernel)?;
        storage.consume_authenticated_apply_receiving_v1(
            request.exact_body(), request.request_id(),
            aos_sandbox_model::ObjectDigest::from_bytes(<sha2::Sha256 as sha2::Digest>::digest(request.exact_body()).into()),
            artifacts, request.peer(), request.peer_policy(), protocol, boot,
            receiving, journal, &self.socket,
        )
    }

    pub(crate) fn consume_storage_operation_lifecycle_v1(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
        protocol: aos_sandbox_model::ProtocolVersion,
        boot: [u8; 16],
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<Vec<u8>, aos_sandbox_storage::DormantStorageBrokerCallErrorV1> {
        let journal = self.owner.retained_storage_journal_v1()
            .map_err(|_| aos_sandbox_storage::StorageRuntimeError::Receiving)?;
        request.authorization()
            .ok_or(aos_sandbox_storage::DormantStorageBrokerCallErrorV1::StaleKernel)?;
        storage.consume_authenticated_operation_lifecycle_v1(
            request, protocol, boot, receiving, journal, &self.socket,
        )
    }

    pub(crate) fn consume_storage_inventory_receiving_v1(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
        cutoff: u64,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<Vec<u8>, aos_sandbox_storage::StorageRuntimeError> {
        let journal = self.owner.retained_storage_journal_v1()
            .map_err(|_| aos_sandbox_storage::StorageRuntimeError::Receiving)?;
        storage.consume_lifecycle_inventory_receiving_v1(
            request.deadline_boottime_nanoseconds(), cutoff, receiving, journal, &self.socket,
        )
    }

    pub(crate) fn reserve_storage_lifecycle_replay_v1(
        &self,
        replay: &crate::ProtectedBrokerOutcomeReplayV1,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        native_error: &mut Option<aos_sandbox_controller_domain::StorageReceivingClosedV1>,
    ) -> Result<(), BrokerSessionSecurityError> {
        let journal = self.owner.retained_storage_journal_v1()?;
        let extent = match receiving.observe_current_session_extent_v1(journal, &self.socket) {
            Ok(extent) => extent,
            Err(cause) => {
                *native_error = Some(cause);
                return Err(BrokerSessionSecurityError::Currentness);
            }
        };
        let demand = self.owner.retained_storage_replay_outcome_demand_v1(&extent, replay)?;
        receiving.reserve_outcome_v1(journal, &self.socket, demand).map_err(|cause| {
            *native_error = Some(cause);
            BrokerSessionSecurityError::Currentness
        })
    }

    pub(crate) fn compare_retained_storage_replay_v1(
        &mut self,
        replay: &crate::ProtectedBrokerOutcomeReplayV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.owner.compare_retained_storage_replay_v1(replay, self.socket.peer())
    }

    pub(crate) fn compare_retained_storage_terminal_owner_v1(
        &mut self,
        terminal: &crate::recovery::RetainedStorageTerminalV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.owner.compare_retained_storage_terminal_owner_v1(terminal, self.socket.peer())
    }

    pub(crate) fn into_retained_storage_terminal_owner_v1(
        mut self,
        terminal: crate::recovery::RetainedStorageTerminalV1,
    ) -> ProtectedBrokerSessionOwnerV1 {
        self.owner.dispose_storage_positive_replays_v3();
        self.owner.park_retired_storage_terminal_owner_v1(terminal, self.checkpoint);
        self.owner
    }

    pub(crate) fn reserve_storage_lifecycle_outcome_v1(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
        observation: &crate::dormant_handshake::ProtectedBrokerDomainResponseV1,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        let journal = self.owner.retained_storage_journal_v1()?;
        let extent = receiving.observe_current_session_extent_v1(journal, &self.socket)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let demand = self.owner.retained_storage_outcome_demand_v1(&extent, request, observation)?;
        receiving.reserve_outcome_v1(journal, &self.socket, demand)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn borrow_prepared_session_retirement_v1<'cut, 'original>(
        &self,
        receiving: &'cut mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'original>,
    ) -> Result<aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'cut, 'original>, aos_sandbox_controller_domain::StorageReceivingClosedV1> {
        let journal = self.owner.retained_storage_journal_v1()
            .map_err(|_| aos_sandbox_controller_domain::StorageReceivingClosedV1)?;
        receiving.borrow_prepared_session_retirement_v1(journal, &self.socket)
    }

    pub(crate) fn compare_retained_storage_terminal_v1(
        &mut self,
        terminal: &crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.owner.compare_retained_storage_terminal_v1(terminal, self.socket.peer())
    }

    pub(crate) fn end_storage_session_transport_v1(
        &mut self,
    ) -> aos_sandbox_linux::seqpacket::StorageSeqpacketEndAttemptV1 {
        self.socket.end_storage_session_retaining_v1()
    }

    pub(crate) fn prepare_storage_transport_disposal_v1<'phase, 'cut, 'original>(
        &self,
        receiving: &'phase mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'cut, 'original>,
        ended: aos_sandbox_linux::seqpacket::StorageSeqpacketEndAttemptV1,
    ) -> Result<
        aos_sandbox_controller_domain::StorageLifecyclePositiveDisposalV1<'phase, 'cut, 'original>,
        aos_sandbox_controller_domain::StorageLifecycleDisposalErrorV1,
    > {
        // The same fixed Journal was checked before end and has not moved.
        let journal = match self.owner.retained_storage_journal_v1() {
            Ok(journal) => journal,
            Err(_) => std::process::abort(),
        };
        receiving.prepare_session_transport_disposal_v1(journal, &self.socket, ended)
    }

    pub(crate) fn into_retained_storage_owner_v1(
        mut self,
        terminal: crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> ProtectedBrokerSessionOwnerV1 {
        // The sole caller has finished every fallible terminal/native/end post.
        // Preserve the actual terminal and old signed checkpoint before any
        // transport/control copy is disposed. This move does not write history.
        self.owner.dispose_storage_positive_replays_v3();
        self.owner.park_retired_storage_transcript_v1(terminal, self.checkpoint);
        self.owner
    }

    pub(super) fn storage_prepare_native_failure_v1(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.owner.storage_prepare_native_failure()
    }

    pub(super) fn is_original_storage_lifecycle_profile_v2(&self) -> bool {
        aos_sandbox_broker_session_protocol::profile::is_storage_lifecycle_transcript_v2(&self.transcript)
    }

    pub(super) fn is_original_storage_preparation_profile_v1(&self) -> bool {
        aos_sandbox_broker_session_protocol::profile::is_storage_preparation_transcript_v1(&self.transcript)
    }

    pub(super) fn output_registration_transport<'session>(
        &'session mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        state: &'session mut output_registration_continuation::OutputPreparationCustodyV1,
    ) -> output_registration_continuation::HeldOutputPreparationV1<'session> {
        output_registration_continuation::HeldOutputPreparationV1::begin(self, request, state)
    }

    pub(super) fn storage_prepare_outcome_demand_v1(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
        observation: &crate::dormant_handshake::ProtectedBrokerDomainResponseV1,
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        self.owner.storage_prepare_outcome_demand_v1(request, observation)
    }

    pub(super) fn storage_prepare_replay_demand_v1(
        &self,
        terminal: &crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        self.owner.storage_prepare_replay_demand_v1(terminal)
    }

    pub(super) fn storage_prepare_request_demand_v1(
        &self,
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        self.owner.storage_prepare_request_demand_v1()
    }

    pub(super) fn recheck_original_nix_generation_session(
        &mut self,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.owner
            .require_original_storage_output_server(&self.transcript, self.socket.peer())
    }

    pub(super) fn recheck_storage_receiving_v3(&mut self,
        receiving: Option<&mut dyn crate::recovery::StorageFloorFinancialSourceV2>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.owner.require_storage_server_receiving_v3(&self.transcript, self.socket.peer(), receiving)
    }

    pub(super) fn has_selected_capture_candidate_profile(&self) -> bool {
        self.transcript.negotiated_methods().contains(
            &BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE,
        )
    }

    pub(super) fn recheck_original_capture_candidate_client(
        &mut self,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.owner
            .require_original_capture_candidate_client(&self.transcript, self.socket.peer())
    }

    pub(super) fn compare_original_capture_candidate_outcome(
        &mut self,
        currentness: &crate::ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.owner
            .compare_original_capture_candidate_outcome(currentness, self.socket.peer())
    }

    pub(crate) fn revalidate_output_witnesses(&mut self) -> bool {
        if !self.owner.is_output_client_endpoint() {
            return true;
        }
        Self::revalidate_client_witnesses(&mut self.client_witnesses, self.socket.peer())
    }

    fn revalidate_client_witnesses(
        witnesses: &mut Result<Option<AuthenticatedClientWitnessesV1>, HandshakeError>,
        peer: &ConnectionPeerIdentity,
    ) -> bool {
        if matches!(witnesses.as_ref(), Ok(None)) {
            *witnesses = Err(HandshakeError::KernelEvidence);
        }
        match witnesses {
            Ok(Some(witnesses)) => witnesses.revalidate(peer),
            _ => false,
        }
    }

    pub(crate) fn captured_journal_failure_for_v1(&self, returned: &BrokerSessionSecurityError)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        self.owner.retained_revalidation_failure_for(returned)
    }

    pub(crate) fn output_witness_failure(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.client_witnesses {
            Ok(Some(witnesses)) => witnesses.first_failure.as_ref()
                .map(ClientWitnessFailureV1::cause),
            Err(error) => Some(error),
            Ok(None) => None,
        }
    }

    pub(crate) fn output_terminal_witness_failure(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.terminal_witness_failure.then(|| self.output_witness_failure()).flatten()
    }

    pub(crate) fn output_terminal_witness_debt(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.terminal_witness_debt.and_then(|_| self.output_witness_failure())
    }

    pub(crate) fn output_terminal_witness_debt_before_protected(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        if self.terminal_witness_debt == Some(OutputCurrentnessBoundaryV1::PostProtectedFailure) {
            return None;
        }
        self.output_terminal_witness_debt()
    }

    fn mark_terminal_witness_failure(&mut self, boundary: OutputCurrentnessBoundaryV1) {
        match boundary {
            OutputCurrentnessBoundaryV1::BeforeAction => self.terminal_witness_failure = true,
            OutputCurrentnessBoundaryV1::PostAction | OutputCurrentnessBoundaryV1::PostProtectedFailure => {
                if self.terminal_witness_debt.is_none() {
                    self.terminal_witness_debt = Some(boundary);
                }
            }
        }
    }

    pub(crate) fn bookend_output_terminal_witnesses(
        &mut self,
        boundary: OutputCurrentnessBoundaryV1,
    ) -> bool {
        let current = self.revalidate_output_witnesses();
        if !current {
            self.mark_terminal_witness_failure(boundary);
        }
        current
    }

    pub(crate) fn require_output_subject(
        &mut self,
        subject: &KernelAuthorizedRecordSubject,
    ) -> bool {
        if self.owner.is_output_client_endpoint() {
            return self.require_retained_client_subject_v1(subject);
        }
        let peer = self.socket.peer();
        let actual = subject.credentials();
        let expected = peer.credentials();
        actual.pid() == expected.pid()
            && actual.uid() == expected.uid()
            && actual.gid() == expected.gid()
            && subject.initial_info() == peer.initial_info()
    }

    // The closed D Inventory caller has already joined the fixed Client
    // Journal and genuine C17 interval. It must validate the actual initial
    // retained witnesses even for endpoints outside the Output route.
    pub(super) fn revalidate_delete_inventory_witnesses_v1(&mut self) -> bool {
        if matches!(&self.client_witnesses, Ok(None)) {
            self.client_witnesses = Err(HandshakeError::KernelEvidence);
        }
        match &mut self.client_witnesses {
            Ok(Some(witnesses)) => witnesses.revalidate_delete_inventory(self.socket.peer()),
            _ => false,
        }
    }

    pub(super) fn require_delete_inventory_subject_v1(&mut self,
        subject: &KernelAuthorizedRecordSubject,
    ) -> bool {
        if matches!(&self.client_witnesses, Ok(None)) {
            self.client_witnesses = Err(HandshakeError::KernelEvidence);
        }
        match &mut self.client_witnesses {
            Ok(Some(witnesses)) => witnesses.require_delete_inventory_subject(subject),
            _ => false,
        }
    }

    pub(super) fn observe_delete_inventory_witness_post_v1(&self) -> Result<(), HandshakeError> {
        match &self.client_witnesses {
            Ok(Some(witnesses)) => witnesses.observe_delete_inventory_post(self.socket.peer()),
            _ => Err(HandshakeError::KernelEvidence),
        }
    }

    fn require_retained_client_subject_v1(
        &mut self,
        subject: &KernelAuthorizedRecordSubject,
    ) -> bool {
        if matches!(&self.client_witnesses, Ok(None)) {
            self.client_witnesses = Err(HandshakeError::KernelEvidence);
        }
        match &mut self.client_witnesses {
            Ok(Some(witnesses)) => witnesses.require_subject(subject),
            _ => false,
        }
    }

    /// Observes only resident originals and samples the paired clock LAST.
    ///
    /// The caller parks a vacant fixed report before entering. No effect,
    /// request, floor read, re-admission or positive failed-owner getter occurs.
    #[cfg(feature = "online-nix")]
    pub(crate) fn observe_online_postflight(&mut self, report: &mut OnlinePostflightV1) {
        report.client_before = Some(self.require_online_client_currentness());
        self.owner.observe_online_postflight(
            &self.transcript, self.socket.peer(), report,
        );
        report.client_after = Some(self.require_online_client_currentness());
        // Nothing fallible or allocating follows this genuine paired sample.
        report.clock = Some(self.owner.observe_online_postflight_clock());
    }

    #[cfg(feature = "online-nix")]
    fn require_online_client_currentness(&mut self) -> Result<(), BrokerSessionSecurityError> {
        match self.owner.online_endpoint_role()? {
            aos_sandbox_broker_session_protocol::BrokerSessionDurableEndpointV1::Client => {
                let witnesses = self.client_witnesses.as_mut().ok().and_then(Option::as_mut)
                    .ok_or(BrokerSessionSecurityError::Currentness)?;
                witnesses.revalidate_online(self.socket.peer())
            }
            aos_sandbox_broker_session_protocol::BrokerSessionDurableEndpointV1::Broker => Ok(()),
        }
    }

    #[cfg(feature = "online-nix")]
    fn revalidate_online_transport(&mut self) -> Result<(), BrokerSessionSecurityError> {
        self.require_online_client_currentness()?;
        self.owner.revalidate_transport(&self.transcript, self.socket.peer())?;
        self.require_online_client_currentness()
    }

    /// Stages the sole decoder's full result using the already admitted peer.
    #[cfg(feature = "online-nix")]
    pub(crate) fn decode_online_request_into(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        target: &mut Option<Result<
            aos_sandbox_protocol::nix_build::ValidatedNixBuildRequestV2,
            aos_sandbox_protocol::ProtocolValidationError,
        >>,
    ) -> Result<(), OnlineTransportFailureV1> {
        if target.is_some() {
            return Err(OnlineTransportFailureV1::Closed);
        }
        self.require_online_transport(request)?;
        let now = protected_boottime_nanoseconds()?;
        *target = Some(aos_sandbox_protocol::nix_build::decode_nix_build_request_v2(
            request.exact_body(), request.method(), request.peer(), request.peer_policy(), now,
        ));
        if target.as_ref().is_none_or(Result::is_err) {
            return Err(OnlineTransportFailureV1::Decode);
        }
        self.require_online_transport(request)?;
        Ok(())
    }

    /// Uses the actual paired clock and the SAME common plan/lease authenticator.
    #[cfg(feature = "online-nix")]
    pub(crate) fn retain_online_admission(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        checked: &aos_sandbox_protocol::nix_build::ValidatedNixBuildRequestV2,
    ) -> Result<(), OnlineTransportFailureV1> {
        self.require_online_transport(request)?;
        let sample = aos_sandbox_broker::ownership_clock::sample_ownership_clock()?;
        self.owner.retain_online_resolve_admission(
            request, checked, &sample, &self.transcript, self.socket.peer(),
        )?;
        self.require_online_transport(request)?;
        Ok(())
    }

    /// Parks the full native result before its pending-request postcheck.
    #[cfg(feature = "online-nix")]
    pub(crate) fn retain_online_request_commit_into(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        initialize: bool,
        target: &mut Option<OnlineRequestNativeResultV1>,
    ) -> Result<(), OnlineTransportFailureV1> {
        if target.is_some() {
            return Err(OnlineTransportFailureV1::Closed);
        }
        self.require_online_transport(request)?;
        *target = Some(if initialize {
            OnlineRequestNativeResultV1::Initialized(self.initialize_authenticated_request(request))
        } else {
            OnlineRequestNativeResultV1::Appended(self.append_authenticated_request(request))
        });
        if !target.as_ref().is_some_and(OnlineRequestNativeResultV1::is_committed) {
            return Err(OnlineTransportFailureV1::Closed);
        }
        self.require_online_request(request)?;
        Ok(())
    }

    /// Releases completed native preparation only after the final fresh clock.
    #[cfg(feature = "online-nix")]
    pub(crate) fn finish_online_native_step(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_online_transport(request)?;
        self.owner.check_online_resolve_effect(
            request.request_id(), &self.transcript, self.socket.peer(),
        )?;
        self.require_online_client_currentness()?;
        self.owner.release_online_native_step();
        Ok(())
    }

    /// Advances a phase only after this original Session's successful terminal.
    ///
    /// The caller retains its complete prior request/result. This method moves
    /// only the same owner's completed admission into its fixed archive slot;
    /// it neither clears a pending request nor renews any request deadline.
    #[cfg(feature = "online-nix")]
    pub(crate) fn advance_online_nix_terminal(
        &mut self,
        previous: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_online_store_readback(previous)?;
        self.owner.advance_online_nix_terminal(previous, &self.transcript, self.socket.peer())?;
        self.require_online_client_currentness()
    }

    /// Sends once without projecting away the actual returned native cause.
    ///
    /// The caller marks dispatch before entering this method. A later failed
    /// bookend does not establish that no bytes were sent or allow a new send.
    #[cfg(feature = "online-nix")]
    pub(crate) fn send_online_packet(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        packet: &[u8],
        failure: &mut Option<SeqpacketError>,
    ) -> Result<(), OnlineTransportFailureV1> {
        if failure.is_some() {
            return Err(OnlineTransportFailureV1::Closed);
        }
        self.require_online_transport(request)?;
        if let Err(cause) = self.socket.send(packet) {
            *failure = Some(cause);
            return Err(OnlineTransportFailureV1::Send);
        }
        self.require_online_transport(request)?;
        Ok(())
    }

    /// Keeps terminal/pending checks distinct while preserving the same cutoff.
    #[cfg(feature = "online-nix")]
    pub(crate) fn require_online_transport(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        let deadline = OriginalBrokerColdDeadlineV1::online_request(request)?;
        self.owner.bind_online_request_deadline(deadline)?;
        self.revalidate_online_transport()?;
        deadline.check().map_err(|_| BrokerSessionSecurityError::Currentness)?;
        self.owner.check_online_admitted_clock()
    }

    /// Parks a returned packet or actual owning error before caller bookends.
    ///
    /// Only initial nonconsuming EAGAIN/EINTR returns `false`. A fatal lower
    /// error keeps its original attempt/duplicate OFD and shutdown debt in the
    /// supplied slot; it does not imply the original Rust socket FD survived.
    #[cfg(feature = "online-nix")]
    pub(crate) fn receive_online_record_into(
        &mut self,
        record: &mut Option<aos_sandbox_linux::seqpacket::ReceivedRecord>,
        failure: &mut Option<aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>,
    ) -> Result<bool, OnlineTransportFailureV1> {
        if record.is_some() || failure.is_some() {
            return Err(OnlineTransportFailureV1::Closed);
        }
        self.revalidate_online_transport()?;
        if self.transcript.protocol() != BrokerSessionProtocolV1::Nix {
            return Err(OnlineTransportFailureV1::Closed);
        }

        let maximum = match self.owner.online_endpoint_role()? {
            aos_sandbox_broker_session_protocol::BrokerSessionDurableEndpointV1::Client => {
                usize::try_from(self.transcript.negotiated_maximum_response_bytes())
                    .map_err(|_| OnlineTransportFailureV1::Closed)?
                    .min(aos_sandbox_broker_session_protocol::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES)
            }
            aos_sandbox_broker_session_protocol::BrokerSessionDurableEndpointV1::Broker => {
                self.transcript.negotiated_maximum_request_bytes().min(
                    aos_sandbox_broker_session_protocol::maximum_broker_session_request_bytes_v1(
                        BrokerSessionProtocolV1::Nix,
                    ),
                )
            }
        };
        match self.socket.receive_retaining(maximum) {
            Ok(returned) => *record = Some(returned),
            Err(cause) if cause.is_nonconsuming_would_block() || cause.is_nonconsuming_interrupted() => {
                // The lower engine proves that no record/sample was captured.
                // No fatal custody or debt is being discarded on this edge.
                self.revalidate_online_transport()?;
                return Ok(false);
            }
            Err(cause) => {
                *failure = Some(cause);
                return Err(OnlineTransportFailureV1::Receive);
            }
        }

        self.require_online_record(record.as_ref().ok_or(OnlineTransportFailureV1::Closed)?)?;
        self.revalidate_online_transport()?;
        Ok(true)
    }

    #[cfg(feature = "online-nix")]
    fn require_online_record(
        &mut self,
        record: &aos_sandbox_linux::seqpacket::ReceivedRecord,
    ) -> Result<(), OnlineTransportFailureV1> {
        // This named lower method is a borrowed mechanical origin comparator;
        // using it grants neither offline nor online provisioning authority.
        self.socket.require_nix_offline_received_original_v5(record)?;
        if self.owner.online_endpoint_role()? ==
            aos_sandbox_broker_session_protocol::BrokerSessionDurableEndpointV1::Client
        {
            self.require_online_client_currentness()?;
            let witnesses = self.client_witnesses.as_ref().ok().and_then(Option::as_ref)
                .ok_or(OnlineTransportFailureV1::Closed)?;
            witnesses.witnesses
                .require_online_client_subject(record.subject())?;
            self.require_online_client_currentness()?;
            return Ok(());
        }

        // The Broker still receives directly from its connecting Controller.
        let subject = record.subject();
        let credentials = subject.credentials();
        let peer = self.socket.peer();
        let established = peer.credentials();
        if !subject.is_alive()? || !peer.is_alive()?
            || credentials.pid() != established.pid()
            || credentials.uid() != established.uid()
            || credentials.gid() != established.gid()
            || subject.initial_info() != peer.initial_info()
        {
            return Err(OnlineTransportFailureV1::Closed);
        }
        Ok(())
    }

    /// Stages the real admission result before the final protected observation.
    #[cfg(feature = "online-nix")]
    pub(crate) fn admit_online_record_into(
        &mut self,
        record: &aos_sandbox_linux::seqpacket::ReceivedRecord,
        target: &mut Option<Result<
            crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1,
            BrokerSessionSecurityError,
        >>,
    ) -> Result<(), OnlineTransportFailureV1> {
        if target.is_some() {
            return Err(OnlineTransportFailureV1::Closed);
        }
        self.require_online_record(record)?;
        self.revalidate_online_transport()?;
        let now = protected_boottime_nanoseconds()?;
        *target = Some(self.owner.admit_received_request(
            record.payload(), 0, &self.transcript, self.socket.peer(), now,
        ));
        if target.as_ref().is_none_or(Result::is_err) {
            return Err(OnlineTransportFailureV1::Admission);
        }
        self.revalidate_online_transport()?;
        Ok(())
    }

    /// Rechecks the genuine pending method50, original peer and same floor cut.
    #[cfg(feature = "online-nix")]
    pub(crate) fn require_online_request(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_online_client_currentness()?;
        let deadline = OriginalBrokerColdDeadlineV1::online_request(request)?;
        self.owner.bind_online_request_deadline(deadline)?;
        let pending = self.owner.hold_pending_request(
            request, &self.transcript, self.socket.peer(),
        )?;
        drop(pending);
        deadline.check().map_err(|_| BrokerSessionSecurityError::Currentness)?;
        self.owner.check_online_resolve_effect(
            request.request_id(), &self.transcript, self.socket.peer(),
        )?;
        self.require_online_client_currentness()
    }

    /// Checks the original stored request for read-only backing comparisons.
    ///
    /// This also accepts its actual completed terminal row, never a supplied
    /// completion flag. Reader dispatch and request preparation still require
    /// the separate genuine pending borrow above.
    #[cfg(feature = "online-nix")]
    pub(crate) fn require_online_store_readback(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_online_transport(request)?;
        self.owner.check_online_resolve_effect(
            request.request_id(), &self.transcript, self.socket.peer(),
        )?;
        self.require_online_client_currentness()
    }

    /// Compares the remaining native suffix before selected GC-root effects.
    #[cfg(feature = "online-nix")]
    pub(crate) fn require_online_existing_output_suffix(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_online_request(request)?;
        self.owner.require_online_existing_output_suffix(
            request, &self.transcript, self.socket.peer(),
        )?;
        self.require_online_client_currentness()
    }

    /// Sends only the two comparison roles of the held method-49 continuation.
    fn send_host_worker_comparison_packet(
        &mut self,
        packet: &[u8],
        descriptors: [BorrowedFd<'_>; 2],
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        self.owner
            .revalidate_transport(&self.transcript, self.socket.peer())?;
        let sent = self
            .socket
            .send_with_descriptors(packet, &descriptors)
            .map_err(|error| match error {
                SeqpacketError::WouldBlock | SeqpacketError::Interrupted => {
                    DormantBrokerSessionHandshakeErrorV1::Transport
                }
                _ => DormantBrokerSessionHandshakeErrorV1::RemoteInvalid,
            });
        self.owner
            .revalidate_transport(&self.transcript, self.socket.peer())?;
        sent
    }

    /// Checks the actual original peer against the fixed Mount service only.
    pub(super) fn require_original_mount_worker_peer(
        &self,
        verifier: &aos_sandbox_host::peer::ControllerPeerVerifier,
    ) -> Result<(), BrokerSessionSecurityError> {
        verifier
            .verify_mount_broker(self.socket.peer())
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        Ok(())
    }

    pub(super) fn hold_fuse_intent_transport<'session>(
        &'session mut self,
        request: &'session aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<
        fuse_intent_continuation::HeldFuseIntentTransportV1<'session>,
        BrokerSessionSecurityError,
    > {
        fuse_intent_continuation::HeldFuseIntentTransportV1::capture(self, request)
    }

    /// Lends the actual writer and retained transport for one pending request.
    pub(super) fn hold_pending_request<'session>(
        &'session mut self,
        request: &'session aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<
        crate::recovery::ProtectedPendingBrokerRequestCutV1<'session>,
        BrokerSessionSecurityError,
    > {
        self.owner
            .hold_pending_request(request, &self.transcript, self.socket.peer())
    }

    pub(super) fn host_execution_argument_demand_v1(
        &self,
        method: aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod,
        original: &mut crate::HostExecutionSessionReceivingOriginalV1,
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        require_negotiated_method(&self.transcript, method)?;
        self.owner.host_execution_argument_demand_v1(&self.transcript, method, original)
    }

    pub(super) fn execution_output_demand_v1(
        &self,
        method: aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod,
        original: &mut crate::HostExecutionSessionReceivingOriginalV1,
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        require_negotiated_method(&self.transcript, method)?;
        self.owner.execution_output_demand_v1(&self.transcript, method, original)
    }

    pub(super) fn host_stop_request_bound_data_v4(
        &mut self,
        clock: aos_sandbox_model::RawPairedClockSample,
    ) -> Result<u64, BrokerSessionSecurityError> {
        require_negotiated_method(&self.transcript, BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME)?;
        if self.transcript.protocol() != BrokerSessionProtocolV1::Host {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let (maximum, _, _, _) = self.host_stop_limits_data_v5(clock)?;
        Ok(maximum)
    }

    pub(super) fn host_stop_limits_data_v5(
        &mut self,
        clock: aos_sandbox_model::RawPairedClockSample,
    ) -> Result<(u64, u32, aos_sandbox_model::ProtocolVersion,
        aos_sandbox_api::aos::sandbox::local::v1::Audience), BrokerSessionSecurityError> {
        require_negotiated_method(&self.transcript, BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME)?;
        if self.transcript.protocol() != BrokerSessionProtocolV1::Host {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.owner.client_request_limits(&self.transcript, clock.boottime_nanoseconds())
    }

    pub(super) fn host_stop_inventory_demand_v5(&self,
        original: &mut crate::HostExecutionSessionReceivingOriginalV1,
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        require_negotiated_method(&self.transcript, BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME)?;
        self.owner.host_stop_inventory_demand_v5(&self.transcript, original)
    }

    pub(super) fn host_stop_inventory_coordinates_v5(&self,
        effect: &aos_sandbox_controller_domain::PreparedAuthorityEffectV1,
    ) -> Result<crate::DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
        let request = effect.broker_request().map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if request.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let version = request.protocol_version();
        self.start_host_coordinates_data_v2(
            &aos_sandbox_protocol::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2 {
                protocol_major: u32::from(version.major()), protocol_minor: u32::from(version.minor()),
                request_id: request.request_id(), audience: request.audience(),
                deadline_boottime_nanoseconds: request.deadline_boottime_nanoseconds(),
                maximum_response_bytes: request.maximum_response_bytes(),
            }, StartHostCoordinatesPurposeV2::StopInventory)
    }

    pub(super) fn host_stop_demand_v4(
        &self,
        original: &mut crate::HostExecutionSessionReceivingOriginalV1,
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        require_negotiated_method(&self.transcript, BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME)?;
        self.owner.host_stop_demand_v4(&self.transcript, original)
    }

    pub(super) fn storage_capture_history_data_v2(&self) -> Result<&[u8], BrokerSessionSecurityError> {
        require_negotiated_method(&self.transcript, BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1)?;
        self.owner.storage_capture_history_data_v2(&self.transcript)
    }

    pub(super) fn host_execution_history_data_v1(&self) -> Result<&[u8], BrokerSessionSecurityError> {
        require_negotiated_method(&self.transcript, BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION)?;
        self.owner.host_execution_history_data_v1(&self.transcript)
    }

    pub(super) fn host_execution_authorize_observe_demand_v2(
        &self,
        original: &mut crate::HostExecutionSessionReceivingOriginalV1,
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        require_negotiated_method(&self.transcript, BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION)?;
        self.owner.host_execution_authorize_observe_demand_v2(&self.transcript, original)
    }

    pub(super) fn require_negotiated_client_method(
        &mut self,
        method: aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod,
    ) -> Result<(), BrokerSessionSecurityError> {
        require_negotiated_method(&self.transcript, method)?;
        self.owner
            .revalidate_transport(&self.transcript, self.socket.peer())
    }

    /// Reauthenticates the original signed H/T pair under live Host-session custody.
    pub(super) fn historical_host_terminal_no_apply_archive(
        &mut self,
        source: &ControllerExecutionArgumentAttemptV1,
    ) -> Result<AuthenticatedOriginalHostNoApplyJoinV1, BrokerSessionSecurityError> {
        self.owner
            .revalidate_transport(&self.transcript, self.socket.peer())?;
        let joined = self
            .owner
            .historical_host_terminal_no_apply_archive(source)?;
        self.owner
            .revalidate_transport(&self.transcript, self.socket.peer())?;
        Ok(joined)
    }

    /// Copies the complete original pair under the retained session's live peer.
    ///
    /// This is historical DATA, not a request reservation or a live Root grant.
    pub(super) fn capture_failed_create_originals_v3(
        &mut self,
        source: &ControllerExecutionArgumentAttemptV1,
    ) -> Result<crate::recovery::RetainedFailedCreateOriginalsDataV3, BrokerSessionSecurityError> {
        self.owner
            .revalidate_transport(&self.transcript, self.socket.peer())?;
        let originals = self.owner.capture_failed_create_originals_v3(source)?;
        self.owner
            .revalidate_transport(&self.transcript, self.socket.peer())?;
        Ok(originals)
    }

    pub(super) fn current_storage_session_binding(
        &mut self,
    ) -> Result<[u8; 32], BrokerSessionSecurityError> {
        self.owner
            .revalidate_transport(&self.transcript, self.socket.peer())?;
        if self.transcript.protocol() != BrokerSessionProtocolV1::Storage {
            return Err(BrokerSessionSecurityError::manifest(
                "candidate query requires a protected Storage session",
            ));
        }
        Ok(self.transcript.session_binding())
    }

    pub(super) fn retain_authenticated_peer_pidfd(
        &mut self,
    ) -> Result<OwnedFd, DormantBrokerSessionHandshakeErrorV1> {
        self.owner
            .revalidate_transport(&self.transcript, self.socket.peer())?;
        self.socket
            .peer()
            .pidfd()
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)
    }

    pub(super) fn original_storage_inventory_coordinates(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
    ) -> Result<Option<ArchivedStorageInventoryHeadV1>, BrokerSessionSecurityError> {
        self.owner.original_storage_inventory_coordinates(
            group_request_id,
            group_request_digest,
            &self.transcript,
            self.socket.peer(),
        )
    }

    pub(super) fn fresh_storage_inventory_coordinates(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
    ) -> Result<Option<ArchivedStorageInventoryHeadV1>, BrokerSessionSecurityError> {
        self.owner.fresh_storage_inventory_coordinates(
            group_request_id,
            group_request_digest,
            &self.transcript,
            self.socket.peer(),
        )
    }

    pub(super) fn archive_original_storage_inventory(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
        inventory_request_id: [u8; 16],
        inventory_request_digest: [u8; 32],
    ) -> Result<ArchivedStorageInventoryHeadV1, BrokerSessionSecurityError> {
        self.owner.archive_original_storage_inventory(
            group_request_id,
            group_request_digest,
            inventory_request_id,
            inventory_request_digest,
            &self.transcript,
            self.socket.peer(),
        )
    }

    pub(super) fn client_storage_inventory_abandonment_committed(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
        inventory_request_id: [u8; 16],
        inventory_request_digest: [u8; 32],
        client_original_head: [u8; 32],
    ) -> Result<bool, BrokerSessionSecurityError> {
        self.owner.client_storage_inventory_abandonment_committed(
            group_request_id,
            group_request_digest,
            inventory_request_id,
            inventory_request_digest,
            client_original_head,
            &self.transcript,
            self.socket.peer(),
        )
    }

    pub(super) fn verify_original_storage_inventory_terminal(
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
        self.owner.verify_original_storage_inventory_terminal(
            group_request_id,
            group_request_digest,
            inventory_request_id,
            inventory_request_digest,
            packet,
            &self.transcript,
            self.socket.peer(),
        )
    }

    pub(super) fn broker_storage_inventory_recovery_response(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        self.owner.broker_storage_inventory_recovery_response(
            request,
            &self.transcript,
            self.socket.peer(),
        )
    }

    pub(super) fn client_confirm_storage_inventory_abandonment(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
        inventory_request_id: [u8; 16],
        inventory_request_digest: [u8; 32],
    ) -> Result<(), BrokerSessionSecurityError> {
        self.owner.client_confirm_storage_inventory_abandonment(
            group_request_id,
            group_request_digest,
            inventory_request_id,
            inventory_request_digest,
            &self.transcript,
            self.socket.peer(),
        )
    }

    pub(super) fn historical_checkpoint_digest(
        &self,
    ) -> Result<[u8; 32], BrokerSessionSecurityError> {
        self.checkpoint
            .digest()
            .map_err(BrokerSessionSecurityError::from)
    }

    pub(super) fn prior_verified_atomic_storage_history(
        &mut self,
        request_id: [u8; 16],
        request_packet: [u8; 32],
        predecessor_packet: [u8; 32],
        session_binding: [u8; 32],
        checkpoint_digest: [u8; 32],
    ) -> Result<ProtectedVerifiedAtomicStorageHistoryV1, BrokerSessionSecurityError> {
        self.owner.prior_verified_atomic_storage_history(
            request_id,
            request_packet,
            predecessor_packet,
            session_binding,
            checkpoint_digest,
            &self.transcript,
            self.socket.peer(),
        )
    }

    pub(super) fn archive_verified_atomic_storage_history(
        &mut self,
        request_id: [u8; 16],
        request_packet: [u8; 32],
        predecessor_packet: [u8; 32],
        session_binding: [u8; 32],
        checkpoint_digest: [u8; 32],
    ) -> Result<(), BrokerSessionSecurityError> {
        self.owner.archive_verified_atomic_storage_history(
            request_id,
            request_packet,
            predecessor_packet,
            session_binding,
            checkpoint_digest,
            &self.transcript,
            self.socket.peer(),
        )
    }

    pub(super) fn retire_atomic_storage_archive(
        &mut self,
        request_id: [u8; 16],
    ) -> Result<(), BrokerSessionSecurityError> {
        self.owner
            .retire_atomic_storage_archive(request_id, &self.transcript, self.socket.peer())
    }

    pub(super) fn prior_atomic_storage_history(
        &mut self,
        request_id: [u8; 16],
        request_packet: [u8; 32],
        predecessor_packet: [u8; 32],
        session_binding: [u8; 32],
    ) -> Result<ProtectedPriorAtomicStorageHistoryV1, BrokerSessionSecurityError> {
        self.owner.prior_atomic_storage_history(
            request_id,
            request_packet,
            predecessor_packet,
            session_binding,
            &self.transcript,
            self.socket.peer(),
        )
    }

    pub(super) fn prior_terminal_exchange(
        &mut self,
        method: aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod,
        request_id: [u8; 16],
        request_body: &[u8],
    ) -> Result<Option<ProtectedPriorTerminalExchangeV1>, BrokerSessionSecurityError> {
        self.owner.prior_terminal_exchange(
            method,
            request_id,
            request_body,
            &self.transcript,
            self.socket.peer(),
        )
    }

    pub(super) fn operator_repair_inventory_history(
        &mut self,
        request_id: [u8; 16],
        packet: Option<&[u8]>,
    ) -> Result<
        aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        BrokerSessionSecurityError,
    > {
        self.owner.operator_repair_inventory_history(
            request_id,
            packet,
            &self.transcript,
            self.socket.peer(),
        )
    }

    pub(super) fn require_current_node(
        &mut self,
        expected_node: [u8; 16],
    ) -> Result<(), BrokerSessionSecurityError> {
        self.owner
            .require_current_node(expected_node, &self.transcript, self.socket.peer())
    }

    pub(super) fn as_fd(&self) -> Result<BorrowedFd<'_>, DormantBrokerSessionHandshakeErrorV1> {
        self.socket
            .as_fd()
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::Transport)
    }

    pub(super) fn sign_lifecycle_bootstrap_attestation(
        &mut self,
        message: &[u8; 32],
    ) -> Result<[u8; 64], BrokerSessionSecurityError> {
        self.owner.sign_lifecycle_bootstrap_attestation(
            message,
            &self.transcript,
            self.socket.peer(),
        )
    }

    pub(super) fn broker_outcome_verifier(
        &mut self,
    ) -> Result<aos_sandbox_protocol::BrokerTerminalCommitVerifierV1, BrokerSessionSecurityError>
    {
        self.owner
            .broker_outcome_verifier(&self.transcript, self.socket.peer())
    }

    pub(super) fn sign_terminal_commit_receipt_for_committed(
        &mut self,
        reservation: &aos_sandbox_host::DormantHostScopeReplayTicketV1,
        committed: &crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<aos_sandbox_protocol::BrokerTerminalCommitReceiptV1, BrokerSessionSecurityError>
    {
        let protected_generation = committed
            .expected_generation()
            .checked_add(1)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let binding = aos_sandbox_protocol::BrokerTerminalCommitBindingV1::new(
            reservation.reservation_locator(),
            committed.method(),
            committed.request_id(),
            committed.signed_request_digest(),
            committed.session_binding(),
            committed.signed_outcome_digest(),
            protected_generation,
            committed.replacement_head(),
        )
        .ok_or(BrokerSessionSecurityError::Currentness)?;
        self.owner
            .sign_terminal_commit_receipt(binding, &self.transcript, self.socket.peer())
    }

    pub(super) fn sign_terminal_commit_receipt_for_replay(
        &mut self,
        reservation: &aos_sandbox_host::DormantHostScopeReplayReservationV1,
        replay: &crate::ProtectedBrokerOutcomeReplayV1,
    ) -> Result<aos_sandbox_protocol::BrokerTerminalCommitReceiptV1, BrokerSessionSecurityError>
    {
        let binding = aos_sandbox_protocol::BrokerTerminalCommitBindingV1::new(
            reservation.locator(),
            replay.method(),
            replay.request_id(),
            replay.signed_request_digest(),
            replay.session_binding(),
            replay.signed_outcome_digest(),
            replay.protected_generation(),
            replay.protected_head(),
        )
        .ok_or(BrokerSessionSecurityError::Currentness)?;
        self.owner
            .sign_terminal_commit_receipt(binding, &self.transcript, self.socket.peer())
    }

    pub(super) fn client_request_coordinates(
        &mut self,
    ) -> Result<
        (
            [u8; 16],
            u64,
            u32,
            aos_sandbox_model::ProtocolVersion,
            aos_sandbox_api::aos::sandbox::local::v1::Audience,
        ),
        BrokerSessionSecurityError,
    > {
        let now = protected_boottime_nanoseconds()?;
        self.owner.client_request_coordinates(&self.transcript, now)
    }

    pub(super) fn client_request_limits(
        &mut self,
    ) -> Result<
        (
            u64,
            u32,
            aos_sandbox_model::ProtocolVersion,
            aos_sandbox_api::aos::sandbox::local::v1::Audience,
        ),
        BrokerSessionSecurityError,
    > {
        let now = protected_boottime_nanoseconds()?;
        self.owner.client_request_limits(&self.transcript, now)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare_client_request(
        &mut self,
        message: aos_sandbox_api::aos::sandbox::local::v1::BrokerRequestEnvelope,
        method: aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod,
        actual_descriptor_count: usize,
        request_id: [u8; 16],
        deadline_boottime_nanoseconds: u64,
        maximum_response_bytes: u32,
    ) -> Result<
        (
            aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
            bool,
        ),
        BrokerSessionSecurityError,
    >{
        let now = protected_boottime_nanoseconds()?;
        self.owner.prepare_client_request(
            message,
            method,
            actual_descriptor_count,
            request_id,
            deadline_boottime_nanoseconds,
            maximum_response_bytes,
            &self.transcript,
            self.socket.peer(),
            now,
        )
    }

    pub(super) fn send_request_packet(
        &mut self,
        packet: &[u8],
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        self.owner
            .revalidate_transport(&self.transcript, self.socket.peer())?;
        let result = self.socket.send(packet).map_err(|error| match error {
            SeqpacketError::WouldBlock | SeqpacketError::Interrupted => {
                DormantBrokerSessionHandshakeErrorV1::Transport
            }
            _ => DormantBrokerSessionHandshakeErrorV1::RemoteInvalid,
        });
        self.owner
            .revalidate_transport(&self.transcript, self.socket.peer())?;
        result
    }

    pub(super) fn confirm_original_host_argument_archive(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.owner.confirm_original_host_argument_archive(
            request,
            &self.transcript,
            self.socket.peer(),
        )
    }

    pub(super) fn send_request_packet_with_descriptors(
        &mut self,
        packet: &[u8],
        descriptors: &[OwnedFd],
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        self.owner
            .revalidate_transport(&self.transcript, self.socket.peer())?;
        let descriptors = descriptors.iter().map(AsFd::as_fd).collect::<Vec<_>>();
        let result = self
            .socket
            .send_with_descriptors(packet, &descriptors)
            .map_err(|error| match error {
                SeqpacketError::WouldBlock | SeqpacketError::Interrupted => {
                    DormantBrokerSessionHandshakeErrorV1::Transport
                }
                _ => DormantBrokerSessionHandshakeErrorV1::RemoteInvalid,
            });
        self.owner
            .revalidate_transport(&self.transcript, self.socket.peer())?;
        result
    }

    pub(super) fn receive_response_packet(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, DormantBrokerSessionHandshakeErrorV1> {
        self.receive_response_packet_retaining_v1(maximum_bytes, None)
    }

    pub(super) fn receive_response_packet_retaining_v1(
        &mut self,
        maximum_bytes: usize,
        mut original: Option<&mut ExecutionResponsePacketOriginalV1>,
    ) -> Result<Vec<u8>, DormantBrokerSessionHandshakeErrorV1> {
        if original.as_ref().is_some_and(|owner| owner.entered()) {
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        }
        let retained_client = self.owner.is_output_client_endpoint()
            && !matches!(&self.client_witnesses, Ok(None));
        if retained_client && !self.revalidate_output_witnesses() {
            return Err(DormantBrokerSessionHandshakeErrorV1::KernelEvidence);
        }
        self.owner
            .revalidate_transport(&self.transcript, self.socket.peer())?;
        let record = match original.as_deref_mut() {
            Some(owner) => match self.socket.receive_host_execution_response_retaining_v1(maximum_bytes) {
                Ok(record) => record,
                Err(error) if error.is_nonconsuming_would_block() || error.is_nonconsuming_interrupted() => {
                    // This lower proof establishes no captured message/native
                    // obligation; it alone permits the existing readiness loop.
                    return Err(DormantBrokerSessionHandshakeErrorV1::Transport);
                }
                Err(error) => {
                    owner.receive_error = Some(error);
                    return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
                }
            },
            None => self.socket.receive(maximum_bytes).map_err(|error| match error {
                SeqpacketError::WouldBlock | SeqpacketError::Interrupted => {
                    DormantBrokerSessionHandshakeErrorV1::Transport
                }
                _ => DormantBrokerSessionHandshakeErrorV1::RemoteInvalid,
            })?,
        };
        let bound = if let Some(owner) = original.as_deref_mut() {
            match self.socket.bind_received_retaining(record) {
                Ok(bound) => bound,
                Err((error, record)) => {
                    owner.binding_error = Some(error);
                    owner.rejected_record = Some(record);
                    return Err(DormantBrokerSessionHandshakeErrorV1::KernelEvidence);
                }
            }
        } else {
            self.socket.bind_received(record)
                .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?
        };
        let (payload, subject, peer) = bound.into_parts();
        let mut local = None;
        let (payload, subject, alive) = match original.as_deref_mut() {
            Some(owner) => {
                owner.payload = Some(payload);
                owner.subject = Some(subject);
                (owner.payload.as_ref().ok_or(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?,
                 owner.subject.as_ref().ok_or(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?,
                 Some(&mut owner.alive))
            }
            None => {
                local = Some((payload, subject));
                let local = local.as_ref().ok_or(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
                (&local.0, &local.1, None)
            }
        };
        if retained_client {
            let local_alive;
            let alive = if let Some(slot) = alive {
                *slot = Some(subject.is_alive());
                slot.as_ref().ok_or(DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?
            } else {
                local_alive = subject.is_alive();
                &local_alive
            };
            if !*alive.as_ref().map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)? {
                return Err(DormantBrokerSessionHandshakeErrorV1::KernelEvidence);
            }
            let current = match &mut self.client_witnesses {
                Ok(Some(witnesses)) => witnesses.require_subject(subject),
                _ => false,
            };
            if !current {
                return Err(DormantBrokerSessionHandshakeErrorV1::KernelEvidence);
            }
        } else {
            require_connection_record_subject_engine_v1(subject, peer, alive)?;
        }
        let packet = payload.to_vec();
        // Ordinary drops its record before the same native after. Selected
        // custody remains beside the returned packet through caller posts.
        drop(local);
        if retained_client {
            let result = self.owner.revalidate_transport(&self.transcript, self.socket.peer());
            let witness_current = self.revalidate_output_witnesses();
            result?;
            if !witness_current {
                return Err(DormantBrokerSessionHandshakeErrorV1::KernelEvidence);
            }
        } else {
            self.owner
                .revalidate_transport(&self.transcript, self.socket.peer())?;
        }
        Ok(packet)
    }

    pub(super) fn receive_response_packet_with_descriptors(
        &mut self,
        maximum_bytes: usize,
        expected_descriptors: usize,
    ) -> Result<(Vec<u8>, Vec<OwnedFd>), DormantBrokerSessionHandshakeErrorV1> {
        self.owner
            .revalidate_transport(&self.transcript, self.socket.peer())?;
        let record = self
            .socket
            .receive_with_descriptors(maximum_bytes, expected_descriptors)
            .map_err(|error| match error {
                SeqpacketError::WouldBlock | SeqpacketError::Interrupted => {
                    DormantBrokerSessionHandshakeErrorV1::Transport
                }
                _ => DormantBrokerSessionHandshakeErrorV1::RemoteInvalid,
            })?;
        let bound = self
            .socket
            .bind_received_descriptors(record)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?;
        require_connection_record_subject(bound.subject(), bound.peer())?;
        let (packet, _, descriptors, _) = bound.into_parts();
        self.owner
            .revalidate_transport(&self.transcript, self.socket.peer())?;
        Ok((packet, descriptors))
    }

    pub(super) fn prepare_broker_outcome(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        message: aos_sandbox_api::aos::sandbox::local::v1::BrokerResponseEnvelope,
    ) -> Result<crate::ProtectedBrokerOutcomePendingAdvancementV1, BrokerSessionSecurityError> {
        self.owner
            .prepare_broker_outcome(request, message, &self.transcript, self.socket.peer())
    }

    pub(super) fn prepare_broker_outcome_with_storage_receiving_v3(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        message: aos_sandbox_api::aos::sandbox::local::v1::BrokerResponseEnvelope,
        receiving: Option<&mut dyn crate::recovery::StorageFloorFinancialSourceV2>,
    ) -> Result<crate::ProtectedBrokerOutcomePendingAdvancementV1, BrokerSessionSecurityError> {
        self.owner.prepare_broker_outcome_with_storage_receiving_v3(
            request, message, &self.transcript, self.socket.peer(), receiving,
        )
    }

    pub(super) fn prepare_original_nonadmitting_outcome(
        &mut self,
        retained: &mut crate::endpoint::RetainedOriginalBrokerOutcomeV1,
        purpose: crate::endpoint::OriginalBrokerOutcomePurposeV1,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        message: aos_sandbox_api::aos::sandbox::local::v1::BrokerResponseEnvelope,
    ) -> bool {
        self.owner.prepare_original_nonadmitting_outcome(
            retained, purpose, request, message, &self.transcript, self.socket.peer(),
        )
    }

    pub(super) fn sign_original_nonadmitting_outcome(
        &mut self,
        retained: &mut crate::endpoint::RetainedOriginalBrokerOutcomeV1,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> bool {
        self.owner.sign_original_nonadmitting_outcome(
            retained, request, &self.transcript, self.socket.peer(),
        )
    }

    pub(super) fn compare_original_nonadmitting_outcome(
        &mut self,
        committed: &crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.owner.compare_original_nonadmitting_outcome(committed, self.socket.peer())
    }

    pub(super) fn send_original_nonadmitting_packet(
        &mut self,
        committed: &crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
        returned: &mut Option<Result<(), SeqpacketError>>,
    ) -> bool {
        if returned.is_some() {
            return false;
        }
        *returned = Some(self.socket.send(committed.exact_packet()));
        matches!(returned, Some(Ok(())))
    }

    pub(crate) fn send_storage_response_packet_v1(
        &mut self,
        packet: &[u8],
        returned: &mut Option<StorageResponseSendAttemptV1>,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        self.send_storage_packet_retaining_v1(packet, returned)
    }

    pub(super) fn send_storage_response_receiving_v3(&mut self, packet: &[u8],
        returned: &mut Option<StorageResponseSendAttemptV1>,
        receiving: Option<&mut dyn crate::recovery::StorageFloorFinancialSourceV2>,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        self.send_packet_with_storage_receiving_v3(packet, None, returned, receiving)
    }

    // Both closed authenticated directions share the same retained native send
    // and independent protected transport posts. Purpose admission stays above.
    pub(super) fn send_storage_packet_retaining_v1(
        &mut self,
        packet: &[u8],
        returned: &mut Option<StorageResponseSendAttemptV1>,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        self.send_client_packet_retaining_engine_v4(packet, None, returned)
    }

    fn send_client_packet_retaining_engine_v4(
        &mut self, packet: &[u8], content: Option<BorrowedFd<'_>>,
        returned: &mut Option<StorageResponseSendAttemptV1>,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        self.send_packet_with_storage_receiving_v3(packet, content, returned, None)
    }

    fn send_packet_with_storage_receiving_v3(&mut self,
        packet: &[u8], content: Option<BorrowedFd<'_>>,
        returned: &mut Option<StorageResponseSendAttemptV1>,
        mut receiving: Option<&mut dyn crate::recovery::StorageFloorFinancialSourceV2>,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        if returned.as_ref().is_some_and(|attempt| !attempt.is_nonconsuming()) {
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        }
        // Only a fully observed nonconsuming attempt is replaced. It owns no
        // flight or ambiguous effect, and the caller's terminal posts passed
        // before its Pending result permitted this next call.
        let before = self.owner.revalidate_transport_with_storage_receiving_v3(&self.transcript, self.socket.peer(),
            receiving.as_mut().map(|source| &mut **source as &mut dyn crate::recovery::StorageFloorFinancialSourceV2));
        let native = before.is_ok().then(|| match content {
            Some(content) => self.socket.send_network_preparation_retaining_v4(packet, content),
            None => self.socket.send_storage_session_retaining_v1(packet),
        });
        let after = self.owner.revalidate_transport_with_storage_receiving_v3(&self.transcript, self.socket.peer(), receiving);
        *returned = Some(StorageResponseSendAttemptV1 { before, native, after });
        let Some(attempt) = returned.as_ref() else { std::process::abort(); };
        if attempt.is_sent() {
            Ok(())
        } else if attempt.is_nonconsuming() {
            Err(DormantBrokerSessionHandshakeErrorV1::Transport)
        } else {
            // The exact cause is borrowed from the resident attempt; this
            // existing closed status never replaces the native Result.
            Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)
        }
    }

    pub(super) fn send_response_packet(
        &mut self,
        packet: &[u8],
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        self.send_request_packet(packet)
    }

    pub(super) fn send_response_packet_with_descriptors(
        &mut self,
        packet: &[u8],
        descriptors: &[OwnedFd],
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        self.send_request_packet_with_descriptors(packet, descriptors)
    }

    pub(super) fn receive_authenticated_request(
        &mut self,
    ) -> Result<
        crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1,
        DormantBrokerSessionHandshakeErrorV1,
    > {
        let maximum = aos_sandbox_broker_session_protocol::maximum_broker_session_request_bytes_v1(
            self.transcript.protocol(),
        );
        let record = self.socket.receive(maximum).map_err(|error| match error {
            SeqpacketError::WouldBlock | SeqpacketError::Interrupted => {
                DormantBrokerSessionHandshakeErrorV1::Transport
            }
            _ => DormantBrokerSessionHandshakeErrorV1::RemoteInvalid,
        })?;
        let bound = self
            .socket
            .bind_received(record)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?;
        require_connection_record_subject(bound.subject(), bound.peer())?;
        let now = protected_boottime_nanoseconds()
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?;
        let packet = bound.payload().to_vec();
        drop(bound);
        self.owner
            .admit_received_request(&packet, 0, &self.transcript, self.socket.peer(), now)
            .map_err(DormantBrokerSessionHandshakeErrorV1::Protected)
    }

    pub(super) fn receive_authenticated_descriptor_request(
        &mut self,
        expected_descriptors: usize,
    ) -> Result<
        (
            crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1,
            Vec<OwnedFd>,
        ),
        DormantBrokerSessionHandshakeErrorV1,
    > {
        self.receive_authenticated_descriptor_request_inner(Some(expected_descriptors))
    }

    pub(super) fn receive_authenticated_optional_descriptor_request(
        &mut self,
    ) -> Result<
        (
            crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1,
            Vec<OwnedFd>,
        ),
        DormantBrokerSessionHandshakeErrorV1,
    > {
        self.receive_authenticated_descriptor_request_inner(None)
    }

    /// Uses the original native descriptor geometry before shared admission.
    fn receive_authenticated_descriptor_request_inner(
        &mut self,
        expected_descriptors: Option<usize>,
    ) -> Result<
        (
            crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1,
            Vec<OwnedFd>,
        ),
        DormantBrokerSessionHandshakeErrorV1,
    > {
        let maximum = aos_sandbox_broker_session_protocol::maximum_broker_session_request_bytes_v1(
            self.transcript.protocol(),
        );
        let record = match expected_descriptors {
            Some(expected_descriptors) => self
                .socket
                .receive_with_descriptors(maximum, expected_descriptors),
            None => self.socket.receive_with_optional_descriptor(maximum),
        }
        .map_err(|error| match error {
            SeqpacketError::WouldBlock | SeqpacketError::Interrupted => {
                DormantBrokerSessionHandshakeErrorV1::Transport
            }
            _ => DormantBrokerSessionHandshakeErrorV1::RemoteInvalid,
        })?;
        let bound = self
            .socket
            .bind_received_descriptors(record)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?;
        require_connection_record_subject(bound.subject(), bound.peer())?;
        let now = protected_boottime_nanoseconds()
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?;
        let (packet, _, descriptors, _) = bound.into_parts();
        let admission = self
            .owner
            .admit_received_request(
                &packet,
                descriptors.len(),
                &self.transcript,
                self.socket.peer(),
                now,
            )
            .map_err(DormantBrokerSessionHandshakeErrorV1::Protected)?;
        Ok((admission, descriptors))
    }

    fn from_client(
        root: &'static str,
        session: InertProvisionalClientSession,
    ) -> Result<Self, DormantBrokerSessionHandshakeErrorV1> {
        let InertProvisionalClientSession {
            _custody: custody,
            _carrier: carrier,
            _client_packet: client_packet,
            _broker_packet: broker_packet,
            _transcript: transcript,
            ..
        } = session;
        let ClientHandshakeCustodyV1::Fresh(custody) = custody else {
            std::process::abort();
        };
        let context = custody.context_for_handshake(transcript.broker_process())?;
        Self::from_parts(
            root,
            FixedEndpointCustodyV1::Client(custody),
            carrier,
            transcript,
            context,
            client_packet,
            broker_packet,
        )
    }

    fn from_output_client(
        root: &'static str,
        session: InertProvisionalClientSession,
    ) -> Result<Self, DormantBrokerSessionHandshakeErrorV1> {
        let InertProvisionalClientSession {
            _custody: custody,
            _carrier: carrier,
            _publication_packet: publication,
            _client_packet: client_packet,
            _broker_packet: broker_packet,
            _publication_subject: publication_subject,
            _broker_subject: broker_subject,
            _transcript: transcript,
        } = session;
        let witnesses = AuthenticatedClientWitnessesV1 {
            storage_preparation: false,
            establishment: carrier.peer,
            witnesses: VerifiedStorageWitnessesV1::Client {
                _publication: publication,
                _publication_subject: publication_subject,
                _broker_subject: broker_subject,
            },
            first_failure: None,
        };
        let ClientHandshakeCustodyV1::Fresh(custody) = custody else {
            std::process::abort();
        };
        let context = custody.context_for_handshake(transcript.broker_process())?;
        let mut session = Self::from_parts(
            root,
            FixedEndpointCustodyV1::Client(custody),
            carrier,
            transcript,
            context,
            client_packet,
            broker_packet,
        )?;
        session.client_witnesses = Ok(Some(witnesses));
        Ok(session)
    }

    fn from_broker(
        root: &'static str,
        session: InertProvisionalBrokerSession,
    ) -> Result<Self, DormantBrokerSessionHandshakeErrorV1> {
        let InertProvisionalBrokerSession {
            _custody: custody,
            _carrier: carrier,
            _client_packet: client_packet,
            _broker_packet: broker_packet,
            _transcript: transcript,
            ..
        } = session;
        let BrokerHandshakeCustodyV1::Fresh(custody) = custody else {
            // Only the private retained completion path can carry this owner.
            std::process::abort();
        };
        let context = custody.context_for_handshake(transcript.client_process())?;
        Self::from_parts(
            root,
            FixedEndpointCustodyV1::Broker(custody),
            carrier,
            transcript,
            context,
            client_packet,
            broker_packet,
        )
    }

    fn from_parts(
        root: &'static str,
        custody: FixedEndpointCustodyV1,
        carrier: HandshakeCarrier,
        transcript: VerifiedBrokerSessionTranscriptV1,
        context: aos_sandbox_broker_session_protocol::ProtectedBrokerSessionVerificationContextV1,
        client_packet: Vec<u8>,
        broker_packet: Vec<u8>,
    ) -> Result<Self, DormantBrokerSessionHandshakeErrorV1> {
        let socket = carrier.into_ordinary()?;
        let credentials = socket.peer().credentials();
        let peer = PeerCredentials {
            uid: credentials.uid(),
            gid: credentials.gid(),
            pid: Some(credentials.pid().get()),
        };
        let checkpoint = HistoricalSessionCheckpointV1::new(
            context,
            &client_packet,
            &broker_packet,
            peer,
            &transcript,
        )
        .map_err(BrokerSessionSecurityError::from)?;
        let owner = ProtectedBrokerSessionOwnerV1::from_fixed_custody(root, custody)?;
        Ok(Self {
            owner,
            socket,
            transcript,
            checkpoint,
            client_witnesses: Ok(None),
            terminal_witness_failure: false,
            terminal_witness_debt: None,
            execution_cold_native: None,
            recovery_session_native: None,
            stop_cleanup_source_native: None,
        })
    }

    pub(super) fn initialize_authenticated_request(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<crate::ProtectedBrokerSessionInitializationResultV1, BrokerSessionSecurityError>
    {
        self.owner.initialize_authenticated_request(
            request,
            &self.transcript,
            self.socket.peer(),
            &self.checkpoint,
        )
    }

    pub(super) fn initialize_storage_request_receiving_v2(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        initial: Option<&mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>>,
        lifecycle: Option<&mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>>,
    ) -> Result<crate::ProtectedBrokerSessionInitializationResultV1, BrokerSessionSecurityError> {
        let source: &mut dyn crate::recovery::StorageFloorFinancialSourceV2 =
            match (initial, lifecycle) {
                (Some(source), None) => source,
                (None, Some(source)) => source,
                _ => return Err(BrokerSessionSecurityError::Currentness),
            };
        self.owner.initialize_storage_request_receiving_v2(
            request, &self.transcript, self.socket.peer(), &self.checkpoint, source,
        )
    }

    pub(super) fn append_authenticated_request(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<crate::ProtectedBrokerRequestCommitResultV1, BrokerSessionSecurityError> {
        self.owner
            .append_authenticated_request(request, &self.transcript, self.socket.peer())
    }

    pub(super) fn append_storage_request_receiving_v3(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        initial: Option<&mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>>,
        lifecycle: Option<&mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>>,
    ) -> Result<crate::ProtectedBrokerRequestCommitResultV1, BrokerSessionSecurityError> {
        let source: &mut dyn crate::recovery::StorageFloorFinancialSourceV2 = match (initial, lifecycle) {
            (Some(source), None) => source,
            (None, Some(source)) => source,
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        self.owner.append_request_with_storage_receiving_v3(
            request, &self.transcript, self.socket.peer(), Some(source),
        )
    }

    pub(super) fn recover_initialization(
        &mut self,
        recovery: crate::ProtectedBrokerSessionInitializationRecoveryV1,
    ) -> crate::ProtectedBrokerSessionInitializationResultV1 {
        self.owner
            .recover_initialization(recovery, self.socket.peer())
    }

    pub(super) fn recover_request_commit(
        &mut self,
        recovery: crate::ProtectedBrokerRequestCommitRecoveryV1,
    ) -> crate::ProtectedBrokerRequestCommitResultV1 {
        self.owner
            .recover_request_commit(recovery, self.socket.peer())
    }

    pub(super) fn reopen_broker_outcome(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<
        (
            crate::ProtectedBrokerOutcomeAdmissionGateV1,
            aos_sandbox_broker_session_protocol::ProtectedBrokerSessionVerificationContextV1,
        ),
        BrokerSessionSecurityError,
    > {
        let gate =
            self.owner
                .reopen_broker_outcome(request, &self.transcript, self.socket.peer())?;
        let context = gate.verification_context();
        Ok((gate, context))
    }

    pub(super) fn reopen_broker_outcome_with_storage_receiving_v3(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        receiving: Option<&mut dyn crate::recovery::StorageFloorFinancialSourceV2>,
    ) -> Result<(crate::ProtectedBrokerOutcomeAdmissionGateV1,
        aos_sandbox_broker_session_protocol::ProtectedBrokerSessionVerificationContextV1), BrokerSessionSecurityError> {
        let gate = self.owner.reopen_broker_outcome_with_storage_receiving_v3(
            request, &self.transcript, self.socket.peer(), receiving,
        )?;
        let context = gate.verification_context();
        Ok((gate, context))
    }

    pub(super) fn commit_broker_outcome(
        &mut self,
        pending: crate::ProtectedBrokerOutcomePendingAdvancementV1,
    ) -> crate::ProtectedBrokerOutcomeCommitResultV1 {
        self.owner
            .commit_broker_outcome(pending, self.socket.peer())
    }

    pub(super) fn commit_outcome_with_storage_receiving_v3(&mut self,
        pending: crate::ProtectedBrokerOutcomePendingAdvancementV1,
        receiving: Option<&mut dyn crate::recovery::StorageFloorFinancialSourceV2>,
    ) -> crate::ProtectedBrokerOutcomeCommitResultV1 {
        self.owner.commit_outcome_with_storage_receiving_v3(pending, self.socket.peer(), receiving)
    }

    pub(super) fn recover_broker_outcome_commit(
        &mut self,
        recovery: crate::ProtectedBrokerOutcomeCommitRecoveryV1,
    ) -> crate::ProtectedBrokerOutcomeCommitResultV1 {
        self.owner
            .recover_broker_outcome_commit(recovery, self.socket.peer())
    }

    pub(super) fn revalidate_broker_outcome<'session>(
        &'session mut self,
        currentness: crate::ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<crate::ProtectedBrokerOutcomeCurrentV1<'session>, BrokerSessionSecurityError> {
        self.owner
            .revalidate_broker_outcome(currentness, self.socket.peer())
    }

    pub(super) fn arm_execution_client_post_v1(&self,
        original: &mut crate::ExecutionClientPostOriginalV1) -> Result<(), BrokerSessionSecurityError>
    {
        self.owner.arm_execution_client_socket_post_v1(
            &self.transcript, self.socket.as_fd().ok(), original,
        )
    }

    pub(super) fn finish_execution_client_post_v1(&mut self,
        original: &mut crate::ExecutionClientPostOriginalV1) -> Result<(), BrokerSessionSecurityError>
    {
        self.owner.finish_execution_client_socket_post_v1(
            &self.transcript, self.socket.peer(), self.socket.as_fd().ok(), original,
        )
    }

    pub(super) fn retain_execution_outcome_current_with_post_v1<'authority>(
        &'authority mut self, owner: crate::ProtectedBrokerOutcomeCurrentnessOwnerV1,
        original: &mut crate::ExecutionClientPostOriginalV1,
    ) -> Result<crate::ProtectedBrokerOutcomeCurrentV1<'authority>,
        (crate::ProtectedBrokerOutcomeCurrentnessOwnerV1, BrokerSessionSecurityError)>
    {
        self.owner.retain_execution_outcome_current_with_post_v1(
            owner, self.socket.peer(), original, self.socket.as_fd().ok(),
        )
    }

    /// Forwards the same socket and sole owner without taking failed custody.
    ///
    /// # Errors
    ///
    /// Returns the original owner with the actual fixed execution check error.
    pub(super) fn retain_execution_outcome_current<'session>(
        &'session mut self,
        currentness: crate::ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<
        crate::ProtectedBrokerOutcomeCurrentV1<'session>,
        (crate::ProtectedBrokerOutcomeCurrentnessOwnerV1, BrokerSessionSecurityError),
    > {
        self.owner
            .retain_execution_outcome_current(currentness, self.socket.peer())
    }

    pub(super) fn compare_atomic_snapshot_predecessor_v3(
        &mut self,
        currentness: &crate::ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.owner.compare_atomic_snapshot_predecessor_v3(currentness, self.socket.peer())
    }

    pub(super) fn compare_host_storage_output_outcome_v1(
        &mut self,
        currentness: &crate::ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.owner.compare_host_storage_output_outcome_v1(currentness, self.socket.peer())
    }

    pub(super) fn compare_original_storage_output_outcome_v1(
        &mut self,
        currentness: &crate::ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.owner.compare_original_storage_output_outcome_v1(currentness, self.socket.peer())
    }

    pub(super) fn compare_git_coverage_outcome_v1(
        &mut self,
        currentness: &crate::ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.owner
            .compare_git_coverage_outcome_v1(currentness, self.socket.peer())
    }

    pub(super) fn capture_git_coverage_checkpoint_v1(
        &mut self,
        currentness: &crate::ProtectedBrokerOutcomeCurrentnessOwnerV1,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        self.owner.capture_git_coverage_checkpoint_v1(
            currentness, self.socket.peer(), maximum_bytes,
        )
    }

    pub(super) fn revalidate_broker_replay(
        &mut self,
        replay: crate::ProtectedBrokerOutcomeReplayV1,
    ) -> Result<
        crate::ProtectedBrokerOutcomeReplayV1,
        (
            BrokerSessionSecurityError,
            crate::ProtectedBrokerOutcomeReplayV1,
        ),
    > {
        self.owner
            .revalidate_broker_replay(replay, self.socket.peer())
    }

    pub(super) fn revalidate_storage_replay_receiving_v3(&mut self,
        replay: crate::ProtectedBrokerOutcomeReplayV1,
        receiving: Option<&mut dyn crate::recovery::StorageFloorFinancialSourceV2>,
    ) -> Result<crate::ProtectedBrokerOutcomeReplayV1,
        (BrokerSessionSecurityError, crate::ProtectedBrokerOutcomeReplayV1)> {
        self.owner.revalidate_storage_replay_receiving_v3(replay, self.socket.peer(), receiving)
    }

    pub(super) fn revalidate_broker_committed(
        &mut self,
        committed: crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<
        crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
        (
            BrokerSessionSecurityError,
            crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
        ),
    > {
        self.owner
            .revalidate_broker_committed(committed, self.socket.peer())
    }

    pub(super) fn revalidate_storage_committed_receiving_v3(&mut self,
        committed: crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
        receiving: Option<&mut dyn crate::recovery::StorageFloorFinancialSourceV2>,
    ) -> Result<crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
        (BrokerSessionSecurityError, crate::ProtectedBrokerOutcomeCommittedAdvancementV1)> {
        self.owner.revalidate_storage_committed_receiving_v3(committed, self.socket.peer(), receiving)
    }

    pub(crate) fn compare_storage_terminal_receiving_v3(&mut self,
        terminal: &crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
        receiving: &mut dyn crate::recovery::StorageFloorFinancialSourceV2,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.owner.compare_storage_terminal_receiving_v3(terminal, self.socket.peer(), receiving)
    }

    pub(crate) fn dispose_storage_positive_replays_v3(&mut self) {
        self.owner.dispose_storage_positive_replays_v3();
    }

    pub(crate) fn compare_storage_terminal_owner_receiving_v3(&mut self,
        terminal: &crate::recovery::RetainedStorageTerminalV1,
        receiving: &mut dyn crate::recovery::StorageFloorFinancialSourceV2,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.owner.compare_storage_terminal_owner_receiving_v3(terminal, self.socket.peer(), receiving)
    }

    pub(crate) fn compare_storage_replay_receiving_v3(&mut self,
        replay: &crate::ProtectedBrokerOutcomeReplayV1,
        receiving: &mut dyn crate::recovery::StorageFloorFinancialSourceV2,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.owner.compare_storage_replay_receiving_v3(replay, self.socket.peer(), receiving)
    }

    pub(super) fn prepare_effect_handoff<'session>(
        &'session mut self,
        currentness: crate::ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<crate::ProtectedBrokerEffectHandoffV1<'session>, BrokerSessionSecurityError> {
        self.owner
            .prepare_effect_handoff(currentness, self.socket.peer())
    }
}

fn require_negotiated_method(
    transcript: &VerifiedBrokerSessionTranscriptV1,
    method: aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod,
) -> Result<(), BrokerSessionSecurityError> {
    if !transcript.negotiated_methods().contains(&method) {
        return Err(BrokerSessionSecurityError::UnnegotiatedMethod);
    }
    Ok(())
}

/// Samples the original direct BOOTTIME clock without accepting caller clock facts.
///
/// # Errors
/// Returns the original currentness error for invalid or unrepresentable clock values.
pub fn protected_boottime_nanoseconds() -> Result<u64, BrokerSessionSecurityError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| BrokerSessionSecurityError::Currentness)?;
    let nanoseconds =
        u64::try_from(now.tv_nsec).map_err(|_| BrokerSessionSecurityError::Currentness)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(BrokerSessionSecurityError::Currentness)
}

impl ProtectedBrokerSessionFixedCustodyV1 {
    /// Adopts an already-connected socket into the fixed client hello flight.
    ///
    /// This performs no connect, listener, registration, routing, descriptor,
    /// or broker effect operation.
    ///
    /// # Errors
    ///
    /// Returns an error unless this is a controller-client endpoint and the
    /// retained kernel peer and protected custody are current.
    pub(super) fn begin_client_handshake_inner(
        self,
        socket: SeqpacketSocket,
        hello: BrokerClientHello,
    ) -> Result<DormantControllerClientHandshakeV1, DormantBrokerSessionHandshakeErrorV1> {
        let (root, _, _, _, custody) = self.into_handshake_parts();
        let FixedEndpointCustodyV1::Client(custody) = custody else {
            return Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole);
        };
        DormantControllerClientHandshakeV1::begin(root, custody, socket, hello)
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
    pub(super) fn begin_broker_handshake_inner(
        self,
        socket: SeqpacketSocket,
        hello: BrokerServerHello,
    ) -> Result<DormantBrokerEndpointHandshakeV1, DormantBrokerSessionHandshakeErrorV1> {
        let (root, _, _, _, custody) = self.into_handshake_parts();
        let FixedEndpointCustodyV1::Broker(custody) = custody else {
            return Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole);
        };
        DormantBrokerEndpointHandshakeV1::begin(root, custody, socket, hello)
    }
}

#[allow(
    dead_code,
    reason = "P0-10 keeps the sealed traffic proof production-unreachable"
)]
mod traffic;

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "kernel-tests"))]
mod qualification_credentials;

#[cfg(all(test, feature = "kernel-tests"))]
mod storage_rpc_qualification;

#[cfg(test)]
mod storage_terminal_tests;

// Only the genuine query original supplies the nonce/cutoff. The selection
// stays beside the private Session fields; the upper wrapper projects DATA.
pub(crate) fn delete_inventory_coordinates_v1(
    session: &DormantAuthenticatedBrokerSessionV1,
    original: &aos_sandbox_controller_domain::DeleteInventorySessionAppendOriginalV1<'_, '_, '_, '_, '_, '_>,
) -> Result<
    ([u8; 16], u64, u32, aos_sandbox_model::ProtocolVersion,
        aos_sandbox_api::aos::sandbox::local::v1::Audience),
    BrokerSessionSecurityError,
> {
    let method = session.owner.delete_inventory_client_method_v1()?;
    if !session.transcript.negotiated_methods().contains(&method) {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    let (request_id, cutoff) = original.query_coordinates_v1()
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    controller_inventory_coordinates_v1(session, request_id, cutoff)

}

impl DormantAuthenticatedBrokerSessionV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_client_request_retaining_v1(&mut self,
        message: aos_sandbox_api::aos::sandbox::local::v1::BrokerRequestEnvelope,
        method: aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod, actual_descriptor_count: usize,
        request_id: [u8; 16], deadline_boottime_nanoseconds: u64, maximum_response_bytes: u32,
        originals: &mut crate::recovery::ClientRequestOriginalsV1,
    ) -> Result<(aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1, bool), BrokerSessionSecurityError> {
        self.owner.prepare_client_request_retaining_v1(message, method, actual_descriptor_count,
            request_id, deadline_boottime_nanoseconds, maximum_response_bytes, &self.transcript,
            self.socket.peer(), originals)
    }
}

pub(crate) fn operator_recover_inventory_coordinates_v1(
    session: &DormantAuthenticatedBrokerSessionV1,
    original: &aos_sandbox_controller_domain::ControllerRecoveryInventoryLoanV2<'_, '_, '_, '_, '_>,
) -> Result<([u8; 16], u64, u32, aos_sandbox_model::ProtocolVersion,
    aos_sandbox_api::aos::sandbox::local::v1::Audience), BrokerSessionSecurityError>
{
    if original.is_operator_recover_storage_data_v2() {
        session.owner.operator_recover_inventory_journal_v1()?;
        if !aos_sandbox_broker_session_protocol::profile::is_storage_operator_recover_transcript_v1(&session.transcript) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
    } else {
        session.owner.reconciliation_inventory_client_journal_v2(original.method_data_v2())?;
    }
    let (request_id, cutoff) = original.query_coordinates_v1()
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    controller_inventory_coordinates_v1(session, request_id, cutoff)
}

fn controller_inventory_coordinates_v1(
    session: &DormantAuthenticatedBrokerSessionV1, request_id: [u8; 16], cutoff: u64,
) -> Result<([u8; 16], u64, u32, aos_sandbox_model::ProtocolVersion,
    aos_sandbox_api::aos::sandbox::local::v1::Audience), BrokerSessionSecurityError>
{
    let authenticated = u32::try_from(aos_sandbox_broker_session_protocol::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES)
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    let (major, minor) = session.transcript.protocol_version();
    Ok((
        request_id, cutoff,
        session.transcript.negotiated_maximum_response_bytes().min(authenticated),
        aos_sandbox_model::ProtocolVersion::new(major, minor),
        session.transcript.audience(),
    ))
}

impl DormantAuthenticatedBrokerSessionV1 {
    pub(crate) fn borrow_storage_host_client_receiving_v1<'loan, 'cut, 'original>(
        &'loan mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        lifecycle: &'loan mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'cut, 'original>,
    ) -> Result<crate::recovery::StorageHostClientReceivingV1<'loan, 'cut, 'original>, BrokerSessionSecurityError> {
        self.owner.borrow_storage_host_client_receiving_v1(&self.socket, request, &self.transcript, lifecycle)
    }

    pub(crate) fn storage_host_unmodified_prefix_bound_v1(&self)
        -> Result<aos_sandbox_controller_domain::journal::ProtectedJournalPreopenReplayExtentV1, BrokerSessionSecurityError>
    { self.owner.storage_host_unmodified_prefix_bound_v1() }

}

impl DormantAuthenticatedBrokerSessionV1 {
    pub(super) fn park_output_client_coordinates_v1(
        &mut self,
        method: BrokerMethod,
        original_cutoff: u64,
        flight: &mut output_registration_continuation::OriginalOutputClientFlightV1,
    ) {
        if flight.coordinates.is_some() { return; }
        flight.coordinates = Some((|| {
            if !matches!(method, BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT)
                || original_cutoff == 0
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            self.require_negotiated_client_method(method)?;
            let (request_id, deadline, maximum_response_bytes, protocol_version, audience) = self.client_request_coordinates()?;
            Ok(crate::DormantBrokerRequestCoordinatesV1::from_session_data_v1(
                request_id,
                deadline.min(original_cutoff),
                maximum_response_bytes,
                protocol_version,
                audience,
            ))
        })());
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum StorageHostExchangeDemandErrorV1 {
    #[error("the original Host Session receiving boundary is unavailable: {0}")]
    Boundary(#[from] BrokerSessionSecurityError),
    #[error("the Host Session receiving representation is invalid: {0}")]
    Geometry(#[from] aos_sandbox_controller_domain::journal::broker_session_receiving::StorageSessionGeometryRefusalV1),
}

impl DormantAuthenticatedBrokerSessionV1 {
    pub(crate) fn storage_host_output_receiving_demand_v1(&self)
        -> Result<aos_sandbox_model::ResourceVector, StorageHostExchangeDemandErrorV1>
    {
        let extent = self.owner.storage_host_unmodified_prefix_bound_v1()?;
        Ok(aos_sandbox_controller_domain::journal::broker_session_receiving::execution_output_client_demand_v1(
            &extent, &self.transcript, BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT,
        )?)
    }
}

mod storage_capture_query;

mod storage_capture_candidate;


impl DormantBrokerEndpointHandshakeV1 {
    // Diagnostic only: no advancement, retry or replacement of native custody.
    fn pending_native_failure_v4(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let carrier = match &self.state {
            DormantBrokerHandshakeStateV1::SendPublication(stage) => &stage.carrier,
            DormantBrokerHandshakeStateV1::AwaitClientHello(stage) => &stage.carrier,
            DormantBrokerHandshakeStateV1::SendHello(stage) => &stage.carrier,
        };
        carrier.selected_send.as_ref().and_then(|native| native.failure())
    }
}

// These finite borrowers preserve the exact private Session association for
// sibling owning wrappers. They create no Session or currentness authority.
impl DormantAuthenticatedBrokerSessionV1 {
    // Borrows the actual completed receiver/endpoint/main association without
    // exposing the private Session owner to its sibling wrapper.
    pub(crate) fn completed_initial_native_borrow_for_maintenance_v2<'held>(
        &'held self,
        receiving: &'held aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingV1,
    ) -> Result<aos_sandbox_controller_domain::ControllerInitialSessionCompletedNativeBorrowV1<'held>, BrokerSessionSecurityError> {
        self.owner.completed_initial_native_borrow_for_maintenance_v2(receiving)
    }

    pub(crate) fn pending_delete_inventory_transcript_v2(
        &self,
    ) -> &VerifiedBrokerSessionTranscriptV1 {
        &self.transcript
    }

    pub(crate) fn operator_recover_inventory_journal_v1(
        &self,
    ) -> Result<&aos_sandbox_controller_domain::Journal, BrokerSessionSecurityError> {
        self.owner.operator_recover_inventory_journal_v1()
    }

    pub(crate) fn operator_reconciliation_inventory_journal_v2(
        &self, method: BrokerMethod,
    ) -> Result<&aos_sandbox_controller_domain::Journal, BrokerSessionSecurityError> {
        self.owner.reconciliation_inventory_client_journal_v2(method)
    }

    pub(crate) fn reserve_storage_output_domain_additional_v1(
        &self,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        demand: aos_sandbox_model::ResourceVector,
    ) -> Result<(), BrokerSessionSecurityError> {
        let journal = self.owner.retained_storage_journal_v1()?;
        receiving.reserve_domain_additional_v1(journal, &self.socket, demand)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    // Both SDK entry and its public passive view use this held transcript.
    pub(crate) fn delete_storage_preparation_shape_v3(&self, request_bound: usize)
        -> Option<aos_sandbox_controller_domain::StorageProvisioningSessionIoShapeDataV1> {
        crate::controller_composition::delete_storage_preparation_security_shape_v3(
            self.transcript.negotiated_maximum_response_bytes() as usize, request_bound)
    }

    pub(crate) fn delete_storage_apply_shape_v3(&self, request_bound: usize)
        -> Option<aos_sandbox_controller_domain::StorageProvisioningSessionIoShapeDataV1> {
        crate::controller_composition::delete_storage_apply_security_shape_v3(
            self.transcript.negotiated_maximum_response_bytes() as usize, request_bound)
    }

    // The real signed26 fixes every header field; Session limits can only refuse it.
    pub(crate) fn delete_storage_preparation_coordinates_v3(
        &mut self,
        header: &aos_sandbox_api::aos::sandbox::local::v1::RequestHeader,
    ) -> Result<crate::DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
        self.delete_storage_coordinates_v3(header, DeleteStorageCoordinatesPurposeV3::Preparation)
    }

    pub(crate) fn delete_storage_apply_coordinates_v3(
        &mut self,
        header: &aos_sandbox_api::aos::sandbox::local::v1::RequestHeader,
    ) -> Result<crate::DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
        self.delete_storage_coordinates_v3(header, DeleteStorageCoordinatesPurposeV3::Apply)
    }

    pub(crate) fn delete_network_apply_shape_v4(&self, request_bound: usize)
        -> Option<aos_sandbox_controller_domain::StorageProvisioningSessionIoShapeDataV1> {
        crate::controller_composition::delete_network_apply_security_shape_v4(
            self.transcript.negotiated_maximum_response_bytes() as usize, request_bound)
    }

    pub(crate) fn delete_network_apply_coordinates_v4(&mut self,
        header: &aos_sandbox_api::aos::sandbox::local::v1::RequestHeader,
    ) -> Result<crate::DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
        self.delete_storage_coordinates_v3(header, DeleteStorageCoordinatesPurposeV3::Network)
    }

    pub(crate) fn delete_mount_reap_shape_v4(&self, request_bound: usize)
        -> Option<aos_sandbox_controller_domain::StorageProvisioningSessionIoShapeDataV1> {
        crate::controller_composition::delete_mount_reap_security_shape_v4(
            self.transcript.negotiated_maximum_response_bytes() as usize, request_bound)
    }

    pub(crate) fn delete_mount_reap_coordinates_v4(&mut self,
        header: &aos_sandbox_api::aos::sandbox::local::v1::RequestHeader,
    ) -> Result<crate::DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
        self.delete_storage_coordinates_v3(header, DeleteStorageCoordinatesPurposeV3::Mount)
    }

    fn delete_storage_coordinates_v3(
        &mut self,
        header: &aos_sandbox_api::aos::sandbox::local::v1::RequestHeader,
        purpose: DeleteStorageCoordinatesPurposeV3,
    ) -> Result<crate::DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
        match purpose {
            DeleteStorageCoordinatesPurposeV3::Preparation | DeleteStorageCoordinatesPurposeV3::Apply => {
                self.owner.retained_storage_client_journal_v1()?;
            }
            DeleteStorageCoordinatesPurposeV3::Network => {
                if self.transcript.protocol() != aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Network {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                self.owner.delete_inventory_client_journal_v1()?;
            }
            DeleteStorageCoordinatesPurposeV3::Mount => {
                if self.transcript.protocol() != aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Mount {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                self.owner.delete_inventory_client_journal_v1()?;
            }
        }
        self.require_negotiated_client_method(match purpose {
            DeleteStorageCoordinatesPurposeV3::Preparation => BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG,
            DeleteStorageCoordinatesPurposeV3::Apply => BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
            DeleteStorageCoordinatesPurposeV3::Network => BrokerMethod::BROKER_METHOD_NETWORK_APPLY,
            DeleteStorageCoordinatesPurposeV3::Mount => BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1,
        })?;
        let (deadline, maximum, protocol_version, audience) = self.client_request_limits()?;
        let request_id: [u8; 16] = header.request_id.as_slice().try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if request_id == [0; 16] || header.deadline_boottime_nanoseconds == 0
            || header.deadline_boottime_nanoseconds > deadline
            || header.maximum_response_bytes == 0 || header.maximum_response_bytes > maximum
            || header.maximum_response_bytes as usize > aos_sandbox_broker_session_protocol::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES
            || header.protocol_major != u32::from(protocol_version.major())
            || header.protocol_minor != u32::from(protocol_version.minor())
            || header.audience.as_known() != Some(audience)
            || audience != aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
        { return Err(BrokerSessionSecurityError::Currentness); }
        Ok(crate::DormantBrokerRequestCoordinatesV1::from_session_data_v1(
            request_id, header.deadline_boottime_nanoseconds,
            header.maximum_response_bytes, protocol_version, audience))
    }

    pub(crate) fn start_resource_provisioning_coordinates_v2(
        &mut self,
        header: &aos_sandbox_protocol::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2,
        inventory: bool,
    ) -> Result<crate::DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
        if !aos_sandbox_broker_session_protocol::profile::is_start_resource_transcript_v2(
            &self.transcript,
        ) || header.deadline_boottime_nanoseconds == 0
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        if self.transcript.protocol() == aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Host {
            return self.start_host_coordinates_data_v2(header, if inventory { StartHostCoordinatesPurposeV2::Inventory } else { StartHostCoordinatesPurposeV2::Launch });
        }
        let method = match (self.transcript.protocol(), inventory) {
            (aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Network, false) => BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2,
            (aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Network, true) => BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
            (aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage, false) => BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT,
            (aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage, true) => BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
            (aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Mount, false) => BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1,
            (aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Mount, true) => BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS,
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        self.require_negotiated_client_method(method)?;
        let (deadline, maximum, version, audience) = self.client_request_limits()?;
        if header.deadline_boottime_nanoseconds > deadline
            || header.maximum_response_bytes > maximum
            || header.protocol_major != u32::from(version.major())
            || header.protocol_minor != u32::from(version.minor())
            || header.audience != audience
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let (request_id, cutoff, response) = if inventory {
            let (id, cutoff, response, _, _) = self.client_request_coordinates()?;
            (
                id,
                cutoff.min(header.deadline_boottime_nanoseconds),
                response.min(maximum),
            )
        } else {
            (
                header.request_id,
                header.deadline_boottime_nanoseconds,
                header.maximum_response_bytes,
            )
        };
        Ok(crate::DormantBrokerRequestCoordinatesV1::from_session_data_v1(
            request_id,
            cutoff,
            response,
            version,
            audience,
        ))
    }
}

impl DormantAuthenticatedBrokerSessionV1 {
    // Coordinates are DATA derived from the actual prepared Host header and
    // verified transcript. The sole retained prepare_captured_engine owns the
    // fresh context/history/peer/native checks and signing after this step.
    pub(crate) fn start_host_catalog_coordinates_v2(&self,
        header: &aos_sandbox_protocol::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2,
    ) -> Result<crate::DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
        if !aos_sandbox_broker_session_protocol::profile::is_start_host_catalog_launch_transcript_v2(&self.transcript) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.start_host_coordinates_data_v2(header, StartHostCoordinatesPurposeV2::Catalog)
    }

    // The genuine maintenance IoLoan, not the Start profile, supplies the
    // current Catalog17 coordinates. Reuse the exact private DATA fold.
    pub(crate) fn maintenance_catalog_coordinates_v2(&self,
        header: &aos_sandbox_protocol::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2,
    ) -> Result<crate::DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
        self.owner.catalog_maintenance_client_journal_v2()?;
        self.start_host_coordinates_data_v2(header, StartHostCoordinatesPurposeV2::Catalog)
    }

    fn start_host_coordinates_data_v2(&self,
        header: &aos_sandbox_protocol::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2,
        purpose: StartHostCoordinatesPurposeV2,
    ) -> Result<crate::DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
        let method = match purpose {
            StartHostCoordinatesPurposeV2::Launch => BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            StartHostCoordinatesPurposeV2::Inventory | StartHostCoordinatesPurposeV2::StopInventory => BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
            StartHostCoordinatesPurposeV2::Catalog => BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG,
        };
        require_negotiated_method(&self.transcript, method)?;
        let (major, minor) = self.transcript.protocol_version();
        if header.protocol_major != u32::from(major) || header.protocol_minor != u32::from(minor)
            || header.audience != self.transcript.audience() || header.request_id == [0; 16]
            || header.deadline_boottime_nanoseconds == 0 || header.maximum_response_bytes == 0
            || header.maximum_response_bytes > self.transcript.negotiated_maximum_response_bytes() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let request_id = if matches!(purpose, StartHostCoordinatesPurposeV2::Inventory | StartHostCoordinatesPurposeV2::StopInventory) {
            use sha2::Digest;
            let mut hash = sha2::Sha256::new();
            hash.update(match purpose {
                StartHostCoordinatesPurposeV2::StopInventory => b"aos.original-stop.host-inventory-request.v5\0".as_slice(),
                _ => b"aos.original-start.host-inventory-request.v2\0".as_slice(),
            });
            hash.update(self.transcript.session_binding());
            hash.update(self.transcript.protected_context_digest());
            hash.update(header.request_id);
            let digest = hash.finalize();
            let mut request_id = [0; 16];
            request_id.copy_from_slice(&digest[..16]);
            if request_id == [0; 16] || request_id == header.request_id {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            request_id
        } else { header.request_id };
        Ok(crate::DormantBrokerRequestCoordinatesV1::from_session_data_v1(
            request_id, header.deadline_boottime_nanoseconds, header.maximum_response_bytes,
            aos_sandbox_model::ProtocolVersion::new(major, minor), self.transcript.audience()))
    }
}

// These are private coordinate recipes, never caller-selected Session authority.
#[derive(Clone, Copy)]
enum StartHostCoordinatesPurposeV2 { Launch, Inventory, Catalog, StopInventory }

// Compiled SHA state and fixed output/ID backing for the actual private Host
// coordinate recipes; no field or map-entry proxy is charged.
pub(crate) fn start_host_coordinates_receiving_bytes_v2() -> Option<usize> {
    std::mem::size_of::<sha2::Sha256>().checked_mul(2)?
        .checked_add(std::mem::size_of::<sha2::digest::Output<sha2::Sha256>>())?
        .checked_add(std::mem::size_of::<[u8; 16]>())
}

#[derive(Clone, Copy)]
enum DeleteStorageCoordinatesPurposeV3 { Preparation, Apply, Network, Mount }
