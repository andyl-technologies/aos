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
pub(super) mod host_worker_comparison;

use aos_sandbox::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1;
use aos_sandbox_broker_session_protocol::{
    BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES, BrokerSessionProtocolV1, CLIENT_HELLO_MAXIMUM_BYTES,
    SERVER_HELLO_MAXIMUM_BYTES, UntrustedBrokerSessionEndpointPublicationV1,
    VerifiedBrokerSessionTranscriptV1, decode_canonical_client_hello_v1,
    decode_canonical_server_hello_v1,
    hello_message::{BrokerClientHello, BrokerServerHello},
    verify_broker_session_transcript_after_client_v1, verify_broker_session_transcript_v1,
    verify_client_hello_context_v1, verify_client_hello_signature_v1,
};
use aos_sandbox_linux::pidfd::{PidFd, PidFdCredentials, PidFdInfo, PidFdProcessIdentity};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_linux::seqpacket::{
    ConnectionPeerIdentity, KernelAuthorizedRecordSubject, SeqpacketError, SeqpacketSocket,
};
use aos_sandbox_protocol::PeerCredentials;

use crate::recovery::{
    ArchivedStorageInventoryHeadV1, AuthenticatedOriginalHostNoApplyJoinV1, FixedEndpointCustodyV1,
    HistoricalSessionCheckpointV1, ProtectedBrokerSessionOwnerV1,
    ProtectedPriorAtomicStorageHistoryV1, ProtectedPriorTerminalExchangeV1,
    ProtectedVerifiedAtomicStorageHistoryV1,
};
use crate::{
    BrokerSessionSecurityError, ProtectedBrokerSessionBrokerV1, ProtectedBrokerSessionClientV1,
    ProtectedBrokerSessionFixedCustodyV1,
};

struct HandshakeCarrier {
    transport: HandshakeTransport,
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
        Ok(Self {
            transport: HandshakeTransport::Ordinary(socket),
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

    fn descriptor(socket: DescriptorSubjectSocket) -> Result<Self, HandshakeError> {
        let peer = ProcessEvidence::capture_peer(socket.peer())?;
        Ok(Self {
            transport: HandshakeTransport::Descriptor(socket),
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
                let record = socket.receive(maximum).map_err(HandshakeError::transport)?;
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
        self.peer.validate_connection(peer)
    }

    fn close(&mut self) {
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
        let before = pidfd.info().map_err(|_| HandshakeError::KernelEvidence)?;
        let identity = pidfd
            .process_identity()
            .map_err(|_| HandshakeError::KernelEvidence)?;
        let after = pidfd.info().map_err(|_| HandshakeError::KernelEvidence)?;
        let alive = pidfd.is_alive().map_err(|_| HandshakeError::KernelEvidence);

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

enum HandshakeError {
    Local(BrokerSessionSecurityError),
    RemoteInvalid,
    KernelEvidence,
    RetryableTransport,
    Transport,
}

impl core::fmt::Debug for HandshakeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Local(error) => formatter.debug_tuple("Local").field(error).finish(),
            Self::RemoteInvalid => formatter.write_str("RemoteInvalid"),
            Self::KernelEvidence => formatter.write_str("KernelEvidence"),
            Self::RetryableTransport => formatter.write_str("RetryableTransport"),
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
            Self::RetryableTransport => formatter.write_str("original handshake transport was not ready"),
            Self::Transport => formatter.write_str("original handshake transport failed"),
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Local(error) => Some(error),
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

enum Transition<Complete, Retry> {
    Complete(Complete),
    Retry(Retry),
    Failed(HandshakeError),
}

struct BrokerPublicationFlight {
    custody: ProtectedBrokerSessionBrokerV1,
    carrier: HandshakeCarrier,
    pending: [u8; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES],
    broker_hello: BrokerServerHello,
}

impl BrokerPublicationFlight {
    fn begin(
        mut custody: ProtectedBrokerSessionBrokerV1,
        carrier: HandshakeCarrier,
        broker_hello: BrokerServerHello,
    ) -> Result<Self, HandshakeError> {
        carrier.validate_peer()?;
        let pending = custody.finalize_endpoint_publication()?;
        Ok(Self {
            custody,
            carrier,
            pending,
            broker_hello,
        })
    }

    fn send(mut self) -> Transition<BrokerAwaitClientHello, Self> {
        if let Err(error) = self.custody.revalidate_handshake_custody() {
            return Transition::Failed(error.into());
        }
        if let Err(error) = self.carrier.validate_peer() {
            return Transition::Failed(error);
        }
        let send_result = self.carrier.send(&self.pending);
        let currentness = self
            .custody
            .revalidate_handshake_custody()
            .map_err(HandshakeError::from)
            .and_then(|()| self.carrier.validate_peer());
        if let Err(error) = currentness {
            self.carrier.close();
            return Transition::Failed(error);
        }
        match send_result {
            Ok(()) => {}
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                return Transition::Retry(self);
            }
            Err(_) => {
                self.carrier.close();
                return Transition::Failed(HandshakeError::Transport);
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
    custody: ProtectedBrokerSessionBrokerV1,
    carrier: HandshakeCarrier,
    publication: [u8; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES],
    broker_hello: BrokerServerHello,
}

impl BrokerAwaitClientHello {
    fn receive(mut self) -> Transition<BrokerHelloFlight, Self> {
        if let Err(error) = self.custody.revalidate_handshake_custody() {
            return Transition::Failed(error.into());
        }
        if let Err(error) = self.carrier.validate_peer() {
            self.carrier.close();
            return Transition::Failed(error);
        }
        let receive_result = self.carrier.receive(CLIENT_HELLO_MAXIMUM_BYTES);
        let currentness = self
            .custody
            .revalidate_handshake_custody()
            .map_err(HandshakeError::from)
            .and_then(|()| self.carrier.validate_peer());
        if let Err(error) = currentness {
            self.carrier.close();
            return Transition::Failed(error);
        }
        let flight = match receive_result {
            Ok(flight) => flight,
            Err(HandshakeError::RetryableTransport) => return Transition::Retry(self),
            Err(error) => {
                self.carrier.close();
                return Transition::Failed(error);
            }
        };
        let completed = (|| {
            flight.subject.validate()?;
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
            let broker_packet = self
                .custody
                .finalize_broker_hello(self.broker_hello.clone(), &canonical_client)?;
            let broker = decode_canonical_server_hello_v1(&broker_packet)
                .map_err(|_| HandshakeError::RemoteInvalid)?;
            let transcript = verify_broker_session_transcript_after_client_v1(
                &verified_client,
                &broker,
                &context,
            )
            .map_err(|_| HandshakeError::Local(self.custody.poison_handshake_custody()))?;
            self.custody.revalidate_handshake_custody()?;
            self.carrier.validate_peer()?;
            flight.subject.validate()?;
            Ok((broker_packet, transcript))
        })();
        let (broker_packet, transcript) = match completed {
            Ok(value) => value,
            Err(error) => {
                self.carrier.close();
                return Transition::Failed(error);
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
    custody: ProtectedBrokerSessionBrokerV1,
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
            return Transition::Failed(error.into());
        }
        if let Err(error) = self.carrier.validate_peer() {
            self.carrier.close();
            return Transition::Failed(error);
        }
        if let Err(error) = self.client_subject.validate() {
            self.carrier.close();
            return Transition::Failed(error);
        }
        let send_result = self.carrier.send(&self.broker_packet);
        let currentness = self
            .custody
            .revalidate_handshake_custody()
            .map_err(HandshakeError::from)
            .and_then(|()| self.carrier.validate_peer())
            .and_then(|()| self.client_subject.validate());
        if let Err(error) = currentness {
            self.carrier.close();
            return Transition::Failed(error);
        }
        match send_result {
            Ok(()) => {}
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                return Transition::Retry(self);
            }
            Err(_) => {
                self.carrier.close();
                return Transition::Failed(HandshakeError::Transport);
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

struct ClientAwaitPublication {
    custody: ProtectedBrokerSessionClientV1,
    carrier: HandshakeCarrier,
    client_hello: BrokerClientHello,
}

impl ClientAwaitPublication {
    fn begin(
        custody: ProtectedBrokerSessionClientV1,
        carrier: HandshakeCarrier,
        client_hello: BrokerClientHello,
    ) -> Result<Self, HandshakeError> {
        carrier.validate_peer()?;
        Ok(Self {
            custody,
            carrier,
            client_hello,
        })
    }

    fn receive(mut self) -> Transition<ClientHelloFlight, Self> {
        if let Err(error) = self.custody.revalidate_handshake_custody() {
            return Transition::Failed(error.into());
        }
        if let Err(error) = self.carrier.validate_peer() {
            self.carrier.close();
            return Transition::Failed(error);
        }
        let receive_result = self
            .carrier
            .receive(BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES);
        let currentness = self
            .custody
            .revalidate_handshake_custody()
            .map_err(HandshakeError::from)
            .and_then(|()| self.carrier.validate_peer());
        if let Err(error) = currentness {
            self.carrier.close();
            return Transition::Failed(error);
        }
        let flight = match receive_result {
            Ok(flight) => flight,
            Err(HandshakeError::RetryableTransport) => return Transition::Retry(self),
            Err(error) => {
                self.carrier.close();
                return Transition::Failed(error);
            }
        };
        let completed = (|| {
            flight.subject.validate()?;
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
            self.custody.revalidate_handshake_custody()?;
            self.carrier.validate_peer()?;
            flight.subject.validate()?;
            Ok((publication, client_packet))
        })();
        let (publication, client_packet) = match completed {
            Ok(value) => value,
            Err(error) => {
                self.carrier.close();
                return Transition::Failed(error);
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

struct ClientHelloFlight {
    custody: ProtectedBrokerSessionClientV1,
    carrier: HandshakeCarrier,
    publication: UntrustedBrokerSessionEndpointPublicationV1,
    publication_packet: Vec<u8>,
    publication_subject: RetainedSubject,
    client_packet: Vec<u8>,
}

impl ClientHelloFlight {
    fn send(mut self) -> Transition<ClientAwaitBrokerHello, Self> {
        if let Err(error) = self.custody.revalidate_handshake_custody() {
            return Transition::Failed(error.into());
        }
        if let Err(error) = self.carrier.validate_peer() {
            self.carrier.close();
            return Transition::Failed(error);
        }
        if let Err(error) = self.publication_subject.validate() {
            self.carrier.close();
            return Transition::Failed(error);
        }
        let send_result = self.carrier.send(&self.client_packet);
        let currentness = self
            .custody
            .revalidate_handshake_custody()
            .map_err(HandshakeError::from)
            .and_then(|()| self.carrier.validate_peer())
            .and_then(|()| self.publication_subject.validate());
        if let Err(error) = currentness {
            self.carrier.close();
            return Transition::Failed(error);
        }
        match send_result {
            Ok(()) => {}
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                return Transition::Retry(self);
            }
            Err(_) => {
                self.carrier.close();
                return Transition::Failed(HandshakeError::Transport);
            }
        }
        Transition::Complete(ClientAwaitBrokerHello {
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
    custody: ProtectedBrokerSessionClientV1,
    carrier: HandshakeCarrier,
    publication: UntrustedBrokerSessionEndpointPublicationV1,
    publication_packet: Vec<u8>,
    publication_subject: RetainedSubject,
    client_packet: Vec<u8>,
}

impl ClientAwaitBrokerHello {
    fn receive(mut self) -> Transition<InertProvisionalClientSession, Self> {
        if let Err(error) = self.custody.revalidate_handshake_custody() {
            return Transition::Failed(error.into());
        }
        if let Err(error) = self.carrier.validate_peer() {
            self.carrier.close();
            return Transition::Failed(error);
        }
        if let Err(error) = self.publication_subject.validate() {
            self.carrier.close();
            return Transition::Failed(error);
        }
        let receive_result = self.carrier.receive(SERVER_HELLO_MAXIMUM_BYTES);
        let currentness = self
            .custody
            .revalidate_handshake_custody()
            .map_err(HandshakeError::from)
            .and_then(|()| self.carrier.validate_peer())
            .and_then(|()| self.publication_subject.validate());
        if let Err(error) = currentness {
            self.carrier.close();
            return Transition::Failed(error);
        }
        let flight = match receive_result {
            Ok(flight) => flight,
            Err(HandshakeError::RetryableTransport) => return Transition::Retry(self),
            Err(error) => {
                self.carrier.close();
                return Transition::Failed(error);
            }
        };
        let completed = (|| {
            flight.subject.validate()?;
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
            self.publication_subject.validate()?;
            flight.subject.validate()?;
            Ok(transcript)
        })();
        let transcript = match completed {
            Ok(value) => value,
            Err(error) => {
                self.carrier.close();
                return Transition::Failed(error);
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
    _custody: ProtectedBrokerSessionBrokerV1,
    _carrier: HandshakeCarrier,
    _publication: [u8; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES],
    _client_packet: Vec<u8>,
    _client_subject: RetainedSubject,
    _broker_packet: Vec<u8>,
    _transcript: VerifiedBrokerSessionTranscriptV1,
}

struct InertProvisionalClientSession {
    _custody: ProtectedBrokerSessionClientV1,
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
        if matches!(selection, ClientWitnessValidationV1::Output) {
            establishment.validate_connection(peer)?;
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
        publication.validate()?;
        broker.validate()?;
        if !publication.same_execution(broker) {
            return Err(HandshakeError::KernelEvidence);
        }
        establishment.validate_connection(peer)
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
    establishment: ProcessEvidence,
    witnesses: VerifiedStorageWitnessesV1,
    first_failure: Option<ClientWitnessFailureV1>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum OutputCurrentnessBoundaryV1 {
    BeforeAction,
    PostAction,
    // A previous native protected postcheck already owns earlier debt.
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
            self.establishment, peer, ClientWitnessValidationV1::Output,
        ) {
            Ok(()) => true,
            Err(cause) => {
                self.first_failure = Some(ClientWitnessFailureV1::Output(cause));
                false
            }
        }
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
        broker.evidence.validate(subject.pidfd())
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
pub(crate) struct OriginalBrokerColdDeadlineV1(u64);

impl OriginalBrokerColdDeadlineV1 {
    /// Samples the installed Controller's original ten-second cutoff once.
    ///
    /// # Errors
    /// Returns the existing transport projection for clock/overflow failure.
    pub(crate) fn controller() -> Result<Self, crate::DormantBrokerSessionHandshakeErrorV1> {
        crate::production_deadline_after(std::time::Duration::from_secs(10))
            .map(Self)
            .map_err(|_| crate::DormantBrokerSessionHandshakeErrorV1::Transport)
    }

    // Samples the same fixed ten-second handshake bound once and intersects
    // it with the actual original Root flight. Neither cutoff is renewed.
    pub(crate) fn git_coverage(original_root_cut: u64)
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

    pub(crate) fn value(self) -> u64 {
        self.0
    }

    #[cfg(feature = "online-nix")]
    pub(crate) fn online_request(
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        if !matches!(request.method(),
            aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2
                | aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2
                | aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2)
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
    pub(crate) fn check(self) -> Result<(), crate::DormantBrokerSessionHandshakeErrorV1> {
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
        aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER,
        aos_sandbox_broker_session_protocol::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES as u32,
    )?;
    hello.required_methods = vec![
        aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2.into(),
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
        aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER,
        aos_sandbox_broker_session_protocol::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES as u32,
    )?;
    hello.methods = vec![
        aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2.into(),
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
    hello.required_methods.extend([
        aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2.into(),
        aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2.into(),
    ]);
    Ok(hello)
}

/// Advertises the same closed three-method continuation on the original owner.
#[cfg(feature = "online-nix")]
pub(crate) fn online_existing_output_server_hello()
    -> Result<BrokerServerHello, aos_sandbox_broker_session_protocol::BrokerSessionNegotiationError>
{
    let mut hello = online_resolve_server_hello()?;
    hello.methods.extend([
        aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2.into(),
        aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2.into(),
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
    WitnessPostcheck,
    Outer,
}

/// Owns one genuine post-VERIFIED HELLO while cold admission borrows it.
///
/// All returned owners are parked before later gates. Its first outer cause
/// is separate from native/physical causes and cleanup debt retained below.
/// An unfinished selected owner cannot be silently dropped or resumed.
pub(crate) struct RetainedStorageColdOpenV1 {
    verified: VerifiedStorageHandshakeV1,
    deadline: OriginalBrokerColdDeadlineV1,
    #[cfg(feature = "online-nix")]
    online_provision: Option<crate::nix_service::floor::OnlineProvisionV1>,
    #[cfg(feature = "online-nix")]
    online_client_establishment: Option<ProcessEvidence>,
    checkpoint: Option<HistoricalSessionCheckpointV1>,
    main: Option<crate::recovery::BrokerMainOpenV1>,
    owner: Option<ProtectedBrokerSessionOwnerV1>,
    phase: StorageColdPhaseV1,
    first_failure: Option<crate::DormantBrokerSessionHandshakeErrorV1>,
    client_witnesses: Option<Result<AuthenticatedClientWitnessesV1, HandshakeError>>,
    output_failure_site: Option<OutputColdFailureSiteV1>,
    output_witness_debt: bool,
}

impl RetainedStorageColdOpenV1 {
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
            main: None,
            owner: None,
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

    pub(crate) fn is_failed(&self) -> bool {
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
        if !self.phase.may_begin() {
            return Err(self.failure_projection());
        }
        self.phase = StorageColdPhaseV1::Checking;
        if let Err(cause) = self.admit(expected_node) {
            if self.first_failure.is_none() {
                self.first_failure = Some(cause);
            }
            if self.client_witnesses.is_some() {
                self.output_failure_site
                    .get_or_insert(OutputColdFailureSiteV1::Outer);
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
        let socket = match self.verified.carrier.take() {
            Some(HandshakeCarrier {
                transport: HandshakeTransport::Ordinary(socket),
                ..
            }) => socket,
            _ => std::process::abort(),
        };
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
        })
    }

    fn admit(
        &mut self,
        expected_node: Option<[u8; 16]>,
    ) -> Result<(), crate::DormantBrokerSessionHandshakeErrorV1> {
        self.deadline.check()?;
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
        let custody = self.verified.custody
            .as_mut()
            .ok_or(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole)?;
        let context = match custody {
            FixedEndpointCustodyV1::Client(custody) => {
                custody.context_for_handshake(transcript.broker_process())?
            }
            FixedEndpointCustodyV1::Broker(custody) => {
                custody.context_for_handshake(transcript.client_process())?
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
        self.checkpoint = Some(HistoricalSessionCheckpointV1::new(
            context,
            &self.verified.client_packet,
            &self.verified.broker_packet,
            peer,
            transcript,
        )?);
        self.deadline.check()?;

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
        self.main = Some(main);
        let main = self.main
            .as_mut()
            .ok_or(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole)?;
        self.deadline.check()?;
        main.open()?;
        main.finish_into(&mut self.owner);
        self.deadline.check()?;
        let owner = self.owner
            .as_mut()
            .ok_or(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole)?;
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

        // Final node/startup/currentness observations precede the final same-D
        // check inside retirement. Selected Client witnesses move once into
        // the Session; ordinary witnesses keep their original shell lifetime.
        owner.retire_cold_deadline(self.deadline)?;
        Ok(())
    }

    // Resolves only the site latched before the next independent bookend.
    // Later witness debt cannot displace the actual earlier protected cause.
    pub(crate) fn output_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.output_failure_site? {
            OutputColdFailureSiteV1::WitnessCreation
            | OutputColdFailureSiteV1::WitnessPrecheck
            | OutputColdFailureSiteV1::WitnessPostcheck => self.output_witness_cause(),
            OutputColdFailureSiteV1::ProtectedOwner | OutputColdFailureSiteV1::Outer => {
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
        Self {
            root,
            custody: Some(FixedEndpointCustodyV1::Client(custody)),
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
        Self {
            root,
            custody: Some(FixedEndpointCustodyV1::Broker(custody)),
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
pub(super) enum DormantBrokerSessionHandshakeErrorV1 {
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
}

impl From<HandshakeError> for DormantBrokerSessionHandshakeErrorV1 {
    fn from(error: HandshakeError) -> Self {
        match error {
            HandshakeError::Local(error) => Self::Protected(error),
            HandshakeError::RemoteInvalid => Self::RemoteInvalid,
            HandshakeError::KernelEvidence => Self::KernelEvidence,
            HandshakeError::RetryableTransport => Self::Transport,
            HandshakeError::Transport => Self::Transport,
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
    fn begin(
        root: &'static str,
        custody: ProtectedBrokerSessionClientV1,
        socket: SeqpacketSocket,
        hello: BrokerClientHello,
    ) -> Result<Self, DormantBrokerSessionHandshakeErrorV1> {
        let carrier = HandshakeCarrier::ordinary(socket)?;
        let state = ClientAwaitPublication::begin(custody, carrier, hello)?;
        Ok(Self {
            root,
            state: DormantClientHandshakeStateV1::AwaitPublication(state),
        })
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
    // context/checkpoint/main/floor work. Earlier raw receive gaps are unchanged.
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
        let state = BrokerPublicationFlight::begin(custody, carrier, hello)?;
        Ok(Self {
            root,
            state: DormantBrokerHandshakeStateV1::SendPublication(state),
        })
    }

    /// Advances exactly one send or receive flight on the adopted socket.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid remote bytes, changed kernel evidence,
    /// protected-custody failure, or a non-retryable transport failure.
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

    // The same three-flight reducer returns the real verified handoff before
    // context/checkpoint/main/floor work. Earlier raw receive gaps are unchanged.
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
    pub(crate) named: Option<Result<(), aos_sandbox::JournalError>>,
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
    Observation(#[from] aos_sandbox::ownership_resume::OwnershipClockObservationError),
    #[error("the original admitted effect clock failed: {0}")]
    Effect(#[from] aos_sandbox_broker::BrokerAdmissionError),
    #[error("the original admitted clock context is unavailable or already fenced")]
    Unavailable,
}

/// Reports selected transport failures while originals stay in caller slots.
#[cfg(feature = "online-nix")]
#[derive(Debug, thiserror::Error)]
pub(crate) enum OnlineTransportFailureV1 {
    #[error("online protected Session custody failed: {0}")]
    Protected(#[from] BrokerSessionSecurityError),
    #[error("online original record binding failed: {0}")]
    Binding(#[from] aos_sandbox_linux::seqpacket::RecordBindingError),
    #[error("online original record subject failed: {0}")]
    Kernel(#[from] aos_sandbox_linux::Error),
    #[error("online original HELLO witness failed: {0}")]
    Witness(#[from] DormantBrokerSessionHandshakeErrorV1),
    #[error("the actual owning receive failure is retained in this attempt")]
    Receive,
    #[error("the actual request admission error is retained in this attempt")]
    Admission,
    #[error("original paired clock observation failed: {0}")]
    Clock(#[from] aos_sandbox::ownership_resume::OwnershipClockObservationError),
    #[error("the actual selected request decoder error remains in its slot")]
    Decode,
    #[error("the actual selected send error remains in its slot")]
    Send,
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
            if matches!(&self.client_witnesses, Ok(None)) {
                self.client_witnesses = Err(HandshakeError::KernelEvidence);
            }
            return match &mut self.client_witnesses {
                Ok(Some(witnesses)) => witnesses.require_subject(subject),
                _ => false,
            };
        }
        let peer = self.socket.peer();
        let actual = subject.credentials();
        let expected = peer.credentials();
        actual.pid() == expected.pid()
            && actual.uid() == expected.uid()
            && actual.gid() == expected.gid()
            && subject.initial_info() == peer.initial_info()
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
        let sample = crate::controller_service::ownership::sample_ownership_clock()?;
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

    pub(super) fn require_negotiated_client_method(
        &mut self,
        method: aos_proto::aos::sandbox::local::v1::BrokerMethod,
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
        self.checkpoint.digest()
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
        method: aos_proto::aos::sandbox::local::v1::BrokerMethod,
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
            aos_sandbox_core::ProtocolVersion,
            aos_proto::aos::sandbox::local::v1::Audience,
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
            aos_sandbox_core::ProtocolVersion,
            aos_proto::aos::sandbox::local::v1::Audience,
        ),
        BrokerSessionSecurityError,
    > {
        let now = protected_boottime_nanoseconds()?;
        self.owner.client_request_limits(&self.transcript, now)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare_client_request(
        &mut self,
        message: aos_proto::aos::sandbox::local::v1::BrokerRequestEnvelope,
        method: aos_proto::aos::sandbox::local::v1::BrokerMethod,
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
        let retained_client = self.owner.is_output_client_endpoint()
            && !matches!(&self.client_witnesses, Ok(None));
        if retained_client && !self.revalidate_output_witnesses() {
            return Err(DormantBrokerSessionHandshakeErrorV1::KernelEvidence);
        }
        self.owner
            .revalidate_transport(&self.transcript, self.socket.peer())?;
        let record = self
            .socket
            .receive(maximum_bytes)
            .map_err(|error| match error {
                SeqpacketError::WouldBlock | SeqpacketError::Interrupted => {
                    DormantBrokerSessionHandshakeErrorV1::Transport
                }
                _ => DormantBrokerSessionHandshakeErrorV1::RemoteInvalid,
            })?;
        let bound = self
            .socket
            .bind_received(record)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?;
        let credentials = bound.subject().credentials();
        let peer_credentials = bound.peer().credentials();
        if retained_client {
            if !bound.subject().is_alive()
                .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?
            {
                return Err(DormantBrokerSessionHandshakeErrorV1::KernelEvidence);
            }
            let current = match &mut self.client_witnesses {
                Ok(Some(witnesses)) => witnesses.require_subject(bound.subject()),
                _ => false,
            };
            if !current {
                return Err(DormantBrokerSessionHandshakeErrorV1::KernelEvidence);
            }
        } else {
            if !bound
                .subject()
                .is_alive()
                .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?
                || credentials.pid() != peer_credentials.pid()
                || credentials.uid() != peer_credentials.uid()
                || credentials.gid() != peer_credentials.gid()
                || bound.subject().initial_info() != bound.peer().initial_info()
            {
                return Err(DormantBrokerSessionHandshakeErrorV1::KernelEvidence);
            }
        }
        let packet = bound.payload().to_vec();
        drop(bound);
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
        let credentials = bound.subject().credentials();
        let peer_credentials = bound.peer().credentials();
        if !bound
            .subject()
            .is_alive()
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?
            || credentials.pid() != peer_credentials.pid()
            || credentials.uid() != peer_credentials.uid()
            || credentials.gid() != peer_credentials.gid()
            || bound.subject().initial_info() != bound.peer().initial_info()
        {
            return Err(DormantBrokerSessionHandshakeErrorV1::KernelEvidence);
        }
        let (packet, _, descriptors, _) = bound.into_parts();
        self.owner
            .revalidate_transport(&self.transcript, self.socket.peer())?;
        Ok((packet, descriptors))
    }

    pub(super) fn prepare_broker_outcome(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        message: aos_proto::aos::sandbox::local::v1::BrokerResponseEnvelope,
    ) -> Result<crate::ProtectedBrokerOutcomePendingAdvancementV1, BrokerSessionSecurityError> {
        self.owner
            .prepare_broker_outcome(request, message, &self.transcript, self.socket.peer())
    }

    pub(super) fn prepare_original_nonadmitting_outcome(
        &mut self,
        retained: &mut crate::endpoint::RetainedOriginalBrokerOutcomeV1,
        purpose: crate::endpoint::OriginalBrokerOutcomePurposeV1,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        message: aos_proto::aos::sandbox::local::v1::BrokerResponseEnvelope,
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
        let credentials = bound.subject().credentials();
        let peer_credentials = bound.peer().credentials();
        if !bound
            .subject()
            .is_alive()
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?
            || credentials.pid() != peer_credentials.pid()
            || credentials.uid() != peer_credentials.uid()
            || credentials.gid() != peer_credentials.gid()
            || bound.subject().initial_info() != bound.peer().initial_info()
        {
            return Err(DormantBrokerSessionHandshakeErrorV1::KernelEvidence);
        }
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
        let maximum = aos_sandbox_broker_session_protocol::maximum_broker_session_request_bytes_v1(
            self.transcript.protocol(),
        );
        let record = self
            .socket
            .receive_with_descriptors(maximum, expected_descriptors)
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
        let credentials = bound.subject().credentials();
        let peer_credentials = bound.peer().credentials();
        if !bound
            .subject()
            .is_alive()
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?
            || credentials.pid() != peer_credentials.pid()
            || credentials.uid() != peer_credentials.uid()
            || credentials.gid() != peer_credentials.gid()
            || bound.subject().initial_info() != bound.peer().initial_info()
        {
            return Err(DormantBrokerSessionHandshakeErrorV1::KernelEvidence);
        }
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

    pub(super) fn receive_authenticated_optional_descriptor_request(
        &mut self,
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
        let record = self
            .socket
            .receive_with_optional_descriptor(maximum)
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
        let credentials = bound.subject().credentials();
        let peer_credentials = bound.peer().credentials();
        if !bound
            .subject()
            .is_alive()
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?
            || credentials.pid() != peer_credentials.pid()
            || credentials.uid() != peer_credentials.uid()
            || credentials.gid() != peer_credentials.gid()
            || bound.subject().initial_info() != bound.peer().initial_info()
        {
            return Err(DormantBrokerSessionHandshakeErrorV1::KernelEvidence);
        }
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
            establishment: carrier.peer,
            witnesses: VerifiedStorageWitnessesV1::Client {
                _publication: publication,
                _publication_subject: publication_subject,
                _broker_subject: broker_subject,
            },
            first_failure: None,
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
        )?;
        let owner = ProtectedBrokerSessionOwnerV1::from_fixed_custody(root, custody)?;
        Ok(Self {
            owner,
            socket,
            transcript,
            checkpoint,
            client_witnesses: Ok(None),
            terminal_witness_failure: false,
            terminal_witness_debt: None,
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

    pub(super) fn append_authenticated_request(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<crate::ProtectedBrokerRequestCommitResultV1, BrokerSessionSecurityError> {
        self.owner
            .append_authenticated_request(request, &self.transcript, self.socket.peer())
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

    pub(super) fn commit_broker_outcome(
        &mut self,
        pending: crate::ProtectedBrokerOutcomePendingAdvancementV1,
    ) -> crate::ProtectedBrokerOutcomeCommitResultV1 {
        self.owner
            .commit_broker_outcome(pending, self.socket.peer())
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
    method: aos_proto::aos::sandbox::local::v1::BrokerMethod,
) -> Result<(), BrokerSessionSecurityError> {
    if !transcript.negotiated_methods().contains(&method) {
        return Err(BrokerSessionSecurityError::UnnegotiatedMethod);
    }
    Ok(())
}

pub(super) fn protected_boottime_nanoseconds() -> Result<u64, BrokerSessionSecurityError> {
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
