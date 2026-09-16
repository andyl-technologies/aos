//! Dormant authenticated hello-flight composition over adopted sockets.
//!
//! This module owns the exact connected socket across publication, ClientHello,
//! and BrokerHello. Every receive is immediately bound back to that socket,
//! and every transition rechecks protected custody plus retained pidfd evidence.
//! Public fixed-role wrappers drive one bounded flight at a time and retain the
//! resulting transcript with the adopted socket and protected journal owner.
//! They register no peer, transport, descriptor, service, or effect authority.

use std::os::fd::{AsFd, OwnedFd};

use aos_sandbox_broker_session_protocol::{
    BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES, CLIENT_HELLO_MAXIMUM_BYTES,
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

use crate::recovery::{FixedEndpointCustodyV1, ProtectedBrokerSessionOwnerV1};
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
        self.peer.validate(peer.pidfd())?;
        if peer.credentials().pid().get() != self.peer.process_id
            || peer.credentials().uid() != self.peer.effective_user_id
            || peer.credentials().gid() != self.peer.effective_group_id
        {
            return Err(HandshakeError::KernelEvidence);
        }
        Ok(())
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
    ) -> Result<DormantControllerClientHandshakeProgressV1, DormantBrokerSessionHandshakeErrorV1>
    {
        match self.state {
            DormantClientHandshakeStateV1::AwaitPublication(state) => match state.receive() {
                Transition::Complete(state) => {
                    Ok(DormantControllerClientHandshakeProgressV1::Pending(Self {
                        root: self.root,
                        state: DormantClientHandshakeStateV1::SendHello(state),
                    }))
                }
                Transition::Retry(state) => {
                    Ok(DormantControllerClientHandshakeProgressV1::Pending(Self {
                        root: self.root,
                        state: DormantClientHandshakeStateV1::AwaitPublication(state),
                    }))
                }
                Transition::Failed(error) => Err(error.into()),
            },
            DormantClientHandshakeStateV1::SendHello(state) => match state.send() {
                Transition::Complete(state) => {
                    Ok(DormantControllerClientHandshakeProgressV1::Pending(Self {
                        root: self.root,
                        state: DormantClientHandshakeStateV1::AwaitBrokerHello(state),
                    }))
                }
                Transition::Retry(state) => {
                    Ok(DormantControllerClientHandshakeProgressV1::Pending(Self {
                        root: self.root,
                        state: DormantClientHandshakeStateV1::SendHello(state),
                    }))
                }
                Transition::Failed(error) => Err(error.into()),
            },
            DormantClientHandshakeStateV1::AwaitBrokerHello(state) => match state.receive() {
                Transition::Complete(session) => {
                    Ok(DormantControllerClientHandshakeProgressV1::Complete(
                        DormantAuthenticatedBrokerSessionV1::from_client(self.root, session)?,
                    ))
                }
                Transition::Retry(state) => {
                    Ok(DormantControllerClientHandshakeProgressV1::Pending(Self {
                        root: self.root,
                        state: DormantClientHandshakeStateV1::AwaitBrokerHello(state),
                    }))
                }
                Transition::Failed(error) => Err(error.into()),
            },
        }
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
    ) -> Result<DormantBrokerEndpointHandshakeProgressV1, DormantBrokerSessionHandshakeErrorV1>
    {
        match self.state {
            DormantBrokerHandshakeStateV1::SendPublication(state) => match state.send() {
                Transition::Complete(state) => {
                    Ok(DormantBrokerEndpointHandshakeProgressV1::Pending(Self {
                        root: self.root,
                        state: DormantBrokerHandshakeStateV1::AwaitClientHello(state),
                    }))
                }
                Transition::Retry(state) => {
                    Ok(DormantBrokerEndpointHandshakeProgressV1::Pending(Self {
                        root: self.root,
                        state: DormantBrokerHandshakeStateV1::SendPublication(state),
                    }))
                }
                Transition::Failed(error) => Err(error.into()),
            },
            DormantBrokerHandshakeStateV1::AwaitClientHello(state) => match state.receive() {
                Transition::Complete(state) => {
                    Ok(DormantBrokerEndpointHandshakeProgressV1::Pending(Self {
                        root: self.root,
                        state: DormantBrokerHandshakeStateV1::SendHello(state),
                    }))
                }
                Transition::Retry(state) => {
                    Ok(DormantBrokerEndpointHandshakeProgressV1::Pending(Self {
                        root: self.root,
                        state: DormantBrokerHandshakeStateV1::AwaitClientHello(state),
                    }))
                }
                Transition::Failed(error) => Err(error.into()),
            },
            DormantBrokerHandshakeStateV1::SendHello(state) => match state.send() {
                Transition::Complete(session) => {
                    Ok(DormantBrokerEndpointHandshakeProgressV1::Complete(
                        DormantAuthenticatedBrokerSessionV1::from_broker(self.root, session)?,
                    ))
                }
                Transition::Retry(state) => {
                    Ok(DormantBrokerEndpointHandshakeProgressV1::Pending(Self {
                        root: self.root,
                        state: DormantBrokerHandshakeStateV1::SendHello(state),
                    }))
                }
                Transition::Failed(error) => Err(error.into()),
            },
        }
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
}

impl DormantAuthenticatedBrokerSessionV1 {
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
        let packet = bound.payload().to_vec();
        drop(bound);
        self.owner
            .revalidate_transport(&self.transcript, self.socket.peer())?;
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

    fn from_client(
        root: &'static str,
        session: InertProvisionalClientSession,
    ) -> Result<Self, DormantBrokerSessionHandshakeErrorV1> {
        let InertProvisionalClientSession {
            _custody: custody,
            _carrier: carrier,
            _transcript: transcript,
            ..
        } = session;
        Self::from_parts(
            root,
            FixedEndpointCustodyV1::Client(custody),
            carrier,
            transcript,
        )
    }

    fn from_broker(
        root: &'static str,
        session: InertProvisionalBrokerSession,
    ) -> Result<Self, DormantBrokerSessionHandshakeErrorV1> {
        let InertProvisionalBrokerSession {
            _custody: custody,
            _carrier: carrier,
            _transcript: transcript,
            ..
        } = session;
        Self::from_parts(
            root,
            FixedEndpointCustodyV1::Broker(custody),
            carrier,
            transcript,
        )
    }

    fn from_parts(
        root: &'static str,
        custody: FixedEndpointCustodyV1,
        carrier: HandshakeCarrier,
        transcript: VerifiedBrokerSessionTranscriptV1,
    ) -> Result<Self, DormantBrokerSessionHandshakeErrorV1> {
        let socket = carrier.into_ordinary()?;
        let owner = ProtectedBrokerSessionOwnerV1::from_fixed_custody(root, custody)?;
        Ok(Self {
            owner,
            socket,
            transcript,
        })
    }

    pub(super) fn initialize_authenticated_request(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<crate::ProtectedBrokerSessionInitializationResultV1, BrokerSessionSecurityError>
    {
        self.owner
            .initialize_authenticated_request(request, &self.transcript, self.socket.peer())
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
        let (root, custody) = self.into_handshake_parts();
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
        let (root, custody) = self.into_handshake_parts();
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
