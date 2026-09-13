//! Sealed, production-unreachable authenticated hello-flight composition.
//!
//! This module owns the exact connected socket across publication, ClientHello,
//! and BrokerHello. Every receive is immediately bound back to that socket,
//! and every transition rechecks protected custody plus retained pidfd evidence.
//! The resulting provisional transcript is deliberately private and grants no
//! peer, transport, descriptor, or effect authority. Protected peer/MAC policy
//! remains a prerequisite for any production entry point.

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

use crate::{
    BrokerSessionSecurityError, ProtectedBrokerSessionBrokerV1, ProtectedBrokerSessionClientV1,
};

/// Keeps the unreachable composition compiled without implying a public path.
#[allow(
    dead_code,
    reason = "P0-10 keeps this sealed handshake production-unreachable"
)]
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
    Transport,
}

impl core::fmt::Debug for HandshakeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Local(error) => formatter.debug_tuple("Local").field(error).finish(),
            Self::RemoteInvalid => formatter.write_str("RemoteInvalid"),
            Self::KernelEvidence => formatter.write_str("KernelEvidence"),
            Self::Transport => formatter.write_str("Transport"),
        }
    }
}

impl HandshakeError {
    fn transport(error: SeqpacketError) -> Self {
        match error {
            SeqpacketError::WouldBlock | SeqpacketError::Interrupted => Self::Transport,
            _ => Self::RemoteInvalid,
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
            Err(HandshakeError::Transport) => return Transition::Retry(self),
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
            Err(HandshakeError::Transport) => return Transition::Retry(self),
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
            Err(HandshakeError::Transport) => return Transition::Retry(self),
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

#[allow(
    dead_code,
    reason = "P0-10 keeps the sealed traffic proof production-unreachable"
)]
mod traffic;

#[cfg(test)]
mod tests;
