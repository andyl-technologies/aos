//! Authenticated, bounded local ownership-authority client transport.
//!
//! The caller supplies a protected socket path, authority-generation pin,
//! peer UID/GID policy, and a separately provisioned local MAC secret. Those
//! inputs are not accepted from public requests. The first two packets select
//! a fresh semantic session; every subsequent request and response is bound
//! to that transcript, its direction, and a monotonically increasing sequence.
//! A failed exchange closes the socket because a sent mutation may already
//! have reached the authority.

use std::path::Path;
use std::time::Duration;

use aos_sandbox::ownership_resume::{
    OwnershipAuthoritySessionClient, OwnershipSessionTransportError,
    UntrustedOwnershipResponsePartsV1,
};
use aos_sandbox_core::{ProtocolVersion, model::KeyReference};
use aos_sandbox_linux::seqpacket::{SeqpacketError, SeqpacketSocket};
use aos_sandbox_ownership_protocol::authenticated::{
    OwnershipRecordAuthenticatorV1, OwnershipRecordDirectionV1,
};
use aos_sandbox_ownership_protocol::carrier::{
    MAXIMUM_OWNERSHIP_HELLO_BYTES, decode_response_v1, decode_server_hello_v1,
    encode_client_hello_v1, encode_request_v1,
};
use aos_sandbox_ownership_protocol::protocol::{
    MAXIMUM_OWNERSHIP_RESPONSE_BYTES, NegotiatedOwnershipSessionV1, OwnershipClientHelloV1,
    OwnershipMethodV1, OwnershipRequestEnvelopeV1,
};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use zeroize::Zeroizing;

use crate::entropy::{KernelEntropy, nonzero_random};
use crate::production_service::production_deadline_after;

pub(crate) const METHODS: [OwnershipMethodV1; 3] = [
    OwnershipMethodV1::Begin,
    OwnershipMethodV1::CompleteOrResume,
    OwnershipMethodV1::Query,
];

/// One live, authenticated connection to the configured local authority.
pub struct LocalOwnershipAuthorityClientV1 {
    socket: SeqpacketSocket,
    session: NegotiatedOwnershipSessionV1,
    authenticator: OwnershipRecordAuthenticatorV1,
    peer_uid: u32,
    peer_gid: u32,
    deadline: Duration,
    next_sequence: u64,
}

impl LocalOwnershipAuthorityClientV1 {
    /// Connects to the protected authority endpoint and negotiates an exact session.
    ///
    /// The caller must obtain `path`, `authority`, `peer_uid`, `peer_gid`, and
    /// `secret` from protected service configuration. Credential checks are
    /// defense in depth: only the transcript-bound MAC authenticates records
    /// written through a Unix socket descriptor delegated to another process.
    ///
    /// # Errors
    ///
    /// Returns an unavailable error for a failed connection or deadline, and
    /// an integrity error for an invalid peer, handshake, or MAC configuration.
    pub fn connect(
        path: &Path,
        authority: KeyReference,
        peer_uid: u32,
        peer_gid: u32,
        secret: Zeroizing<[u8; 32]>,
        deadline: Duration,
    ) -> Result<Self, OwnershipSessionTransportError> {
        let socket = SeqpacketSocket::connect(path)
            .map_err(|_| OwnershipSessionTransportError::Unavailable)?;
        Self::negotiate(socket, authority, peer_uid, peer_gid, secret, deadline)
    }

    pub(crate) fn negotiate(
        mut socket: SeqpacketSocket,
        authority: KeyReference,
        peer_uid: u32,
        peer_gid: u32,
        secret: Zeroizing<[u8; 32]>,
        deadline: Duration,
    ) -> Result<Self, OwnershipSessionTransportError> {
        if socket.peer().credentials().uid() != peer_uid
            || socket.peer().credentials().gid() != peer_gid
        {
            return Err(OwnershipSessionTransportError::IntegrityFailure);
        }
        let until = production_deadline_after(deadline)
            .map_err(|_| OwnershipSessionTransportError::Unavailable)?;
        let nonce = nonzero_random::<32, _>(&mut KernelEntropy)
            .map_err(|_| OwnershipSessionTransportError::Unavailable)?;
        let hello = OwnershipClientHelloV1::new(
            nonce,
            ProtocolVersion::new(1, 0),
            authority,
            METHODS.to_vec(),
            MAXIMUM_OWNERSHIP_RESPONSE_BYTES,
        )
        .map_err(|_| OwnershipSessionTransportError::IntegrityFailure)?;
        send_record(&mut socket, &encode_client_hello_v1(&hello), until)?;
        let response = receive_record(
            &mut socket,
            MAXIMUM_OWNERSHIP_HELLO_BYTES,
            peer_uid,
            peer_gid,
            until,
        )?;
        let session = decode_server_hello_v1(&hello, &response)
            .map_err(|_| OwnershipSessionTransportError::IntegrityFailure)?;
        let authenticator = OwnershipRecordAuthenticatorV1::new(secret, &session)
            .map_err(|_| OwnershipSessionTransportError::IntegrityFailure)?;

        Ok(Self {
            socket,
            session,
            authenticator,
            peer_uid,
            peer_gid,
            deadline,
            next_sequence: 1,
        })
    }

    fn exchange_inner(
        &mut self,
        request: &OwnershipRequestEnvelopeV1,
    ) -> Result<UntrustedOwnershipResponsePartsV1, OwnershipSessionTransportError> {
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(OwnershipSessionTransportError::IntegrityFailure)?;
        let until = production_deadline_after(self.deadline)
            .map_err(|_| OwnershipSessionTransportError::Unavailable)?;
        let record = encode_request_v1(&self.session, request)
            .map_err(|_| OwnershipSessionTransportError::IntegrityFailure)?;
        let frame = self
            .authenticator
            .seal(
                OwnershipRecordDirectionV1::ClientToAuthority,
                self.next_sequence,
                &record,
                self.session.maximum_request_bytes(),
            )
            .map_err(|_| OwnershipSessionTransportError::IntegrityFailure)?;

        send_record(&mut self.socket, &frame, until)?;
        let response = receive_record(
            &mut self.socket,
            self.session.maximum_response_bytes() as usize,
            self.peer_uid,
            self.peer_gid,
            until,
        )?;
        let canonical = self
            .authenticator
            .open(
                OwnershipRecordDirectionV1::AuthorityToClient,
                self.next_sequence,
                &response,
                self.session.maximum_response_bytes(),
            )
            .map_err(|_| OwnershipSessionTransportError::IntegrityFailure)?;
        let decoded = decode_response_v1(&self.session, request, canonical)
            .map_err(|_| OwnershipSessionTransportError::IntegrityFailure)?;
        self.next_sequence = next_sequence;

        Ok(UntrustedOwnershipResponsePartsV1::new(
            *decoded.session_binding(),
            decoded.method(),
            decoded.transaction(),
            decoded.outcome().clone(),
        ))
    }
}

impl OwnershipAuthoritySessionClient for LocalOwnershipAuthorityClientV1 {
    fn session(&self) -> &NegotiatedOwnershipSessionV1 {
        &self.session
    }

    fn exchange(
        &mut self,
        request: &OwnershipRequestEnvelopeV1,
    ) -> Result<UntrustedOwnershipResponsePartsV1, OwnershipSessionTransportError> {
        let result = self.exchange_inner(request);
        if result.is_err() {
            self.socket.close();
        }
        result
    }
}

pub(crate) fn send_record(
    socket: &mut SeqpacketSocket,
    payload: &[u8],
    until: u64,
) -> Result<(), OwnershipSessionTransportError> {
    loop {
        match socket.send(payload) {
            Ok(()) => return Ok(()),
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                wait_ready(socket, PollFlags::OUT, until)?;
            }
            Err(_) => return Err(OwnershipSessionTransportError::Unavailable),
        }
    }
}

pub(crate) fn receive_record(
    socket: &mut SeqpacketSocket,
    maximum_bytes: usize,
    peer_uid: u32,
    peer_gid: u32,
    until: u64,
) -> Result<Vec<u8>, OwnershipSessionTransportError> {
    loop {
        match socket.receive(maximum_bytes) {
            Ok(record) => {
                let bound = socket
                    .bind_received(record)
                    .map_err(|_| OwnershipSessionTransportError::IntegrityFailure)?;
                let credentials = bound.subject().credentials();
                if credentials.uid() != peer_uid || credentials.gid() != peer_gid {
                    return Err(OwnershipSessionTransportError::IntegrityFailure);
                }
                return Ok(bound.payload().to_vec());
            }
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                wait_ready(socket, PollFlags::IN, until)?;
            }
            Err(SeqpacketError::RecordTooLarge { .. }) => {
                return Err(OwnershipSessionTransportError::IntegrityFailure);
            }
            Err(SeqpacketError::Closed | SeqpacketError::Kernel(_)) => {
                return Err(OwnershipSessionTransportError::Unavailable);
            }
            Err(_) => return Err(OwnershipSessionTransportError::IntegrityFailure),
        }
    }
}

fn wait_ready(
    socket: &SeqpacketSocket,
    interest: PollFlags,
    until: u64,
) -> Result<(), OwnershipSessionTransportError> {
    let now = production_deadline_after(Duration::ZERO)
        .map_err(|_| OwnershipSessionTransportError::Unavailable)?;
    let remaining = until
        .checked_sub(now)
        .filter(|remaining| *remaining != 0)
        .ok_or(OwnershipSessionTransportError::Unavailable)?;
    let timeout = Timespec::try_from(Duration::from_nanos(remaining))
        .map_err(|_| OwnershipSessionTransportError::Unavailable)?;
    let fd = socket
        .as_fd()
        .map_err(|_| OwnershipSessionTransportError::Unavailable)?;
    let mut descriptors = [PollFd::new(&fd, interest)];
    match poll(&mut descriptors, Some(&timeout)) {
        Ok(0) => Err(OwnershipSessionTransportError::Unavailable),
        // A peer may close immediately after sending its last record, leaving
        // readable data and HUP set together. Read the queued record first.
        Ok(_) if descriptors[0].revents().contains(interest) => Ok(()),
        Ok(_) => Err(OwnershipSessionTransportError::Unavailable),
        Err(rustix::io::Errno::INTR) => Ok(()),
        Err(_) => Err(OwnershipSessionTransportError::Unavailable),
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use aos_sandbox_core::{
        ObjectDigest,
        model::{KeyUsage, StableKeyId},
    };
    use aos_sandbox_ownership_protocol::authenticated::OwnershipRecordDirectionV1;
    use aos_sandbox_ownership_protocol::carrier::{
        decode_client_hello_v1, decode_request_v1, encode_response_v1, encode_server_hello_v1,
    };
    use aos_sandbox_ownership_protocol::protocol::{
        OwnershipRequestBodyV1, OwnershipResponseOutcomeV1, OwnershipTransactionReferenceV1,
        OwnershipTransactionStatusV1,
    };

    use super::*;

    fn authority() -> KeyReference {
        let id = StableKeyId::new("test-ownership-authority".to_owned())
            .unwrap_or_else(|error| panic!("test authority ID failed: {error}"));
        KeyReference::new(
            id,
            1,
            ObjectDigest::from_bytes([7; 32]),
            KeyUsage::OwnershipLease,
        )
    }

    fn run_exchange(
        tamper_response: bool,
    ) -> Result<(UntrustedOwnershipResponsePartsV1, [u8; 32]), OwnershipSessionTransportError> {
        let (socket, endpoint) = SeqpacketSocket::pair_with_record_subjects()
            .unwrap_or_else(|error| panic!("test socket pair failed: {error}"));
        let uid = socket.peer().credentials().uid();
        let gid = socket.peer().credentials().gid();
        let authority = authority();
        let server_authority = authority.clone();
        let server = thread::spawn(move || {
            let mut socket = SeqpacketSocket::from_owned(endpoint)
                .unwrap_or_else(|error| panic!("test server adoption failed: {error}"));
            let until = production_deadline_after(Duration::from_secs(5))
                .unwrap_or_else(|error| panic!("test deadline failed: {error}"));
            let client_hello =
                receive_record(&mut socket, MAXIMUM_OWNERSHIP_HELLO_BYTES, uid, gid, until)
                    .unwrap_or_else(|error| panic!("test client hello receipt failed: {error}"));
            let hello = decode_client_hello_v1(&client_hello)
                .unwrap_or_else(|error| panic!("test client hello decode failed: {error}"));
            let session = NegotiatedOwnershipSessionV1::negotiate(
                &hello,
                [12; 32],
                server_authority,
                METHODS.to_vec(),
            )
            .unwrap_or_else(|error| panic!("test session negotiation failed: {error}"));
            let server_hello = encode_server_hello_v1(&hello, [12; 32], &session)
                .unwrap_or_else(|error| panic!("test server hello encoding failed: {error}"));
            send_record(&mut socket, &server_hello, until)
                .unwrap_or_else(|error| panic!("test server hello delivery failed: {error}"));

            let request_frame = receive_record(
                &mut socket,
                session.maximum_request_bytes() as usize,
                uid,
                gid,
                until,
            )
            .unwrap_or_else(|error| panic!("test request receipt failed: {error}"));
            let authenticator =
                OwnershipRecordAuthenticatorV1::new(Zeroizing::new([9; 32]), &session)
                    .unwrap_or_else(|error| panic!("test authenticator failed: {error}"));
            let canonical = authenticator
                .open(
                    OwnershipRecordDirectionV1::ClientToAuthority,
                    1,
                    &request_frame,
                    session.maximum_request_bytes(),
                )
                .unwrap_or_else(|error| panic!("test request authentication failed: {error}"));
            let request = decode_request_v1(&session, canonical)
                .unwrap_or_else(|error| panic!("test request decoding failed: {error}"));
            let response = session
                .response(
                    &request,
                    OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Absent),
                )
                .unwrap_or_else(|error| panic!("test response construction failed: {error}"));
            let canonical = encode_response_v1(&session, &request, &response)
                .unwrap_or_else(|error| panic!("test response encoding failed: {error}"));
            let mut response_frame = authenticator
                .seal(
                    OwnershipRecordDirectionV1::AuthorityToClient,
                    1,
                    &canonical,
                    session.maximum_response_bytes(),
                )
                .unwrap_or_else(|error| panic!("test response authentication failed: {error}"));
            if tamper_response {
                let last = response_frame.len() - 1;
                response_frame[last] ^= 1;
            }
            send_record(&mut socket, &response_frame, until)
                .unwrap_or_else(|error| panic!("test response delivery failed: {error}"));
        });

        let mut client = LocalOwnershipAuthorityClientV1::negotiate(
            socket,
            authority,
            uid,
            gid,
            Zeroizing::new([9; 32]),
            Duration::from_secs(5),
        )?;
        let transaction =
            OwnershipTransactionReferenceV1::new([3; 16], ObjectDigest::from_bytes([4; 32]))
                .unwrap_or_else(|error| panic!("test transaction failed: {error}"));
        let request = client
            .session()
            .request(OwnershipRequestBodyV1::Query(transaction))
            .unwrap_or_else(|error| panic!("test request construction failed: {error}"));
        let binding = *client.session().binding();
        let result = client.exchange(&request);
        server
            .join()
            .unwrap_or_else(|_| panic!("test server thread panicked"));
        result.map(|response| (response, binding))
    }

    #[test]
    fn authenticated_query_crosses_bounded_socket() {
        let (response, binding) =
            run_exchange(false).unwrap_or_else(|error| panic!("test query failed: {error}"));
        assert_eq!(
            response,
            UntrustedOwnershipResponsePartsV1::new(
                binding,
                OwnershipMethodV1::Query,
                OwnershipTransactionReferenceV1::new([3; 16], ObjectDigest::from_bytes([4; 32]),)
                    .unwrap_or_else(|error| panic!("test transaction failed: {error}")),
                OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Absent),
            ),
        );
    }

    #[test]
    fn altered_mac_fails_closed() {
        assert_eq!(
            run_exchange(true),
            Err(OwnershipSessionTransportError::IntegrityFailure),
        );
    }

    #[test]
    fn queued_record_remains_readable_after_peer_hangup() {
        let (mut receiver, endpoint) = SeqpacketSocket::pair_with_record_subjects()
            .unwrap_or_else(|error| panic!("test socket pair failed: {error}"));
        let uid = receiver.peer().credentials().uid();
        let gid = receiver.peer().credentials().gid();
        let mut sender = SeqpacketSocket::from_owned(endpoint)
            .unwrap_or_else(|error| panic!("test sender adoption failed: {error}"));
        sender
            .send(b"last record")
            .unwrap_or_else(|error| panic!("test record send failed: {error}"));
        drop(sender);

        let until = production_deadline_after(Duration::from_secs(1))
            .unwrap_or_else(|error| panic!("test deadline failed: {error}"));
        let record = receive_record(&mut receiver, 64, uid, gid, until)
            .unwrap_or_else(|error| panic!("queued record was lost: {error}"));
        assert_eq!(record, b"last record");
    }
}
