//! Authenticated local carrier for the durable ownership-authority service.
//!
//! A protected service owns the accepted socket, authority-generation pin,
//! controller UID/GID policy, and MAC secret. The first two records negotiate
//! a fresh exact session; subsequent records must authenticate before a
//! request reaches the durable authority. This adapter does not create a
//! listener or load credentials. Production activation must supply both from
//! protected service configuration.

use std::time::Duration;

use aos_sandbox::ownership_service::OwnershipProtocolRequestHandler;
use aos_sandbox_core::model::KeyReference;
use aos_sandbox_linux::seqpacket::SeqpacketSocket;
use aos_sandbox_ownership_protocol::authenticated::{
    OwnershipRecordAuthenticatorV1, OwnershipRecordDirectionV1,
};
use aos_sandbox_ownership_protocol::carrier::{
    MAXIMUM_OWNERSHIP_HELLO_BYTES, decode_client_hello_v1, decode_request_v1, encode_response_v1,
    encode_server_hello_v1,
};
use aos_sandbox_ownership_protocol::protocol::NegotiatedOwnershipSessionV1;
use zeroize::Zeroizing;

use crate::entropy::{KernelEntropy, nonzero_random};
use crate::ownership_authority_client::{METHODS, receive_record, send_record};
use crate::production_service::production_deadline_after;

/// Reports an unavailable carrier or a fail-closed authentication failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LocalOwnershipAuthorityServerErrorV1 {
    /// The socket, entropy source, deadline, or delivery failed.
    #[error("local ownership-authority carrier is unavailable")]
    Unavailable,
    /// Peer identity, authentication, framing, or service binding failed.
    #[error("local ownership-authority carrier integrity failed")]
    IntegrityFailure,
}

impl From<aos_sandbox::OwnershipSessionTransportError> for LocalOwnershipAuthorityServerErrorV1 {
    fn from(error: aos_sandbox::OwnershipSessionTransportError) -> Self {
        match error {
            aos_sandbox::OwnershipSessionTransportError::Unavailable => Self::Unavailable,
            aos_sandbox::OwnershipSessionTransportError::IntegrityFailure => Self::IntegrityFailure,
        }
    }
}

/// One accepted, authenticated authority connection with ordered records.
pub struct LocalOwnershipAuthorityServerV1 {
    socket: SeqpacketSocket,
    session: NegotiatedOwnershipSessionV1,
    authenticator: OwnershipRecordAuthenticatorV1,
    peer_uid: u32,
    peer_gid: u32,
    deadline: Duration,
    next_sequence: u64,
}

impl LocalOwnershipAuthorityServerV1 {
    /// Negotiates one accepted socket against protected service configuration.
    ///
    /// The local MAC secret must be provisioned outside the socket and must
    /// never be taken from the client hello or a public request. UID/GID
    /// checks reject mismatched nominated subjects, but only the MAC proves
    /// application authorship after Unix descriptor delegation.
    ///
    /// # Errors
    ///
    /// Returns an unavailable error for carrier failure and an integrity
    /// error for peer, handshake, or authentication-configuration mismatch.
    pub fn from_accepted(
        mut socket: SeqpacketSocket,
        authority: KeyReference,
        peer_uid: u32,
        peer_gid: u32,
        secret: Zeroizing<[u8; 32]>,
        deadline: Duration,
    ) -> Result<Self, LocalOwnershipAuthorityServerErrorV1> {
        if socket.peer().credentials().uid() != peer_uid
            || socket.peer().credentials().gid() != peer_gid
        {
            return Err(LocalOwnershipAuthorityServerErrorV1::IntegrityFailure);
        }
        let until = production_deadline_after(deadline)
            .map_err(|_| LocalOwnershipAuthorityServerErrorV1::Unavailable)?;
        let client_record = receive_record(
            &mut socket,
            MAXIMUM_OWNERSHIP_HELLO_BYTES,
            peer_uid,
            peer_gid,
            until,
        )?;
        let hello = decode_client_hello_v1(&client_record)
            .map_err(|_| LocalOwnershipAuthorityServerErrorV1::IntegrityFailure)?;
        let nonce = nonzero_random::<32, _>(&mut KernelEntropy)
            .map_err(|_| LocalOwnershipAuthorityServerErrorV1::Unavailable)?;
        let session =
            NegotiatedOwnershipSessionV1::negotiate(&hello, nonce, authority, METHODS.to_vec())
                .map_err(|_| LocalOwnershipAuthorityServerErrorV1::IntegrityFailure)?;
        let authenticator = OwnershipRecordAuthenticatorV1::new(secret, &session)
            .map_err(|_| LocalOwnershipAuthorityServerErrorV1::IntegrityFailure)?;
        let server_record = encode_server_hello_v1(&hello, nonce, &session)
            .map_err(|_| LocalOwnershipAuthorityServerErrorV1::IntegrityFailure)?;
        send_record(&mut socket, &server_record, until)?;

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

    /// Returns the exact negotiated semantic contract for this connection.
    #[must_use]
    pub const fn session(&self) -> &NegotiatedOwnershipSessionV1 {
        &self.session
    }

    /// Authenticates and dispatches one request to the durable authority.
    ///
    /// The handler must have been constructed for this same negotiated
    /// session. A transport failure after durable dispatch leaves the client
    /// to query the exact transaction on a new authenticated connection.
    /// Every failure closes this socket; no sequence may be reused afterward.
    ///
    /// # Errors
    ///
    /// Returns an unavailable error for delivery or deadline failure and an
    /// integrity error for record, sequence, or service-contract mismatch.
    pub fn serve_one<H>(
        &mut self,
        handler: &mut H,
    ) -> Result<(), LocalOwnershipAuthorityServerErrorV1>
    where
        H: OwnershipProtocolRequestHandler,
    {
        let result = self.serve_one_inner(handler);
        if result.is_err() {
            self.socket.close();
        }
        result
    }

    fn serve_one_inner<H>(
        &mut self,
        handler: &mut H,
    ) -> Result<(), LocalOwnershipAuthorityServerErrorV1>
    where
        H: OwnershipProtocolRequestHandler,
    {
        if handler.authority() != self.session.authority() {
            return Err(LocalOwnershipAuthorityServerErrorV1::IntegrityFailure);
        }
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(LocalOwnershipAuthorityServerErrorV1::IntegrityFailure)?;
        let until = production_deadline_after(self.deadline)
            .map_err(|_| LocalOwnershipAuthorityServerErrorV1::Unavailable)?;
        let frame = receive_record(
            &mut self.socket,
            self.session.maximum_request_bytes() as usize,
            self.peer_uid,
            self.peer_gid,
            until,
        )?;
        let canonical = self
            .authenticator
            .open(
                OwnershipRecordDirectionV1::ClientToAuthority,
                self.next_sequence,
                &frame,
                self.session.maximum_request_bytes(),
            )
            .map_err(|_| LocalOwnershipAuthorityServerErrorV1::IntegrityFailure)?;
        let request = decode_request_v1(&self.session, canonical)
            .map_err(|_| LocalOwnershipAuthorityServerErrorV1::IntegrityFailure)?;

        let response = handler
            .handle(&self.session, &request)
            .map_err(|_| LocalOwnershipAuthorityServerErrorV1::IntegrityFailure)?;
        let canonical = encode_response_v1(&self.session, &request, &response)
            .map_err(|_| LocalOwnershipAuthorityServerErrorV1::IntegrityFailure)?;
        let frame = self
            .authenticator
            .seal(
                OwnershipRecordDirectionV1::AuthorityToClient,
                self.next_sequence,
                &canonical,
                self.session.maximum_response_bytes(),
            )
            .map_err(|_| LocalOwnershipAuthorityServerErrorV1::IntegrityFailure)?;
        send_record(&mut self.socket, &frame, until)?;
        self.next_sequence = next_sequence;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use aos_sandbox::ownership_resume::{
        OwnershipAuthoritySessionClient, UntrustedOwnershipResponsePartsV1,
    };
    use aos_sandbox::ownership_service::OwnershipProtocolServiceError;
    use aos_sandbox_core::{
        ObjectDigest,
        model::{KeyUsage, StableKeyId},
    };
    use aos_sandbox_ownership_protocol::protocol::{
        OwnershipRequestBodyV1, OwnershipRequestEnvelopeV1, OwnershipResponseEnvelopeV1,
        OwnershipResponseOutcomeV1, OwnershipTransactionReferenceV1, OwnershipTransactionStatusV1,
    };

    use super::*;
    use crate::ownership_authority_client::LocalOwnershipAuthorityClientV1;

    struct QueryOnlyHandler {
        authority: KeyReference,
        calls: usize,
    }

    impl OwnershipProtocolRequestHandler for QueryOnlyHandler {
        fn authority(&self) -> &KeyReference {
            &self.authority
        }

        fn handle(
            &mut self,
            session: &NegotiatedOwnershipSessionV1,
            request: &OwnershipRequestEnvelopeV1,
        ) -> Result<OwnershipResponseEnvelopeV1, OwnershipProtocolServiceError> {
            self.calls += 1;
            session
                .response(
                    request,
                    OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Absent),
                )
                .map_err(OwnershipProtocolServiceError::Protocol)
        }
    }

    fn authority() -> KeyReference {
        KeyReference::new(
            StableKeyId::new("test-ownership-authority".to_owned())
                .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
            3,
            ObjectDigest::from_bytes([7; 32]),
            KeyUsage::OwnershipLease,
        )
    }

    #[test]
    fn accepted_socket_negotiates_the_client_session() {
        let (client_socket, server_endpoint) = SeqpacketSocket::pair_with_record_subjects()
            .unwrap_or_else(|error| panic!("test socket pair failed: {error}"));
        let uid = client_socket.peer().credentials().uid();
        let gid = client_socket.peer().credentials().gid();
        let authority = authority();
        let server_authority = authority.clone();
        let server = thread::spawn(move || {
            let socket = SeqpacketSocket::from_owned(server_endpoint)
                .unwrap_or_else(|error| panic!("test server socket adoption failed: {error}"));
            let server = LocalOwnershipAuthorityServerV1::from_accepted(
                socket,
                server_authority,
                uid,
                gid,
                Zeroizing::new([9; 32]),
                Duration::from_secs(5),
            )
            .unwrap_or_else(|error| panic!("test server negotiation failed: {error}"));
            server.session().clone()
        });
        let client = LocalOwnershipAuthorityClientV1::negotiate(
            client_socket,
            authority,
            uid,
            gid,
            Zeroizing::new([9; 32]),
            Duration::from_secs(5),
        )
        .unwrap_or_else(|error| panic!("test client negotiation failed: {error}"));
        let server_session = server
            .join()
            .unwrap_or_else(|_| panic!("test server thread panicked"));
        assert_eq!(client.session(), &server_session);
    }

    fn serve_query(
        client_secret: [u8; 32],
    ) -> (
        Result<UntrustedOwnershipResponsePartsV1, aos_sandbox::OwnershipSessionTransportError>,
        Result<(), LocalOwnershipAuthorityServerErrorV1>,
        usize,
        [u8; 32],
    ) {
        let (client_socket, server_endpoint) = SeqpacketSocket::pair_with_record_subjects()
            .unwrap_or_else(|error| panic!("test socket pair failed: {error}"));
        let uid = client_socket.peer().credentials().uid();
        let gid = client_socket.peer().credentials().gid();
        let authority = authority();
        let server_authority = authority.clone();
        let server = thread::spawn(move || {
            let socket = SeqpacketSocket::from_owned(server_endpoint)
                .unwrap_or_else(|error| panic!("test server socket adoption failed: {error}"));
            let mut server = LocalOwnershipAuthorityServerV1::from_accepted(
                socket,
                server_authority.clone(),
                uid,
                gid,
                Zeroizing::new([9; 32]),
                Duration::from_secs(5),
            )
            .unwrap_or_else(|error| panic!("test server negotiation failed: {error}"));
            let mut handler = QueryOnlyHandler {
                authority: server_authority,
                calls: 0,
            };
            let result = server.serve_one(&mut handler);
            (result, handler.calls)
        });
        let mut client = LocalOwnershipAuthorityClientV1::negotiate(
            client_socket,
            authority,
            uid,
            gid,
            Zeroizing::new(client_secret),
            Duration::from_secs(5),
        )
        .unwrap_or_else(|error| panic!("test client negotiation failed: {error}"));
        let binding = *client.session().binding();
        let transaction =
            OwnershipTransactionReferenceV1::new([3; 16], ObjectDigest::from_bytes([4; 32]))
                .unwrap_or_else(|error| panic!("test transaction failed: {error}"));
        let request = client
            .session()
            .request(OwnershipRequestBodyV1::Query(transaction))
            .unwrap_or_else(|error| panic!("test request failed: {error}"));
        let response = client.exchange(&request);
        let (server_result, calls) = server
            .join()
            .unwrap_or_else(|_| panic!("test server thread panicked"));
        (response, server_result, calls, binding)
    }

    #[test]
    fn authenticated_query_reaches_the_handler() {
        let (response, server_result, calls, binding) = serve_query([9; 32]);
        assert_eq!(server_result, Ok(()));
        assert_eq!(calls, 1);
        assert_eq!(
            response,
            Ok(UntrustedOwnershipResponsePartsV1::new(
                binding,
                aos_sandbox_ownership_protocol::protocol::OwnershipMethodV1::Query,
                OwnershipTransactionReferenceV1::new([3; 16], ObjectDigest::from_bytes([4; 32]),)
                    .unwrap_or_else(|error| panic!("test transaction failed: {error}")),
                OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Absent),
            )),
        );
    }

    #[test]
    fn wrong_client_mac_never_reaches_the_handler() {
        let (_, server_result, calls, _) = serve_query([8; 32]);
        assert_eq!(
            server_result,
            Err(LocalOwnershipAuthorityServerErrorV1::IntegrityFailure),
        );
        assert_eq!(calls, 0);
    }
}
