//! Shares the local authority's handshake, MAC and sequence state.
//!
//! This owner interprets canonical records only. It never admits a socket,
//! authenticates a process, reserves resources or authorizes lease issuance.
//! The transport owns native outcomes and advances only after actual delivery.

use aos_sandbox_core::model::KeyReference;
use zeroize::Zeroizing;

use crate::authenticated::{OwnershipRecordAuthenticationErrorV1, OwnershipRecordAuthenticatorV1,
    OwnershipRecordDirectionV1};
use crate::carrier::{OwnershipCarrierErrorV1, decode_request_v1,
    encode_response_v1, encode_server_hello_v1};
use crate::protocol::{NegotiatedOwnershipSessionV1, OwnershipClientHelloV1, OwnershipMethodV1,
    OwnershipProtocolValidationError, OwnershipRequestEnvelopeV1,
    OwnershipResponseEnvelopeV1, OwnershipTransactionReferenceV1};

/// Lists the canonical methods served by the local authority.
pub const LOCAL_AUTHORITY_METHODS_V1: [OwnershipMethodV1; 3] = [
    OwnershipMethodV1::Begin, OwnershipMethodV1::CompleteOrResume, OwnershipMethodV1::Query,
];

/// Reports exact semantic failure without replacing a transport's native cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuthorityRecordErrorV1 {
    /// The canonical record parser refused the bytes.
    #[error(transparent)]
    Carrier(#[from] OwnershipCarrierErrorV1),
    /// The original transcript MAC or record sequence is invalid.
    #[error(transparent)]
    Authentication(#[from] OwnershipRecordAuthenticationErrorV1),
    /// The semantic handshake or request binding is invalid.
    #[error(transparent)]
    Protocol(#[from] OwnershipProtocolValidationError),
    /// The semantic exchange has failed or is already awaiting a response.
    #[error("the ownership record exchange is closed or incomplete")]
    Closed,
}

/// Holds one exact negotiated transcript and its outstanding request.
///
/// Native observation, funding and delivery remain the transport's obligations.
/// A successful DATA transition cannot prove that any socket sent bytes.
pub struct AuthorityRecordStateV1 {
    session: NegotiatedOwnershipSessionV1,
    authenticator: OwnershipRecordAuthenticatorV1,
    next_sequence: u64,
    pending: Option<(OwnershipMethodV1, OwnershipTransactionReferenceV1)>,
    encoded: bool,
    first_error: Option<AuthorityRecordErrorV1>,
}

impl AuthorityRecordStateV1 {
    /// Negotiates the existing fixed local contract and encodes its server hello.
    ///
    /// # Errors
    /// Returns the original canonical, protocol or MAC-configuration error.
    pub fn negotiate(
        hello: &OwnershipClientHelloV1, server_nonce: [u8; 32], authority: KeyReference,
        secret: Zeroizing<[u8; 32]>,
    ) -> Result<(Self, Vec<u8>), AuthorityRecordErrorV1> {
        let session = NegotiatedOwnershipSessionV1::negotiate(
            hello, server_nonce, authority, LOCAL_AUTHORITY_METHODS_V1.to_vec(),
        )?;
        let authenticator = OwnershipRecordAuthenticatorV1::new(secret, &session)?;
        let server_record = encode_server_hello_v1(hello, server_nonce, &session)?;
        Ok((Self { session, authenticator, next_sequence: 1, pending: None,
            encoded: false, first_error: None }, server_record))
    }

    /// Borrows the exact negotiated contract without granting process identity.
    #[must_use]
    pub const fn session(&self) -> &NegotiatedOwnershipSessionV1 { &self.session }

    /// Checks sequence capacity before the transport observes another request.
    ///
    /// # Errors
    /// Returns the retained first refusal or rejects an unfinished exchange.
    pub fn require_request_slot(&self) -> Result<(), AuthorityRecordErrorV1> {
        if let Some(error) = self.first_error { return Err(error); }
        if self.pending.is_some() || self.next_sequence.checked_add(1).is_none() {
            return Err(AuthorityRecordErrorV1::Closed);
        }
        Ok(())
    }

    /// Authenticates and decodes one request under the unchanged sequence.
    ///
    /// # Errors
    /// Retains the first MAC, framing, semantic or outstanding-request refusal.
    pub fn open_request(&mut self, frame: &[u8]) -> Result<OwnershipRequestEnvelopeV1, AuthorityRecordErrorV1> {
        let observed = (|| {
            self.require_request_slot()?;
            let canonical = self.authenticator.open(OwnershipRecordDirectionV1::ClientToAuthority,
                self.next_sequence, frame, self.session.maximum_request_bytes())?;
            Ok::<_, AuthorityRecordErrorV1>(decode_request_v1(&self.session, canonical)?)
        })();
        match observed {
            Ok(request) => {
                self.pending = Some((request.method(), request.transaction()));
                Ok(request)
            }
            Err(error) => Err(self.fail(error)),
        }
    }

    /// Encodes one response for the exact outstanding request without advancing.
    ///
    /// # Errors
    /// Retains substitution, replay, canonical response or MAC refusal.
    pub fn encode_response(
        &mut self, request: &OwnershipRequestEnvelopeV1, response: &OwnershipResponseEnvelopeV1,
    ) -> Result<Vec<u8>, AuthorityRecordErrorV1> {
        let observed = (|| {
            if self.first_error.is_some() || self.encoded ||
                self.pending != Some((request.method(), request.transaction())) {
                return Err(AuthorityRecordErrorV1::Closed);
            }
            let canonical = encode_response_v1(&self.session, request, response)?;
            Ok(self.authenticator.seal(OwnershipRecordDirectionV1::AuthorityToClient,
                self.next_sequence, &canonical, self.session.maximum_response_bytes())?)
        })();
        match observed {
            Ok(frame) => { self.encoded = true; Ok(frame) }
            Err(error) => Err(self.fail(error)),
        }
    }

    /// Advances semantic order after the transport's actual successful delivery.
    ///
    /// This records DATA supplied by the transport and proves no native result.
    /// Genuine paid adapters invoke it only after their own retained send/posts.
    ///
    /// # Errors
    /// Refuses missing encoding, reentry, prior failure or sequence exhaustion.
    pub fn response_sent(&mut self) -> Result<(), AuthorityRecordErrorV1> {
        if self.first_error.is_some() || !self.encoded || self.pending.is_none() {
            return Err(self.fail(AuthorityRecordErrorV1::Closed));
        }
        let Some(next) = self.next_sequence.checked_add(1) else {
            return Err(self.fail(AuthorityRecordErrorV1::Closed));
        };
        self.next_sequence = next;
        self.pending = None;
        self.encoded = false;
        Ok(())
    }

    fn fail(&mut self, error: AuthorityRecordErrorV1) -> AuthorityRecordErrorV1 {
        *self.first_error.get_or_insert(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::{ObjectDigest, ProtocolVersion, model::{KeyUsage, StableKeyId}};
    use crate::carrier::{encode_request_v1, decode_response_v1};
    use crate::protocol::{MAXIMUM_OWNERSHIP_RESPONSE_BYTES, OwnershipRequestBodyV1,
        OwnershipResponseOutcomeV1, OwnershipTransactionStatusV1};

    fn negotiated() -> (AuthorityRecordStateV1, OwnershipRecordAuthenticatorV1) {
        let authority = KeyReference::new(StableKeyId::new("local-ownership-test".into()).unwrap(),
            1, ObjectDigest::from_bytes([7; 32]), KeyUsage::OwnershipLease);
        let hello = OwnershipClientHelloV1::new([2; 32], ProtocolVersion::new(1, 0),
            authority.clone(), LOCAL_AUTHORITY_METHODS_V1.to_vec(), MAXIMUM_OWNERSHIP_RESPONSE_BYTES).unwrap();
        let (server, _) = AuthorityRecordStateV1::negotiate(&hello, [3; 32], authority,
            Zeroizing::new([4; 32])).unwrap();
        let client = OwnershipRecordAuthenticatorV1::new(Zeroizing::new([4; 32]), server.session()).unwrap();
        (server, client)
    }

    #[test]
    fn encoded_response_keeps_sequence_outstanding_until_actual_transport_advancement() {
        let (mut server, client) = negotiated();
        let reference = OwnershipTransactionReferenceV1::new([5; 16], ObjectDigest::from_bytes([6; 32])).unwrap();
        let request = server.session().request(OwnershipRequestBodyV1::Query(reference)).unwrap();
        let canonical = encode_request_v1(server.session(), &request).unwrap();
        let first = client.seal(OwnershipRecordDirectionV1::ClientToAuthority, 1, &canonical,
            server.session().maximum_request_bytes()).unwrap();
        let observed = server.open_request(&first).unwrap();
        let response = server.session().response(&observed,
            OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Pending)).unwrap();

        let encoded = server.encode_response(&observed, &response).unwrap();
        assert!(server.require_request_slot().is_err());
        let canonical_response = client.open(OwnershipRecordDirectionV1::AuthorityToClient,
            1, &encoded, server.session().maximum_response_bytes()).unwrap();
        assert_eq!(decode_response_v1(server.session(), &observed, canonical_response).unwrap(), response);

        server.response_sent().unwrap();
        let second = client.seal(OwnershipRecordDirectionV1::ClientToAuthority, 2, &canonical,
            server.session().maximum_request_bytes()).unwrap();
        assert_eq!(server.open_request(&second).unwrap(), request);
    }

    #[test]
    fn bad_mac_stays_closed_even_when_the_original_frame_is_reoffered() {
        let (mut server, client) = negotiated();
        let reference = OwnershipTransactionReferenceV1::new([5; 16], ObjectDigest::from_bytes([6; 32])).unwrap();
        let request = server.session().request(OwnershipRequestBodyV1::Query(reference)).unwrap();
        let canonical = encode_request_v1(server.session(), &request).unwrap();
        let original = client.seal(OwnershipRecordDirectionV1::ClientToAuthority, 1, &canonical,
            server.session().maximum_request_bytes()).unwrap();
        let mut substituted = original.clone();
        *substituted.last_mut().unwrap() ^= 1;

        let first = server.open_request(&substituted).unwrap_err();
        assert_eq!(server.open_request(&original).unwrap_err(), first);
        assert_eq!(server.require_request_slot().unwrap_err(), first);
        assert_eq!(server.response_sent().unwrap_err(), first);
    }
}
