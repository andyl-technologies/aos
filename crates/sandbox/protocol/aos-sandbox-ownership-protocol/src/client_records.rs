//! Shares client transcript, canonical MAC and sequence mechanics.
//!
//! These transitions interpret supplied bytes only. The actual transport owns
//! authentication, funding, whole native results and response-currentness posts.

use zeroize::Zeroizing;
use crate::authenticated::{OwnershipRecordAuthenticatorV1, OwnershipRecordDirectionV1};
use crate::authority_records::AuthorityRecordErrorV1;
use crate::carrier::{decode_response_v1, decode_server_hello_v1, encode_request_v1};
use crate::protocol::{NegotiatedOwnershipSessionV1, OwnershipClientHelloV1,
    OwnershipMethodV1, OwnershipRequestEnvelopeV1, OwnershipResponseEnvelopeV1,
    OwnershipTransactionReferenceV1};

/// Keeps one client transcript and its exact outstanding record sequence.
///
/// A completed DATA transition supplies no process identity, paid observation
/// or lease authority. Failed state remains closed even on exact-byte retry.
pub struct OwnershipClientRecordStateV1 {
    session: NegotiatedOwnershipSessionV1,
    authenticator: OwnershipRecordAuthenticatorV1,
    next_sequence: u64,
    pending: Option<(OwnershipMethodV1, OwnershipTransactionReferenceV1)>,
    response_opened: bool,
    first: Option<AuthorityRecordErrorV1>,
}

impl OwnershipClientRecordStateV1 {
    /// Validates the existing server hello and binds the provisioned MAC secret.
    ///
    /// # Errors
    /// Returns the exact canonical/semantic or MAC-configuration refusal.
    pub fn negotiate(hello: &OwnershipClientHelloV1, server_record: &[u8],
        secret: Zeroizing<[u8; 32]>) -> Result<Self, AuthorityRecordErrorV1> {
        let session = decode_server_hello_v1(hello, server_record)?;
        let authenticator = OwnershipRecordAuthenticatorV1::new(secret, &session)?;
        Ok(Self { session, authenticator, next_sequence: 1, pending: None,
            response_opened: false, first: None })
    }

    /// Borrows the exact negotiated semantic contract.
    #[must_use]
    pub const fn session(&self) -> &NegotiatedOwnershipSessionV1 { &self.session }

    /// Checks outstanding order before transport deadline or record work.
    ///
    /// # Errors
    /// Returns a retained failure, unfinished request or exhausted sequence.
    pub fn require_request_slot(&self) -> Result<(), AuthorityRecordErrorV1> {
        if let Some(cause) = self.first { return Err(cause); }
        if self.pending.is_some() || self.next_sequence.checked_add(1).is_none() {
            return Err(AuthorityRecordErrorV1::Closed);
        }
        Ok(())
    }

    /// Encodes a request while retaining its exact method/transaction as pending.
    ///
    /// # Errors
    /// Retains reentry, sequence exhaustion, canonical request or MAC refusal.
    pub fn encode_request(&mut self, request: &OwnershipRequestEnvelopeV1)
        -> Result<Vec<u8>, AuthorityRecordErrorV1> {
        let result = (|| {
            self.require_request_slot()?;
            let canonical = encode_request_v1(&self.session, request)?;
            Ok(self.authenticator.seal(OwnershipRecordDirectionV1::ClientToAuthority,
                self.next_sequence, &canonical, self.session.maximum_request_bytes())?)
        })();
        match result {
            Ok(record) => { self.pending = Some((request.method(), request.transaction())); Ok(record) }
            Err(cause) => Err(self.fail(cause)),
        }
    }

    /// Authenticates and validates the response without advancing past its posts.
    ///
    /// # Errors
    /// Retains wrong sequence, request substitution, MAC or canonical refusal.
    pub fn open_response(&mut self, request: &OwnershipRequestEnvelopeV1, frame: &[u8])
        -> Result<OwnershipResponseEnvelopeV1, AuthorityRecordErrorV1> {
        let result = (|| {
            if let Some(cause) = self.first { return Err(cause); }
            if self.response_opened || self.pending != Some((request.method(), request.transaction())) {
                return Err(AuthorityRecordErrorV1::Closed);
            }
            let canonical = self.authenticator.open(OwnershipRecordDirectionV1::AuthorityToClient,
                self.next_sequence, frame, self.session.maximum_response_bytes())?;
            Ok::<_, AuthorityRecordErrorV1>(decode_response_v1(&self.session, request, canonical)?)
        })();
        match result {
            Ok(response) => { self.response_opened = true; Ok(response) }
            Err(cause) => Err(self.fail(cause)),
        }
    }

    /// Advances DATA only after the transport completes its real response posts.
    ///
    /// # Errors
    /// Retains missing response, reentry, prior error or sequence exhaustion.
    pub fn response_received(&mut self) -> Result<(), AuthorityRecordErrorV1> {
        if let Some(cause) = self.first { return Err(cause); }
        if !self.response_opened || self.pending.is_none() {
            return Err(self.fail(AuthorityRecordErrorV1::Closed));
        }
        let Some(next) = self.next_sequence.checked_add(1) else {
            return Err(self.fail(AuthorityRecordErrorV1::Closed));
        };
        self.next_sequence = next;
        self.pending = None;
        self.response_opened = false;
        Ok(())
    }

    fn fail(&mut self, cause: AuthorityRecordErrorV1) -> AuthorityRecordErrorV1 {
        *self.first.get_or_insert(cause)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority_records::{AuthorityRecordStateV1, LOCAL_AUTHORITY_METHODS_V1};
    use crate::protocol::{OwnershipRequestBodyV1, OwnershipResponseOutcomeV1,
        OwnershipTransactionStatusV1, MAXIMUM_OWNERSHIP_RESPONSE_BYTES};
    use aos_sandbox_model::{ObjectDigest, ProtocolVersion};
    use aos_sandbox_model::model::{KeyReference, KeyUsage, StableKeyId};

    fn peers() -> (OwnershipClientRecordStateV1, AuthorityRecordStateV1) {
        let key = KeyReference::new(StableKeyId::new("ownership-client-records".into()).unwrap(),
            1, ObjectDigest::from_bytes([7; 32]), KeyUsage::OwnershipLease);
        let hello = OwnershipClientHelloV1::new([2; 32], ProtocolVersion::new(1, 0),
            key.clone(), LOCAL_AUTHORITY_METHODS_V1.to_vec(), MAXIMUM_OWNERSHIP_RESPONSE_BYTES).unwrap();
        let (server, reply) = AuthorityRecordStateV1::negotiate(&hello, [3; 32], key,
            Zeroizing::new([4; 32])).unwrap();
        let client = OwnershipClientRecordStateV1::negotiate(&hello, &reply,
            Zeroizing::new([4; 32])).unwrap();
        (client, server)
    }

    fn query(client: &OwnershipClientRecordStateV1, id: u8) -> OwnershipRequestEnvelopeV1 {
        let reference = OwnershipTransactionReferenceV1::new([id; 16], ObjectDigest::from_bytes([6; 32])).unwrap();
        client.session().request(OwnershipRequestBodyV1::Query(reference)).unwrap()
    }

    #[test]
    fn real_mac_roundtrip_keeps_next_request_closed_until_response_posts() {
        let (mut client, mut server) = peers();
        let request = query(&client, 5);
        let frame = client.encode_request(&request).unwrap();
        let received = server.open_request(&frame).unwrap();
        let reply = server.session().response(&received,
            OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Pending)).unwrap();
        let frame = server.encode_response(&received, &reply).unwrap();
        client.open_response(&request, &frame).unwrap();

        assert!(client.require_request_slot().is_err());
        server.response_sent().unwrap();
        client.response_received().unwrap();
        let next = client.encode_request(&request).unwrap();
        assert_eq!(server.open_request(&next).unwrap(), request);
    }

    #[test]
    fn wrong_request_cannot_open_valid_response_or_revive_original_sequence() {
        let (mut client, mut server) = peers();
        let original = query(&client, 5);
        let substituted = query(&client, 8);
        let frame = client.encode_request(&original).unwrap();
        let request = server.open_request(&frame).unwrap();
        let reply = server.session().response(&request,
            OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Pending)).unwrap();
        let frame = server.encode_response(&request, &reply).unwrap();

        let first = client.open_response(&substituted, &frame).unwrap_err();

        assert_eq!(client.open_response(&original, &frame).unwrap_err(), first);
        assert_eq!(client.response_received().unwrap_err(), first);
        assert_eq!(client.encode_request(&original).unwrap_err(), first);
    }
}
