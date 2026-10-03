//! Application-authenticated ownership records for a local process carrier.
//!
//! Kernel peer credentials and nominated record subjects do not prove which
//! process wrote a delegated Unix socket. A separately provisioned 32-byte
//! secret authenticates each post-negotiation record and binds its exact
//! payload, direction, sequence, and fresh two-nonce session transcript.
//! This is not a remote transport or a substitute for protected key loading,
//! local peer policy, or the ownership authority's signed lease verification.
//!
//! ```text
//! sequence:u64be | canonical-record | hmac-sha256:32
//! mac-input = "aos.ownership.local-record.v1\0" | binding:32 |
//!             direction:u8 | sequence:u64be | record-len:u32be | canonical-record
//! ```

use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::protocol::{MAXIMUM_OWNERSHIP_RESPONSE_BYTES, NegotiatedOwnershipSessionV1};

type HmacSha256 = Hmac<Sha256>;

const MAC_DOMAIN: &[u8] = b"aos.ownership.local-record.v1\0";
const SEQUENCE_BYTES: usize = 8;
const TAG_BYTES: usize = 32;
const FRAME_OVERHEAD: usize = SEQUENCE_BYTES + TAG_BYTES;

/// Maximum complete local authenticated record before socket allocation.
pub const MAXIMUM_AUTHENTICATED_OWNERSHIP_FRAME_BYTES: usize =
    MAXIMUM_OWNERSHIP_RESPONSE_BYTES as usize;

/// Selects one non-interchangeable direction of a local ownership session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipRecordDirectionV1 {
    /// Controller request sent to the ownership authority.
    ClientToAuthority,
    /// Ownership authority response sent to the controller.
    AuthorityToClient,
}

impl OwnershipRecordDirectionV1 {
    const fn code(self) -> u8 {
        match self {
            Self::ClientToAuthority => 1,
            Self::AuthorityToClient => 2,
        }
    }
}

/// Reports invalid local record authentication or framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OwnershipRecordAuthenticationErrorV1 {
    /// The provisioned secret or negotiated session binding is invalid.
    #[error("ownership record authentication configuration is invalid")]
    InvalidConfiguration,
    /// The complete frame or canonical payload exceeds its caller-owned bound.
    #[error("ownership record exceeds its negotiated bound")]
    Oversized,
    /// The frame is empty, truncated, or uses a zero or unexpected sequence.
    #[error("ownership record frame is malformed or out of order")]
    Malformed,
    /// The record did not authenticate under the exact transcript and direction.
    #[error("ownership record authentication failed")]
    AuthenticationFailed,
}

/// Holds one provisioned local key and negotiated session transcript.
///
/// Sequence ownership stays with the socket adapter. It must discard the
/// connection after an ambiguous send, rather than assigning a new sequence
/// or replaying the old frame on a different negotiated session.
pub struct OwnershipRecordAuthenticatorV1 {
    secret: Zeroizing<[u8; 32]>,
    binding: [u8; 32],
}

impl OwnershipRecordAuthenticatorV1 {
    /// Binds a nonzero local secret to one freshly negotiated session.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipRecordAuthenticationErrorV1::InvalidConfiguration`]
    /// for an all-zero secret or session transcript.
    pub fn new(
        secret: Zeroizing<[u8; 32]>,
        session: &NegotiatedOwnershipSessionV1,
    ) -> Result<Self, OwnershipRecordAuthenticationErrorV1> {
        if *secret == [0; 32] || session.binding() == &[0; 32] {
            return Err(OwnershipRecordAuthenticationErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            secret,
            binding: *session.binding(),
        })
    }

    /// Authenticates one already-encoded canonical record.
    ///
    /// `maximum_frame_bytes` is the exact negotiated complete-record ceiling,
    /// including the 40-byte sequence and MAC. A successful return does not
    /// advance a socket sequence.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipRecordAuthenticationErrorV1`] for a zero sequence,
    /// empty or oversized payload, or a complete frame above the V1 cap.
    pub fn seal(
        &self,
        direction: OwnershipRecordDirectionV1,
        sequence: u64,
        canonical_record: &[u8],
        maximum_frame_bytes: u32,
    ) -> Result<Vec<u8>, OwnershipRecordAuthenticationErrorV1> {
        self.validate_payload(sequence, canonical_record.len(), maximum_frame_bytes)?;

        let mut frame = Vec::with_capacity(FRAME_OVERHEAD + canonical_record.len());
        frame.extend_from_slice(&sequence.to_be_bytes());
        frame.extend_from_slice(canonical_record);
        frame.extend_from_slice(&self.tag(direction, sequence, canonical_record)?);
        Ok(frame)
    }

    /// Authenticates one complete frame before returning its borrowed record.
    ///
    /// The socket adapter must reject frames above `maximum_frame_bytes`
    /// before allocating. This method repeats that check and rejects replay
    /// or gaps at `expected_sequence`.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipRecordAuthenticationErrorV1`] for malformed framing,
    /// wrong sequence, an oversized payload, or invalid authentication.
    pub fn open<'frame>(
        &self,
        direction: OwnershipRecordDirectionV1,
        expected_sequence: u64,
        frame: &'frame [u8],
        maximum_frame_bytes: u32,
    ) -> Result<&'frame [u8], OwnershipRecordAuthenticationErrorV1> {
        if frame.len() <= FRAME_OVERHEAD {
            return Err(OwnershipRecordAuthenticationErrorV1::Malformed);
        }
        let payload_length = frame.len() - FRAME_OVERHEAD;
        self.validate_payload(expected_sequence, payload_length, maximum_frame_bytes)?;
        let sequence = u64::from_be_bytes(
            frame[..SEQUENCE_BYTES]
                .try_into()
                .map_err(|_| OwnershipRecordAuthenticationErrorV1::Malformed)?,
        );
        if sequence != expected_sequence {
            return Err(OwnershipRecordAuthenticationErrorV1::Malformed);
        }

        let record_end = SEQUENCE_BYTES + payload_length;
        let record = &frame[SEQUENCE_BYTES..record_end];
        let tag = &frame[record_end..];
        let mac = self.mac(direction, sequence, record)?;
        mac.verify_slice(tag)
            .map_err(|_| OwnershipRecordAuthenticationErrorV1::AuthenticationFailed)?;
        Ok(record)
    }

    fn validate_payload(
        &self,
        sequence: u64,
        payload_length: usize,
        maximum_frame_bytes: u32,
    ) -> Result<(), OwnershipRecordAuthenticationErrorV1> {
        let frame_length = payload_length
            .checked_add(FRAME_OVERHEAD)
            .ok_or(OwnershipRecordAuthenticationErrorV1::Oversized)?;
        if maximum_frame_bytes == 0
            || maximum_frame_bytes > MAXIMUM_OWNERSHIP_RESPONSE_BYTES
            || frame_length > maximum_frame_bytes as usize
        {
            return Err(OwnershipRecordAuthenticationErrorV1::Oversized);
        }
        if sequence == 0 || payload_length == 0 {
            return Err(OwnershipRecordAuthenticationErrorV1::Malformed);
        }
        Ok(())
    }

    fn tag(
        &self,
        direction: OwnershipRecordDirectionV1,
        sequence: u64,
        record: &[u8],
    ) -> Result<[u8; TAG_BYTES], OwnershipRecordAuthenticationErrorV1> {
        let bytes = self
            .mac(direction, sequence, record)?
            .finalize()
            .into_bytes();
        Ok(bytes.into())
    }

    fn mac(
        &self,
        direction: OwnershipRecordDirectionV1,
        sequence: u64,
        record: &[u8],
    ) -> Result<HmacSha256, OwnershipRecordAuthenticationErrorV1> {
        let length = u32::try_from(record.len())
            .map_err(|_| OwnershipRecordAuthenticationErrorV1::Oversized)?;
        let mut mac = HmacSha256::new_from_slice(&*self.secret)
            .map_err(|_| OwnershipRecordAuthenticationErrorV1::InvalidConfiguration)?;
        mac.update(MAC_DOMAIN);
        mac.update(&self.binding);
        mac.update(&[direction.code()]);
        mac.update(&sequence.to_be_bytes());
        mac.update(&length.to_be_bytes());
        mac.update(record);
        Ok(mac)
    }
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::model::{KeyReference, KeyUsage, StableKeyId};
    use aos_sandbox_core::{ObjectDigest, ProtocolVersion};

    use super::*;
    use crate::carrier::{decode_request_v1, encode_request_v1};
    use crate::protocol::{
        MAXIMUM_OWNERSHIP_REQUEST_BYTES, OwnershipClientHelloV1, OwnershipMethodV1,
        OwnershipRequestBodyV1, OwnershipTransactionReferenceV1,
    };

    fn session(server_nonce: [u8; 32]) -> NegotiatedOwnershipSessionV1 {
        let authority = KeyReference::new(
            StableKeyId::new("ownership-record-auth-test".to_owned())
                .unwrap_or_else(|error| panic!("ownership carrier test failed: {error}")),
            7,
            ObjectDigest::from_bytes([8; 32]),
            KeyUsage::OwnershipLease,
        );
        let methods = vec![
            OwnershipMethodV1::Begin,
            OwnershipMethodV1::CompleteOrResume,
            OwnershipMethodV1::Query,
        ];
        let hello = OwnershipClientHelloV1::new(
            [9; 32],
            ProtocolVersion::new(1, 0),
            authority.clone(),
            methods.clone(),
            MAXIMUM_OWNERSHIP_RESPONSE_BYTES,
        )
        .unwrap_or_else(|error| panic!("ownership carrier test failed: {error}"));
        NegotiatedOwnershipSessionV1::negotiate(&hello, server_nonce, authority, methods)
            .unwrap_or_else(|error| panic!("ownership carrier test failed: {error}"))
    }

    #[test]
    fn frame_authenticates_direction_sequence_and_payload() {
        let session = session([10; 32]);
        let authenticator = OwnershipRecordAuthenticatorV1::new(Zeroizing::new([11; 32]), &session)
            .unwrap_or_else(|error| panic!("ownership carrier test failed: {error}"));
        let frame = authenticator
            .seal(
                OwnershipRecordDirectionV1::ClientToAuthority,
                1,
                b"canonical-request",
                MAXIMUM_OWNERSHIP_REQUEST_BYTES,
            )
            .unwrap_or_else(|error| panic!("ownership carrier test failed: {error}"));
        assert_eq!(
            authenticator.open(
                OwnershipRecordDirectionV1::ClientToAuthority,
                1,
                &frame,
                MAXIMUM_OWNERSHIP_REQUEST_BYTES,
            ),
            Ok(b"canonical-request".as_slice())
        );
        assert_eq!(
            authenticator.open(
                OwnershipRecordDirectionV1::AuthorityToClient,
                1,
                &frame,
                MAXIMUM_OWNERSHIP_RESPONSE_BYTES,
            ),
            Err(OwnershipRecordAuthenticationErrorV1::AuthenticationFailed)
        );
        assert_eq!(
            authenticator.open(
                OwnershipRecordDirectionV1::ClientToAuthority,
                2,
                &frame,
                MAXIMUM_OWNERSHIP_REQUEST_BYTES,
            ),
            Err(OwnershipRecordAuthenticationErrorV1::Malformed)
        );

        let mut changed = frame;
        changed[SEQUENCE_BYTES] ^= 1;
        assert_eq!(
            authenticator.open(
                OwnershipRecordDirectionV1::ClientToAuthority,
                1,
                &changed,
                MAXIMUM_OWNERSHIP_REQUEST_BYTES,
            ),
            Err(OwnershipRecordAuthenticationErrorV1::AuthenticationFailed)
        );
    }

    #[test]
    fn authenticated_query_reaches_the_negotiated_decoder() {
        let session = session([10; 32]);
        let authenticator = OwnershipRecordAuthenticatorV1::new(Zeroizing::new([11; 32]), &session)
            .unwrap_or_else(|error| panic!("ownership carrier test failed: {error}"));
        let transaction =
            OwnershipTransactionReferenceV1::new([12; 16], ObjectDigest::from_bytes([13; 32]))
                .unwrap_or_else(|error| panic!("ownership carrier test failed: {error}"));
        let request = session
            .request(OwnershipRequestBodyV1::Query(transaction))
            .unwrap_or_else(|error| panic!("ownership carrier test failed: {error}"));
        let record = encode_request_v1(&session, &request)
            .unwrap_or_else(|error| panic!("ownership carrier test failed: {error}"));
        let frame = authenticator
            .seal(
                OwnershipRecordDirectionV1::ClientToAuthority,
                1,
                &record,
                session.maximum_request_bytes(),
            )
            .unwrap_or_else(|error| panic!("ownership carrier test failed: {error}"));
        let verified = authenticator
            .open(
                OwnershipRecordDirectionV1::ClientToAuthority,
                1,
                &frame,
                session.maximum_request_bytes(),
            )
            .unwrap_or_else(|error| panic!("ownership carrier test failed: {error}"));

        assert_eq!(decode_request_v1(&session, verified), Ok(request));
    }

    #[test]
    fn frame_cannot_cross_sessions_or_provisioned_secrets() {
        let first = session([10; 32]);
        let second = session([12; 32]);
        let sender = OwnershipRecordAuthenticatorV1::new(Zeroizing::new([11; 32]), &first)
            .unwrap_or_else(|error| panic!("ownership carrier test failed: {error}"));
        let wrong_session = OwnershipRecordAuthenticatorV1::new(Zeroizing::new([11; 32]), &second)
            .unwrap_or_else(|error| panic!("ownership carrier test failed: {error}"));
        let wrong_secret = OwnershipRecordAuthenticatorV1::new(Zeroizing::new([13; 32]), &first)
            .unwrap_or_else(|error| panic!("ownership carrier test failed: {error}"));
        let frame = sender
            .seal(
                OwnershipRecordDirectionV1::AuthorityToClient,
                8,
                b"canonical-response",
                MAXIMUM_OWNERSHIP_RESPONSE_BYTES,
            )
            .unwrap_or_else(|error| panic!("ownership carrier test failed: {error}"));

        for verifier in [&wrong_session, &wrong_secret] {
            assert_eq!(
                verifier.open(
                    OwnershipRecordDirectionV1::AuthorityToClient,
                    8,
                    &frame,
                    MAXIMUM_OWNERSHIP_RESPONSE_BYTES,
                ),
                Err(OwnershipRecordAuthenticationErrorV1::AuthenticationFailed)
            );
        }
    }

    #[test]
    fn frame_rejects_invalid_configuration_and_bounds() {
        let session = session([10; 32]);
        assert!(matches!(
            OwnershipRecordAuthenticatorV1::new(Zeroizing::new([0; 32]), &session),
            Err(OwnershipRecordAuthenticationErrorV1::InvalidConfiguration)
        ));
        let authenticator = OwnershipRecordAuthenticatorV1::new(Zeroizing::new([11; 32]), &session)
            .unwrap_or_else(|error| panic!("ownership carrier test failed: {error}"));
        assert_eq!(
            authenticator.seal(OwnershipRecordDirectionV1::ClientToAuthority, 0, b"x", 4096),
            Err(OwnershipRecordAuthenticationErrorV1::Malformed)
        );
        assert_eq!(
            authenticator.seal(OwnershipRecordDirectionV1::ClientToAuthority, 1, b"xy", 1),
            Err(OwnershipRecordAuthenticationErrorV1::Oversized)
        );
        let minimal_frame = authenticator
            .seal(OwnershipRecordDirectionV1::ClientToAuthority, 1, b"x", 41)
            .unwrap_or_else(|error| panic!("ownership carrier test failed: {error}"));
        assert_eq!(minimal_frame.len(), 41);
        assert_eq!(
            authenticator.open(
                OwnershipRecordDirectionV1::ClientToAuthority,
                1,
                &minimal_frame,
                40,
            ),
            Err(OwnershipRecordAuthenticationErrorV1::Oversized)
        );
        assert_eq!(
            authenticator.open(
                OwnershipRecordDirectionV1::ClientToAuthority,
                1,
                &[0; 40],
                4096
            ),
            Err(OwnershipRecordAuthenticationErrorV1::Malformed)
        );
    }
}
