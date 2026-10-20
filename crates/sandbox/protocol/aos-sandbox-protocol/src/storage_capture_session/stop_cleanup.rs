//! Frames fresh Stop permission for containment of one retained Capture original.
//!
//! This packet carries comparison DATA on one prepaid native-authenticated
//! cancellation connection to the SAME retained original.
//! It does not renew the execution lifetime or prove EOF, output completeness,
//! worker death, population emptiness, native disposal, or Controller settlement.
//!
//! ```text
//! AOSCSN04 | version:u16 | zero[2] | stop-cutoff:u64 | nonce[32]
//!         | begin-digest[32] | source-digest[32] | attempt[16]
//!         | lengths:u32[5] | Stop-body | plan | plan-signature
//!         | ownership-lease | lease-signature | frame-digest[32]
//! ```

pub use super::stop_cleanup_receipt::{
    CAPTURE_STOP_RECEIPT_BYTES_V4, CaptureQuiescentIncompleteFieldsDataV4,
    CaptureQuiescentIncompleteReceiptDataV4,
};

use crate::session::{
    AuthorizationArtifactBytes, MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES, MAXIMUM_BROKER_PLAN_BYTES,
    MAXIMUM_OWNERSHIP_LEASE_BYTES,
};
use sha2::{Digest as _, Sha256};

const MAGIC: &[u8; 8] = b"AOSCSN04";
const DOMAIN: &[u8] = b"aos.sandbox.capture.stop-own-resource.v4\0";
const HEADER_BYTES: usize = 152;
const DIGEST_BYTES: usize = 32;

// All fields in these three protobuf messages have single-byte tags. Their
// fixed identity byte fields and the nested messages have one-byte lengths.
// Header: protocol major/minor/response u32, request16, audience, BOOT u64.
const PROTO_TAG: usize = 1;
const PROTO_LENGTH: usize = 1;
const PROTO_U32: usize = 5;
const PROTO_U64: usize = 10;
const STOP_HEADER_BYTES: usize = 3 * (PROTO_TAG + PROTO_U32)
    + PROTO_TAG
    + PROTO_LENGTH
    + 16
    + PROTO_TAG
    + 1
    + PROTO_TAG
    + PROTO_U64;
// Fence: sandbox16, incarnation16, epoch u64, desired u64, assignment32.
const STOP_FENCE_BYTES: usize = 2 * (PROTO_TAG + PROTO_LENGTH + 16)
    + 2 * (PROTO_TAG + PROTO_U64)
    + PROTO_TAG
    + PROTO_LENGTH
    + 32;

/// Bounds canonical Stop-only Header, Fence and action by their real wire widths.
///
/// The closed decoder rejects launch/Guardian, unknown and noncanonical fields.
/// No request model is allocated before this byte ceiling is checked.
pub const MAXIMUM_CANONICAL_CAPTURE_STOP_BODY_BYTES_V4: usize = PROTO_TAG
    + PROTO_LENGTH
    + STOP_HEADER_BYTES
    + PROTO_TAG
    + PROTO_LENGTH
    + STOP_FENCE_BYTES
    + PROTO_TAG
    + 1;

/// Bounds the whole frame by the Stop schema and existing artifact field caps.
pub const MAXIMUM_CAPTURE_STOP_REQUEST_BYTES_V4: usize = HEADER_BYTES
    + DIGEST_BYTES
    + MAXIMUM_CANONICAL_CAPTURE_STOP_BODY_BYTES_V4
    + MAXIMUM_BROKER_PLAN_BYTES
    + MAXIMUM_OWNERSHIP_LEASE_BYTES
    + 2 * MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES;

/// Refuses malformed, oversized, substituted or noncanonical outer framing.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the fresh Capture Stop cleanup frame is invalid")]
pub struct CaptureStopCleanupProtocolErrorV4;

type Result<T> = std::result::Result<T, CaptureStopCleanupProtocolErrorV4>;

/// Borrows the complete fresh Stop artifacts and exact retained Capture selector.
///
/// Construction only validates framing. The receiver must independently verify
/// signed Stop permission, native peer, same original identities and all posts.
pub struct CaptureStopCleanupRequestDataV4<'wire> {
    cutoff: u64,
    nonce: [u8; 32],
    begin: [u8; 32],
    source: [u8; 32],
    attempt: [u8; 16],
    fields: [&'wire [u8]; 5],
    lengths: [u32; 5],
    encoded_bytes: usize,
}

impl<'wire> CaptureStopCleanupRequestDataV4<'wire> {
    /// Checks the exact fresh Stop fields without parsing or trusting artifacts.
    ///
    /// # Errors
    /// Refuses zero coordinates, empty fields, existing field ceilings or overflow.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cutoff: u64,
        nonce: [u8; 32],
        begin: [u8; 32],
        source: [u8; 32],
        attempt: [u8; 16],
        stop_body: &'wire [u8],
        artifacts: AuthorizationArtifactBytes<'wire>,
    ) -> Result<Self> {
        if cutoff == 0
            || nonce == [0; 32]
            || begin == [0; 32]
            || source == [0; 32]
            || attempt == [0; 16]
        {
            return Err(CaptureStopCleanupProtocolErrorV4);
        }
        let fields = [
            stop_body,
            artifacts.broker_plan,
            artifacts.broker_plan_signature,
            artifacts.ownership_lease,
            artifacts.ownership_lease_signature,
        ];
        let caps = [
            MAXIMUM_CANONICAL_CAPTURE_STOP_BODY_BYTES_V4,
            MAXIMUM_BROKER_PLAN_BYTES,
            MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES,
            MAXIMUM_OWNERSHIP_LEASE_BYTES,
            MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES,
        ];
        let mut lengths = [0; 5];
        let mut encoded_bytes = HEADER_BYTES + DIGEST_BYTES;
        for (index, (field, cap)) in fields.iter().zip(caps).enumerate() {
            if field.is_empty() || field.len() > cap {
                return Err(CaptureStopCleanupProtocolErrorV4);
            }
            lengths[index] =
                u32::try_from(field.len()).map_err(|_| CaptureStopCleanupProtocolErrorV4)?;
            encoded_bytes = encoded_bytes
                .checked_add(field.len())
                .ok_or(CaptureStopCleanupProtocolErrorV4)?;
        }
        if encoded_bytes > MAXIMUM_CAPTURE_STOP_REQUEST_BYTES_V4 {
            return Err(CaptureStopCleanupProtocolErrorV4);
        }
        Ok(Self {
            cutoff,
            nonce,
            begin,
            source,
            attempt,
            fields,
            lengths,
            encoded_bytes,
        })
    }

    /// Borrows bounded original fields through the same outer framing checks.
    ///
    /// # Errors
    /// Refuses truncation, trailing bytes, wrong version, reserved fields, digest,
    /// or any constructor refusal. This decoder performs no allocation or IO.
    pub fn decode_v4(bytes: &'wire [u8]) -> Result<Self> {
        if bytes.len() < HEADER_BYTES + DIGEST_BYTES
            || bytes.len() > MAXIMUM_CAPTURE_STOP_REQUEST_BYTES_V4
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..12) != Some([0, 4, 0, 0].as_slice())
        {
            return Err(CaptureStopCleanupProtocolErrorV4);
        }
        let number = |offset| -> Result<u32> {
            Ok(u32::from_be_bytes(
                bytes
                    .get(offset..offset + 4)
                    .ok_or(CaptureStopCleanupProtocolErrorV4)?
                    .try_into()
                    .map_err(|_| CaptureStopCleanupProtocolErrorV4)?,
            ))
        };
        let mut fields: [&[u8]; 5] = [&[]; 5];
        let mut cursor = HEADER_BYTES;
        for (index, field) in fields.iter_mut().enumerate() {
            let length = usize::try_from(number(132 + 4 * index)?)
                .map_err(|_| CaptureStopCleanupProtocolErrorV4)?;
            let end = cursor
                .checked_add(length)
                .ok_or(CaptureStopCleanupProtocolErrorV4)?;
            *field = bytes
                .get(cursor..end)
                .ok_or(CaptureStopCleanupProtocolErrorV4)?;
            cursor = end;
        }
        if cursor.checked_add(DIGEST_BYTES) != Some(bytes.len()) {
            return Err(CaptureStopCleanupProtocolErrorV4);
        }
        let value = Self::new(
            u64::from_be_bytes(
                bytes[12..20]
                    .try_into()
                    .map_err(|_| CaptureStopCleanupProtocolErrorV4)?,
            ),
            bytes[20..52]
                .try_into()
                .map_err(|_| CaptureStopCleanupProtocolErrorV4)?,
            bytes[52..84]
                .try_into()
                .map_err(|_| CaptureStopCleanupProtocolErrorV4)?,
            bytes[84..116]
                .try_into()
                .map_err(|_| CaptureStopCleanupProtocolErrorV4)?,
            bytes[116..132]
                .try_into()
                .map_err(|_| CaptureStopCleanupProtocolErrorV4)?,
            fields[0],
            AuthorizationArtifactBytes {
                broker_plan: fields[1],
                broker_plan_signature: fields[2],
                ownership_lease: fields[3],
                ownership_lease_signature: fields[4],
            },
        )?;
        if bytes.get(cursor..) != Some(value.digest_v4().as_slice()) {
            return Err(CaptureStopCleanupProtocolErrorV4);
        }
        Ok(value)
    }

    fn header_v4(&self) -> [u8; HEADER_BYTES] {
        let mut bytes = [0; HEADER_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&4u16.to_be_bytes());
        bytes[12..20].copy_from_slice(&self.cutoff.to_be_bytes());
        bytes[20..52].copy_from_slice(&self.nonce);
        bytes[52..84].copy_from_slice(&self.begin);
        bytes[84..116].copy_from_slice(&self.source);
        bytes[116..132].copy_from_slice(&self.attempt);
        for (index, length) in self.lengths.iter().enumerate() {
            bytes[132 + 4 * index..136 + 4 * index].copy_from_slice(&length.to_be_bytes());
        }
        bytes
    }

    /// Returns the exact full frame width for prepayment before encoding.
    #[must_use]
    pub const fn encoded_bytes_v4(&self) -> usize {
        self.encoded_bytes
    }

    /// Encodes the checked outer frame after the caller has paid its backing.
    ///
    /// # Errors
    /// Refuses allocation failure without changing any execution authority.
    pub fn encode_v4(&self) -> std::result::Result<Vec<u8>, std::collections::TryReserveError> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(self.encoded_bytes)?;
        bytes.extend_from_slice(&self.header_v4());
        for field in self.fields {
            bytes.extend_from_slice(field);
        }
        bytes.extend_from_slice(&self.digest_v4());
        Ok(bytes)
    }

    /// Commits all exact coordinates and all five original fields as DATA.
    #[must_use]
    pub fn digest_v4(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(self.header_v4());
        for field in self.fields {
            hash.update(field);
        }
        hash.finalize().into()
    }

    /// Returns only this fresh Stop's cutoff, never an extended Capture lifetime.
    #[must_use]
    pub const fn cutoff_v4(&self) -> u64 {
        self.cutoff
    }
    /// Returns the exact held-channel challenge.
    #[must_use]
    pub const fn nonce_v4(&self) -> &[u8; 32] {
        &self.nonce
    }
    /// Returns the exact original Begin digest.
    #[must_use]
    pub const fn begin_digest_v4(&self) -> &[u8; 32] {
        &self.begin
    }
    /// Returns the complete original Source944 digest.
    #[must_use]
    pub const fn source_digest_v4(&self) -> &[u8; 32] {
        &self.source
    }
    /// Returns the exact resident physical attempt.
    #[must_use]
    pub const fn attempt_v4(&self) -> &[u8; 16] {
        &self.attempt
    }
    /// Borrows the exact fresh authenticated Stop request body.
    #[must_use]
    pub const fn stop_body_v4(&self) -> &'wire [u8] {
        self.fields[0]
    }
    /// Borrows the original signed quartet without decoding or adopting it.
    #[must_use]
    pub const fn authorization_v4(&self) -> AuthorizationArtifactBytes<'wire> {
        AuthorizationArtifactBytes {
            broker_plan: self.fields[1],
            broker_plan_signature: self.fields[2],
            ownership_lease: self.fields[3],
            ownership_lease_signature: self.fields[4],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_preserves_whole_artifacts_and_rejects_substitution_or_trailing_bytes() {
        let request = CaptureStopCleanupRequestDataV4::new(
            7,
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 16],
            b"stop",
            AuthorizationArtifactBytes {
                broker_plan: b"plan",
                broker_plan_signature: b"plan-signature",
                ownership_lease: b"lease",
                ownership_lease_signature: b"lease-signature",
            },
        )
        .unwrap();
        let mut bytes = request.encode_v4().unwrap();
        let decoded = CaptureStopCleanupRequestDataV4::decode_v4(&bytes).unwrap();
        assert_eq!(decoded.stop_body_v4(), b"stop");
        assert_eq!(
            decoded.authorization_v4().ownership_lease_signature,
            b"lease-signature"
        );
        assert_eq!(decoded.digest_v4(), request.digest_v4());
        bytes[84] ^= 1;
        assert!(CaptureStopCleanupRequestDataV4::decode_v4(&bytes).is_err());
        bytes[84] ^= 1;
        bytes.push(0);
        assert!(CaptureStopCleanupRequestDataV4::decode_v4(&bytes).is_err());
    }
}
