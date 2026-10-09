//! Descriptor-free readback of one historical Inventory reservation.
//!
//! The current authenticated session challenges Provider about an exact old
//! signed request. A signed Completed answer attests Provider's protected
//! journal readback; it is not an Inventory result until Mount verifies the
//! historical response against its own protected attempt and session.
//!
//! ```text
//! query: AOSSPI01 | kind=1 | version=1 | reserved[6]=0 |
//!        current-session[32] | nonce[32] | sequence:u64be |
//!        provider-id[16] | holder-id[16] | old-request-digest[32] |
//!        mount-attempt-record-digest[32]
//! answer: AOSSPI01 | kind=2 | version=1 | reserved[6]=0 |
//!         current-session[32] | query-digest[32] | old-request-digest[32] |
//!         mount-attempt-record-digest[32] | response-digest[32] |
//!         completed-at:i64be | deadline:i64be | response-length:u32be |
//!         status:u8 (1=unavailable, 2=completed) | reserved[3]=0 |
//!         provider-outcome-signer[120] | signature[64] | response[response-length]
//! ```

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

use crate::crypto::{
    SourceProviderKeyUsageV1, SourceProviderSignature, SourceProviderSignatureError,
    SourceProviderSigningKeyV1, decode_signer, encode_signer, sign_bytes, verify_bytes,
};
use crate::{MAXIMUM_FRAME_BYTES, SourceProviderMethod, provider_response_artifact_digest_v1};

const MAGIC: &[u8; 8] = b"AOSSPI01";
const VERSION: u8 = 1;
const QUERY_KIND: u8 = 1;
const ANSWER_KIND: u8 = 2;
const QUERY_BYTES: usize = 184;
const ANSWER_SUBJECT_BYTES: usize = 200;
const ANSWER_FIXED_BYTES: usize = ANSWER_SUBJECT_BYTES + 120 + 64;
/// Maximum readback packet containing one complete legacy response and its signed envelope.
pub const MAXIMUM_INVENTORY_READBACK_PACKET_BYTES: usize = MAXIMUM_FRAME_BYTES + ANSWER_FIXED_BYTES;
const UNAVAILABLE: u8 = 1;
const COMPLETED: u8 = 2;
const QUERY_DIGEST_DOMAIN: &[u8] = b"aos-source-provider-inventory-readback-query-v1\0";
const ANSWER_SIGNATURE_DOMAIN: &[u8] = b"aos-source-provider-inventory-readback-answer-v1\0";

/// Rejects malformed, substituted, or unauthenticated Inventory readback.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InventoryReadbackErrorV1 {
    /// The packet does not use the exact version-one representation.
    #[error("noncanonical Inventory readback record")]
    Noncanonical,
    /// The answer does not name the exact live challenge.
    #[error("Inventory readback answer differs from its challenge")]
    Stale,
    /// The Provider outcome signature is invalid.
    #[error("Inventory readback signature failed: {0}")]
    Signature(#[from] SourceProviderSignatureError),
}

/// Challenges Provider about one old protected Mount Inventory attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryReadbackQueryV1 {
    session_binding: ObjectDigest,
    nonce: [u8; 32],
    sequence: u64,
    provider_id: [u8; 16],
    holder_id: [u8; 16],
    signed_request_digest: ObjectDigest,
    mount_attempt_record_digest: ObjectDigest,
}

impl InventoryReadbackQueryV1 {
    /// Constructs a nonce-bound challenge with no request or effect authority.
    ///
    /// # Errors
    ///
    /// Rejects zero session, nonce, sequence, authority, or digest fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_binding: ObjectDigest,
        nonce: [u8; 32],
        sequence: u64,
        provider_id: [u8; 16],
        holder_id: [u8; 16],
        signed_request_digest: ObjectDigest,
        mount_attempt_record_digest: ObjectDigest,
    ) -> Result<Self, InventoryReadbackErrorV1> {
        if session_binding.as_bytes() == &[0; 32]
            || nonce == [0; 32]
            || sequence == 0
            || provider_id == [0; 16]
            || holder_id == [0; 16]
            || signed_request_digest.as_bytes() == &[0; 32]
            || mount_attempt_record_digest.as_bytes() == &[0; 32]
        {
            return Err(InventoryReadbackErrorV1::Noncanonical);
        }
        Ok(Self {
            session_binding,
            nonce,
            sequence,
            provider_id,
            holder_id,
            signed_request_digest,
            mount_attempt_record_digest,
        })
    }

    /// Returns the current authenticated session binding.
    #[must_use]
    pub const fn session_binding(&self) -> ObjectDigest {
        self.session_binding
    }

    /// Returns the monotonic sequence on this carrier.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the historical Provider and RootMount authority IDs.
    #[must_use]
    pub const fn authorities(&self) -> ([u8; 16], [u8; 16]) {
        (self.provider_id, self.holder_id)
    }

    /// Returns the exact signed request digest named by Mount's journal.
    #[must_use]
    pub const fn signed_request_digest(&self) -> ObjectDigest {
        self.signed_request_digest
    }

    /// Returns the exact protected Mount attempt record digest.
    #[must_use]
    pub const fn mount_attempt_record_digest(&self) -> ObjectDigest {
        self.mount_attempt_record_digest
    }

    /// Encodes the sole canonical challenge representation.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> [u8; QUERY_BYTES] {
        let mut bytes = [0; QUERY_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = QUERY_KIND;
        bytes[9] = VERSION;
        bytes[16..48].copy_from_slice(self.session_binding.as_bytes());
        bytes[48..80].copy_from_slice(&self.nonce);
        bytes[80..88].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[88..104].copy_from_slice(&self.provider_id);
        bytes[104..120].copy_from_slice(&self.holder_id);
        bytes[120..152].copy_from_slice(self.signed_request_digest.as_bytes());
        bytes[152..184].copy_from_slice(self.mount_attempt_record_digest.as_bytes());
        bytes
    }

    /// Decodes one exact canonical challenge.
    ///
    /// # Errors
    ///
    /// Rejects changed length, version, kind, reserved bytes, or sentinels.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, InventoryReadbackErrorV1> {
        require_header(bytes, QUERY_BYTES, QUERY_KIND)?;
        Self::new(
            digest_at(bytes, 16)?,
            array_at(bytes, 48)?,
            u64_at(bytes, 80)?,
            array_at(bytes, 88)?,
            array_at(bytes, 104)?,
            digest_at(bytes, 120)?,
            digest_at(bytes, 152)?,
        )
    }

    /// Commits every challenge byte for the signed answer.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        let mut hasher = Sha256::new();
        hasher.update(QUERY_DIGEST_DOMAIN);
        hasher.update(self.to_canonical_bytes());
        ObjectDigest::from_bytes(hasher.finalize().into())
    }
}

/// Carries one signed protected Provider readback or explicit non-authorizing absence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedInventoryReadbackV1 {
    session_binding: ObjectDigest,
    query_digest: ObjectDigest,
    signed_request_digest: ObjectDigest,
    mount_attempt_record_digest: ObjectDigest,
    response_digest: ObjectDigest,
    completed_at_seconds: i64,
    deadline_seconds: i64,
    status: u8,
    response: Vec<u8>,
    signer: SourceProviderSigningKeyV1,
    signature: SourceProviderSignature,
}

impl SignedInventoryReadbackV1 {
    /// Signs only caller-proven protected readback facts, never a new Inventory.
    ///
    /// `None` is a non-authorizing unavailable answer. The caller must establish
    /// its absence or unresolved state under Provider's protected journal.
    ///
    /// # Errors
    ///
    /// Rejects invalid completion times, response shape, signer, or key.
    pub fn sign(
        query: &InventoryReadbackQueryV1,
        completed: Option<(Vec<u8>, i64, i64)>,
        signer: SourceProviderSigningKeyV1,
        signing_key: &SigningKey,
    ) -> Result<Self, InventoryReadbackErrorV1> {
        let (status, response, completed_at_seconds, deadline_seconds) = match completed {
            Some((response, completed_at, deadline)) => {
                (COMPLETED, response, completed_at, deadline)
            }
            None => (UNAVAILABLE, Vec::new(), 0, 0),
        };
        let response_digest = if status == COMPLETED {
            provider_response_artifact_digest_v1(SourceProviderMethod::Inventory, &response)
        } else {
            ObjectDigest::from_bytes([0; 32])
        };
        let mut value = Self {
            session_binding: query.session_binding,
            query_digest: query.digest(),
            signed_request_digest: query.signed_request_digest,
            mount_attempt_record_digest: query.mount_attempt_record_digest,
            response_digest,
            completed_at_seconds,
            deadline_seconds,
            status,
            response,
            signer,
            signature: SourceProviderSignature::from_bytes([0; 64]),
        };
        value.require_shape()?;
        if value.signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
            || value.signer.authority_id() != query.provider_id
        {
            return Err(InventoryReadbackErrorV1::Noncanonical);
        }
        value.signature = sign_bytes(
            ANSWER_SIGNATURE_DOMAIN,
            ANSWER_KIND,
            &value.subject_bytes(),
            &value.signer,
            signing_key,
        )?;
        Ok(value)
    }

    /// Verifies the live challenge, exact signer, response digest, and signature.
    ///
    /// # Errors
    ///
    /// Rejects a substituted challenge, provider key, response, or fact.
    pub fn verify_for_query(
        &self,
        query: &InventoryReadbackQueryV1,
        expected_signer: &SourceProviderSigningKeyV1,
        public_key: &[u8; 32],
    ) -> Result<(), InventoryReadbackErrorV1> {
        self.require_shape()?;
        if self.session_binding != query.session_binding
            || self.query_digest != query.digest()
            || self.signed_request_digest != query.signed_request_digest
            || self.mount_attempt_record_digest != query.mount_attempt_record_digest
            || self.signer != *expected_signer
            || self.signer.authority_id() != query.provider_id
        {
            return Err(InventoryReadbackErrorV1::Stale);
        }
        verify_bytes(
            ANSWER_SIGNATURE_DOMAIN,
            ANSWER_KIND,
            &self.subject_bytes(),
            &self.signer,
            &self.signature,
            public_key,
        )?;
        Ok(())
    }

    /// Returns the exact historical response and protected completion times.
    #[must_use]
    pub fn completed(&self) -> Option<(&[u8], i64, i64)> {
        (self.status == COMPLETED).then_some((
            self.response.as_slice(),
            self.completed_at_seconds,
            self.deadline_seconds,
        ))
    }

    /// Encodes the exact signed answer and bounded historical response.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.subject_bytes();
        encode_signer(&mut bytes, &self.signer);
        bytes.extend_from_slice(self.signature.as_bytes());
        bytes.extend_from_slice(&self.response);
        bytes
    }

    /// Decodes one canonical signed answer.
    ///
    /// # Errors
    ///
    /// Rejects malformed fields, length, signer, or response shape.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, InventoryReadbackErrorV1> {
        if bytes.len() < ANSWER_FIXED_BYTES || bytes.len() > MAXIMUM_INVENTORY_READBACK_PACKET_BYTES
        {
            return Err(InventoryReadbackErrorV1::Noncanonical);
        }
        require_header_prefix(bytes, ANSWER_KIND)?;
        let response_length = u32_at(bytes, 192)? as usize;
        let total_length = ANSWER_FIXED_BYTES
            .checked_add(response_length)
            .ok_or(InventoryReadbackErrorV1::Noncanonical)?;
        if bytes.len() != total_length || bytes[197..200] != [0; 3] {
            return Err(InventoryReadbackErrorV1::Noncanonical);
        }
        let value = Self {
            session_binding: digest_at(bytes, 16)?,
            query_digest: digest_at(bytes, 48)?,
            signed_request_digest: digest_at(bytes, 80)?,
            mount_attempt_record_digest: digest_at(bytes, 112)?,
            response_digest: digest_at(bytes, 144)?,
            completed_at_seconds: i64_at(bytes, 176)?,
            deadline_seconds: i64_at(bytes, 184)?,
            status: bytes[196],
            response: bytes[ANSWER_FIXED_BYTES..].to_vec(),
            signer: decode_signer(&bytes[200..320])?,
            signature: SourceProviderSignature::from_bytes(array_at(bytes, 320)?),
        };
        value.require_shape()?;
        if value.to_canonical_bytes() != bytes {
            return Err(InventoryReadbackErrorV1::Noncanonical);
        }
        Ok(value)
    }

    fn require_shape(&self) -> Result<(), InventoryReadbackErrorV1> {
        let present = self.status == COMPLETED;
        if self.session_binding.as_bytes() == &[0; 32]
            || self.query_digest.as_bytes() == &[0; 32]
            || self.signed_request_digest.as_bytes() == &[0; 32]
            || self.mount_attempt_record_digest.as_bytes() == &[0; 32]
            || self.signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
            || self.response.len() > MAXIMUM_FRAME_BYTES
            || (present
                && (self.response.is_empty()
                    || self.response_digest.as_bytes() == &[0; 32]
                    || self.completed_at_seconds < 0
                    || self.deadline_seconds <= self.completed_at_seconds
                    || self.response_digest
                        != provider_response_artifact_digest_v1(
                            SourceProviderMethod::Inventory,
                            &self.response,
                        )))
            || (!present
                && (self.status != UNAVAILABLE
                    || !self.response.is_empty()
                    || self.response_digest.as_bytes() != &[0; 32]
                    || self.completed_at_seconds != 0
                    || self.deadline_seconds != 0))
        {
            return Err(InventoryReadbackErrorV1::Noncanonical);
        }
        Ok(())
    }

    fn subject_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ANSWER_SUBJECT_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.push(ANSWER_KIND);
        bytes.push(VERSION);
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(self.session_binding.as_bytes());
        bytes.extend_from_slice(self.query_digest.as_bytes());
        bytes.extend_from_slice(self.signed_request_digest.as_bytes());
        bytes.extend_from_slice(self.mount_attempt_record_digest.as_bytes());
        bytes.extend_from_slice(self.response_digest.as_bytes());
        bytes.extend_from_slice(&self.completed_at_seconds.to_be_bytes());
        bytes.extend_from_slice(&self.deadline_seconds.to_be_bytes());
        bytes.extend_from_slice(&(self.response.len() as u32).to_be_bytes());
        bytes.push(self.status);
        bytes.extend_from_slice(&[0; 3]);
        bytes
    }
}

fn require_header(bytes: &[u8], length: usize, kind: u8) -> Result<(), InventoryReadbackErrorV1> {
    if bytes.len() != length {
        return Err(InventoryReadbackErrorV1::Noncanonical);
    }
    require_header_prefix(bytes, kind)
}

fn require_header_prefix(bytes: &[u8], kind: u8) -> Result<(), InventoryReadbackErrorV1> {
    if bytes.len() < 16
        || &bytes[..8] != MAGIC
        || bytes[8] != kind
        || bytes[9] != VERSION
        || bytes[10..16] != [0; 6]
    {
        return Err(InventoryReadbackErrorV1::Noncanonical);
    }
    Ok(())
}

fn array_at<const N: usize>(
    bytes: &[u8],
    start: usize,
) -> Result<[u8; N], InventoryReadbackErrorV1> {
    bytes
        .get(start..start + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(InventoryReadbackErrorV1::Noncanonical)
}

fn digest_at(bytes: &[u8], start: usize) -> Result<ObjectDigest, InventoryReadbackErrorV1> {
    Ok(ObjectDigest::from_bytes(array_at(bytes, start)?))
}

fn u64_at(bytes: &[u8], start: usize) -> Result<u64, InventoryReadbackErrorV1> {
    Ok(u64::from_be_bytes(array_at(bytes, start)?))
}

fn u32_at(bytes: &[u8], start: usize) -> Result<u32, InventoryReadbackErrorV1> {
    Ok(u32::from_be_bytes(array_at(bytes, start)?))
}

fn i64_at(bytes: &[u8], start: usize) -> Result<i64, InventoryReadbackErrorV1> {
    Ok(i64::from_be_bytes(array_at(bytes, start)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> InventoryReadbackQueryV1 {
        InventoryReadbackQueryV1::new(
            ObjectDigest::from_bytes([1; 32]),
            [2; 32],
            1,
            [3; 16],
            [4; 16],
            ObjectDigest::from_bytes([5; 32]),
            ObjectDigest::from_bytes([6; 32]),
        )
        .unwrap()
    }

    fn signer(key: &SigningKey) -> SourceProviderSigningKeyV1 {
        SourceProviderSigningKeyV1::for_signing_key(
            [3; 16],
            1,
            ObjectDigest::from_bytes([7; 32]),
            [8; 16],
            1,
            SourceProviderKeyUsageV1::ProviderOutcome,
            key,
        )
        .unwrap()
    }

    #[test]
    fn completed_readback_rejects_forked_query_and_response() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let query = query();
        let answer = SignedInventoryReadbackV1::sign(
            &query,
            Some((b"historical response".to_vec(), 10, 20)),
            signer(&key),
            &key,
        )
        .unwrap();
        let bytes = answer.to_canonical_bytes();
        let decoded = SignedInventoryReadbackV1::from_canonical_bytes(&bytes).unwrap();

        decoded
            .verify_for_query(&query, &signer(&key), &key.verifying_key().to_bytes())
            .unwrap();
        let wrong_key = SigningKey::from_bytes(&[10; 32]);
        assert!(
            decoded
                .verify_for_query(&query, &signer(&key), &wrong_key.verifying_key().to_bytes())
                .is_err()
        );
        let fork = InventoryReadbackQueryV1::new(
            query.session_binding(),
            [2; 32],
            2,
            query.authorities().0,
            query.authorities().1,
            query.signed_request_digest(),
            query.mount_attempt_record_digest(),
        )
        .unwrap();
        assert!(
            decoded
                .verify_for_query(&fork, &signer(&key), &key.verifying_key().to_bytes())
                .is_err()
        );
        let changed_mount_record = InventoryReadbackQueryV1::new(
            query.session_binding(),
            [2; 32],
            1,
            query.authorities().0,
            query.authorities().1,
            query.signed_request_digest(),
            ObjectDigest::from_bytes([11; 32]),
        )
        .unwrap();
        assert!(
            decoded
                .verify_for_query(
                    &changed_mount_record,
                    &signer(&key),
                    &key.verifying_key().to_bytes(),
                )
                .is_err()
        );

        let mut tampered = bytes;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(SignedInventoryReadbackV1::from_canonical_bytes(&tampered).is_err());

        let mut downgraded = answer.to_canonical_bytes();
        downgraded[196] = UNAVAILABLE;
        assert!(SignedInventoryReadbackV1::from_canonical_bytes(&downgraded).is_err());

        let mut oversized_length = answer.to_canonical_bytes();
        oversized_length[192..196].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(SignedInventoryReadbackV1::from_canonical_bytes(&oversized_length).is_err());
    }

    #[test]
    fn unavailable_readback_carries_no_historical_response() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let query = query();
        let answer = SignedInventoryReadbackV1::sign(&query, None, signer(&key), &key).unwrap();
        let decoded =
            SignedInventoryReadbackV1::from_canonical_bytes(&answer.to_canonical_bytes()).unwrap();

        decoded
            .verify_for_query(&query, &signer(&key), &key.verifying_key().to_bytes())
            .unwrap();
        assert!(decoded.completed().is_none());
        assert!(SignedInventoryReadbackV1::sign(
            &query,
            Some((Vec::new(), 10, 20)),
            signer(&key),
            &key,
        )
        .is_err());
    }

    #[test]
    fn completed_readback_carries_the_largest_legacy_response() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let query = query();
        let response = vec![42; MAXIMUM_FRAME_BYTES];
        let answer = SignedInventoryReadbackV1::sign(
            &query,
            Some((response.clone(), 10, 20)),
            signer(&key),
            &key,
        )
        .unwrap();
        let bytes = answer.to_canonical_bytes();

        assert_eq!(bytes.len(), MAXIMUM_INVENTORY_READBACK_PACKET_BYTES);
        let decoded = SignedInventoryReadbackV1::from_canonical_bytes(&bytes).unwrap();
        decoded
            .verify_for_query(&query, &signer(&key), &key.verifying_key().to_bytes())
            .unwrap();
        assert_eq!(decoded.completed().unwrap().0, response);

        let oversized = vec![42; MAXIMUM_FRAME_BYTES + 1];
        assert!(
            SignedInventoryReadbackV1::sign(&query, Some((oversized, 10, 20)), signer(&key), &key,)
                .is_err()
        );
    }
}
