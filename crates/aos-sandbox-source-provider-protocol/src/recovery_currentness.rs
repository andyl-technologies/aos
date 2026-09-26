//! Descriptor-free recovery of one original selected Acquire attempt.
//!
//! A new authenticated carrier may query an old protected attempt, but this
//! format cannot carry a lease, descriptor, or successful Acquire result. The
//! signed response is an explicit unavailable observation, not an old-session
//! SourceProvider response or permission to create a successor attempt.
//!
//! ```text
//! query: AOSSPR01 | kind=1 | version=1 | reserved[6]=0 |
//!        new-session[32] | nonce[32] | sequence:u64be |
//!        provider-id[16] | holder-id[16] | acquisition-id[32] |
//!        original-signed-request-digest[32] | mount-attempt-record-digest[32]
//! response: AOSSPR01 | kind=2 | version=1 | reserved[6]=0 |
//!        new-session[32] | query-digest[32] | acquisition-id[32] |
//!        original-signed-request-digest[32] | mount-attempt-record-digest[32] |
//!        signed-storage-plan-digest[32] | status:u8=1 | reserved[7]=0 |
//!        provider-outcome-signer[120] | signature[64]
//! ```

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

use crate::crypto::{
    SourceProviderKeyUsageV1, SourceProviderSignature, SourceProviderSignatureError,
    SourceProviderSigningKeyV1, decode_signer, encode_signer, sign_bytes, verify_bytes,
};

const MAGIC: &[u8; 8] = b"AOSSPR01";
const VERSION: u8 = 1;
const QUERY_KIND: u8 = 1;
const RESPONSE_KIND: u8 = 2;
const QUERY_BYTES: usize = 216;
const RESPONSE_SUBJECT_BYTES: usize = 216;
const RESPONSE_BYTES: usize = RESPONSE_SUBJECT_BYTES + 120 + 64;
const UNAVAILABLE_STATUS: u8 = 1;
const QUERY_DIGEST_DOMAIN: &[u8] = b"aos-source-provider-recovery-query-v1\0";
const RESPONSE_SIGNATURE_DOMAIN: &[u8] = b"aos-source-provider-recovery-unavailable-v1\0";

/// Rejects malformed, stale, or unauthenticated recovery control records.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecoveryCurrentnessErrorV1 {
    /// The packet is not the exact canonical version-one format.
    #[error("noncanonical SourceProvider recovery record")]
    Noncanonical,
    /// The response is not bound to the exact live original-attempt query.
    #[error("SourceProvider recovery response does not match the query")]
    Stale,
    /// The Provider outcome signature or signer is invalid.
    #[error("SourceProvider recovery signature failed: {0}")]
    Signature(#[from] SourceProviderSignatureError),
}

/// Challenges one new session about an exact original Acquire attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCurrentnessQueryV1 {
    session_binding: ObjectDigest,
    nonce: [u8; 32],
    sequence: u64,
    provider_id: [u8; 16],
    holder_id: [u8; 16],
    acquisition_id: ObjectDigest,
    original_signed_request_digest: ObjectDigest,
    original_attempt_digest: ObjectDigest,
}

impl RecoveryCurrentnessQueryV1 {
    /// Constructs a nonauthorizing, nonce-bound original-attempt query.
    ///
    /// # Errors
    ///
    /// Rejects zero identity, nonce, sequence, or digest fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_binding: ObjectDigest,
        nonce: [u8; 32],
        sequence: u64,
        provider_id: [u8; 16],
        holder_id: [u8; 16],
        acquisition_id: ObjectDigest,
        original_signed_request_digest: ObjectDigest,
        original_attempt_digest: ObjectDigest,
    ) -> Result<Self, RecoveryCurrentnessErrorV1> {
        if session_binding.as_bytes() == &[0; 32]
            || nonce == [0; 32]
            || sequence == 0
            || provider_id == [0; 16]
            || holder_id == [0; 16]
            || acquisition_id.as_bytes() == &[0; 32]
            || original_signed_request_digest.as_bytes() == &[0; 32]
            || original_attempt_digest.as_bytes() == &[0; 32]
        {
            return Err(RecoveryCurrentnessErrorV1::Noncanonical);
        }
        Ok(Self {
            session_binding,
            nonce,
            sequence,
            provider_id,
            holder_id,
            acquisition_id,
            original_signed_request_digest,
            original_attempt_digest,
        })
    }

    /// Returns the new authenticated session binding.
    #[must_use]
    pub const fn session_binding(&self) -> ObjectDigest {
        self.session_binding
    }

    /// Returns the strictly increasing query sequence on this carrier.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the original Provider and RootMount authority IDs.
    #[must_use]
    pub const fn authorities(&self) -> ([u8; 16], [u8; 16]) {
        (self.provider_id, self.holder_id)
    }

    /// Returns the original acquisition ID.
    #[must_use]
    pub const fn acquisition_id(&self) -> ObjectDigest {
        self.acquisition_id
    }

    /// Returns the original signed RootMount request digest.
    #[must_use]
    pub const fn original_signed_request_digest(&self) -> ObjectDigest {
        self.original_signed_request_digest
    }

    /// Returns the original protected Mount attempt record digest.
    #[must_use]
    pub const fn original_attempt_digest(&self) -> ObjectDigest {
        self.original_attempt_digest
    }

    /// Encodes the exact fixed-size query.
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
        bytes[120..152].copy_from_slice(self.acquisition_id.as_bytes());
        bytes[152..184].copy_from_slice(self.original_signed_request_digest.as_bytes());
        bytes[184..216].copy_from_slice(self.original_attempt_digest.as_bytes());
        bytes
    }

    /// Decodes only one canonical query packet.
    ///
    /// # Errors
    ///
    /// Rejects changed kind, version, size, reserved bytes, or sentinels.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RecoveryCurrentnessErrorV1> {
        require_header(bytes, QUERY_BYTES, QUERY_KIND)?;
        Self::new(
            digest_at(bytes, 16)?,
            array_at(bytes, 48)?,
            u64_at(bytes, 80)?,
            array_at(bytes, 88)?,
            array_at(bytes, 104)?,
            digest_at(bytes, 120)?,
            digest_at(bytes, 152)?,
            digest_at(bytes, 184)?,
        )
    }

    /// Commits every challenge byte for the signed response.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        let mut hasher = Sha256::new();
        hasher.update(QUERY_DIGEST_DOMAIN);
        hasher.update(self.to_canonical_bytes());
        ObjectDigest::from_bytes(hasher.finalize().into())
    }
}

/// Signs a descriptor-free Unavailable result for the exact old attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedRecoveryUnavailableV1 {
    session_binding: ObjectDigest,
    query_digest: ObjectDigest,
    acquisition_id: ObjectDigest,
    original_signed_request_digest: ObjectDigest,
    original_attempt_digest: ObjectDigest,
    signed_storage_plan_digest: ObjectDigest,
    signer: SourceProviderSigningKeyV1,
    signature: SourceProviderSignature,
}

impl SignedRecoveryUnavailableV1 {
    /// Signs only the response shape; protected journal/readback is caller-owned.
    ///
    /// # Errors
    ///
    /// Rejects a zero plan digest, wrong-use signer, or key mismatch.
    pub fn sign(
        query: &RecoveryCurrentnessQueryV1,
        signed_storage_plan_digest: ObjectDigest,
        signer: SourceProviderSigningKeyV1,
        signing_key: &SigningKey,
    ) -> Result<Self, RecoveryCurrentnessErrorV1> {
        if signed_storage_plan_digest.as_bytes() == &[0; 32]
            || signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
            || signer.authority_id() != query.authorities().0
        {
            return Err(RecoveryCurrentnessErrorV1::Noncanonical);
        }
        let mut value = Self {
            session_binding: query.session_binding,
            query_digest: query.digest(),
            acquisition_id: query.acquisition_id,
            original_signed_request_digest: query.original_signed_request_digest,
            original_attempt_digest: query.original_attempt_digest,
            signed_storage_plan_digest,
            signer,
            signature: SourceProviderSignature::from_bytes([0; 64]),
        };
        value.signature = sign_bytes(
            RESPONSE_SIGNATURE_DOMAIN,
            RESPONSE_KIND,
            &value.subject_bytes(),
            &value.signer,
            signing_key,
        )?;
        Ok(value)
    }

    /// Verifies the exact challenge and independently pinned Provider key.
    ///
    /// # Errors
    ///
    /// Rejects another query, signer, status, or signature.
    pub fn verify_for_query(
        &self,
        query: &RecoveryCurrentnessQueryV1,
        expected_signer: &SourceProviderSigningKeyV1,
        public_key: &[u8; 32],
    ) -> Result<(), RecoveryCurrentnessErrorV1> {
        if self.session_binding != query.session_binding
            || self.query_digest != query.digest()
            || self.acquisition_id != query.acquisition_id
            || self.original_signed_request_digest != query.original_signed_request_digest
            || self.original_attempt_digest != query.original_attempt_digest
            || self.signed_storage_plan_digest.as_bytes() == &[0; 32]
            || &self.signer != expected_signer
            || self.signer.authority_id() != query.authorities().0
        {
            return Err(RecoveryCurrentnessErrorV1::Stale);
        }
        verify_bytes(
            RESPONSE_SIGNATURE_DOMAIN,
            RESPONSE_KIND,
            &self.subject_bytes(),
            &self.signer,
            &self.signature,
            public_key,
        )?;
        Ok(())
    }

    /// Returns the exact signed Storage plan observed before this result.
    #[must_use]
    pub const fn signed_storage_plan_digest(&self) -> ObjectDigest {
        self.signed_storage_plan_digest
    }

    /// Encodes the only accepted signed recovery result.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.subject_bytes();
        encode_signer(&mut bytes, &self.signer);
        bytes.extend_from_slice(self.signature.as_bytes());
        bytes
    }

    /// Decodes one canonical signed Unavailable result.
    ///
    /// # Errors
    ///
    /// Rejects changed size, version, status, reserved bytes, or signer.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RecoveryCurrentnessErrorV1> {
        require_header(bytes, RESPONSE_BYTES, RESPONSE_KIND)?;
        if bytes[208] != UNAVAILABLE_STATUS || bytes[209..216] != [0; 7] {
            return Err(RecoveryCurrentnessErrorV1::Noncanonical);
        }
        let signer = decode_signer(&bytes[216..336])?;
        if signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome {
            return Err(RecoveryCurrentnessErrorV1::Noncanonical);
        }
        let value = Self {
            session_binding: digest_at(bytes, 16)?,
            query_digest: digest_at(bytes, 48)?,
            acquisition_id: digest_at(bytes, 80)?,
            original_signed_request_digest: digest_at(bytes, 112)?,
            original_attempt_digest: digest_at(bytes, 144)?,
            signed_storage_plan_digest: digest_at(bytes, 176)?,
            signer,
            signature: SourceProviderSignature::from_bytes(array_at(bytes, 336)?),
        };
        if value.session_binding.as_bytes() == &[0; 32]
            || value.query_digest.as_bytes() == &[0; 32]
            || value.acquisition_id.as_bytes() == &[0; 32]
            || value.original_signed_request_digest.as_bytes() == &[0; 32]
            || value.original_attempt_digest.as_bytes() == &[0; 32]
            || value.signed_storage_plan_digest.as_bytes() == &[0; 32]
            || value.to_canonical_bytes().as_slice() != bytes
        {
            return Err(RecoveryCurrentnessErrorV1::Noncanonical);
        }
        Ok(value)
    }

    fn subject_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RESPONSE_SUBJECT_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.push(RESPONSE_KIND);
        bytes.push(VERSION);
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(self.session_binding.as_bytes());
        bytes.extend_from_slice(self.query_digest.as_bytes());
        bytes.extend_from_slice(self.acquisition_id.as_bytes());
        bytes.extend_from_slice(self.original_signed_request_digest.as_bytes());
        bytes.extend_from_slice(self.original_attempt_digest.as_bytes());
        bytes.extend_from_slice(self.signed_storage_plan_digest.as_bytes());
        bytes.push(UNAVAILABLE_STATUS);
        bytes.extend_from_slice(&[0; 7]);
        bytes
    }
}

fn require_header(bytes: &[u8], length: usize, kind: u8) -> Result<(), RecoveryCurrentnessErrorV1> {
    if bytes.len() != length
        || &bytes[..8] != MAGIC
        || bytes[8] != kind
        || bytes[9] != VERSION
        || bytes[10..16] != [0; 6]
    {
        return Err(RecoveryCurrentnessErrorV1::Noncanonical);
    }
    Ok(())
}

fn array_at<const N: usize>(
    bytes: &[u8],
    start: usize,
) -> Result<[u8; N], RecoveryCurrentnessErrorV1> {
    bytes
        .get(start..start + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(RecoveryCurrentnessErrorV1::Noncanonical)
}

fn digest_at(bytes: &[u8], start: usize) -> Result<ObjectDigest, RecoveryCurrentnessErrorV1> {
    Ok(ObjectDigest::from_bytes(array_at(bytes, start)?))
}

fn u64_at(bytes: &[u8], start: usize) -> Result<u64, RecoveryCurrentnessErrorV1> {
    Ok(u64::from_be_bytes(array_at(bytes, start)?))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn query() -> RecoveryCurrentnessQueryV1 {
        RecoveryCurrentnessQueryV1::new(
            digest(1),
            [2; 32],
            3,
            [4; 16],
            [5; 16],
            digest(6),
            digest(7),
            digest(8),
        )
        .unwrap()
    }

    fn signed(query: &RecoveryCurrentnessQueryV1) -> SignedRecoveryUnavailableV1 {
        let key = SigningKey::from_bytes(&[9; 32]);
        let signer = SourceProviderSigningKeyV1::for_signing_key(
            [4; 16],
            10,
            digest(11),
            [12; 16],
            13,
            SourceProviderKeyUsageV1::ProviderOutcome,
            &key,
        )
        .unwrap();
        SignedRecoveryUnavailableV1::sign(query, digest(14), signer, &key).unwrap()
    }

    #[test]
    fn exact_query_response_roundtrip_and_signature() {
        let query = query();
        let decoded_query =
            RecoveryCurrentnessQueryV1::from_canonical_bytes(&query.to_canonical_bytes()).unwrap();
        assert_eq!(decoded_query, query);

        let response = signed(&query);
        let decoded =
            SignedRecoveryUnavailableV1::from_canonical_bytes(&response.to_canonical_bytes())
                .unwrap();
        let key = SigningKey::from_bytes(&[9; 32]);
        decoded
            .verify_for_query(&query, &response.signer, key.verifying_key().as_bytes())
            .unwrap();
        assert_eq!(decoded.signed_storage_plan_digest(), digest(14));
    }

    #[test]
    fn replay_fork_downgrade_and_status_tamper_fail() {
        let query = query();
        let response = signed(&query);
        let key = SigningKey::from_bytes(&[9; 32]);
        let changed = RecoveryCurrentnessQueryV1::new(
            digest(1),
            [3; 32],
            3,
            [4; 16],
            [5; 16],
            digest(6),
            digest(7),
            digest(8),
        )
        .unwrap();
        assert!(
            response
                .verify_for_query(&changed, &response.signer, key.verifying_key().as_bytes())
                .is_err()
        );
        let old_session = RecoveryCurrentnessQueryV1::new(
            digest(15),
            [2; 32],
            3,
            [4; 16],
            [5; 16],
            digest(6),
            digest(7),
            digest(8),
        )
        .unwrap();
        assert!(
            response
                .verify_for_query(
                    &old_session,
                    &response.signer,
                    key.verifying_key().as_bytes()
                )
                .is_err()
        );
        let forked_attempt = RecoveryCurrentnessQueryV1::new(
            digest(1),
            [2; 32],
            3,
            [4; 16],
            [5; 16],
            digest(6),
            digest(7),
            digest(16),
        )
        .unwrap();
        assert!(
            response
                .verify_for_query(
                    &forked_attempt,
                    &response.signer,
                    key.verifying_key().as_bytes()
                )
                .is_err()
        );

        let mut bytes = response.to_canonical_bytes();
        bytes[208] = 2;
        assert!(SignedRecoveryUnavailableV1::from_canonical_bytes(&bytes).is_err());
        let mut bytes = response.to_canonical_bytes();
        bytes[176] ^= 1;
        let forged = SignedRecoveryUnavailableV1::from_canonical_bytes(&bytes).unwrap();
        assert!(
            forged
                .verify_for_query(&query, &response.signer, key.verifying_key().as_bytes())
                .is_err()
        );
        let mut bytes = query.to_canonical_bytes();
        bytes[10] = 1;
        assert!(RecoveryCurrentnessQueryV1::from_canonical_bytes(&bytes).is_err());
        let mut bytes = query.to_canonical_bytes().to_vec();
        bytes.push(0);
        assert!(RecoveryCurrentnessQueryV1::from_canonical_bytes(&bytes).is_err());
    }
}
