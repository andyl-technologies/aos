//! Descriptor-free catalog-currentness exchange after the signed hello.
//!
//! This control record is deliberately separate from the SourceProvider 1.0
//! effect methods. It proves a fresh provider-journal head to one authenticated
//! Root Mount session, but does not authorize Acquire, Release, or Inventory.
//!
//! ```text
//! query:    AOSSPC01 || kind=1 || version=1 || reserved[6]=0 ||
//!           session[32] || nonce[32] || sequence:u64be ||
//!           minimum-generation:u64be || minimum-digest[32]
//! response: AOSSPC01 || kind=2 || version=1 || reserved[6]=0 ||
//!           session[32] || query-digest[32] || head-generation:u64be || head-digest[32] ||
//!           floor-generation:u64be || floor-digest[32] || head-commitment[32] ||
//!           publication-digest[32] || provider-outcome-signer[120] || signature[64]
//! ```

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

use crate::crypto::{
    SourceProviderKeyUsageV1, SourceProviderSignature, SourceProviderSignatureError,
    SourceProviderSigningKeyV1, decode_signer, encode_signer, sign_bytes, verify_bytes,
};

const MAGIC: &[u8; 8] = b"AOSSPC01";
const VERSION: u8 = 1;
const QUERY_KIND: u8 = 1;
const RESPONSE_KIND: u8 = 2;
const QUERY_BYTES: usize = 128;
const RESPONSE_SUBJECT_BYTES: usize = 224;
const RESPONSE_BYTES: usize = RESPONSE_SUBJECT_BYTES + 120 + 64;
const QUERY_DIGEST_DOMAIN: &[u8] = b"aos-source-provider-catalog-query-v1\0";
const RESPONSE_SIGNATURE_DOMAIN: &[u8] = b"aos-source-provider-catalog-currentness-v1\0";

/// Reports malformed, replayed, downgraded, or unauthenticated catalog control.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CatalogCurrentnessErrorV1 {
    /// A control record was not canonical or used a sentinel value.
    #[error("noncanonical catalog-currentness record")]
    Noncanonical,
    /// The response does not answer the exact live query and its floor.
    #[error("catalog-currentness response is stale or below the requested floor")]
    Stale,
    /// The provider outcome signature or signer is invalid.
    #[error("catalog-currentness signature failed: {0}")]
    Signature(#[from] SourceProviderSignatureError),
}

/// Challenges one provider session for an exact minimum catalog floor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogCurrentnessQueryV1 {
    session_binding: ObjectDigest,
    nonce: [u8; 32],
    sequence: u64,
    minimum_generation: u64,
    minimum_digest: ObjectDigest,
}

impl CatalogCurrentnessQueryV1 {
    /// Constructs one nonce-bound floor challenge.
    ///
    /// # Errors
    ///
    /// Rejects zero session, nonce, sequence, generation, or floor digest.
    pub fn new(
        session_binding: ObjectDigest,
        nonce: [u8; 32],
        sequence: u64,
        minimum_generation: u64,
        minimum_digest: ObjectDigest,
    ) -> Result<Self, CatalogCurrentnessErrorV1> {
        if session_binding.as_bytes() == &[0; 32]
            || nonce == [0; 32]
            || sequence == 0
            || minimum_generation == 0
            || minimum_digest.as_bytes() == &[0; 32]
        {
            return Err(CatalogCurrentnessErrorV1::Noncanonical);
        }
        Ok(Self {
            session_binding,
            nonce,
            sequence,
            minimum_generation,
            minimum_digest,
        })
    }

    /// Returns the exact authenticated session binding.
    #[must_use]
    pub const fn session_binding(&self) -> ObjectDigest {
        self.session_binding
    }

    /// Returns the strictly increasing session-local query sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the requested minimum catalog head.
    #[must_use]
    pub const fn minimum(&self) -> (u64, ObjectDigest) {
        (self.minimum_generation, self.minimum_digest)
    }

    /// Returns the canonical fixed-size control record.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> [u8; QUERY_BYTES] {
        let mut bytes = [0; QUERY_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = QUERY_KIND;
        bytes[9] = VERSION;
        bytes[16..48].copy_from_slice(self.session_binding.as_bytes());
        bytes[48..80].copy_from_slice(&self.nonce);
        bytes[80..88].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[88..96].copy_from_slice(&self.minimum_generation.to_be_bytes());
        bytes[96..128].copy_from_slice(self.minimum_digest.as_bytes());
        bytes
    }

    /// Decodes only the exact canonical query format.
    ///
    /// # Errors
    ///
    /// Rejects wrong length, version, kind, reserved bytes, or sentinels.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CatalogCurrentnessErrorV1> {
        require_header(bytes, QUERY_BYTES, QUERY_KIND)?;
        Self::new(
            digest_at(bytes, 16)?,
            array_at(bytes, 48)?,
            u64_at(bytes, 80)?,
            u64_at(bytes, 88)?,
            digest_at(bytes, 96)?,
        )
    }

    /// Commits the exact challenge bytes for a signed response.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        let mut hasher = Sha256::new();
        hasher.update(QUERY_DIGEST_DOMAIN);
        hasher.update(self.to_canonical_bytes());
        ObjectDigest::from_bytes(hasher.finalize().into())
    }
}

/// Carries one provider-signed current catalog head and protected floor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedCatalogCurrentnessV1 {
    session_binding: ObjectDigest,
    query_digest: ObjectDigest,
    head_generation: u64,
    head_digest: ObjectDigest,
    floor_generation: u64,
    floor_digest: ObjectDigest,
    head_commitment: ObjectDigest,
    publication_digest: ObjectDigest,
    signer: SourceProviderSigningKeyV1,
    signature: SourceProviderSignature,
}

impl SignedCatalogCurrentnessV1 {
    /// Signs an exact current provider-journal projection for one live query.
    ///
    /// This constructor is cryptographic only. The provider owner must derive
    /// every projection field from its current protected journal and signed
    /// publication immediately before calling it.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical or downgraded projection, wrong signer use, or
    /// signing key that differs from the committed signer reference.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        query: &CatalogCurrentnessQueryV1,
        head: (u64, ObjectDigest),
        floor: (u64, ObjectDigest),
        head_commitment: ObjectDigest,
        publication_digest: ObjectDigest,
        signer: SourceProviderSigningKeyV1,
        signing_key: &SigningKey,
    ) -> Result<Self, CatalogCurrentnessErrorV1> {
        let mut value = Self {
            session_binding: query.session_binding,
            query_digest: query.digest(),
            head_generation: head.0,
            head_digest: head.1,
            floor_generation: floor.0,
            floor_digest: floor.1,
            head_commitment,
            publication_digest,
            signer,
            signature: SourceProviderSignature::from_bytes([0; 64]),
        };
        value.require_projection(query)?;
        if value.signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome {
            return Err(CatalogCurrentnessErrorV1::Noncanonical);
        }
        value.signature = sign_bytes(
            RESPONSE_SIGNATURE_DOMAIN,
            RESPONSE_KIND,
            &value.subject_bytes(),
            &value.signer,
            signing_key,
        )?;
        Ok(value)
    }

    /// Verifies one exact fresh response with the configured provider key.
    ///
    /// # Errors
    ///
    /// Rejects a different query, session, floor, signer, or signature.
    pub fn verify_for_query(
        &self,
        query: &CatalogCurrentnessQueryV1,
        expected_signer: &SourceProviderSigningKeyV1,
        public_key: &[u8; 32],
    ) -> Result<(), CatalogCurrentnessErrorV1> {
        self.require_projection(query)?;
        if self.signer != *expected_signer
            || self.signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
        {
            return Err(CatalogCurrentnessErrorV1::Stale);
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

    /// Returns the authenticated current head.
    #[must_use]
    pub const fn head(&self) -> (u64, ObjectDigest) {
        (self.head_generation, self.head_digest)
    }

    /// Returns the authenticated retained floor.
    #[must_use]
    pub const fn floor(&self) -> (u64, ObjectDigest) {
        (self.floor_generation, self.floor_digest)
    }

    /// Returns the exact protected head commitment.
    #[must_use]
    pub const fn head_commitment(&self) -> ObjectDigest {
        self.head_commitment
    }

    /// Returns the signed publication artifact digest.
    #[must_use]
    pub const fn publication_digest(&self) -> ObjectDigest {
        self.publication_digest
    }

    /// Returns the exact canonical response including signer and signature.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.subject_bytes();
        encode_signer(&mut bytes, &self.signer);
        bytes.extend_from_slice(self.signature.as_bytes());
        bytes
    }

    /// Decodes only the exact canonical response format.
    ///
    /// # Errors
    ///
    /// Rejects wrong length, version, kind, reserved bytes, or signer encoding.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CatalogCurrentnessErrorV1> {
        require_header(bytes, RESPONSE_BYTES, RESPONSE_KIND)?;
        let signer = decode_signer(&bytes[RESPONSE_SUBJECT_BYTES..RESPONSE_SUBJECT_BYTES + 120])?;
        Ok(Self {
            session_binding: digest_at(bytes, 16)?,
            query_digest: digest_at(bytes, 48)?,
            head_generation: u64_at(bytes, 80)?,
            head_digest: digest_at(bytes, 88)?,
            floor_generation: u64_at(bytes, 120)?,
            floor_digest: digest_at(bytes, 128)?,
            head_commitment: digest_at(bytes, 160)?,
            publication_digest: digest_at(bytes, 192)?,
            signer,
            signature: SourceProviderSignature::from_bytes(array_at(bytes, 344)?),
        })
    }

    fn require_projection(
        &self,
        query: &CatalogCurrentnessQueryV1,
    ) -> Result<(), CatalogCurrentnessErrorV1> {
        if self.session_binding != query.session_binding
            || self.query_digest != query.digest()
            || self.head_generation == 0
            || self.head_digest.as_bytes() == &[0; 32]
            || self.floor_generation == 0
            || self.floor_generation > self.head_generation
            || self.floor_digest.as_bytes() == &[0; 32]
            || self.head_commitment.as_bytes() == &[0; 32]
            || self.publication_digest.as_bytes() == &[0; 32]
            || self.head_generation < query.minimum_generation
            || (self.head_generation == query.minimum_generation
                && self.head_digest != query.minimum_digest)
            || self.floor_generation < query.minimum_generation
            || (self.floor_generation == query.minimum_generation
                && self.floor_digest != query.minimum_digest)
            || (self.floor_generation == self.head_generation
                && self.floor_digest != self.head_digest)
        {
            return Err(CatalogCurrentnessErrorV1::Stale);
        }
        Ok(())
    }

    fn subject_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RESPONSE_SUBJECT_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.push(RESPONSE_KIND);
        bytes.push(VERSION);
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(self.session_binding.as_bytes());
        bytes.extend_from_slice(self.query_digest.as_bytes());
        bytes.extend_from_slice(&self.head_generation.to_be_bytes());
        bytes.extend_from_slice(self.head_digest.as_bytes());
        bytes.extend_from_slice(&self.floor_generation.to_be_bytes());
        bytes.extend_from_slice(self.floor_digest.as_bytes());
        bytes.extend_from_slice(self.head_commitment.as_bytes());
        bytes.extend_from_slice(self.publication_digest.as_bytes());
        bytes
    }
}

fn require_header(bytes: &[u8], length: usize, kind: u8) -> Result<(), CatalogCurrentnessErrorV1> {
    if bytes.len() != length
        || &bytes[..8] != MAGIC
        || bytes[8] != kind
        || bytes[9] != VERSION
        || bytes[10..16] != [0; 6]
    {
        return Err(CatalogCurrentnessErrorV1::Noncanonical);
    }
    Ok(())
}

fn array_at<const N: usize>(
    bytes: &[u8],
    start: usize,
) -> Result<[u8; N], CatalogCurrentnessErrorV1> {
    bytes
        .get(start..start + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(CatalogCurrentnessErrorV1::Noncanonical)
}

fn digest_at(bytes: &[u8], start: usize) -> Result<ObjectDigest, CatalogCurrentnessErrorV1> {
    Ok(ObjectDigest::from_bytes(array_at(bytes, start)?))
}

fn u64_at(bytes: &[u8], start: usize) -> Result<u64, CatalogCurrentnessErrorV1> {
    Ok(u64::from_be_bytes(array_at(bytes, start)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn signer(key: &SigningKey) -> SourceProviderSigningKeyV1 {
        SourceProviderSigningKeyV1::new(
            [1; 16],
            1,
            digest(2),
            [3; 16],
            1,
            ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
            SourceProviderKeyUsageV1::ProviderOutcome,
        )
        .unwrap()
    }

    #[test]
    fn currentness_round_trip_is_exact_and_fresh() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let query = CatalogCurrentnessQueryV1::new(digest(1), [2; 32], 1, 4, digest(4)).unwrap();
        let decoded_query =
            CatalogCurrentnessQueryV1::from_canonical_bytes(&query.to_canonical_bytes()).unwrap();
        assert_eq!(decoded_query, query);

        let response = SignedCatalogCurrentnessV1::sign(
            &query,
            (5, digest(5)),
            (4, digest(4)),
            digest(6),
            digest(7),
            signer(&key),
            &key,
        )
        .unwrap();
        let decoded =
            SignedCatalogCurrentnessV1::from_canonical_bytes(&response.to_canonical_bytes())
                .unwrap();
        decoded
            .verify_for_query(&query, &signer(&key), key.verifying_key().as_bytes())
            .unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn response_replay_under_new_nonce_is_rejected() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let first = CatalogCurrentnessQueryV1::new(digest(1), [2; 32], 1, 4, digest(4)).unwrap();
        let second = CatalogCurrentnessQueryV1::new(digest(1), [3; 32], 2, 4, digest(4)).unwrap();
        let response = SignedCatalogCurrentnessV1::sign(
            &first,
            (5, digest(5)),
            (4, digest(4)),
            digest(6),
            digest(7),
            signer(&key),
            &key,
        )
        .unwrap();

        assert_eq!(
            response.verify_for_query(&second, &signer(&key), key.verifying_key().as_bytes()),
            Err(CatalogCurrentnessErrorV1::Stale)
        );
    }

    #[test]
    fn lower_floor_and_tampered_head_are_rejected() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let query = CatalogCurrentnessQueryV1::new(digest(1), [2; 32], 1, 4, digest(4)).unwrap();
        assert_eq!(
            SignedCatalogCurrentnessV1::sign(
                &query,
                (5, digest(5)),
                (3, digest(3)),
                digest(6),
                digest(7),
                signer(&key),
                &key,
            ),
            Err(CatalogCurrentnessErrorV1::Stale)
        );

        let response = SignedCatalogCurrentnessV1::sign(
            &query,
            (5, digest(5)),
            (4, digest(4)),
            digest(6),
            digest(7),
            signer(&key),
            &key,
        )
        .unwrap();
        let mut bytes = response.to_canonical_bytes();
        bytes[88] ^= 1;
        let tampered = SignedCatalogCurrentnessV1::from_canonical_bytes(&bytes).unwrap();
        assert!(matches!(
            tampered.verify_for_query(&query, &signer(&key), key.verifying_key().as_bytes()),
            Err(CatalogCurrentnessErrorV1::Signature(_))
        ));
    }
}
