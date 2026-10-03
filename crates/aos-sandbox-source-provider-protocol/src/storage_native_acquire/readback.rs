//! Authenticated historical acceptance metadata, without positive Acquire authority.
//!
//! A fresh ProviderOutcome carrier queries the exact original signed request,
//! independently of that request's old key, session, nonce, or expiry. Storage
//! returns only its original unsigned V3 acceptance, including for a tombstoned
//! row. Neither answer renews a receipt, proves current custody, nor authorizes
//! a descriptor send, retirement, remount, or positive Acquire completion.
//!
//! ```text
//! AOSZNR01 | version:u16be=1 | reserved[6]=0 |
//! carrier-binding[32] | nonce[32] | metadata-sequence:u64be |
//! provider-id[16] | historical-holder-id[16] | acquisition-id[32] |
//! original-signed-native-request-digest[32] |
//! ProviderOutcome-signer[120] | signature[64]
//! AOSZNS01 | version:u16be=1 | reserved[6]=0 |
//! signed-readback-query-digest[32] | observed-issuance-sequence:u64be |
//! disposition:u8=Found(1)/NotFound(2) | reserved[7]=0 |
//! original-unsigned-AOSZNA03[216] (all zero for NotFound) |
//! AOSZHSG1-signer[88] | signature[64]
//! ```
//!
//! The Storage owner must hold its protected readback cut through the reply
//! and reject an occupied provider/acquisition key with a different historical
//! holder or signed request digest. It must not disguise that conflict as
//! NotFound. NotFound observes only that cut: it is never a permanent absence
//! proof, because this exchange does not fence future admission.
//!
//! These scalar codecs do not authenticate a current carrier, perform owner
//! lookup, or establish freshness themselves. Consumers must independently pin
//! the current Provider and Storage roles and enforce exact peer, record,
//! cgroup, and zero-descriptor transport checks. Historical request signatures
//! must retain their original byte identity across key rotation; this exchange
//! neither re-signs those bytes nor reconstructs a positive signed acceptance.
//!
//! The metadata sequence and nonce correlate an outstanding query only. They
//! are not a global replay fence or a claim of latest-state freshness, and this
//! read-only exchange requires no new durable admission allocator or journal.
//! An identical query may reobserve a different held cut. Reply verification
//! authenticates an observation, not currentness: consumers must not promote a
//! cached or replayed negative into permanent absence or retirement authority.

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::{Signer as _, SigningKey};

use super::acceptance::{storage_signing_message, verify_storage_signature};
use super::{
    Reader, STORAGE_NATIVE_ACCEPTANCE_BYTES_V3, SignedStorageNativeAcquireRequestV2,
    StorageNativeAcceptanceV3, StorageNativeAcquireErrorV2, digest, nonzero, versioned_header,
};
use crate::crypto::{decode_signer, encode_signer, sign_bytes, verify_bytes};
use crate::{
    SourceProviderKeyUsageV1, SourceProviderSignature, SourceProviderSigningKeyV1,
    StorageZfsHoldSignerV1, StorageZfsHoldVerifierV1,
};

const VERSION: u16 = 1;
const QUERY_MAGIC: &[u8; 8] = b"AOSZNR01";
const ANSWER_MAGIC: &[u8; 8] = b"AOSZNS01";
const QUERY_BYTES: usize = 184;
const ANSWER_BYTES: usize = 64 + STORAGE_NATIVE_ACCEPTANCE_BYTES_V3;
const FOUND: u8 = 1;
const NOT_FOUND: u8 = 2;
const QUERY_SIGNATURE_DOMAIN: &[u8] =
    b"aos.sandbox.provider.native-acceptance-readback.query.signature.v1\0";
const QUERY_DIGEST_DOMAIN: &[u8] =
    b"aos.sandbox.provider.native-acceptance-readback.query.digest.v1\0";
const ANSWER_SIGNATURE_DOMAIN: &[u8] =
    b"aos.sandbox.storage.native-acceptance-readback.answer.signature.v1\0";
const ANSWER_DIGEST_DOMAIN: &[u8] =
    b"aos.sandbox.storage.native-acceptance-readback.answer.digest.v1\0";

/// Gives the exact descriptor-free signed metadata query width.
pub const SIGNED_STORAGE_NATIVE_ACCEPTANCE_READBACK_QUERY_BYTES_V1: usize = 368;

/// Gives the exact descriptor-free signed metadata answer width.
pub const SIGNED_STORAGE_NATIVE_ACCEPTANCE_READBACK_BYTES_V1: usize = 432;

const _: () =
    assert!(SIGNED_STORAGE_NATIVE_ACCEPTANCE_READBACK_QUERY_BYTES_V1 == QUERY_BYTES + 184);
const _: () = assert!(SIGNED_STORAGE_NATIVE_ACCEPTANCE_READBACK_BYTES_V1 == ANSWER_BYTES + 152);

/// Names an immutable original acquisition over an independent metadata carrier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageNativeAcceptanceReadbackQueryV1 {
    carrier_binding: ObjectDigest,
    nonce: [u8; 32],
    sequence: u64,
    provider_id: [u8; 16],
    holder_id: [u8; 16],
    acquisition_id: ObjectDigest,
    request_digest: ObjectDigest,
}

impl StorageNativeAcceptanceReadbackQueryV1 {
    /// Constructs a metadata query from the original signed request bytes.
    ///
    /// The carrier sequence, binding, and nonce belong only to this readback;
    /// they do not replace either original Acquire sequence or challenge.
    ///
    /// # Errors
    ///
    /// Rejects zero carrier or original identity sentinels.
    pub fn new(
        sequence: u64,
        carrier_binding: ObjectDigest,
        nonce: [u8; 32],
        original: &SignedStorageNativeAcquireRequestV2,
    ) -> Result<Self, StorageNativeAcquireErrorV2> {
        let claims = original.request().claims();
        let value = Self {
            carrier_binding,
            nonce,
            sequence,
            provider_id: claims.provider_acquisition().0,
            holder_id: claims.holder_session().0,
            acquisition_id: claims.provider_acquisition().1,
            request_digest: original.digest(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Returns the correlation-only metadata sequence, carrier binding, and nonce.
    #[must_use]
    pub const fn carrier(&self) -> (u64, ObjectDigest, [u8; 32]) {
        (self.sequence, self.carrier_binding, self.nonce)
    }

    /// Returns the original Provider, historical holder, and acquisition identity.
    #[must_use]
    pub const fn scope(&self) -> ([u8; 16], [u8; 16], ObjectDigest) {
        (self.provider_id, self.holder_id, self.acquisition_id)
    }

    /// Returns the digest of the exact original signed native request bytes.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(QUERY_BYTES);
        versioned_header(&mut bytes, QUERY_MAGIC, VERSION);
        bytes.extend_from_slice(self.carrier_binding.as_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.provider_id);
        bytes.extend_from_slice(&self.holder_id);
        bytes.extend_from_slice(self.acquisition_id.as_bytes());
        bytes.extend_from_slice(self.request_digest.as_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, StorageNativeAcquireErrorV2> {
        if bytes.len() != QUERY_BYTES {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        let mut reader = Reader::versioned(bytes, QUERY_MAGIC, VERSION)?;
        let value = Self {
            carrier_binding: reader.digest()?,
            nonce: reader.take()?,
            sequence: reader.u64()?,
            provider_id: reader.take()?,
            holder_id: reader.take()?,
            acquisition_id: reader.digest()?,
            request_digest: reader.digest()?,
        };
        reader.done()?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), StorageNativeAcquireErrorV2> {
        if !nonzero(self.carrier_binding)
            || self.nonce == [0; 32]
            || self.sequence == 0
            || self.provider_id == [0; 16]
            || self.holder_id == [0; 16]
            || !nonzero(self.acquisition_id)
            || !nonzero(self.request_digest)
        {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        Ok(())
    }
}

/// Authenticates only an exact historical metadata query with ProviderOutcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedStorageNativeAcceptanceReadbackQueryV1 {
    query: StorageNativeAcceptanceReadbackQueryV1,
    signer: SourceProviderSigningKeyV1,
    signature: SourceProviderSignature,
}

impl SignedStorageNativeAcceptanceReadbackQueryV1 {
    /// Signs metadata intent with the Provider's current outcome role.
    ///
    /// # Errors
    ///
    /// Rejects a foreign Provider authority, wrong key usage, or mismatched key.
    pub fn sign(
        query: StorageNativeAcceptanceReadbackQueryV1,
        signer: SourceProviderSigningKeyV1,
        key: &SigningKey,
    ) -> Result<Self, StorageNativeAcquireErrorV2> {
        if signer.authority_id() != query.provider_id
            || signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
        {
            return Err(StorageNativeAcquireErrorV2::Authority);
        }
        let signature = sign_bytes(QUERY_SIGNATURE_DOMAIN, 1, &query.encode(), &signer, key)
            .map_err(|_| StorageNativeAcquireErrorV2::Authority)?;
        Ok(Self {
            query,
            signer,
            signature,
        })
    }

    /// Returns the claimed original scope and independent metadata carrier.
    #[must_use]
    pub const fn query(&self) -> &StorageNativeAcceptanceReadbackQueryV1 {
        &self.query
    }

    /// Returns the claimed current Provider signer for independent pinning.
    #[must_use]
    pub const fn signer(&self) -> &SourceProviderSigningKeyV1 {
        &self.signer
    }

    /// Encodes the sole fixed-width signed metadata query representation.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.query.encode();
        encode_signer(&mut bytes, &self.signer);
        bytes.extend_from_slice(self.signature.as_bytes());
        bytes
    }

    /// Decodes a metadata query without authenticating its carrier or claims.
    ///
    /// # Errors
    ///
    /// Rejects wrong framing, size, sentinels, signer role, or zero signature.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StorageNativeAcquireErrorV2> {
        if bytes.len() != SIGNED_STORAGE_NATIVE_ACCEPTANCE_READBACK_QUERY_BYTES_V1 {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        let query = StorageNativeAcceptanceReadbackQueryV1::decode(&bytes[..QUERY_BYTES])?;
        let signer = decode_signer(&bytes[QUERY_BYTES..QUERY_BYTES + 120])
            .map_err(|_| StorageNativeAcquireErrorV2::Noncanonical)?;
        let signature = SourceProviderSignature::from_bytes(
            bytes[QUERY_BYTES + 120..]
                .try_into()
                .map_err(|_| StorageNativeAcquireErrorV2::Noncanonical)?,
        );
        if signer.authority_id() != query.provider_id
            || signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
            || signature.as_bytes() == &[0; 64]
        {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        Ok(Self {
            query,
            signer,
            signature,
        })
    }

    /// Verifies an independently pinned current Provider signer and key.
    ///
    /// This does not verify the original Acquire or establish carrier freshness.
    ///
    /// # Errors
    ///
    /// Rejects a different signer, key, signature, or signing purpose.
    pub fn verify(
        &self,
        expected_signer: &SourceProviderSigningKeyV1,
        key: &[u8; 32],
    ) -> Result<(), StorageNativeAcquireErrorV2> {
        if &self.signer != expected_signer {
            return Err(StorageNativeAcquireErrorV2::Authority);
        }
        verify_bytes(
            QUERY_SIGNATURE_DOMAIN,
            1,
            &self.query.encode(),
            &self.signer,
            &self.signature,
            key,
        )
        .map_err(|_| StorageNativeAcquireErrorV2::Authority)
    }

    /// Commits exact signed query bytes under the metadata-only digest domain.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        digest(QUERY_DIGEST_DOMAIN, &self.to_canonical_bytes())
    }
}

/// Authenticates an observational Storage readback without any live capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedStorageNativeAcceptanceReadbackV1 {
    query_digest: ObjectDigest,
    observed_issuance_sequence: u64,
    acceptance: Option<StorageNativeAcceptanceV3>,
    signer: StorageZfsHoldSignerV1,
    signature: [u8; 64],
}

impl SignedStorageNativeAcceptanceReadbackV1 {
    /// Signs claimed historical metadata with the existing dedicated Storage role.
    ///
    /// This scalar helper performs no protected owner lookup. A production
    /// owner must independently establish the exact Found or transient NotFound
    /// observation under its held readback cut before signing.
    ///
    /// # Errors
    ///
    /// Rejects a Found acceptance for another signed request or a zero Found cut.
    pub fn sign(
        query: &SignedStorageNativeAcceptanceReadbackQueryV1,
        observed_issuance_sequence: u64,
        acceptance: Option<StorageNativeAcceptanceV3>,
        signer: StorageZfsHoldSignerV1,
        key: &SigningKey,
    ) -> Result<Self, StorageNativeAcquireErrorV2> {
        if acceptance
            .as_ref()
            .is_some_and(|value| value.request_digest() != query.query.request_digest)
        {
            return Err(StorageNativeAcquireErrorV2::Mismatch);
        }
        let mut value = Self {
            query_digest: query.digest(),
            observed_issuance_sequence,
            acceptance,
            signer,
            signature: [0; 64],
        };
        value.validate_subject()?;
        value.signature = key
            .sign(&storage_signing_message(
                ANSWER_SIGNATURE_DOMAIN,
                &value.encode_subject(),
                signer,
            ))
            .to_bytes();
        Ok(value)
    }

    /// Returns original unsigned historical metadata, whether active or tombstoned.
    ///
    /// `None` is only a transient NotFound observation, never a retirement or
    /// permanent absence proof. `Some` grants no currentness or custody authority.
    #[must_use]
    pub const fn acceptance(&self) -> Option<&StorageNativeAcceptanceV3> {
        self.acceptance.as_ref()
    }

    /// Returns the diagnostic protected issuance sequence observed by Storage.
    ///
    /// This sequence is not the receipt head or a renewable positive authority.
    #[must_use]
    pub const fn observed_issuance_sequence(&self) -> u64 {
        self.observed_issuance_sequence
    }

    /// Encodes the sole fixed-width signed metadata answer representation.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.encode_subject();
        bytes.extend_from_slice(&self.signer.encode());
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// Decodes historical metadata without verifying its signature or freshness.
    ///
    /// # Errors
    ///
    /// Rejects wrong framing, padding, sentinels, disposition, nested V3
    /// acceptance, signer role, or signature width/zero value.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StorageNativeAcquireErrorV2> {
        if bytes.len() != SIGNED_STORAGE_NATIVE_ACCEPTANCE_READBACK_BYTES_V1 {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        let mut reader = Reader::versioned(&bytes[..ANSWER_BYTES], ANSWER_MAGIC, VERSION)?;
        let query_digest = reader.digest()?;
        let observed_issuance_sequence = reader.u64()?;
        let disposition = reader.take::<1>()?[0];
        if reader.take::<7>()? != [0; 7] {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        let payload = reader.bytes(STORAGE_NATIVE_ACCEPTANCE_BYTES_V3)?;
        let acceptance = match disposition {
            FOUND => Some(StorageNativeAcceptanceV3::from_canonical_bytes(payload)?),
            NOT_FOUND if payload == [0; STORAGE_NATIVE_ACCEPTANCE_BYTES_V3] => None,
            _ => return Err(StorageNativeAcquireErrorV2::Noncanonical),
        };
        reader.done()?;
        let signer = StorageZfsHoldSignerV1::decode(&bytes[ANSWER_BYTES..ANSWER_BYTES + 88])
            .map_err(|_| StorageNativeAcquireErrorV2::Noncanonical)?;
        let signature = bytes[ANSWER_BYTES + 88..]
            .try_into()
            .map_err(|_| StorageNativeAcquireErrorV2::Noncanonical)?;
        let value = Self {
            query_digest,
            observed_issuance_sequence,
            acceptance,
            signer,
            signature,
        };
        value.validate_subject()?;
        if value.signature == [0; 64] {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        Ok(value)
    }

    /// Verifies the pinned Storage metadata signature and exact query crosslinks.
    ///
    /// Success authenticates only this readback. It creates no verified Acquire,
    /// positive signed acceptance, live origin, or permanent absence proof. The
    /// caller must separately authenticate the current query carrier.
    ///
    /// # Errors
    ///
    /// Rejects a different pinned Storage signer/key, signing purpose, signed
    /// query, or original request commitment.
    pub fn verify_for(
        &self,
        query: &SignedStorageNativeAcceptanceReadbackQueryV1,
        verifier: StorageZfsHoldVerifierV1,
    ) -> Result<(), StorageNativeAcquireErrorV2> {
        verify_storage_signature(
            ANSWER_SIGNATURE_DOMAIN,
            &self.encode_subject(),
            self.signer,
            &self.signature,
            verifier,
        )?;
        if self.query_digest != query.digest()
            || self
                .acceptance
                .as_ref()
                .is_some_and(|value| value.request_digest() != query.query.request_digest)
        {
            return Err(StorageNativeAcquireErrorV2::Mismatch);
        }
        Ok(())
    }

    /// Commits exact signed answer bytes under the metadata-only digest domain.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        digest(ANSWER_DIGEST_DOMAIN, &self.to_canonical_bytes())
    }

    fn encode_subject(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ANSWER_BYTES);
        versioned_header(&mut bytes, ANSWER_MAGIC, VERSION);
        bytes.extend_from_slice(self.query_digest.as_bytes());
        bytes.extend_from_slice(&self.observed_issuance_sequence.to_be_bytes());
        bytes.push(if self.acceptance.is_some() {
            FOUND
        } else {
            NOT_FOUND
        });
        bytes.extend_from_slice(&[0; 7]);
        if let Some(acceptance) = &self.acceptance {
            bytes.extend_from_slice(&acceptance.to_canonical_bytes());
        } else {
            bytes.extend_from_slice(&[0; STORAGE_NATIVE_ACCEPTANCE_BYTES_V3]);
        }
        bytes
    }

    fn validate_subject(&self) -> Result<(), StorageNativeAcquireErrorV2> {
        if !nonzero(self.query_digest)
            || (self.acceptance.is_some() && self.observed_issuance_sequence == 0)
        {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        Ok(())
    }
}
