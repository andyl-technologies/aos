//! Authenticated cleanup of an original acceptance without positive replay.
//!
//! A fresh carrier may ask about an old acceptance after custody loss. This
//! does not rebind its old session, renew a receipt, or authorize remount.
//!
//! ```text
//! AOSZNC02 | version:u16be=2 | reserved[6]=0 | sequence:u64be |
//! cleanup-session[32] | nonce[32] | reason:u8 | reserved[7]=0 |
//! original-request-digest[32] | acceptance-digest[32] | receipt-digest[32] |
//! acquisition-id[32] | original-descriptor-commitment[32] |
//! provider-id[16] | holder-id[16] | ProviderOutcome-signer[120] | signature[64]
//! AOSZND02 | version:u16be=2 | reserved[6]=0 | cleanup-request-digest[32] |
//! acceptance-digest[32] | storage-cleanup-observation-digest[32] |
//! disposition:u8 | reserved[7]=0 | AOSZHSG1-signer[88] | signature[64]
//! ```
//!
//! The Provider query is a cleanup intent, never a Storage absence proof.
//! Storage may sign Retired/Absent only after its protected issuance and
//! physical-owner cut independently establishes the exact terminal fact.

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::{Signer as _, SigningKey};

use super::acceptance::{storage_signing_message, verify_storage_signature};
use super::{
    Reader, SignedStorageNativeAcquireRequestV2, StorageNativeAcceptanceV3,
    StorageNativeAcquireErrorV2, digest, header, nonzero,
};
use crate::crypto::{decode_signer, encode_signer, sign_bytes, verify_bytes};
use crate::{
    SourceProviderKeyUsageV1, SourceProviderSignature, SourceProviderSigningKeyV1,
    StorageZfsHoldSignerV1, StorageZfsHoldVerifierV1,
};

const QUERY_MAGIC: &[u8; 8] = b"AOSZNC02";
const RECEIPT_MAGIC: &[u8; 8] = b"AOSZND02";
const QUERY_BYTES: usize = 288;
const RECEIPT_BYTES: usize = 120;
const QUERY_SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.provider.native-cleanup.signature.v2\0";
const QUERY_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.provider.native-cleanup.digest.v2\0";
const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.storage.native-cleanup.signature.v2\0";

/// Explains why a Provider cannot continue the original positive acquisition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageNativeCleanupReasonV2 {
    /// Requests the normal exact acquisition retirement.
    ReleaseRequested = 1,
    /// Reports total loss of original live descriptor custody.
    CustodyLost = 2,
}

/// Requests terminal cleanup of exact original evidence over a fresh carrier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageNativeCleanupRequestV2 {
    sequence: u64,
    session_binding: ObjectDigest,
    nonce: [u8; 32],
    reason: StorageNativeCleanupReasonV2,
    request_digest: ObjectDigest,
    acceptance_digest: ObjectDigest,
    receipt_digest: ObjectDigest,
    acquisition_id: ObjectDigest,
    descriptor_commitment: ObjectDigest,
    provider_id: [u8; 16],
    holder_id: [u8; 16],
}

impl StorageNativeCleanupRequestV2 {
    /// Constructs cleanup intent from the immutable original request and acceptance.
    ///
    /// # Errors
    ///
    /// Rejects sentinel carrier values or an acceptance for another request.
    pub fn new(
        sequence: u64,
        session_binding: ObjectDigest,
        nonce: [u8; 32],
        reason: StorageNativeCleanupReasonV2,
        request: &SignedStorageNativeAcquireRequestV2,
        acceptance: &StorageNativeAcceptanceV3,
    ) -> Result<Self, StorageNativeAcquireErrorV2> {
        if sequence == 0
            || !nonzero(session_binding)
            || nonce == [0; 32]
            || acceptance.request_digest() != request.digest()
        {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        let claims = request.request().claims();
        Ok(Self {
            sequence,
            session_binding,
            nonce,
            reason,
            request_digest: request.digest(),
            acceptance_digest: acceptance.digest(),
            receipt_digest: acceptance.receipt_digest(),
            acquisition_id: claims.provider_acquisition().1,
            descriptor_commitment: acceptance.descriptor_commitment(),
            provider_id: claims.provider_acquisition().0,
            holder_id: claims.holder_session().0,
        })
    }

    /// Returns the fresh cleanup sequence, session, and nonce.
    #[must_use]
    pub const fn carrier(&self) -> (u64, ObjectDigest, [u8; 32]) {
        (self.sequence, self.session_binding, self.nonce)
    }

    /// Returns the original signed request and stable unsigned acceptance commitments.
    #[must_use]
    pub const fn original(&self) -> (ObjectDigest, ObjectDigest) {
        (self.request_digest, self.acceptance_digest)
    }

    /// Returns the exact original receipt, acquisition, and descriptor commitments.
    #[must_use]
    pub const fn evidence(&self) -> (ObjectDigest, ObjectDigest, ObjectDigest) {
        (
            self.receipt_digest,
            self.acquisition_id,
            self.descriptor_commitment,
        )
    }

    /// Returns the asserted cleanup reason, not proof of physical absence.
    #[must_use]
    pub const fn reason(&self) -> StorageNativeCleanupReasonV2 {
        self.reason
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(QUERY_BYTES);
        header(&mut bytes, QUERY_MAGIC);
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(self.session_binding.as_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.push(self.reason as u8);
        bytes.extend_from_slice(&[0; 7]);
        for value in [
            self.request_digest,
            self.acceptance_digest,
            self.receipt_digest,
            self.acquisition_id,
            self.descriptor_commitment,
        ] {
            bytes.extend_from_slice(value.as_bytes());
        }
        bytes.extend_from_slice(&self.provider_id);
        bytes.extend_from_slice(&self.holder_id);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, StorageNativeAcquireErrorV2> {
        if bytes.len() != QUERY_BYTES {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        let mut reader = Reader::new(bytes, QUERY_MAGIC)?;
        let sequence = reader.u64()?;
        let session_binding = reader.digest()?;
        let nonce = reader.take()?;
        let reason = match reader.take::<1>()? {
            [1] => StorageNativeCleanupReasonV2::ReleaseRequested,
            [2] => StorageNativeCleanupReasonV2::CustodyLost,
            _ => return Err(StorageNativeAcquireErrorV2::Noncanonical),
        };
        if reader.take::<7>()? != [0; 7] {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        let value = Self {
            sequence,
            session_binding,
            nonce,
            reason,
            request_digest: reader.digest()?,
            acceptance_digest: reader.digest()?,
            receipt_digest: reader.digest()?,
            acquisition_id: reader.digest()?,
            descriptor_commitment: reader.digest()?,
            provider_id: reader.take()?,
            holder_id: reader.take()?,
        };
        reader.done()?;
        if value.sequence == 0
            || value.nonce == [0; 32]
            || value.provider_id == [0; 16]
            || value.holder_id == [0; 16]
            || [
                value.session_binding,
                value.request_digest,
                value.acceptance_digest,
                value.receipt_digest,
                value.acquisition_id,
                value.descriptor_commitment,
            ]
            .iter()
            .any(|value| !nonzero(*value))
        {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        Ok(value)
    }
}

/// Carries a ProviderOutcome-signed cleanup intent, never a success capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedStorageNativeCleanupRequestV2 {
    request: StorageNativeCleanupRequestV2,
    signer: SourceProviderSigningKeyV1,
    signature: SourceProviderSignature,
}

impl SignedStorageNativeCleanupRequestV2 {
    /// Signs cleanup intent with the Provider's current outcome role.
    ///
    /// # Errors
    ///
    /// Rejects a foreign Provider authority, usage, or key.
    pub fn sign(
        request: StorageNativeCleanupRequestV2,
        signer: SourceProviderSigningKeyV1,
        key: &SigningKey,
    ) -> Result<Self, StorageNativeAcquireErrorV2> {
        if signer.authority_id() != request.provider_id
            || signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
        {
            return Err(StorageNativeAcquireErrorV2::Authority);
        }
        let signature = sign_bytes(QUERY_SIGNATURE_DOMAIN, 2, &request.encode(), &signer, key)
            .map_err(|_| StorageNativeAcquireErrorV2::Authority)?;
        Ok(Self {
            request,
            signer,
            signature,
        })
    }

    /// Returns the original evidence and fresh cleanup carrier.
    #[must_use]
    pub const fn request(&self) -> &StorageNativeCleanupRequestV2 {
        &self.request
    }

    /// Encodes the canonical signed cleanup intent.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.request.encode();
        encode_signer(&mut bytes, &self.signer);
        bytes.extend_from_slice(self.signature.as_bytes());
        bytes
    }

    /// Decodes exact signed cleanup intent without authenticating its claims.
    ///
    /// # Errors
    ///
    /// Rejects wrong size, malformed subject/signer, role, or zero signature.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StorageNativeAcquireErrorV2> {
        if bytes.len() != QUERY_BYTES + 184 {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        let request = StorageNativeCleanupRequestV2::decode(&bytes[..QUERY_BYTES])?;
        let signer = decode_signer(&bytes[QUERY_BYTES..QUERY_BYTES + 120])
            .map_err(|_| StorageNativeAcquireErrorV2::Noncanonical)?;
        let signature = SourceProviderSignature::from_bytes(
            bytes[QUERY_BYTES + 120..]
                .try_into()
                .map_err(|_| StorageNativeAcquireErrorV2::Noncanonical)?,
        );
        if signer.authority_id() != request.provider_id
            || signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
            || signature.as_bytes() == &[0; 64]
        {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        Ok(Self {
            request,
            signer,
            signature,
        })
    }

    /// Verifies a protected Provider signer and the exact cleanup signature.
    ///
    /// # Errors
    ///
    /// Rejects a different signer, key, or signature.
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
            2,
            &self.request.encode(),
            &self.signer,
            &self.signature,
            key,
        )
        .map_err(|_| StorageNativeAcquireErrorV2::Authority)
    }

    /// Commits exact signed cleanup bytes, including the fresh nonce/session.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        digest(QUERY_DIGEST_DOMAIN, &self.to_canonical_bytes())
    }
}

/// Names a Storage-owned terminal fact, never a positive Acquire result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageNativeCleanupDispositionV2 {
    /// Storage durably retired the exact original issuance interest.
    Retired = 1,
    /// Storage independently proved exact original interest and custody absent.
    Absent = 2,
}

/// Commits a terminal cleanup observation to its exact fresh signed query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageNativeCleanupReceiptV2 {
    query_digest: ObjectDigest,
    acceptance_digest: ObjectDigest,
    observation_digest: ObjectDigest,
    disposition: StorageNativeCleanupDispositionV2,
}

impl StorageNativeCleanupReceiptV2 {
    /// Constructs a claimed terminal fact after independent Storage cleanup.
    ///
    /// # Errors
    ///
    /// Rejects a zero protected cleanup/absence observation commitment.
    pub fn new(
        query: &SignedStorageNativeCleanupRequestV2,
        observation_digest: ObjectDigest,
        disposition: StorageNativeCleanupDispositionV2,
    ) -> Result<Self, StorageNativeAcquireErrorV2> {
        if !nonzero(observation_digest) {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        Ok(Self {
            query_digest: query.digest(),
            acceptance_digest: query.request.acceptance_digest,
            observation_digest,
            disposition,
        })
    }

    /// Returns the terminal disposition, not permission to remount or retry.
    #[must_use]
    pub const fn disposition(&self) -> StorageNativeCleanupDispositionV2 {
        self.disposition
    }

    /// Returns the independently expected cleanup observation commitment.
    #[must_use]
    pub const fn observation_digest(&self) -> ObjectDigest {
        self.observation_digest
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECEIPT_BYTES);
        header(&mut bytes, RECEIPT_MAGIC);
        for value in [
            self.query_digest,
            self.acceptance_digest,
            self.observation_digest,
        ] {
            bytes.extend_from_slice(value.as_bytes());
        }
        bytes.push(self.disposition as u8);
        bytes.extend_from_slice(&[0; 7]);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, StorageNativeAcquireErrorV2> {
        if bytes.len() != RECEIPT_BYTES {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        let mut reader = Reader::new(bytes, RECEIPT_MAGIC)?;
        let query_digest = reader.digest()?;
        let acceptance_digest = reader.digest()?;
        let observation_digest = reader.digest()?;
        let disposition = match reader.take::<1>()? {
            [1] => StorageNativeCleanupDispositionV2::Retired,
            [2] => StorageNativeCleanupDispositionV2::Absent,
            _ => return Err(StorageNativeAcquireErrorV2::Noncanonical),
        };
        if reader.take::<7>()? != [0; 7]
            || !nonzero(query_digest)
            || !nonzero(acceptance_digest)
            || !nonzero(observation_digest)
        {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        reader.done()?;
        Ok(Self {
            query_digest,
            acceptance_digest,
            observation_digest,
            disposition,
        })
    }
}

/// Authenticates exact terminal cleanup with the dedicated Storage receipt role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedStorageNativeCleanupReceiptV2 {
    receipt: StorageNativeCleanupReceiptV2,
    signer: StorageZfsHoldSignerV1,
    signature: [u8; 64],
}

impl SignedStorageNativeCleanupReceiptV2 {
    /// Signs a claimed Storage terminal fact without performing cleanup.
    #[must_use]
    pub fn sign(
        receipt: StorageNativeCleanupReceiptV2,
        signer: StorageZfsHoldSignerV1,
        key: &SigningKey,
    ) -> Self {
        let signature = key
            .sign(&storage_signing_message(
                RECEIPT_SIGNATURE_DOMAIN,
                &receipt.encode(),
                signer,
            ))
            .to_bytes();
        Self {
            receipt,
            signer,
            signature,
        }
    }

    /// Returns the signed terminal fact for independently expected comparison.
    #[must_use]
    pub const fn receipt(&self) -> &StorageNativeCleanupReceiptV2 {
        &self.receipt
    }

    /// Encodes the descriptor-free dedicated-role terminal receipt.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.receipt.encode();
        bytes.extend_from_slice(&self.signer.encode());
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// Decodes exact signed terminal receipt bytes without accepting authority.
    ///
    /// # Errors
    ///
    /// Rejects size, subject, signer role, or zero signature errors.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StorageNativeAcquireErrorV2> {
        if bytes.len() != RECEIPT_BYTES + 152 {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        let receipt = StorageNativeCleanupReceiptV2::decode(&bytes[..RECEIPT_BYTES])?;
        let signer = StorageZfsHoldSignerV1::decode(&bytes[RECEIPT_BYTES..RECEIPT_BYTES + 88])
            .map_err(|_| StorageNativeAcquireErrorV2::Noncanonical)?;
        let signature = bytes[RECEIPT_BYTES + 88..]
            .try_into()
            .map_err(|_| StorageNativeAcquireErrorV2::Noncanonical)?;
        if signature == [0; 64] {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        Ok(Self {
            receipt,
            signer,
            signature,
        })
    }

    /// Verifies the exact query, protected observation, and dedicated signature.
    ///
    /// The caller must authenticate the query separately. This cannot
    /// establish the physical or journal provenance of `expected`.
    ///
    /// # Errors
    ///
    /// Rejects a changed query, expected terminal fact, signer, or signature.
    pub fn verify_for(
        &self,
        query: &SignedStorageNativeCleanupRequestV2,
        expected: &StorageNativeCleanupReceiptV2,
        verifier: StorageZfsHoldVerifierV1,
    ) -> Result<(), StorageNativeAcquireErrorV2> {
        verify_storage_signature(
            RECEIPT_SIGNATURE_DOMAIN,
            &self.receipt.encode(),
            self.signer,
            &self.signature,
            verifier,
        )?;
        if self.receipt != *expected
            || self.receipt.query_digest != query.digest()
            || self.receipt.acceptance_digest != query.request.acceptance_digest
        {
            return Err(StorageNativeAcquireErrorV2::Mismatch);
        }
        Ok(())
    }
}
