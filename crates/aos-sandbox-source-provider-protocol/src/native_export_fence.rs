//! Versioned Provider-local no-future-export result, never custody absence.
//!
//! The fixed native Release profile is separate from generic V1 responses.
//! It carries Pending, one purpose-separated ProviderOutcome signature, and
//! no descriptors. The claim refers to a protected cut before its own result
//! is committed; it is not a Storage currentness or physical-retirement proof.
//!
//! ```text
//! AOSNEF01 | version:u16be=1 | reserved[6]=0 | Release[288] |
//! original-Acquire[216] | native-request-digest[32] |
//! signed-acceptance-digest[32] | unsigned-AOSZNA03[216] | cut[88]
//! AOSNES01 | version:u16be=1 | reserved[6]=0 |
//! ProviderOutcome-signer[120] | AOSNEF01[888] | signature[64]
//! AOSNER02 | version:u16be=2 | reserved[6]=0 |
//! signed-status-length:u32be | signed-Pending-status | AOSNES01[1088]
//! ```

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

use crate::{
    ReleaseSourceResponseV1, SignedSourceProviderStatusV1, SourceProviderAuthorityV1,
    SourceProviderKeyUsageV1, SourceProviderMethod, SourceProviderSignature,
    SourceProviderSignatureError, SourceProviderSigningKeyV1, SourceProviderStatus,
    StorageNativeAcceptanceV3, decode_release_response, empty_descriptor_set_commitment_v1,
    encode_release_response, response_result_digest_v1,
};

const SUBJECT_MAGIC: &[u8; 8] = b"AOSNEF01";
const SIGNED_MAGIC: &[u8; 8] = b"AOSNES01";
const RESPONSE_MAGIC: &[u8; 8] = b"AOSNER02";
const DOMAIN: &[u8] = b"aos.sandbox.source-provider.no-future-native-exports.signature.v1\0";

/// Exact width of the unsigned Provider-local export-fence claim.
pub const SOURCE_PROVIDER_NATIVE_EXPORT_FENCE_BYTES_V1: usize =
    16 + 288 + 216 + 32 + 32 + crate::STORAGE_NATIVE_ACCEPTANCE_BYTES_V3 + 88;

/// Exact width of its purpose-separated ProviderOutcome signed envelope.
pub const SIGNED_SOURCE_PROVIDER_NATIVE_EXPORT_FENCE_BYTES_V1: usize =
    16 + 120 + SOURCE_PROVIDER_NATIVE_EXPORT_FENCE_BYTES_V1 + 64;

/// Exact width of the existing canonical signed response-status envelope.
pub const SIGNED_SOURCE_PROVIDER_RESPONSE_STATUS_BYTES_V1: usize =
    140 + (8 + 16 + 32 + 16 + 32 + 8 + 32 + 32) + 64;

/// Exact width of the native response, preserving every original request limit.
pub const MAXIMUM_NATIVE_RELEASE_RESPONSE_BYTES_V2: usize = 16
    + 4
    + SIGNED_SOURCE_PROVIDER_RESPONSE_STATUS_BYTES_V1
    + SIGNED_SOURCE_PROVIDER_NATIVE_EXPORT_FENCE_BYTES_V1;

/// Identifies the current signed Root Release and its Provider reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeExportFenceReleaseV1 {
    /// Exact Provider authority at fence signing.
    pub provider: SourceProviderAuthorityV1,
    /// Exact holder authority of the new Release request.
    pub holder: SourceProviderAuthorityV1,
    /// Root Release request identity.
    pub request_id: [u8; 16],
    /// Digest of the exact signed Root Release bytes.
    pub signed_request_digest: ObjectDigest,
    /// Digest of the canonical Release subject.
    pub typed_request_digest: ObjectDigest,
    /// Provider attempt identity for this Release, not the Acquire attempt.
    pub attempt_digest: ObjectDigest,
    /// Release-time authenticated session, independently of Acquire history.
    pub session_binding: ObjectDigest,
    /// Reserved Root-to-Provider sequence.
    pub request_sequence: u64,
    /// Independently reserved Provider-to-Root sequence.
    pub response_sequence: u64,
    /// Live Provider execution instance that signs the cut.
    pub provider_process_instance: [u8; 16],
}

/// Identifies the immutable original acquisition and its lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeExportFenceAcquireV1 {
    /// Stable provider acquisition identity.
    pub acquisition_id: ObjectDigest,
    /// Original holder-scoped acquisition sequence.
    pub acquisition_sequence: u64,
    /// Exact original signed Root Acquire digest.
    pub root_request_digest: ObjectDigest,
    /// Original Provider Acquire attempt identity.
    pub attempt_digest: ObjectDigest,
    /// Original Acquire session, never replaced by the Release session.
    pub session_binding: ObjectDigest,
    /// Derived native dispatch identity; no-dispatch identity is not eligible.
    pub backend_id: [u8; 32],
    /// Original lease identity.
    pub lease_id: [u8; 16],
    /// Exact signed original lease digest.
    pub lease_digest: ObjectDigest,
}

/// Names the exact pre-result Provider-local protected fence cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeExportFenceCutV1 {
    /// Protected sequence at sealing, before the result-bearing append.
    pub sequence: u64,
    /// Exact status4 reservation admission transaction identity.
    pub admission_transaction_id: [u8; 16],
    /// Exact status4 reservation identity, not original native7 capacity.
    pub reservation_id: [u8; 32],
    /// Domain-separated canonical commitments of the validated fence graph.
    pub fence_digest: ObjectDigest,
}

/// Claims only that the Provider will make no further exports for this issuance.
///
/// Public scalar construction and signature verification grant no journal,
/// descriptor, currentness, negative-custody or retirement authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderNativeExportFenceV1 {
    release: NativeExportFenceReleaseV1,
    acquire: NativeExportFenceAcquireV1,
    native_request_digest: ObjectDigest,
    signed_acceptance_digest: ObjectDigest,
    acceptance: StorageNativeAcceptanceV3,
    cut: NativeExportFenceCutV1,
}

impl SourceProviderNativeExportFenceV1 {
    /// Constructs nonauthorizing claims over exact retained native artifacts.
    ///
    /// # Errors
    ///
    /// Rejects sentinels or native acceptance mismatch. Both direction-local
    /// sequences must be nonzero, but their independently admitted values need
    /// not be equal.
    pub fn new(
        release: NativeExportFenceReleaseV1,
        acquire: NativeExportFenceAcquireV1,
        native_request_digest: ObjectDigest,
        signed_acceptance_digest: ObjectDigest,
        acceptance: StorageNativeAcceptanceV3,
        cut: NativeExportFenceCutV1,
    ) -> Result<Self, SourceProviderSignatureError> {
        let digests = [
            release.signed_request_digest,
            release.typed_request_digest,
            release.attempt_digest,
            release.session_binding,
            acquire.acquisition_id,
            acquire.root_request_digest,
            acquire.attempt_digest,
            acquire.session_binding,
            acquire.lease_digest,
            native_request_digest,
            signed_acceptance_digest,
            cut.fence_digest,
        ];
        if digests.iter().any(|digest| digest.as_bytes() == &[0; 32])
            || release.request_id == [0; 16]
            || release.provider_process_instance == [0; 16]
            || release.request_sequence == 0
            || release.response_sequence == 0
            || acquire.acquisition_sequence == 0
            || acquire.backend_id == [0; 32]
            || acquire.lease_id == [0; 16]
            || cut.sequence == 0
            || cut.admission_transaction_id == [0; 16]
            || cut.reservation_id == [0; 32]
            || acceptance.request_digest() != native_request_digest
        {
            return Err(SourceProviderSignatureError::InvalidEnvelope);
        }
        Ok(Self {
            release,
            acquire,
            native_request_digest,
            signed_acceptance_digest,
            acceptance,
            cut,
        })
    }

    /// Returns the exact current Release bindings.
    #[must_use]
    pub const fn release(&self) -> &NativeExportFenceReleaseV1 {
        &self.release
    }

    /// Returns the immutable original Acquire bindings.
    #[must_use]
    pub const fn acquire(&self) -> &NativeExportFenceAcquireV1 {
        &self.acquire
    }

    /// Returns the exact unsigned acceptance, including issuance and original root.
    #[must_use]
    pub const fn acceptance(&self) -> &StorageNativeAcceptanceV3 {
        &self.acceptance
    }

    /// Returns the exact signed native request commitment.
    #[must_use]
    pub const fn native_request_digest(&self) -> ObjectDigest {
        self.native_request_digest
    }

    /// Returns the exact original signed acceptance commitment.
    #[must_use]
    pub const fn signed_acceptance_digest(&self) -> ObjectDigest {
        self.signed_acceptance_digest
    }

    /// Returns the signed historical pre-result cut, not a currentness token.
    #[must_use]
    pub const fn cut(&self) -> NativeExportFenceCutV1 {
        self.cut
    }

    /// Encodes the exact fixed-width unsigned claim.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = header(SUBJECT_MAGIC, 1);
        for authority in [&self.release.provider, &self.release.holder] {
            bytes.extend_from_slice(&authority.authority_id());
            bytes.extend_from_slice(&authority.authority_generation().to_be_bytes());
            bytes.extend_from_slice(authority.authority_digest().as_bytes());
        }
        bytes.extend_from_slice(&self.release.request_id);
        for digest in [
            self.release.signed_request_digest,
            self.release.typed_request_digest,
            self.release.attempt_digest,
            self.release.session_binding,
        ] {
            bytes.extend_from_slice(digest.as_bytes());
        }
        bytes.extend_from_slice(&self.release.request_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.release.response_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.release.provider_process_instance);
        bytes.extend_from_slice(self.acquire.acquisition_id.as_bytes());
        bytes.extend_from_slice(&self.acquire.acquisition_sequence.to_be_bytes());
        for digest in [
            self.acquire.root_request_digest,
            self.acquire.attempt_digest,
            self.acquire.session_binding,
        ] {
            bytes.extend_from_slice(digest.as_bytes());
        }
        bytes.extend_from_slice(&self.acquire.backend_id);
        bytes.extend_from_slice(&self.acquire.lease_id);
        bytes.extend_from_slice(self.acquire.lease_digest.as_bytes());
        bytes.extend_from_slice(self.native_request_digest.as_bytes());
        bytes.extend_from_slice(self.signed_acceptance_digest.as_bytes());
        bytes.extend_from_slice(&self.acceptance.to_canonical_bytes());
        bytes.extend_from_slice(&self.cut.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.cut.admission_transaction_id);
        bytes.extend_from_slice(&self.cut.reservation_id);
        bytes.extend_from_slice(self.cut.fence_digest.as_bytes());
        debug_assert_eq!(bytes.len(), SOURCE_PROVIDER_NATIVE_EXPORT_FENCE_BYTES_V1);
        bytes
    }

    /// Decodes exact framing and scalar crosslinks, without verifying authority.
    ///
    /// # Errors
    ///
    /// Rejects wrong width/version, reserved bytes, sentinels or artifact mismatch.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SourceProviderSignatureError> {
        if bytes.len() != SOURCE_PROVIDER_NATIVE_EXPORT_FENCE_BYTES_V1 {
            return Err(SourceProviderSignatureError::InvalidEnvelope);
        }
        let mut reader = Reader(bytes);
        reader.header(SUBJECT_MAGIC, 1)?;
        let release = NativeExportFenceReleaseV1 {
            provider: reader.authority()?,
            holder: reader.authority()?,
            request_id: reader.array()?,
            signed_request_digest: reader.digest()?,
            typed_request_digest: reader.digest()?,
            attempt_digest: reader.digest()?,
            session_binding: reader.digest()?,
            request_sequence: reader.u64()?,
            response_sequence: reader.u64()?,
            provider_process_instance: reader.array()?,
        };
        let acquire = NativeExportFenceAcquireV1 {
            acquisition_id: reader.digest()?,
            acquisition_sequence: reader.u64()?,
            root_request_digest: reader.digest()?,
            attempt_digest: reader.digest()?,
            session_binding: reader.digest()?,
            backend_id: reader.array()?,
            lease_id: reader.array()?,
            lease_digest: reader.digest()?,
        };
        let native_request_digest = reader.digest()?;
        let signed_acceptance_digest = reader.digest()?;
        let acceptance = StorageNativeAcceptanceV3::from_canonical_bytes(
            reader.take(crate::STORAGE_NATIVE_ACCEPTANCE_BYTES_V3)?,
        )
        .map_err(|_| SourceProviderSignatureError::InvalidEnvelope)?;
        let cut = NativeExportFenceCutV1 {
            sequence: reader.u64()?,
            admission_transaction_id: reader.array()?,
            reservation_id: reader.array()?,
            fence_digest: reader.digest()?,
        };
        Self::new(
            release,
            acquire,
            native_request_digest,
            signed_acceptance_digest,
            acceptance,
            cut,
        )
    }
}

/// Carries a purpose-separated claim under the existing ProviderOutcome key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedSourceProviderNativeExportFenceV1 {
    subject: SourceProviderNativeExportFenceV1,
    signer: SourceProviderSigningKeyV1,
    signature: SourceProviderSignature,
}

impl SignedSourceProviderNativeExportFenceV1 {
    /// Signs nonauthorizing claims using only the matching ProviderOutcome role.
    ///
    /// # Errors
    ///
    /// Rejects a different authority, role, fingerprint or invalid key.
    pub fn sign(
        subject: SourceProviderNativeExportFenceV1,
        signer: SourceProviderSigningKeyV1,
        key: &SigningKey,
    ) -> Result<Self, SourceProviderSignatureError> {
        require_signer(&subject, &signer)?;
        let signature =
            crate::crypto::sign_bytes(DOMAIN, 3, &subject.to_canonical_bytes(), &signer, key)?;
        Ok(Self {
            subject,
            signer,
            signature,
        })
    }

    /// Verifies only the signature; no custody or retirement authority results.
    ///
    /// # Errors
    ///
    /// Rejects role/authority/fingerprint drift or an invalid signature.
    pub fn verify(&self, key: &[u8; 32]) -> Result<(), SourceProviderSignatureError> {
        require_signer(&self.subject, &self.signer)?;
        crate::crypto::verify_bytes(
            DOMAIN,
            3,
            &self.subject.to_canonical_bytes(),
            &self.signer,
            &self.signature,
            key,
        )
    }

    /// Returns nonauthorizing signed claims.
    #[must_use]
    pub const fn subject(&self) -> &SourceProviderNativeExportFenceV1 {
        &self.subject
    }

    /// Returns the exact ProviderOutcome signer identity.
    #[must_use]
    pub const fn signer(&self) -> &SourceProviderSigningKeyV1 {
        &self.signer
    }

    /// Encodes the fixed canonical signed result.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = header(SIGNED_MAGIC, 1);
        crate::crypto::encode_signer(&mut bytes, &self.signer);
        bytes.extend_from_slice(&self.subject.to_canonical_bytes());
        bytes.extend_from_slice(self.signature.as_bytes());
        debug_assert_eq!(
            bytes.len(),
            SIGNED_SOURCE_PROVIDER_NATIVE_EXPORT_FENCE_BYTES_V1
        );
        bytes
    }

    /// Decodes the fixed result, without promoting signed bytes to authority.
    ///
    /// # Errors
    ///
    /// Rejects malformed framing, role, authority or nested claims.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SourceProviderSignatureError> {
        if bytes.len() != SIGNED_SOURCE_PROVIDER_NATIVE_EXPORT_FENCE_BYTES_V1 {
            return Err(SourceProviderSignatureError::InvalidEnvelope);
        }
        let mut reader = Reader(bytes);
        reader.header(SIGNED_MAGIC, 1)?;
        let signer = crate::crypto::decode_signer(reader.take(120)?)?;
        let subject = SourceProviderNativeExportFenceV1::from_canonical_bytes(
            reader.take(SOURCE_PROVIDER_NATIVE_EXPORT_FENCE_BYTES_V1)?,
        )?;
        let signature = SourceProviderSignature::from_bytes(reader.array()?);
        require_signer(&subject, &signer)?;
        Ok(Self {
            subject,
            signer,
            signature,
        })
    }
}

/// Carries only Pending plus the exact native no-future-export result and zero FDs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseSourceResponseV2 {
    signed_status: SignedSourceProviderStatusV1,
    fence: SignedSourceProviderNativeExportFenceV1,
    result: Vec<u8>,
}

impl ReleaseSourceResponseV2 {
    /// Joins exact Pending status, signer, Release correlation and empty FD set.
    ///
    /// # Errors
    ///
    /// Rejects another status/method/signer, result digest or Release/session identity.
    pub fn new(
        signed_status: SignedSourceProviderStatusV1,
        fence: SignedSourceProviderNativeExportFenceV1,
    ) -> Result<Self, SourceProviderSignatureError> {
        let result = fence.to_canonical_bytes();
        let status = signed_status.subject();
        let release = fence.subject().release();
        if status.method() != SourceProviderMethod::Release
            || status.status() != SourceProviderStatus::Pending
            || signed_status.signer() != fence.signer()
            || status.request_id() != release.request_id
            || status.signed_request_digest() != release.signed_request_digest
            || status.session_binding() != release.session_binding
            || status.response_sequence() != release.response_sequence
            || status.provider_process_instance() != release.provider_process_instance
            || status.descriptor_commitment() != empty_descriptor_set_commitment_v1()
            || status.result_digest()
                != response_result_digest_v1(
                    SourceProviderMethod::Release,
                    SourceProviderStatus::Pending,
                    Some(&result),
                )
        {
            return Err(SourceProviderSignatureError::InvalidEnvelope);
        }
        Ok(Self {
            signed_status,
            fence,
            result,
        })
    }

    /// Returns the exact native signed fence, not a terminal release receipt.
    #[must_use]
    pub const fn fence(&self) -> &SignedSourceProviderNativeExportFenceV1 {
        &self.fence
    }

    /// Returns the exact signed Pending status.
    #[must_use]
    pub const fn signed_status(&self) -> &SignedSourceProviderStatusV1 {
        &self.signed_status
    }

    /// Encodes the explicitly versioned profile body.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let status = self.signed_status.to_canonical_bytes();
        debug_assert_eq!(
            status.len(),
            SIGNED_SOURCE_PROVIDER_RESPONSE_STATUS_BYTES_V1
        );
        let mut bytes = header(RESPONSE_MAGIC, 2);
        bytes.extend_from_slice(&(status.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&status);
        bytes.extend_from_slice(&self.result);
        debug_assert_eq!(bytes.len(), MAXIMUM_NATIVE_RELEASE_RESPONSE_BYTES_V2);
        bytes
    }

    /// Decodes only the explicit native profile; generic V1 cannot be inferred.
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized, noncanonical or substituted status/result data.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SourceProviderSignatureError> {
        if bytes.len() > MAXIMUM_NATIVE_RELEASE_RESPONSE_BYTES_V2 {
            return Err(SourceProviderSignatureError::InvalidEnvelope);
        }
        let mut reader = Reader(bytes);
        reader.header(RESPONSE_MAGIC, 2)?;
        let length = u32::from_be_bytes(reader.array()?) as usize;
        if length != SIGNED_SOURCE_PROVIDER_RESPONSE_STATUS_BYTES_V1 {
            return Err(SourceProviderSignatureError::InvalidEnvelope);
        }
        let status = SignedSourceProviderStatusV1::from_canonical_bytes(reader.take(length)?)?;
        let fence = SignedSourceProviderNativeExportFenceV1::from_canonical_bytes(reader.0)?;
        Self::new(status, fence)
    }
}

/// Keeps legacy responses and the explicitly versioned native profile disjoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseSourceResponseProfileV2 {
    /// Unchanged generic V1 semantics, including terminal Complete receipts.
    Legacy(ReleaseSourceResponseV1),
    /// Pending Provider-local native fence, never terminal physical Release.
    Native(ReleaseSourceResponseV2),
}

impl ReleaseSourceResponseProfileV2 {
    /// Reconstitutes exact retained parts with explicit nested native framing.
    ///
    /// # Errors
    ///
    /// Rejects an invalid native envelope or unchanged generic V1 shape.
    pub fn from_parts(
        status: SignedSourceProviderStatusV1,
        result: Option<Vec<u8>>,
    ) -> Result<Self, SourceProviderSignatureError> {
        if let Some(bytes) = result.as_deref()
            && bytes.starts_with(SIGNED_MAGIC)
        {
            return ReleaseSourceResponseV2::new(
                status,
                SignedSourceProviderNativeExportFenceV1::from_canonical_bytes(bytes)?,
            )
            .map(Self::Native);
        }
        ReleaseSourceResponseV1::new(status, result)
            .map(Self::Legacy)
            .map_err(|_| SourceProviderSignatureError::InvalidEnvelope)
    }

    /// Decodes exact profile framing, never treating a native result as V1.
    ///
    /// # Errors
    ///
    /// Rejects malformed native framing or an invalid unchanged legacy response.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SourceProviderSignatureError> {
        if bytes.starts_with(RESPONSE_MAGIC) {
            return ReleaseSourceResponseV2::from_canonical_bytes(bytes).map(Self::Native);
        }
        decode_release_response(bytes)
            .map(Self::Legacy)
            .map_err(Into::into)
    }

    /// Returns the exact canonical profile body.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        match self {
            Self::Legacy(value) => encode_release_response(value),
            Self::Native(value) => value.to_canonical_bytes(),
        }
    }

    /// Returns the signed correlated status for either closed profile.
    #[must_use]
    pub fn signed_status(&self) -> &SignedSourceProviderStatusV1 {
        match self {
            Self::Legacy(value) => value.signed_status(),
            Self::Native(value) => value.signed_status(),
        }
    }

    /// Returns the profile's exact closed disposition.
    #[must_use]
    pub fn status(&self) -> SourceProviderStatus {
        self.signed_status().subject().status()
    }

    /// Returns the exact optional result; callers must distinguish its profile.
    #[must_use]
    pub fn signed_result(&self) -> Option<&[u8]> {
        match self {
            Self::Legacy(value) => value.signed_receipt(),
            Self::Native(value) => Some(&value.result),
        }
    }

    /// Returns native fence evidence only for the explicit versioned profile.
    #[must_use]
    pub fn native_fence(&self) -> Option<&SignedSourceProviderNativeExportFenceV1> {
        match self {
            Self::Native(value) => Some(value.fence()),
            Self::Legacy(_) => None,
        }
    }
}

fn require_signer(
    subject: &SourceProviderNativeExportFenceV1,
    signer: &SourceProviderSigningKeyV1,
) -> Result<(), SourceProviderSignatureError> {
    let provider = &subject.release.provider;
    if signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
        || signer.authority_id() != provider.authority_id()
        || signer.authority_generation() != provider.authority_generation()
        || signer.authority_digest() != provider.authority_digest()
    {
        return Err(SourceProviderSignatureError::SignerMismatch);
    }
    Ok(())
}

fn header(magic: &[u8; 8], version: u16) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.extend_from_slice(&[0; 6]);
    bytes
}

struct Reader<'a>(&'a [u8]);

/// Computes the unchanged native dispatch identity for exact cross-owner joins.
///
/// This pure commitment grants no dispatch, signing or descriptor authority.
#[must_use]
pub fn native_dispatch_backend_identity_v2(
    intent_digest: ObjectDigest,
    catalog_generation: u64,
    catalog_digest: ObjectDigest,
    attempt_digest: ObjectDigest,
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"aos.sandbox.source-provider.native-dispatch.v2\0")
        .chain_update(intent_digest.as_bytes())
        .chain_update(catalog_generation.to_be_bytes())
        .chain_update(catalog_digest.as_bytes())
        .chain_update(attempt_digest.as_bytes())
        .finalize()
        .into()
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], SourceProviderSignatureError> {
        if length > self.0.len() {
            return Err(SourceProviderSignatureError::InvalidEnvelope);
        }
        let (value, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SourceProviderSignatureError> {
        self.take(N)?
            .try_into()
            .map_err(|_| SourceProviderSignatureError::InvalidEnvelope)
    }

    fn u64(&mut self) -> Result<u64, SourceProviderSignatureError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn digest(&mut self) -> Result<ObjectDigest, SourceProviderSignatureError> {
        Ok(ObjectDigest::from_bytes(self.array()?))
    }

    fn authority(&mut self) -> Result<SourceProviderAuthorityV1, SourceProviderSignatureError> {
        SourceProviderAuthorityV1::new(self.array()?, self.u64()?, self.digest()?)
            .map_err(|_| SourceProviderSignatureError::InvalidEnvelope)
    }

    fn header(
        &mut self,
        magic: &[u8; 8],
        version: u16,
    ) -> Result<(), SourceProviderSignatureError> {
        if self.array::<8>()? != *magic
            || u16::from_be_bytes(self.array()?) != version
            || self.array::<6>()? != [0; 6]
        {
            return Err(SourceProviderSignatureError::InvalidEnvelope);
        }
        Ok(())
    }
}
