//! Provider-signed native selection and original RootMount request binding.

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::SigningKey;

use super::{Reader, StorageNativeAcquireErrorV2, digest, header};
use crate::crypto::{decode_signer, encode_signer, sign_bytes, verify_bytes};
use crate::{
    ACQUIRE_SOURCE_REQUEST_VERSION_V2, ACQUIRE_SOURCE_REQUEST_VERSION_V3, MAXIMUM_FRAME_BYTES,
    MAXIMUM_STORAGE_ZFS_HOLD_REQUEST_PACKET_BYTES_V1, SignedSourceProviderRequestV1,
    SourceProviderKeyUsageV1, SourceProviderMethod, SourceProviderSignature,
    SourceProviderSigningKeyV1, StorageZfsHoldTransportRequestV1, decode_acquire_request,
    verify_request,
};

const MAGIC: &[u8; 8] = b"AOSZNQ02";
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.provider.native-acquire.signature.v2\0";
const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.provider.native-acquire.digest.v2\0";

/// Bounds the complete Provider-signed native Acquire request.
pub const MAXIMUM_SIGNED_STORAGE_NATIVE_ACQUIRE_REQUEST_BYTES_V2: usize =
    24 + MAXIMUM_STORAGE_ZFS_HOLD_REQUEST_PACKET_BYTES_V1 + MAXIMUM_FRAME_BYTES + 184;

/// Binds native selection claims to the exact original RootMount Acquire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageNativeAcquireRequestV2 {
    claims: StorageZfsHoldTransportRequestV1,
    signed_root_request: SignedSourceProviderRequestV1,
}

impl StorageNativeAcquireRequestV2 {
    /// Constructs matching claims for an exact version-two original request.
    ///
    /// The claim sequence orders Provider-to-Storage traffic. The embedded
    /// RootMount request sequence orders RootMount-to-Provider traffic. These
    /// independent spaces are retained exactly, not compared for equality.
    /// Immutable ZFS snapshots require a non-kernel-coupled RootMount request;
    /// LocalLive export requests cannot be carried by this native contract.
    ///
    /// # Errors
    ///
    /// Rejects legacy, kernel-coupled, mismatched, or overlong requests.
    pub fn new(
        claims: StorageZfsHoldTransportRequestV1,
        signed_root_request: SignedSourceProviderRequestV1,
    ) -> Result<Self, StorageNativeAcquireErrorV2> {
        Self::new_for_version(
            claims,
            signed_root_request,
            ACQUIRE_SOURCE_REQUEST_VERSION_V2,
        )
    }

    /// Binds native claims to an exact version-three original RootMount request.
    ///
    /// Retains every original signed byte, including all seven native catalog
    /// claims, without changing the version-two Storage envelope. The catalog
    /// namespace and head must equal the carried catalog; the current-head
    /// commitment must equal the claimed selection head. Holder, session,
    /// acquisition, logical binding, and validity use the same checks as V2.
    ///
    /// This inert construction authenticates neither independently signed
    /// catalog floor/publication evidence nor the complete protected selected
    /// tuple. Those checks belong to the Provider owner before signing. Carrier
    /// sequence, original Root sequence, and attempt identity remain distinct.
    ///
    /// # Errors
    ///
    /// Rejects another embedded version, a missing native profile, kernel
    /// coupling, or mismatched catalog, selection, identity, or validity claims.
    pub fn new_native_v3(
        claims: StorageZfsHoldTransportRequestV1,
        signed_root_request: SignedSourceProviderRequestV1,
    ) -> Result<Self, StorageNativeAcquireErrorV2> {
        Self::new_for_version(
            claims,
            signed_root_request,
            ACQUIRE_SOURCE_REQUEST_VERSION_V3,
        )
    }

    fn new_for_version(
        claims: StorageZfsHoldTransportRequestV1,
        signed_root_request: SignedSourceProviderRequestV1,
        root_version: u16,
    ) -> Result<Self, StorageNativeAcquireErrorV2> {
        let root = decode_acquire_request(signed_root_request.subject())
            .map_err(|_| StorageNativeAcquireErrorV2::Noncanonical)?;
        let (holder, session) = claims.holder_session();
        let (_, acquisition) = claims.provider_acquisition();
        let (binding, _) = claims.selection();
        let (issued, expires) = claims.validity();
        if signed_root_request.method() != SourceProviderMethod::Acquire
            || root.acquisition_version() != root_version
            || root.kernel_coupled()
            || holder != root.holder_authority_id()
            || session != root.session_binding()
            || acquisition != root.acquisition_id()
            || binding != root.binding_digest()
            || expires <= issued
            || issued > root.deadline_seconds()
            || expires > root.deadline_seconds()
            || expires.checked_sub(issued).is_none_or(|duration| {
                duration <= 0 || duration as u64 > root.requested_lease_seconds()
            })
        {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }

        if root_version == ACQUIRE_SOURCE_REQUEST_VERSION_V3 {
            let native = root
                .native_catalog()
                .ok_or(StorageNativeAcquireErrorV2::Noncanonical)?;
            let catalog = claims.catalog();
            if native.resource_namespace_digest() != catalog.namespace_digest()
                || native.head() != (catalog.generation(), catalog.digest())
                || native.current_head_commitment() != claims.selection().1
            {
                return Err(StorageNativeAcquireErrorV2::Noncanonical);
            }
        }

        Ok(Self {
            claims,
            signed_root_request,
        })
    }

    /// Returns native claims, including the original Provider-to-Storage sequence.
    #[must_use]
    pub const fn claims(&self) -> &StorageZfsHoldTransportRequestV1 {
        &self.claims
    }

    /// Returns the original signed broker request, never a replacement session.
    #[must_use]
    pub const fn signed_root_request(&self) -> &SignedSourceProviderRequestV1 {
        &self.signed_root_request
    }

    fn encode(&self) -> Vec<u8> {
        let claims = self.claims.to_canonical_bytes();
        let root = self.signed_root_request.to_canonical_bytes();
        let mut bytes = Vec::with_capacity(24 + claims.len() + root.len());
        header(&mut bytes, MAGIC);
        bytes.extend_from_slice(&(claims.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&claims);
        bytes.extend_from_slice(&(root.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&root);
        bytes
    }
}

/// Carries exact ProviderOutcome-signed native claims and broker authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedStorageNativeAcquireRequestV2 {
    request: StorageNativeAcquireRequestV2,
    signer: SourceProviderSigningKeyV1,
    signature: SourceProviderSignature,
}

impl SignedStorageNativeAcquireRequestV2 {
    /// Signs a claim after owner-side checks, without performing those checks.
    ///
    /// # Errors
    ///
    /// Rejects a foreign Provider role, authority ID, or signing key.
    pub fn sign(
        request: StorageNativeAcquireRequestV2,
        signer: SourceProviderSigningKeyV1,
        key: &SigningKey,
    ) -> Result<Self, StorageNativeAcquireErrorV2> {
        if signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
            || signer.authority_id() != request.claims.provider_acquisition().0
        {
            return Err(StorageNativeAcquireErrorV2::Authority);
        }
        let signature = sign_bytes(SIGNATURE_DOMAIN, 2, &request.encode(), &signer, key)
            .map_err(|_| StorageNativeAcquireErrorV2::Authority)?;
        Ok(Self {
            request,
            signer,
            signature,
        })
    }

    /// Returns the exact signed selection and original request.
    #[must_use]
    pub const fn request(&self) -> &StorageNativeAcquireRequestV2 {
        &self.request
    }

    /// Returns the Provider signer to resolve through protected trust.
    #[must_use]
    pub const fn signer(&self) -> &SourceProviderSigningKeyV1 {
        &self.signer
    }

    /// Encodes the canonical version-two envelope with its exact original request.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.request.encode();
        encode_signer(&mut bytes, &self.signer);
        bytes.extend_from_slice(self.signature.as_bytes());
        bytes
    }

    /// Decodes bounded bytes without authenticating any claimed authority.
    ///
    /// # Errors
    ///
    /// Rejects invalid lengths, nested records, roles, sentinels, or tails.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StorageNativeAcquireErrorV2> {
        if bytes.len() > MAXIMUM_SIGNED_STORAGE_NATIVE_ACQUIRE_REQUEST_BYTES_V2 {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        let mut reader = Reader::new(bytes, MAGIC)?;
        let claims_length = u32::from_be_bytes(reader.take()?) as usize;
        if claims_length > MAXIMUM_STORAGE_ZFS_HOLD_REQUEST_PACKET_BYTES_V1 {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        let claims =
            StorageZfsHoldTransportRequestV1::from_canonical_bytes(reader.bytes(claims_length)?)
                .map_err(|_| StorageNativeAcquireErrorV2::Noncanonical)?;
        let root_length = u32::from_be_bytes(reader.take()?) as usize;
        if root_length > MAXIMUM_FRAME_BYTES {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        let signed_root_request =
            SignedSourceProviderRequestV1::from_canonical_bytes(reader.bytes(root_length)?)
                .map_err(|_| StorageNativeAcquireErrorV2::Noncanonical)?;
        let root = decode_acquire_request(signed_root_request.subject())
            .map_err(|_| StorageNativeAcquireErrorV2::Noncanonical)?;
        let request = match root.acquisition_version() {
            ACQUIRE_SOURCE_REQUEST_VERSION_V2 => {
                StorageNativeAcquireRequestV2::new(claims, signed_root_request)?
            }
            ACQUIRE_SOURCE_REQUEST_VERSION_V3 => {
                StorageNativeAcquireRequestV2::new_native_v3(claims, signed_root_request)?
            }
            _ => return Err(StorageNativeAcquireErrorV2::Noncanonical),
        };
        let signer = decode_signer(reader.bytes(120)?)
            .map_err(|_| StorageNativeAcquireErrorV2::Noncanonical)?;
        let signature = SourceProviderSignature::from_bytes(reader.take()?);
        reader.done()?;
        if signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
            || signer.authority_id() != request.claims.provider_acquisition().0
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

    /// Verifies independently pinned Provider and original RootMount signatures.
    ///
    /// This establishes no current session, protected selection, or custody.
    ///
    /// # Errors
    ///
    /// Rejects either foreign signer, key, role, or signature.
    pub fn verify(
        &self,
        provider_signer: &SourceProviderSigningKeyV1,
        provider_key: &[u8; 32],
        root_signer: &SourceProviderSigningKeyV1,
        root_key: &[u8; 32],
    ) -> Result<(), StorageNativeAcquireErrorV2> {
        if &self.signer != provider_signer
            || self.request.signed_root_request.signer() != root_signer
            || root_signer.usage() != SourceProviderKeyUsageV1::RootMountRecord
        {
            return Err(StorageNativeAcquireErrorV2::Authority);
        }
        verify_request(&self.request.signed_root_request, root_key)
            .map_err(|_| StorageNativeAcquireErrorV2::Authority)?;
        verify_bytes(
            SIGNATURE_DOMAIN,
            2,
            &self.request.encode(),
            &self.signer,
            &self.signature,
            provider_key,
        )
        .map_err(|_| StorageNativeAcquireErrorV2::Authority)
    }

    /// Commits the exact signed request for Storage journal idempotency.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        digest(DIGEST_DOMAIN, &self.to_canonical_bytes())
    }

    /// Requires identical signed bytes for a retained acquisition identity.
    ///
    /// This structural comparison does not authorize retry or an effect.
    ///
    /// # Errors
    ///
    /// Rejects a matching acquisition ID with different signed request bytes.
    pub fn require_exact_replay(&self, previous: &Self) -> Result<(), StorageNativeAcquireErrorV2> {
        if self.request.claims.provider_acquisition()
            != previous.request.claims.provider_acquisition()
            || self.digest() != previous.digest()
        {
            return Err(StorageNativeAcquireErrorV2::ReplayConflict);
        }
        Ok(())
    }
}
