//! Canonical deadline- and session-independent acquisition intent.
//!
//! This module is a pure format boundary. Its values authenticate no caller,
//! establish no protected-state currentness, and grant no effect authority.
//!
//! ```text
//! AOSNPI01 | version:u16be | source_use:u8 | flags:u8 | profile:u8 | reserved[3] |
//! acquisition_id[32] | acquisition_sequence:u64be | provider_authority[56] | holder_authority[56] |
//! node_id[16] | boot_id[16] | route_id[16] | route_generation:u64be |
//! route_digest[32] | namespace_digest[32] | revocation_generation:u64be |
//! revocation_digest[32] | requested_lease_seconds:u64be |
//! requested_maximum_submounts:u32be | template_len:u32be |
//! template_digest[32] | binding_len:u32be | binding_digest[32] |
//! native_catalog[176 only for version 3/profile 1] |
//! template[template_len] | binding[binding_len]
//! ```
//!
//! Version 2 retains its exact all-zero profile header and common layout.
//! Version 3 carries the complete native catalog block defined by the Acquire
//! subject, with a separate digest domain. Neither profile proves currentness.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::{
    AcquireSourceRequestV1, MAXIMUM_SOURCE_LEASE_SECONDS, MAXIMUM_SOURCE_SUBMOUNTS,
    NativeAcquireCatalogBindingV3, SourceProviderAuthorityV1, SourceUseV1,
    digest_logical_binding_bytes, prospective_mount_apply_template_digest_v1,
    source_acquisition_id_v2,
};

const MAXIMUM_APPLY_TEMPLATE_BYTES: usize = 2_048;
const MAXIMUM_LOGICAL_BINDING_BYTES: usize = 65_536;

const MAGIC: &[u8; 8] = b"AOSNPI01";
const VERSION: u16 = 2;
const NATIVE_VERSION: u16 = 3;
const NATIVE_PROFILE_KIND: u8 = 1;
const FIXED_BYTES: usize = 412;
const NATIVE_CATALOG_BYTES: usize = 176;
const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.source-provider.normalized-acquisition-intent.v2\0";
const NATIVE_DIGEST_DOMAIN: &[u8] =
    b"aos.sandbox.source-provider.normalized-acquisition-intent.v3\0";

/// Maximum exact canonical legacy version-2 normalized acquisition bytes.
pub const MAXIMUM_NORMALIZED_ACQUISITION_INTENT_V2_BYTES: usize =
    FIXED_BYTES + MAXIMUM_APPLY_TEMPLATE_BYTES + MAXIMUM_LOGICAL_BINDING_BYTES;

/// Maximum exact canonical normalized acquisition bytes across both profiles.
pub const MAXIMUM_NORMALIZED_ACQUISITION_INTENT_BYTES: usize =
    MAXIMUM_NORMALIZED_ACQUISITION_INTENT_V2_BYTES + NATIVE_CATALOG_BYTES;

const _: () = assert!(
    8 + 2
        + 1
        + 1
        + 4
        + 32
        + 8
        + 56
        + 56
        + 16
        + 16
        + 16
        + 8
        + 32
        + 32
        + 8
        + 32
        + 8
        + 4
        + 4
        + 32
        + 4
        + 32
        == FIXED_BYTES
);
const _: () = assert!(MAXIMUM_NORMALIZED_ACQUISITION_INTENT_BYTES == 68_172);
const _: () = assert!(MAXIMUM_NORMALIZED_ACQUISITION_INTENT_V2_BYTES == 67_996);

/// Separates legacy normalization from the complete native selection claims.
#[derive(Clone, Debug, Eq, PartialEq)]
enum AcquisitionProfile {
    LegacyV2,
    NativeV3(NativeAcquireCatalogBindingV3),
}

/// Retains one stable acquisition meaning across sessions and process instances.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedAcquisitionIntentV1 {
    profile: AcquisitionProfile,
    pub(crate) source_use: SourceUseV1,
    pub(crate) recursive: bool,
    pub(crate) kernel_coupled: bool,
    pub(crate) acquisition_id: ObjectDigest,
    pub(crate) acquisition_sequence: u64,
    pub(crate) provider: SourceProviderAuthorityV1,
    pub(crate) holder: SourceProviderAuthorityV1,
    pub(crate) node_id: [u8; 16],
    pub(crate) boot_id: [u8; 16],
    pub(crate) route_id: [u8; 16],
    pub(crate) route_generation: u64,
    pub(crate) route_digest: ObjectDigest,
    pub(crate) resource_namespace_digest: ObjectDigest,
    pub(crate) holder_revocation_generation: u64,
    pub(crate) holder_revocation_digest: ObjectDigest,
    pub(crate) requested_lease_seconds: u64,
    pub(crate) requested_maximum_submounts: u32,
    pub(crate) prospective_apply_template: Vec<u8>,
    pub(crate) prospective_apply_template_digest: ObjectDigest,
    pub(crate) binding: Vec<u8>,
    pub(crate) binding_digest: ObjectDigest,
}

/// Preserves the historical name of the canonical acquisition-intent carrier.
///
/// `AOSNPI01` is the format-family magic; the embedded version is authoritative.
/// The legacy constructor still emits only version 2 and rejects Acquire V3.
/// Explicit profile reconstruction and decoding also retain native version 3;
/// neither path silently interprets version-1 bytes or strips catalog claims.
pub type NormalizedAcquisitionIntentV2 = NormalizedAcquisitionIntentV1;

/// Reports malformed or noncanonical AOSNPI01 bytes or fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NormalizedAcquisitionIntentError {
    /// A required field, limit, digest, flag, or canonical encoding is invalid.
    #[error("invalid normalized SourceProvider acquisition intent")]
    Invalid,
}

impl NormalizedAcquisitionIntentV1 {
    /// Constructs the canonical stable intent for one decoded Acquire request.
    ///
    /// The explicit authority, route, namespace, and revocation inputs must be
    /// resolved by the caller from its protected historical/current state.
    /// Construction itself grants no such provenance or effect authority.
    ///
    /// Native Acquire V3 is rejected rather than dropping its catalog claims
    /// into the legacy version-2 durable format.
    ///
    /// # Errors
    ///
    /// Returns [`NormalizedAcquisitionIntentError`] if an input is sentinel,
    /// exceeds a format ceiling, disagrees with a request commitment, or is a
    /// native version-3 request unsupported by this version-2 format.
    #[allow(clippy::too_many_arguments)]
    pub fn from_acquire_request(
        request: &AcquireSourceRequestV1,
        provider: SourceProviderAuthorityV1,
        holder: SourceProviderAuthorityV1,
        node_id: [u8; 16],
        boot_id: [u8; 16],
        route_id: [u8; 16],
        route_generation: u64,
        route_digest: ObjectDigest,
        resource_namespace_digest: ObjectDigest,
        holder_revocation_generation: u64,
        holder_revocation_digest: ObjectDigest,
    ) -> Result<Self, NormalizedAcquisitionIntentError> {
        if request.acquisition_version() == crate::ACQUIRE_SOURCE_REQUEST_VERSION_V3 {
            return Err(NormalizedAcquisitionIntentError::Invalid);
        }
        Self::from_original_acquire_request(
            request,
            provider,
            holder,
            node_id,
            boot_id,
            route_id,
            route_generation,
            route_digest,
            resource_namespace_digest,
            holder_revocation_generation,
            holder_revocation_digest,
        )
    }

    /// Reconstructs the exact profile from an original decoded Acquire subject.
    ///
    /// Version 3 retains all seven native catalog fields; older requests retain
    /// the unchanged version-2 normalization. The supplied owner coordinates
    /// are checked as data, not authenticated by this pure reconstruction.
    ///
    /// # Errors
    ///
    /// Rejects invalid coordinates or commitments, a missing native catalog,
    /// kernel-coupled native data, or a catalog outside the supplied namespace.
    #[allow(clippy::too_many_arguments)]
    pub fn from_original_acquire_request(
        request: &AcquireSourceRequestV1,
        provider: SourceProviderAuthorityV1,
        holder: SourceProviderAuthorityV1,
        node_id: [u8; 16],
        boot_id: [u8; 16],
        route_id: [u8; 16],
        route_generation: u64,
        route_digest: ObjectDigest,
        resource_namespace_digest: ObjectDigest,
        holder_revocation_generation: u64,
        holder_revocation_digest: ObjectDigest,
    ) -> Result<Self, NormalizedAcquisitionIntentError> {
        let profile = match request.native_catalog() {
            Some(catalog)
                if request.acquisition_version() == crate::ACQUIRE_SOURCE_REQUEST_VERSION_V3 =>
            {
                AcquisitionProfile::NativeV3(catalog.clone())
            }
            None if request.acquisition_version() != crate::ACQUIRE_SOURCE_REQUEST_VERSION_V3 => {
                AcquisitionProfile::LegacyV2
            }
            _ => return Err(NormalizedAcquisitionIntentError::Invalid),
        };
        if node_id != request.node_id()
            || boot_id != request.boot_id()
            || holder.authority_id() != request.holder_authority_id()
            || holder.authority_generation() != request.holder_generation()
            || holder.authority_digest() != request.holder_authority_digest()
            || holder_revocation_digest != request.revocation_digest()
        {
            return Err(NormalizedAcquisitionIntentError::Invalid);
        }
        let value = Self {
            profile,
            source_use: request.source_use(),
            recursive: request.recursive(),
            kernel_coupled: request.kernel_coupled(),
            acquisition_id: request.acquisition_id(),
            acquisition_sequence: request.acquisition_sequence(),
            provider,
            holder,
            node_id,
            boot_id,
            route_id,
            route_generation,
            route_digest,
            resource_namespace_digest,
            holder_revocation_generation,
            holder_revocation_digest,
            requested_lease_seconds: request.requested_lease_seconds(),
            requested_maximum_submounts: request.requested_maximum_submounts(),
            prospective_apply_template: request.prospective_apply_template().to_vec(),
            prospective_apply_template_digest: request.prospective_apply_template_digest(),
            binding: request.binding().to_vec(),
            binding_digest: request.binding_digest(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Borrows the complete native catalog profile, absent for legacy data.
    #[must_use]
    pub const fn native_catalog(&self) -> Option<&NativeAcquireCatalogBindingV3> {
        match &self.profile {
            AcquisitionProfile::LegacyV2 => None,
            AcquisitionProfile::NativeV3(catalog) => Some(catalog),
        }
    }

    /// Compares the complete retained meaning with an original Acquire subject.
    ///
    /// Reconstruction uses this value's retained owner coordinates and checks
    /// every normalized semantic field, including the native catalog profile.
    /// Session, attempt and deadline fields deliberately remain outside this
    /// stable intent. This is not a signature or current-authority check.
    #[must_use]
    pub fn matches_original_acquire_request(&self, request: &AcquireSourceRequestV1) -> bool {
        Self::from_original_acquire_request(
            request,
            self.provider.clone(),
            self.holder.clone(),
            self.node_id,
            self.boot_id,
            self.route_id,
            self.route_generation,
            self.route_digest,
            self.resource_namespace_digest,
            self.holder_revocation_generation,
            self.holder_revocation_digest,
        )
        .is_ok_and(|reconstructed| reconstructed == *self)
    }

    /// Returns the stable acquisition identity.
    #[must_use]
    pub const fn acquisition_id(&self) -> ObjectDigest {
        self.acquisition_id
    }

    /// Returns the holder-authority-scoped monotone acquisition sequence.
    #[must_use]
    pub const fn acquisition_sequence(&self) -> u64 {
        self.acquisition_sequence
    }

    /// Returns the provider authority bound into the intent.
    #[must_use]
    pub const fn provider(&self) -> &SourceProviderAuthorityV1 {
        &self.provider
    }

    /// Returns the holder authority bound into the intent.
    #[must_use]
    pub const fn holder(&self) -> &SourceProviderAuthorityV1 {
        &self.holder
    }

    /// Returns whether the selected proof must cover recursive topology.
    #[must_use]
    pub const fn recursive(&self) -> bool {
        self.recursive
    }

    /// Returns whether the selected proof must be kernel coupled.
    #[must_use]
    pub const fn kernel_coupled(&self) -> bool {
        self.kernel_coupled
    }

    /// Returns the committed resource namespace.
    #[must_use]
    pub const fn resource_namespace_digest(&self) -> ObjectDigest {
        self.resource_namespace_digest
    }

    /// Returns the requested lease duration in seconds.
    #[must_use]
    pub const fn requested_lease_seconds(&self) -> u64 {
        self.requested_lease_seconds
    }

    /// Returns the maximum recursive submount count accepted by the request.
    #[must_use]
    pub const fn requested_maximum_submounts(&self) -> u32 {
        self.requested_maximum_submounts
    }

    /// Returns the holder revocation commitment.
    #[must_use]
    pub const fn holder_revocation_digest(&self) -> ObjectDigest {
        self.holder_revocation_digest
    }

    /// Returns the exact logical-binding commitment.
    #[must_use]
    pub const fn binding_digest(&self) -> ObjectDigest {
        self.binding_digest
    }

    /// Returns the exact canonical intent commitment.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        let encoded = self.to_canonical_bytes();
        let mut hasher = Sha256::new();
        hasher.update(match self.profile {
            AcquisitionProfile::LegacyV2 => DIGEST_DOMAIN,
            AcquisitionProfile::NativeV3(_) => NATIVE_DIGEST_DOMAIN,
        });
        hasher.update((encoded.len() as u32).to_be_bytes());
        hasher.update(encoded);
        ObjectDigest::from_bytes(hasher.finalize().into())
    }

    /// Returns the exact canonical AOSNPI01 bytes.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            self.fixed_bytes() + self.prospective_apply_template.len() + self.binding.len(),
        );
        bytes.extend_from_slice(MAGIC);
        let (version, profile_kind) = match self.profile {
            AcquisitionProfile::LegacyV2 => (VERSION, 0),
            AcquisitionProfile::NativeV3(_) => (NATIVE_VERSION, NATIVE_PROFILE_KIND),
        };
        bytes.extend_from_slice(&version.to_be_bytes());
        bytes.push(self.source_use as u8);
        bytes.push(u8::from(self.recursive) | (u8::from(self.kernel_coupled) << 1));
        bytes.push(profile_kind);
        bytes.extend_from_slice(&[0; 3]);
        bytes.extend_from_slice(self.acquisition_id.as_bytes());
        bytes.extend_from_slice(&self.acquisition_sequence.to_be_bytes());
        encode_authority(&mut bytes, &self.provider);
        encode_authority(&mut bytes, &self.holder);
        bytes.extend_from_slice(&self.node_id);
        bytes.extend_from_slice(&self.boot_id);
        bytes.extend_from_slice(&self.route_id);
        bytes.extend_from_slice(&self.route_generation.to_be_bytes());
        bytes.extend_from_slice(self.route_digest.as_bytes());
        bytes.extend_from_slice(self.resource_namespace_digest.as_bytes());
        bytes.extend_from_slice(&self.holder_revocation_generation.to_be_bytes());
        bytes.extend_from_slice(self.holder_revocation_digest.as_bytes());
        bytes.extend_from_slice(&self.requested_lease_seconds.to_be_bytes());
        bytes.extend_from_slice(&self.requested_maximum_submounts.to_be_bytes());
        bytes.extend_from_slice(&(self.prospective_apply_template.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.prospective_apply_template_digest.as_bytes());
        bytes.extend_from_slice(&(self.binding.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.binding_digest.as_bytes());
        if let Some(catalog) = self.native_catalog() {
            bytes.extend_from_slice(catalog.resource_namespace_digest().as_bytes());
            bytes.extend_from_slice(&catalog.head().0.to_be_bytes());
            bytes.extend_from_slice(catalog.head().1.as_bytes());
            bytes.extend_from_slice(&catalog.floor().0.to_be_bytes());
            bytes.extend_from_slice(catalog.floor().1.as_bytes());
            bytes.extend_from_slice(catalog.current_head_commitment().as_bytes());
            bytes.extend_from_slice(catalog.canonical_publication_digest().as_bytes());
        }
        bytes.extend_from_slice(&self.prospective_apply_template);
        bytes.extend_from_slice(&self.binding);
        bytes
    }

    /// Decodes one exact canonical AOSNPI01 value.
    ///
    /// # Errors
    ///
    /// Returns [`NormalizedAcquisitionIntentError`] for malformed, oversized,
    /// sentinel, digest-inconsistent, or noncanonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, NormalizedAcquisitionIntentError> {
        if bytes.len() < FIXED_BYTES
            || bytes.len() > MAXIMUM_NORMALIZED_ACQUISITION_INTENT_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(13..16) != Some([0_u8; 3].as_slice())
        {
            return Err(NormalizedAcquisitionIntentError::Invalid);
        }
        let profile = match (u16::from_be_bytes(read_array(bytes, 8)?), bytes[12]) {
            (VERSION, 0) => AcquisitionProfile::LegacyV2,
            (NATIVE_VERSION, NATIVE_PROFILE_KIND) => AcquisitionProfile::NativeV3(
                NativeAcquireCatalogBindingV3::new(
                    ObjectDigest::from_bytes(read_array(bytes, FIXED_BYTES)?),
                    read_u64(bytes, FIXED_BYTES + 32)?,
                    ObjectDigest::from_bytes(read_array(bytes, FIXED_BYTES + 40)?),
                    read_u64(bytes, FIXED_BYTES + 72)?,
                    ObjectDigest::from_bytes(read_array(bytes, FIXED_BYTES + 80)?),
                    ObjectDigest::from_bytes(read_array(bytes, FIXED_BYTES + 112)?),
                    ObjectDigest::from_bytes(read_array(bytes, FIXED_BYTES + 144)?),
                )
                .map_err(|_| NormalizedAcquisitionIntentError::Invalid)?,
            ),
            _ => return Err(NormalizedAcquisitionIntentError::Invalid),
        };
        let fixed_bytes = match profile {
            AcquisitionProfile::LegacyV2 => FIXED_BYTES,
            AcquisitionProfile::NativeV3(_) => FIXED_BYTES + NATIVE_CATALOG_BYTES,
        };
        let source_use = match bytes[10] {
            1 => SourceUseV1::MountCreate,
            _ => return Err(NormalizedAcquisitionIntentError::Invalid),
        };
        if bytes[11] & !0b11 != 0 {
            return Err(NormalizedAcquisitionIntentError::Invalid);
        }
        let template_len = read_u32(bytes, 340)? as usize;
        let binding_len = read_u32(bytes, 376)? as usize;
        let expected = fixed_bytes
            .checked_add(template_len)
            .and_then(|length| length.checked_add(binding_len))
            .ok_or(NormalizedAcquisitionIntentError::Invalid)?;
        if template_len > MAXIMUM_APPLY_TEMPLATE_BYTES
            || binding_len > MAXIMUM_LOGICAL_BINDING_BYTES
            || expected != bytes.len()
        {
            return Err(NormalizedAcquisitionIntentError::Invalid);
        }
        let template_end = fixed_bytes + template_len;
        let value = Self {
            profile,
            source_use,
            recursive: bytes[11] & 1 != 0,
            kernel_coupled: bytes[11] & 2 != 0,
            acquisition_id: ObjectDigest::from_bytes(read_array(bytes, 16)?),
            acquisition_sequence: read_u64(bytes, 48)?,
            provider: decode_authority(bytes, 56)?,
            holder: decode_authority(bytes, 112)?,
            node_id: read_array(bytes, 168)?,
            boot_id: read_array(bytes, 184)?,
            route_id: read_array(bytes, 200)?,
            route_generation: read_u64(bytes, 216)?,
            route_digest: ObjectDigest::from_bytes(read_array(bytes, 224)?),
            resource_namespace_digest: ObjectDigest::from_bytes(read_array(bytes, 256)?),
            holder_revocation_generation: read_u64(bytes, 288)?,
            holder_revocation_digest: ObjectDigest::from_bytes(read_array(bytes, 296)?),
            requested_lease_seconds: read_u64(bytes, 328)?,
            requested_maximum_submounts: read_u32(bytes, 336)?,
            prospective_apply_template: bytes[fixed_bytes..template_end].to_vec(),
            prospective_apply_template_digest: ObjectDigest::from_bytes(read_array(bytes, 344)?),
            binding: bytes[template_end..].to_vec(),
            binding_digest: ObjectDigest::from_bytes(read_array(bytes, 380)?),
        };
        value.validate()?;
        if value.to_canonical_bytes() != bytes {
            return Err(NormalizedAcquisitionIntentError::Invalid);
        }
        Ok(value)
    }

    fn fixed_bytes(&self) -> usize {
        match self.profile {
            AcquisitionProfile::LegacyV2 => FIXED_BYTES,
            AcquisitionProfile::NativeV3(_) => FIXED_BYTES + NATIVE_CATALOG_BYTES,
        }
    }

    fn validate(&self) -> Result<(), NormalizedAcquisitionIntentError> {
        if self.native_catalog().is_some_and(|catalog| {
            self.kernel_coupled
                || catalog.resource_namespace_digest() != self.resource_namespace_digest
        }) {
            return Err(NormalizedAcquisitionIntentError::Invalid);
        }
        if self.acquisition_id.as_bytes() == &[0; 32]
            || self.acquisition_sequence == 0
            || self.acquisition_id
                != source_acquisition_id_v2(
                    self.holder.authority_id(),
                    self.holder.authority_generation(),
                    self.holder.authority_digest(),
                    self.acquisition_sequence,
                )
            || self.node_id == [0; 16]
            || self.boot_id == [0; 16]
            || self.route_id == [0; 16]
            || self.route_generation == 0
            || self.route_digest.as_bytes() == &[0; 32]
            || self.resource_namespace_digest.as_bytes() == &[0; 32]
            || self.holder_revocation_generation == 0
            || self.holder_revocation_digest.as_bytes() == &[0; 32]
            || self.requested_lease_seconds == 0
            || self.requested_lease_seconds > MAXIMUM_SOURCE_LEASE_SECONDS
            || self.requested_maximum_submounts > MAXIMUM_SOURCE_SUBMOUNTS
            || (!self.recursive && self.requested_maximum_submounts != 0)
            || self.prospective_apply_template.is_empty()
            || self.prospective_apply_template.len() > MAXIMUM_APPLY_TEMPLATE_BYTES
            || self.binding.is_empty()
            || self.binding.len() > MAXIMUM_LOGICAL_BINDING_BYTES
            || !matches!(
                prospective_mount_apply_template_digest_v1(&self.prospective_apply_template),
                Ok(digest) if digest == self.prospective_apply_template_digest
            )
            || digest_logical_binding_bytes(&self.binding) != self.binding_digest
        {
            return Err(NormalizedAcquisitionIntentError::Invalid);
        }
        Ok(())
    }
}

fn encode_authority(bytes: &mut Vec<u8>, authority: &SourceProviderAuthorityV1) {
    bytes.extend_from_slice(&authority.authority_id());
    bytes.extend_from_slice(&authority.authority_generation().to_be_bytes());
    bytes.extend_from_slice(authority.authority_digest().as_bytes());
}

fn decode_authority(
    bytes: &[u8],
    offset: usize,
) -> Result<SourceProviderAuthorityV1, NormalizedAcquisitionIntentError> {
    SourceProviderAuthorityV1::new(
        read_array(bytes, offset)?,
        read_u64(bytes, offset + 16)?,
        ObjectDigest::from_bytes(read_array(bytes, offset + 24)?),
    )
    .map_err(|_| NormalizedAcquisitionIntentError::Invalid)
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], NormalizedAcquisitionIntentError> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(NormalizedAcquisitionIntentError::Invalid)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, NormalizedAcquisitionIntentError> {
    Ok(u32::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, NormalizedAcquisitionIntentError> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}
