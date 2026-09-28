//! Data-only exact catalog binding for native Acquire subject version 3.
//!
//! The fixed catalog block follows the version-3 native-profile header and
//! precedes the unchanged explicit-sequence Acquire body:
//!
//! ```text
//! namespace[32] | head-generation:u64be | head-digest[32] |
//! floor-generation:u64be | floor-digest[32] | current-head-commitment[32] |
//! canonical-publication-digest[32]
//! ```
//!
//! These claims establish no signature, currentness, selection, or effect
//! authority. Production owners must independently join the signed request to
//! the current protected catalog; the opaque logical binding remains owned by
//! its existing semantic validator.

use aos_sandbox_core::ObjectDigest;

use super::{
    ACQUIRE_SOURCE_REQUEST_VERSION_V2, ACQUIRE_SOURCE_REQUEST_VERSION_V3, AcquireSourceRequestV1,
    SourceProviderValidationError, require_digest, require_generation,
};

/// Names the exact catalog head and floor requested by one native Acquire.
///
/// This validated data carries no protected-journal or live-session provenance.
/// The publication digest commits the complete canonical signed publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeAcquireCatalogBindingV3 {
    resource_namespace_digest: ObjectDigest,
    head_generation: u64,
    head_digest: ObjectDigest,
    floor_generation: u64,
    floor_digest: ObjectDigest,
    current_head_commitment: ObjectDigest,
    canonical_publication_digest: ObjectDigest,
}

impl NativeAcquireCatalogBindingV3 {
    /// Constructs the nonauthorizing exact-catalog claims for a native request.
    ///
    /// # Errors
    ///
    /// Rejects zero digests or generations, a floor above the head, or different
    /// digests at the same head and floor generation.
    pub fn new(
        resource_namespace_digest: ObjectDigest,
        head_generation: u64,
        head_digest: ObjectDigest,
        floor_generation: u64,
        floor_digest: ObjectDigest,
        current_head_commitment: ObjectDigest,
        canonical_publication_digest: ObjectDigest,
    ) -> Result<Self, SourceProviderValidationError> {
        require_digest("native Acquire namespace", resource_namespace_digest)?;
        require_generation("native Acquire catalog head", head_generation)?;
        require_digest("native Acquire catalog head", head_digest)?;
        require_generation("native Acquire catalog floor", floor_generation)?;
        require_digest("native Acquire catalog floor", floor_digest)?;
        require_digest("native Acquire current head", current_head_commitment)?;
        require_digest("native Acquire publication", canonical_publication_digest)?;
        if floor_generation > head_generation
            || (floor_generation == head_generation && floor_digest != head_digest)
        {
            return Err(SourceProviderValidationError::CommitmentMismatch(
                "native Acquire catalog floor",
            ));
        }

        Ok(Self {
            resource_namespace_digest,
            head_generation,
            head_digest,
            floor_generation,
            floor_digest,
            current_head_commitment,
            canonical_publication_digest,
        })
    }

    /// Returns the claimed catalog resource namespace.
    #[must_use]
    pub const fn resource_namespace_digest(&self) -> ObjectDigest {
        self.resource_namespace_digest
    }

    /// Returns the exact requested catalog head generation and digest.
    #[must_use]
    pub const fn head(&self) -> (u64, ObjectDigest) {
        (self.head_generation, self.head_digest)
    }

    /// Returns the exact retained catalog floor generation and digest.
    #[must_use]
    pub const fn floor(&self) -> (u64, ObjectDigest) {
        (self.floor_generation, self.floor_digest)
    }

    /// Returns the claimed protected current-head commitment.
    #[must_use]
    pub const fn current_head_commitment(&self) -> ObjectDigest {
        self.current_head_commitment
    }

    /// Returns the digest of the complete canonical signed publication.
    #[must_use]
    pub const fn canonical_publication_digest(&self) -> ObjectDigest {
        self.canonical_publication_digest
    }
}

impl AcquireSourceRequestV1 {
    /// Constructs a native-only version-3 subject from validated version-2 data.
    ///
    /// The holder-scoped identity and every original request field are retained.
    /// This explicit data construction grants no authority to dispatch or select
    /// a catalog row. Version 3 has no LocalLive catalog profile; the logical
    /// binding's meaning must still be checked by the Mount and Provider owners.
    ///
    /// # Errors
    ///
    /// Rejects another input version or a kernel-coupled request.
    pub fn new_native_v3(
        mut request: Self,
        catalog: NativeAcquireCatalogBindingV3,
    ) -> Result<Self, SourceProviderValidationError> {
        if request.acquisition_version != ACQUIRE_SOURCE_REQUEST_VERSION_V2 {
            return Err(SourceProviderValidationError::CommitmentMismatch(
                "native Acquire input version",
            ));
        }
        if request.kernel_coupled {
            return Err(SourceProviderValidationError::ProofCapabilityMismatch);
        }

        request.acquisition_version = ACQUIRE_SOURCE_REQUEST_VERSION_V3;
        request.native_catalog = Some(catalog);
        Ok(request)
    }

    /// Borrows the exact native catalog claims present only in version 3.
    #[must_use]
    pub const fn native_catalog(&self) -> Option<&NativeAcquireCatalogBindingV3> {
        self.native_catalog.as_ref()
    }
}
