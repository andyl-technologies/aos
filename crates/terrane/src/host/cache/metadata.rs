//! Reads canonical host-local metadata without repository-routing authority.
//!
//! This view reuses the bounded encoded reader and its physical identity checks.
//! It exposes neither a guest `ContentStore` nor a sealed backing handle. Private
//! host-local domains are allowed here; shared-directory policy remains separate.

use super::{HostDomainLocation, HostReadLimits, HostReadOnlyContent};
use crate::{
    bucket::BucketBinding,
    store::{ContentStore, ContentValidator, LocalFs, StoreErrorKind, StoreFailure},
};
use terrane_core::identity::{Identity, IdentityKind};

/// Provides verified metadata lookup for one configured physical host domain.
///
/// No repository ref, tree root or repository path is invented. Trusted native
/// composition separately retains actual domain-root/charge-owner custody.
pub struct HostMetadataReader<F, V> {
    inner: HostReadOnlyContent<F, V, HostDomainLocation>,
}

impl<F: LocalFs + BucketBinding, V: ContentValidator + BucketBinding> HostMetadataReader<F, V> {
    /// Opens an existing host-local metadata view without any write probes.
    ///
    /// # Errors
    /// Refuses missing/replaced/symlinked roots, zero allocation budgets and
    /// unsupported physical identity observations. It creates no directories.
    pub async fn open_existing(
        location: HostDomainLocation,
        fs: F,
        validator: V,
        limits: HostReadLimits,
    ) -> Result<Self, StoreFailure> {
        let inner = HostReadOnlyContent::open_location(location, fs, validator, limits).await?;
        Ok(Self { inner })
    }

    /// Reads canonical metadata after pack structure, identity and schema checks.
    ///
    /// The exact returned length supplies the manifest descriptor size during
    /// recovery. Missing content remains absent; size is never guessed. Chunk
    /// and whole-pack identities are deliberately unavailable in this view.
    ///
    /// # Errors
    /// Returns unsupported for chunk/pack identities, absent for missing metadata,
    /// capacity for the operator budget, and malformed/corrupt/native I/O errors.
    pub async fn get(&self, identity: &Identity) -> Result<Vec<u8>, StoreFailure> {
        if matches!(identity.kind(), IdentityKind::Chunk | IdentityKind::Pack) {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        self.inner.get(identity, None).await
    }

    /// Returns the physical root identity observed during opening.
    ///
    /// This observation is not authorization or proof of kernel quota coverage.
    pub fn directory_identity(&self) -> (u64, u64) {
        self.inner.directory_identity()
    }
}
