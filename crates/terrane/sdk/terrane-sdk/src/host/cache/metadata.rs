//! Reads canonical host-local metadata without repository-routing authority.
//!
//! This view reuses the bounded encoded reader and its physical identity checks.
//! It exposes neither a guest `ContentStore` nor a sealed backing handle. Private
//! host-local domains are allowed here; shared-directory policy remains separate.

use super::{HostDomainLocation, HostReadLimits, HostReadOnlyContent};
use crate::{
    bucket::BucketBinding,
    pack::PackId,
    store::{
        ByteRange, ContentValidator, IdentityPrefix, InvalidReason, LocalFs, StoreErrorKind,
        StoreFailure,
    },
};
use terrane_format::identity::{Identity, IdentityKind};

/// Provides verified metadata lookup for one configured physical host domain.
///
/// No repository ref, tree root or repository path is invented. Trusted native
/// composition separately retains actual domain-root/charge-owner custody.
pub struct HostMetadataReader<F, V> {
    inner: HostReadOnlyContent<F, V, HostDomainLocation>,
}

/// Describes freshly verified canonical metadata in an existing ordinary pack.
///
/// This is derived read data, not a retained native descriptor or durability,
/// pin, quota or publication receipt. Native retention must independently open
/// and verify the actual pack and index under its physical owner custody.
pub struct HostMetadataEntry {
    /// Exact canonical metadata bytes, verified against the requested identity.
    pub canonical: Vec<u8>,
    /// Existing-format pack identifier selected by verified index lookup.
    pub pack_id: PackId,
    /// Exact canonical body span within that pack.
    pub range: ByteRange,
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
        Ok(self.get_entry(identity).await?.canonical)
    }

    /// Reads verified metadata and its existing pack-body location.
    ///
    /// The returned location is not native retention or durability proof. No
    /// state record is written and no inode remains pinned by this operation.
    ///
    /// # Errors
    /// Returns the same identity, capacity, absence, corruption and filesystem
    /// failures as `get`; refuses any result lacking an ordinary pack location.
    pub async fn get_entry(&self, identity: &Identity) -> Result<HostMetadataEntry, StoreFailure> {
        if matches!(identity.kind(), IdentityKind::Chunk | IdentityKind::Pack) {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        let result = self.inner.read_encoded(identity, true).await?;
        let (pack_id, range) = result
            .pack
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))?;
        Ok(HostMetadataEntry {
            canonical: result.bytes,
            pack_id,
            range,
        })
    }

    /// Lists bounded ordinary-content candidates for recovery, GC or scrub.
    ///
    /// The result is advisory and may be partial or immediately stale. It grants
    /// no serving, native adoption, deletion or pin authority. Sealed-only chunk
    /// residences are omitted; consumers verify every candidate independently.
    /// Existing ordinary packs and standalone chunks use the same bounded,
    /// no-follow reads and identity checks as the encoded content reader.
    ///
    /// # Errors
    /// Refuses a digest prefix longer than 32 bytes, a zero or exhausted result
    /// budget, changed roots, invalid/corrupt content and filesystem failures.
    pub async fn list_candidates(
        &self,
        prefix: &IdentityPrefix,
        max_entries: usize,
    ) -> Result<Vec<Identity>, StoreFailure> {
        if prefix.digest_prefix.len() > 32 {
            return Err(StoreFailure::new(StoreErrorKind::Invalid(
                InvalidReason::MalformedRequest,
            )));
        }
        if max_entries == 0 {
            return Err(StoreFailure::new(StoreErrorKind::Capacity));
        }
        self.inner.list_bounded(prefix, max_entries).await
    }

    /// Returns the physical root identity observed during opening.
    ///
    /// This observation is not authorization or proof of kernel quota coverage.
    pub fn directory_identity(&self) -> (u64, u64) {
        self.inner.directory_identity()
    }
}
