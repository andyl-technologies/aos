//! Retains verified opaque container reads for existing body membership.
//!
//! A live body row and independently selected inventory must both agree with the
//! actual sealed pair. This reads physical pack bytes for integrity; it never
//! performs a typed Chunk get, decodes Chunk plaintext, or derives an attribute.

use super::catalog::Catalog;
use super::held::HeldBucket;
use super::publication::SelectedObservation;
use super::publication::receipts::RecordRead;
use super::{BucketBinding, FileBucket, files};
use crate::pack::{MergedEntry, PackReader};
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use terrane_format::bucket::PackInventoryEntry;
use terrane_format::identity::{Identity, IdentityKind};

/// Retains actual independently verified membership without granting rights.
///
/// Only the held backend constructs this from a live row and verified inventory.
/// A complete signed owner and current request must separately qualify its use.
pub(crate) struct ExistingPlacement {
    identity: Identity,
    location: MergedEntry,
    inventory: PackInventoryEntry,
    reads: [RecordRead; 2],
}

impl ExistingPlacement {
    /// Borrows the exact identity independently resolved by the live body row.
    pub(crate) fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Borrows the actual opaque pack and detached-index reads for final refresh.
    pub(crate) fn reads(&self) -> &[RecordRead] {
        &self.reads
    }

    /// Borrows the exact encoded member bytes from the verified opaque pair.
    ///
    /// Content interpretation belongs to the caller above the backend. This
    /// exposes only the member geometry already bound to the live row and pair.
    ///
    /// # Errors
    /// Returns corruption if retained pack bytes or member bounds are invalid.
    pub(crate) fn encoded_member(&self) -> Result<&[u8], StoreFailure> {
        let pack = self.reads[0].bytes().ok_or_else(files::layout_corrupt)?;
        let entry = self.location.entry();
        let start = usize::try_from(entry.offset()).map_err(|_| files::layout_corrupt())?;
        let length = usize::try_from(entry.body_len()).map_err(|_| files::layout_corrupt())?;
        let end = start
            .checked_add(length)
            .ok_or_else(files::layout_corrupt)?;
        pack.get(start..end).ok_or_else(files::layout_corrupt)
    }

    /// Rechecks the exact eligible placement and original physical preimages.
    ///
    /// # Errors
    /// Preserves current catalogue, corruption and I/O errors. Refuses a changed
    /// row, inventory, inode, protection, length, or opaque bytes; no Chunk body
    /// decoding is substituted for the original admitted container association.
    pub(crate) async fn revalidate<F, B, V, const WRITABLE: bool>(
        &self,
        held: &HeldBucket<'_, F, B, V, WRITABLE>,
        observed: &SelectedObservation<'_>,
    ) -> Result<(), StoreFailure>
    where
        F: LocalFs + BucketBinding,
        B: Clock + BucketBinding,
        V: ContentValidator + BucketBinding,
    {
        let fresh = held.existing_placement(observed, &self.identity).await?;
        if fresh.location != self.location || fresh.inventory != self.inventory {
            return Err(files::layout_corrupt());
        }
        for (old, fresh) in self.reads.iter().zip(&fresh.reads) {
            if old.path() != fresh.path() || old.bytes() != fresh.bytes() {
                return Err(files::layout_corrupt());
            }
            let old = old.metadata().ok_or_else(files::layout_corrupt)?;
            let fresh = fresh.metadata().ok_or_else(files::layout_corrupt)?;
            if !same_leaf(old, fresh) {
                return Err(files::layout_corrupt());
            }
        }
        observed.revalidate().await
    }
}

impl<F, B, V, const WRITABLE: bool> HeldBucket<'_, F, B, V, WRITABLE>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    /// Qualifies actual member placement under this borrowed namespace holder.
    ///
    /// # Errors
    /// Rejects unsupported kinds, unknown inventory, absence/exclusions and
    /// corrupt or unavailable opaque artifacts. Whole-pack inventory without a
    /// member Live row cannot produce this observation.
    pub(crate) async fn existing_placement(
        &self,
        observed: &SelectedObservation<'_>,
        identity: &Identity,
    ) -> Result<ExistingPlacement, StoreFailure> {
        observed.revalidate().await?;
        if observed.identity().root() != self.root()
            || observed.identity().physical_identity() != self.physical_identity()
        {
            return Err(files::layout_corrupt());
        }
        let bucket = self.bucket();
        let catalog = bucket.catalog_observed(observed).await?;
        let placement = bucket
            .existing_placement_from_catalog(observed, &catalog, identity)
            .await?;
        observed.revalidate().await?;
        Ok(placement)
    }
}

impl<F, B, V> FileBucket<F, B, V>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    async fn existing_placement_from_catalog(
        &self,
        observed: &SelectedObservation<'_>,
        catalog: &Catalog,
        identity: &Identity,
    ) -> Result<ExistingPlacement, StoreFailure> {
        if !matches!(
            identity.kind(),
            IdentityKind::Chunk | IdentityKind::Manifest
        ) {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        if catalog.exclusions.is_none() || catalog.burns.is_none() {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        if self.is_excluded(catalog, identity)? {
            return Err(StoreFailure::new(StoreErrorKind::Absent(identity.clone())));
        }
        let location = self.location(catalog, identity)?.clone();
        let inventory = catalog
            .inventory
            .as_ref()
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry.pack_id == *location.pack().as_bytes())
            })
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))?
            .clone();
        let (pack, index) = self.verified_container_observed(&inventory).await?;
        let bytes = pack.bytes().ok_or_else(files::layout_corrupt)?;
        let reader = PackReader::open(bytes).map_err(|error| {
            StoreFailure::with_source(super::content::corrupt(identity).kind().clone(), error)
        })?;
        let embedded = reader
            .entries()
            .iter()
            .find(|entry| entry.hash() == location.entry().hash())
            .ok_or_else(|| super::content::corrupt(identity))?;
        if embedded != location.entry() {
            return Err(super::content::corrupt(identity));
        }
        for read in [&pack, &index] {
            let metadata = read.metadata().ok_or_else(files::layout_corrupt)?;
            check_leaf(metadata, observed.configured_operator_uid())?;
        }
        Ok(ExistingPlacement {
            identity: identity.clone(),
            location,
            inventory,
            reads: [pack, index],
        })
    }
}

fn check_leaf(metadata: &std::fs::Metadata, owner: u32) -> Result<(), StoreFailure> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
    {
        return Err(files::layout_corrupt());
    }
    Ok(())
}

fn same_leaf(old: &std::fs::Metadata, fresh: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    (
        old.dev(),
        old.ino(),
        old.uid(),
        old.mode(),
        old.nlink(),
        old.len(),
    ) == (
        fresh.dev(),
        fresh.ino(),
        fresh.uid(),
        fresh.mode(),
        fresh.nlink(),
        fresh.len(),
    )
}
