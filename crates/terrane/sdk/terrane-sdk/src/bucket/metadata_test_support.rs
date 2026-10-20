//! Owns verified metadata pack location support for physical-loss tests.
//!
//! Plain paths never substitute for payload, serving or publication authority.

use super::held::HeldBucket;
use super::publication::SelectedObservation;
use super::{BucketBinding, files};
use crate::pack::PackReader;
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use terrane_format::identity::{Identity, IdentityKind};

impl<F, B, V, const WRITABLE: bool> HeldBucket<'_, F, B, V, WRITABLE>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    /// Returns the actual verified metadata pack path for a physical-loss test.
    ///
    /// This exposes ordinary path data only. It never constructs an existing
    /// payload receipt or any namespace, serving, or publication authority.
    ///
    /// # Errors
    /// Rejects non-Node/Commit identities, mismatched holders, unknown inventory,
    /// excluded or absent members, corrupt pack/index associations and changed
    /// observations; preserves actual storage and protection failures.
    pub(crate) async fn metadata_pack_path_for_tests(
        &self,
        observed: &SelectedObservation<'_>,
        identity: &Identity,
    ) -> Result<std::path::PathBuf, StoreFailure> {
        observed.revalidate().await?;
        if observed.identity().root() != self.root()
            || observed.identity().physical_identity() != self.physical_identity()
        {
            return Err(files::layout_corrupt());
        }
        if !matches!(identity.kind(), IdentityKind::Node | IdentityKind::Commit) {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }

        let bucket = self.bucket();
        let catalog = bucket.catalog_observed(observed).await?;
        if catalog.exclusions.is_none() || catalog.burns.is_none() {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        if bucket.is_excluded(&catalog, identity)? {
            return Err(StoreFailure::new(StoreErrorKind::Absent(identity.clone())));
        }
        let location = bucket.location(&catalog, identity)?;
        let inventory = catalog
            .inventory
            .as_ref()
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry.pack_id == *location.pack().as_bytes())
            })
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))?;

        let (pack, index) = bucket.verified_container_observed(inventory).await?;
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

        let path = pack.path().to_path_buf();
        observed.revalidate().await?;
        Ok(path)
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
