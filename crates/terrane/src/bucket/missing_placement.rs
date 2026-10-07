//! Distinguishes verified live placements from exact physical-loss observations.
//!
//! A missing placement is ordinary admission data derived from the actual held
//! selection. It authorizes no actor, creator, retirement or deletion operation.
//! Only consistent nofollow absence can replace an otherwise live row; corrupt,
//! unavailable, unsafe, excluded and quarantined evidence never becomes absence.

use super::catalog::{Catalog, registered};
use super::content::corrupt;
use super::publication::SelectedObservation;
use super::publication::receipts::RecordRead;
use super::{BucketBinding, FileBucket, files};
use crate::pack::{MergedEntry, PackIndexSnapshot, PackReader};
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use std::{fs::Metadata, io, path::Path};
use terrane_core::identity::{Identity, IdentityKind, TERRANE_V1};
use terrane_core::pack_format::MergedRecord;

/// Carries only actual observations of one selected, unexcluded live placement.
pub(super) struct Placement {
    identity: Identity,
    row: MergedEntry,
    record: MergedRecord,
    root: std::path::PathBuf,
    owner: u32,
    stamp: (u64, [u8; 32]),
    capability_bytes: Vec<u8>,
    reads: [RecordRead; 2],
    parents: Vec<(std::path::PathBuf, Metadata)>,
    missing: bool,
}

impl Placement {
    /// Reports whether an actual canonical artifact was consistently absent.
    pub(super) fn is_missing(&self) -> bool {
        self.missing
    }

    /// Borrows original physical reads for final native publication capture.
    pub(super) fn reads(&self) -> &[RecordRead] {
        &self.reads
    }

    /// Borrows actual ancestor observations from the original physical probe.
    pub(super) fn parents(&self) -> &[(std::path::PathBuf, Metadata)] {
        &self.parents
    }

    /// Checks the exact original live row and selected holder association.
    ///
    /// # Errors
    /// Refuses a different selection, operator, old row or nonmissing placement.
    pub(super) fn check_replacement(
        &self,
        observed: &SelectedObservation<'_>,
        catalog: &Catalog,
        record: &MergedRecord,
    ) -> Result<(), StoreFailure> {
        if !self.missing
            || observed.identity().root() != self.root
            || observed.configured_operator_uid() != self.owner
            || observed.stamp() != self.stamp
            || catalog.capability_bytes != self.capability_bytes
            || record != &self.record
            || record.state != 0
        {
            return Err(corrupt(&self.identity));
        }
        Ok(())
    }

    /// Identifies only the exact live hash and old physical row being replaced.
    pub(super) fn matches(&self, record: &MergedRecord) -> bool {
        record == &self.record
    }
}

fn safe_metadata(metadata: &Metadata, owner: u32) -> Result<(), StoreFailure> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == owner
            && metadata.nlink() == 1
            && metadata.mode() & 0o022 == 0
        {
            return Ok(());
        }
        Err(files::layout_corrupt())
    }
    #[cfg(not(unix))]
    {
        let _ = (metadata, owner);
        Err(StoreFailure::new(StoreErrorKind::Unsupported))
    }
}

fn same_metadata(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (
            left.dev(),
            left.ino(),
            left.uid(),
            left.mode(),
            left.nlink(),
            left.len(),
            left.mtime(),
            left.mtime_nsec(),
            left.ctime(),
            left.ctime_nsec(),
        ) == (
            right.dev(),
            right.ino(),
            right.uid(),
            right.mode(),
            right.nlink(),
            right.len(),
            right.mtime(),
            right.mtime_nsec(),
            right.ctime(),
            right.ctime_nsec(),
        )
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        false
    }
}

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    FileBucket<F, C, V>
{
    async fn placement_read(&self, path: &Path, owner: u32) -> Result<RecordRead, StoreFailure> {
        let before = match self.inner.fs.symlink_metadata(path).await {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(files::io_failure(error)),
        };
        let Some(before) = before else {
            match self.inner.fs.symlink_metadata(path).await {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Ok(RecordRead::observed(path.to_owned(), None, None));
                }
                Err(error) => return Err(files::io_failure(error)),
                Ok(_) => return Err(files::layout_corrupt()),
            }
        };
        safe_metadata(&before, owner)?;

        // A disappearing present descriptor is an I/O failure, never a missing
        // placement. The same named incarnation must survive the nofollow read.
        let bytes = self
            .inner
            .fs
            .read_nofollow(path)
            .await
            .map_err(files::io_failure)?;
        let after = self
            .inner
            .fs
            .symlink_metadata(path)
            .await
            .map_err(files::io_failure)?;
        safe_metadata(&after, owner)?;

        if !same_metadata(&before, &after) || after.len() != bytes.len() as u64 {
            return Err(files::layout_corrupt());
        }
        Ok(RecordRead::observed(
            path.to_owned(),
            Some(bytes),
            Some(after),
        ))
    }

    /// Derives physical-loss data only from an actual held live catalog row.
    ///
    /// Present artifacts are checked against complete inventory identity/size,
    /// their canonical pack ID and the exact selected member entry. Missing
    /// inventory remains unsupported for repair. Missing parent directories are
    /// conservatively unsupported; this lane retains existing canonical ancestry.
    ///
    /// # Errors
    /// Preserves I/O errors and refuses unsafe files, malformed or conflicting
    /// present artifacts, incomplete inventory, changed selection or ancestry.
    pub(super) async fn placement_observed<const WRITABLE: bool>(
        &self,
        held: &super::held::HeldBucket<'_, F, C, V, WRITABLE>,
        observed: &SelectedObservation<'_>,
        catalog: &Catalog,
        identity: &Identity,
    ) -> Result<Option<Placement>, StoreFailure> {
        if !std::ptr::eq(self, held.bucket())
            || observed.identity().root() != self.root()
            || observed
                .logical()
                .get("CAPABILITIES")
                .and_then(Option::as_ref)
                != Some(&catalog.capability_bytes)
        {
            return Err(files::layout_corrupt());
        }
        let row = match self.location(catalog, identity) {
            Ok(row) => row.clone(),
            Err(error) if matches!(error.kind(), StoreErrorKind::Absent(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        let Some(inventory) = catalog.inventory.as_ref().and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry.pack_id == *row.pack().as_bytes())
        }) else {
            // Older placements still use ordinary strict verified-body dedup;
            // an incomplete inventory cannot qualify physical-loss replacement.
            return Ok(None);
        };

        let owner = observed.configured_operator_uid();
        let pack_key = registered(&row.pack().pack_key())?;
        let index_key = registered(&row.pack().index_key())?;
        let mut parents = Vec::new();
        for key in [&pack_key, &index_key] {
            self.check_payload_namespace(key).await?;
            let relative = Path::new(key.as_str())
                .parent()
                .ok_or_else(files::malformed)?;
            let mut parent = self.root().to_owned();
            for part in relative.components() {
                parent.push(part);
                let metadata = match self.inner.fs.symlink_metadata(&parent).await {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        return Err(StoreFailure::with_source(
                            StoreErrorKind::Unsupported,
                            error,
                        ));
                    }
                    Err(error) => return Err(files::io_failure(error)),
                };
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(files::layout_corrupt());
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
                        return Err(files::layout_corrupt());
                    }
                }
                parents.push((parent.clone(), metadata));
            }
        }

        let pack = self.placement_read(&self.path(&pack_key), owner).await?;
        let index = self.placement_read(&self.path(&index_key), owner).await?;
        for (read, kind, hash, size) in [
            (
                &pack,
                IdentityKind::Pack,
                inventory.pack_hash,
                inventory.pack_size,
            ),
            (
                &index,
                IdentityKind::Index,
                inventory.index_hash,
                inventory.index_size,
            ),
        ] {
            if let Some(bytes) = read.bytes() {
                let expected = TERRANE_V1
                    .from_digest(kind, &hash)
                    .map_err(|_| corrupt(identity))?;
                if bytes.len() as u64 != size {
                    return Err(corrupt(&expected));
                }
                TERRANE_V1
                    .verify(&expected, bytes)
                    .map_err(|_| corrupt(&expected))?;
            }
        }
        if let Some(bytes) = pack.bytes() {
            let reader = PackReader::open(bytes).map_err(|_| corrupt(identity))?;
            if reader.header().id() != row.pack()
                || !reader.entries().iter().any(|entry| entry == row.entry())
            {
                return Err(corrupt(identity));
            }
            if let Some(index) = index.bytes() {
                reader
                    .check_index_object(index)
                    .map_err(|_| corrupt(identity))?;
            }
        }
        if let Some(bytes) = index.bytes() {
            let snapshot =
                PackIndexSnapshot::decode(bytes, catalog.capabilities.generation.unwrap_or(0))
                    .map_err(|_| corrupt(identity))?;
            if snapshot.header().id() != row.pack()
                || !snapshot.entries().iter().any(|entry| entry == row.entry())
            {
                return Err(corrupt(identity));
            }
        }
        let shard = catalog
            .shards
            .iter()
            .find(|shard| shard.shard() == row.entry().hash()[0])
            .ok_or_else(files::layout_corrupt)?;
        let record = terrane_core::pack_format::decode_shard(&shard.encode(), shard.shard())
            .map_err(|_| files::layout_corrupt())?
            .into_iter()
            .find(|record| record.record.hash == *row.entry().hash())
            .ok_or_else(files::layout_corrupt)?;
        let missing = pack.bytes().is_none() || index.bytes().is_none();
        observed.revalidate().await?;
        Ok(Some(Placement {
            identity: identity.clone(),
            row,
            record,
            root: self.root().to_owned(),
            owner,
            stamp: observed.stamp(),
            capability_bytes: catalog.capability_bytes.clone(),
            reads: [pack, index],
            parents,
            missing,
        }))
    }

    /// Rechecks exact observed physical preimages before ordinary dedup success.
    ///
    /// # Errors
    /// Refuses changed bytes, absence, incarnation, protection or selected member.
    pub(super) async fn recheck_placement(
        &self,
        placement: &Placement,
    ) -> Result<(), StoreFailure> {
        if placement.row.pack().as_bytes() != &placement.record.pack {
            return Err(corrupt(&placement.identity));
        }
        for (path, original) in &placement.parents {
            let actual = self
                .inner
                .fs
                .symlink_metadata(path)
                .await
                .map_err(files::io_failure)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if !actual.is_dir()
                    || actual.file_type().is_symlink()
                    || (actual.dev(), actual.ino(), actual.uid(), actual.mode())
                        != (
                            original.dev(),
                            original.ino(),
                            original.uid(),
                            original.mode(),
                        )
                {
                    return Err(corrupt(&placement.identity));
                }
            }
            #[cfg(not(unix))]
            {
                let _ = (actual, original);
                return Err(StoreFailure::new(StoreErrorKind::Unsupported));
            }
        }
        for original in &placement.reads {
            let actual = self
                .placement_read(original.path(), placement.owner)
                .await?;
            if actual.bytes() != original.bytes()
                || match (actual.metadata(), original.metadata()) {
                    (Some(actual), Some(original)) => !same_metadata(actual, original),
                    (None, None) => false,
                    _ => true,
                }
            {
                return Err(corrupt(&placement.identity));
            }
        }
        Ok(())
    }
}
