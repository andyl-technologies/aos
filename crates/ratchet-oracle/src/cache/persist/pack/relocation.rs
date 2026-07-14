//! Packfile relocation and trim operations for [`PersistBlobPack`].
//!
//! Splits the record-relocation (compacting rewrite) and tail-trim methods out
//! of the parent module under the RFC-0007 §2 file-size cap. These are a second
//! `impl PersistBlobPack` block; the methods are moved verbatim and access the
//! parent's private fields, helpers, and mapped-read methods as a descendant
//! module. No behavior change.

use std::path::PathBuf;

use ratchet_cache::blob_pack::{
    BlobPackAppender, BlobPackLocation, blob_pack_rewrite_paths_alias, write_staged_blob_pack,
};
use ratchet_cache::file_lock::AdvisoryFileLock;

use super::*;

impl PersistBlobPack {
    /// Writes a compacted copy of the supplied records to `tmp_path`.
    ///
    /// Each relocation is read from the current pack at its old location,
    /// payload-verified against its key, appended to a temporary pack, and
    /// checked against the relocation's planned new location. Callers are
    /// responsible for renaming the completed temporary pack into place with
    /// whatever sidecar updates make those new locations visible.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the current pack cannot be read, a
    /// relocated source record fails verification, the temporary pack cannot be
    /// created or written, `tmp_path` aliases the source pack, a copied record
    /// lands at a different location than planned, or the completed temporary
    /// pack fails validation.
    ///
    /// This is the non-mapped relocation seam: production repack drives
    /// [`write_relocated_records_mapped_to`](Self::write_relocated_records_mapped_to)
    /// (which holds a read lease across the copy), while this direct-read variant
    /// is exercised only by the `value_blob_repack` tests, so it is dead in a
    /// non-test build.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::cache::persist) fn write_relocated_records_to(
        &self,
        tmp_path: impl Into<PathBuf>,
        relocations: &[PersistBlobRecordRelocation],
    ) -> Result<PersistBlobPack, PersistBlobPackError> {
        self.write_relocated_records_from_mapped_source_to(
            tmp_path.into(),
            relocations,
            |pack, location, hash, tmp_appender| {
                pack.with_mapped_blob_unlocked(location, hash, |payload| {
                    tmp_appender
                        .append_payload(durable_hash_to_engine(hash), payload)
                        .map_err(engine_append_error_to_persist)
                })?
            },
        )
    }

    /// Writes a compacted mapped copy of the supplied records to `tmp_path`.
    ///
    /// The temporary pack is staged through the shared engine rewrite helper so
    /// source/temp alias rejection and stale temporary cleanup stay centralized.
    /// Each relocated source record is then verified through a scoped mapped
    /// payload read while `read_lease` is held, appended to the temporary pack,
    /// and checked against the planned new location.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the current pack cannot be read or
    /// mapped, a relocated source record fails verification, the temporary pack
    /// cannot be created or written, `tmp_path` aliases the source pack, a copied
    /// record lands at a different location than planned, or the completed
    /// temporary pack fails validation.
    pub(in crate::cache::persist) fn write_relocated_records_mapped_to(
        &self,
        read_lease: &AdvisoryFileLock,
        tmp_path: impl Into<PathBuf>,
        relocations: &[PersistBlobRecordRelocation],
    ) -> Result<PersistBlobPack, PersistBlobPackError> {
        self.write_relocated_records_from_mapped_source_to(
            tmp_path.into(),
            relocations,
            |pack, location, hash, tmp_appender| {
                pack.with_mapped_blob(read_lease, location, hash, |payload| {
                    tmp_appender
                        .append_payload(durable_hash_to_engine(hash), payload)
                        .map_err(engine_append_error_to_persist)
                })?
            },
        )
    }

    fn write_relocated_records_from_mapped_source_to(
        &self,
        tmp_path: PathBuf,
        relocations: &[PersistBlobRecordRelocation],
        mut append_mapped_payload: impl FnMut(
            &Self,
            PersistBlobLocation,
            DurableBlake3Hash,
            &BlobPackAppender,
        ) -> Result<BlobPackLocation, PersistBlobPackError>,
    ) -> Result<PersistBlobPack, PersistBlobPackError> {
        if blob_pack_rewrite_paths_alias(&self.path, &tmp_path) {
            return Err(PersistBlobPackError::SourceEqualsTemp {
                source_path: self.path.clone(),
                tmp_path,
            });
        }
        open_engine_blob_pack_appender(&self.path)?;
        let (tmp_appender, tmp_reader, ()) =
            write_staged_blob_pack(&self.path, tmp_path, |tmp_appender| {
                for relocation in relocations {
                    let hash = relocation.key().hash();
                    let copied =
                        append_mapped_payload(self, relocation.old_location(), hash, tmp_appender)?;
                    let copied = engine_location_to_persist(copied);
                    if copied != relocation.new_location() {
                        return Err(PersistBlobPackError::RecordLocationMismatch {
                            expected: relocation.new_location(),
                            actual: copied,
                        });
                    }
                }
                Ok(())
            })?;
        let path = tmp_reader.path().to_path_buf();
        Ok(Self {
            appender: tmp_appender,
            path,
            #[cfg(test)]
            mapped_read_count: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// Truncates unneeded bytes after `end_offset`.
    ///
    /// `end_offset` must be at least the fixed pack header length and no larger
    /// than the current file length. The returned value is the number of bytes
    /// removed.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened,
    /// inspected, truncated, or if `end_offset` is outside the packfile.
    pub(in crate::cache::persist) fn trim_tail(&self, end_offset: u64) -> Result<u64, PersistBlobPackError> {
        self.appender
            .trim_tail(end_offset)
            .map_err(engine_trim_error_to_persist)
    }
}
