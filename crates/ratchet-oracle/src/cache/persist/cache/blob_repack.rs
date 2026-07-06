//! Blob-pack repack writer operations.

use super::super::INDEX_REWRITE_ID;
use super::repack_helpers::{
    FileRepackPaths, FileRepackStagePaths, file_relocation_locations, file_repack_replacements,
    relocate_file_artifact_entries, relocate_parse_artifact_entries, swap_repacked_file_store,
    swap_repacked_value_store, value_repack_replacements, write_repacked_blob_index,
    write_repacked_file_artifact_index, write_repacked_parse_artifact_index,
};
use super::*;

use std::sync::atomic::Ordering;

impl PersistCache {
    /// Rewrites the `values/` pack to the current live value roots.
    ///
    /// This explicit maintenance operation builds a value-pack repack plan
    /// while holding the selected store's advisory lock file and same-root value
    /// store write lock, stages a compacted value pack and replacement value
    /// blob index, then swaps both files into place with best-effort rollback
    /// for ordinary filesystem errors. It preserves the latest indexed value
    /// roots and omits records that are not live under the current value blob
    /// index. The cache is advisory: this operation is not crash-transactional,
    /// does not prune node metadata, coordinate with raw lower-level users or
    /// unrelated sidecar writers, or apply the future full GC retention policy.
    ///
    /// # Errors
    ///
    /// Returns [`PersistValueBlobPackRepackError`] if the selected advisory lock
    /// cannot be acquired, the same-root value store write lock is poisoned, if
    /// repack planning fails, if the compacted pack image cannot be written or
    /// swapped, or if the replacement value index cannot be written or swapped.
    pub fn repack_value_blob_pack(
        &self,
    ) -> Result<PersistBlobPackRepackPlan, PersistValueBlobPackRepackError> {
        let (advisory_guard, _write_guard) = self.lock_value_blob_pack_repack()?;
        let plan = self
            .plan_blob_pack_repack_unlocked(PersistBlobStore::Values, &advisory_guard)
            .map_err(|source| PersistValueBlobPackRepackError::Plan { source })?;
        if plan.reclaimable_bytes() == 0 {
            return Ok(plan);
        }
        let rewrite_id = INDEX_REWRITE_ID.fetch_add(1, Ordering::Relaxed);
        let tmp_pack_path = self.value_pack.path().with_extension(format!(
            "repack-pack-{}-{rewrite_id}.tmp",
            std::process::id()
        ));
        let tmp_index_path = self.value_index.path().with_extension(format!(
            "repack-index-{}-{rewrite_id}.tmp",
            std::process::id()
        ));
        let replacements = value_repack_replacements(
            self.value_pack.path(),
            self.value_index.path(),
            &tmp_pack_path,
            &tmp_index_path,
            rewrite_id,
        );
        self.value_pack
            .write_relocated_records_mapped_to(
                &advisory_guard,
                &tmp_pack_path,
                plan.record_relocations(),
            )
            .map_err(|source| PersistValueBlobPackRepackError::Pack { source })?;
        if let Err(source) = write_repacked_blob_index(&tmp_index_path, plan.record_relocations()) {
            replacements.cleanup_staged();
            return Err(PersistValueBlobPackRepackError::BlobIndex { source });
        }
        swap_repacked_value_store(&replacements)?;
        // The value index file was swapped out-of-band, so invalidate the live
        // handle's in-memory index; the relocated records carry new pack offsets.
        self.value_index.mark_stale();
        Ok(plan)
    }

    /// Rewrites the `files/` pack to the current artifact and blob-index roots.
    ///
    /// This explicit maintenance operation builds a file-pack repack plan while
    /// holding the selected store's advisory lock file plus same-root file
    /// store lock plus file-artifact and parse-artifact advisory and same-root
    /// locks, stages a compacted file pack plus relocated file blob,
    /// file-artifact, and parse-artifact sidecars, then swaps them into place
    /// with best-effort rollback for
    /// ordinary filesystem errors. It refuses to run while same-process pending
    /// non-indexed artifact roots exist because those callers still hold old
    /// pack locations that would become invalid after relocation. The cache is
    /// advisory: this operation is not crash-transactional, does not coordinate
    /// with raw lower-level users or cross-process pending artifact publication,
    /// and does not apply the future full GC retention policy.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileBlobPackRepackError`] if the selected advisory lock
    /// cannot be acquired, if a same-root lock is poisoned, if pending artifact
    /// roots exist, if repack planning fails, if an artifact sidecar root has no
    /// planned relocation, if the compacted pack image cannot be written or
    /// swapped, or if any replacement sidecar cannot be written or swapped.
    pub fn repack_file_blob_pack(
        &self,
    ) -> Result<PersistBlobPackRepackPlan, PersistFileBlobPackRepackError> {
        let (advisory_guard, _file_guard) = self.lock_file_blob_pack_repack()?;
        let _file_artifact_guard = self
            .lock_file_artifact_write()
            .map_err(|source| PersistFileBlobPackRepackError::FileArtifactIndex { source })?;
        let _parse_artifact_guard = self
            .lock_parse_artifact_write()
            .map_err(|source| PersistFileBlobPackRepackError::ParseArtifactIndex { source })?;
        let pending_roots = self
            .root_locks
            .pending_file_roots()
            .map_err(|source| PersistFileBlobPackRepackError::PendingRoots { source })?;
        if !pending_roots.is_empty() {
            return Err(PersistFileBlobPackRepackError::PendingArtifactRoots {
                roots: pending_roots.len(),
            });
        }
        let plan = self
            .plan_blob_pack_repack_unlocked(PersistBlobStore::Files, &advisory_guard)
            .map_err(|source| PersistFileBlobPackRepackError::Plan { source })?;
        if plan.reclaimable_bytes() == 0 {
            return Ok(plan);
        }
        let relocation_locations = file_relocation_locations(plan.record_relocations());
        let file_artifact_entries = relocate_file_artifact_entries(
            self.file_artifact_index
                .latest_entries()
                .map_err(|source| PersistFileBlobPackRepackError::FileArtifactIndex { source })?,
            &relocation_locations,
        )?;
        let parse_artifact_entries = relocate_parse_artifact_entries(
            self.parse_artifact_index
                .latest_entries()
                .map_err(|source| PersistFileBlobPackRepackError::ParseArtifactIndex { source })?,
            &relocation_locations,
        )?;

        let rewrite_id = INDEX_REWRITE_ID.fetch_add(1, Ordering::Relaxed);
        let tmp_pack_path = self.file_pack.path().with_extension(format!(
            "repack-pack-{}-{rewrite_id}.tmp",
            std::process::id()
        ));
        let tmp_index_path = self.file_index.path().with_extension(format!(
            "repack-index-{}-{rewrite_id}.tmp",
            std::process::id()
        ));
        let tmp_file_artifact_path = self.file_artifact_index.path().with_extension(format!(
            "repack-file-artifacts-{}-{rewrite_id}.tmp",
            std::process::id()
        ));
        let tmp_parse_artifact_path = self.parse_artifact_index.path().with_extension(format!(
            "repack-parse-artifacts-{}-{rewrite_id}.tmp",
            std::process::id()
        ));
        let stage = FileRepackStagePaths {
            pack: &tmp_pack_path,
            blob_index: &tmp_index_path,
            file_artifact_index: &tmp_file_artifact_path,
            parse_artifact_index: &tmp_parse_artifact_path,
        };
        let paths = FileRepackPaths {
            pack: self.file_pack.path(),
            blob_index: self.file_index.path(),
            file_artifact_index: self.file_artifact_index.path(),
            parse_artifact_index: self.parse_artifact_index.path(),
        };
        let replacements = file_repack_replacements(paths, stage, rewrite_id);
        if let Err(source) = self.file_pack.write_relocated_records_mapped_to(
            &advisory_guard,
            &tmp_pack_path,
            plan.record_relocations(),
        ) {
            replacements.cleanup_staged();
            return Err(PersistFileBlobPackRepackError::Pack { source });
        }
        if let Err(source) = write_repacked_blob_index(&tmp_index_path, plan.record_relocations()) {
            replacements.cleanup_staged();
            return Err(PersistFileBlobPackRepackError::BlobIndex { source });
        }
        if let Err(source) =
            write_repacked_file_artifact_index(&tmp_file_artifact_path, &file_artifact_entries)
        {
            replacements.cleanup_staged();
            return Err(PersistFileBlobPackRepackError::FileArtifactIndex { source });
        }
        if let Err(source) =
            write_repacked_parse_artifact_index(&tmp_parse_artifact_path, &parse_artifact_entries)
        {
            replacements.cleanup_staged();
            return Err(PersistFileBlobPackRepackError::ParseArtifactIndex { source });
        }
        swap_repacked_file_store(&replacements)?;
        // The file index file was swapped out-of-band, so invalidate the live
        // handle's in-memory index; the relocated records carry new pack offsets.
        self.file_index.mark_stale();
        Ok(plan)
    }

    /// Rewrites both persistent blob packs to their current live roots.
    ///
    /// This caller-driven maintenance helper runs
    /// [`Self::repack_value_blob_pack`] and then [`Self::repack_file_blob_pack`].
    /// It is sequential and non-transactional: if the file-pack repack fails,
    /// the value-pack repack may already be committed. Each pack repack holds
    /// its selected store's advisory lock file, and file-pack repack also holds
    /// artifact-mapping advisory locks. The method does not compact unrelated
    /// sidecars, rebuild blob indexes from physical pack scans before planning,
    /// coordinate raw lower-level users or cross-process pending artifact
    /// publication, or apply the future full GC retention policy.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPacksRepackError`] identifying the pack whose
    /// repack failed. Earlier pack rewrites may already be committed.
    pub fn repack_blob_packs(&self) -> Result<PersistBlobPacksRepack, PersistBlobPacksRepackError> {
        let value_blob_pack = self
            .repack_value_blob_pack()
            .map_err(|source| PersistBlobPacksRepackError::ValueBlobPack { source })?;
        let file_blob_pack = self
            .repack_file_blob_pack()
            .map_err(|source| PersistBlobPacksRepackError::FileBlobPack { source })?;
        Ok(PersistBlobPacksRepack::new(value_blob_pack, file_blob_pack))
    }
}
