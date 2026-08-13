//! Blob-index scan and rebuild operations.

use super::*;

impl PersistCache {
    /// Returns verified pack records as typed blob-index entries for `store`.
    ///
    /// This read-only adapter scans the selected store's pack through the
    /// scoped mapped-pack path, verifies every record, and maps each record to
    /// the `PersistBlobIndexEntry` shape used by the hash-to-offset sidecar.
    /// It returns physical pack records, including stale duplicate records and
    /// unindexed records. It does not write or repair the sidecar index, select
    /// live roots, or compact the pack.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the selected store's advisory or
    /// same-root read lock cannot be acquired, if the selected pack cannot be
    /// opened or mapped, if any record header is malformed or truncated, if a
    /// record points past the current packfile length, or if a payload hash
    /// does not match its record header.
    pub fn blob_pack_index_entries(
        &self,
        store: PersistBlobStore,
    ) -> Result<Vec<PersistBlobIndexEntry>, PersistBlobPackError> {
        let (advisory_guard, _read_guard) = self.lock_blob_pack_read(store)?;
        self.blob_pack_index_entries_with_lock(store, &advisory_guard)
    }

    fn blob_pack_index_entries_with_lock(
        &self,
        store: PersistBlobStore,
        advisory_guard: &AdvisoryFileLock,
    ) -> Result<Vec<PersistBlobIndexEntry>, PersistBlobPackError> {
        self.blob_pack(store)
            .with_mapped_records(advisory_guard, |records| {
                records
                    .into_iter()
                    .map(|record| PersistBlobIndexEntry::new(record.key(store), record.location()))
                    .collect()
            })
    }

    /// Returns newest physical pack records as typed blob-index entries.
    ///
    /// This read-only adapter scans the selected store's pack through the
    /// scoped mapped-pack path and collapses duplicate physical records for the
    /// same content hash with
    /// newest-record-wins semantics. Entries are returned in stable encoded-key
    /// order, matching the current fixed-record sidecar's latest-entry
    /// encoded-key ordering. It does not write or repair the sidecar index,
    /// select live roots, or compact the pack.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the selected store's advisory or
    /// same-root read lock cannot be acquired, if the selected pack cannot be
    /// opened or mapped, if any record header is malformed or truncated, if a
    /// record points past the current packfile length, or if a payload hash
    /// does not match its record header.
    pub fn latest_blob_pack_index_entries(
        &self,
        store: PersistBlobStore,
    ) -> Result<Vec<PersistBlobIndexEntry>, PersistBlobPackError> {
        let (advisory_guard, _read_guard) = self.lock_blob_pack_read(store)?;
        self.latest_blob_pack_index_entries_with_lock(store, &advisory_guard)
    }

    fn latest_blob_pack_index_entries_with_lock(
        &self,
        store: PersistBlobStore,
        advisory_guard: &AdvisoryFileLock,
    ) -> Result<Vec<PersistBlobIndexEntry>, PersistBlobPackError> {
        let mut latest = std::collections::BTreeMap::new();
        for entry in self.blob_pack_index_entries_with_lock(store, advisory_guard)? {
            latest.insert(entry.key().index_bytes(), entry);
        }
        Ok(latest.into_values().collect())
    }

    /// Plans a blob-index rebuild from the selected store's verified pack.
    ///
    /// This read-only diagnostic compares the sidecar's newest lookup entries
    /// with [`Self::latest_blob_pack_index_entries`]. `planned_entries` is the
    /// exact newest physical pack entry set a future canonical rewrite would
    /// write; missing, stale, and dangling lists describe semantic lookup
    /// differences between the current sidecar and that set. Older append-only
    /// sidecar records are ignored once the newest entry for a key matches. The
    /// method does not write the sidecar, choose live roots, trim pack bytes,
    /// or coordinate with other writers.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexRebuildPlanError`] if the selected store's
    /// advisory or same-root read lock cannot be acquired, if the selected pack
    /// cannot be fully verified, or if the selected sidecar cannot be
    /// snapshotted.
    pub fn plan_blob_index_rebuild(
        &self,
        store: PersistBlobStore,
    ) -> Result<PersistBlobIndexRebuildPlan, PersistBlobIndexRebuildPlanError> {
        let (advisory_guard, _read_guard) = self
            .lock_blob_pack_read(store)
            .map_err(|source| PersistBlobIndexRebuildPlanError::Pack { source })?;
        self.plan_blob_index_rebuild_with_lock(store, &advisory_guard)
    }

    fn plan_blob_index_rebuild_with_lock(
        &self,
        store: PersistBlobStore,
        advisory_guard: &AdvisoryFileLock,
    ) -> Result<PersistBlobIndexRebuildPlan, PersistBlobIndexRebuildPlanError> {
        let planned_entries = self
            .latest_blob_pack_index_entries_with_lock(store, advisory_guard)
            .map_err(|source| PersistBlobIndexRebuildPlanError::Pack { source })?;
        let current_entries = self
            .blob_index(store)
            .latest_entries()
            .map_err(|source| PersistBlobIndexRebuildPlanError::Index { source })?;

        let mut planned_by_key = std::collections::BTreeMap::new();
        for entry in &planned_entries {
            planned_by_key.insert(entry.key().index_bytes(), *entry);
        }

        let mut current_by_key = std::collections::BTreeMap::new();
        let mut stale_entries = Vec::new();
        let mut dangling_entries = Vec::new();
        for entry in current_entries {
            let key = entry.key().index_bytes();
            current_by_key.insert(key, entry);
            match planned_by_key.get(&key) {
                Some(planned) if *planned == entry => {}
                Some(planned) => {
                    stale_entries.push(PersistBlobIndexStaleEntry::new(entry, *planned));
                }
                None => dangling_entries.push(entry),
            }
        }

        let mut missing_entries = Vec::new();
        for entry in &planned_entries {
            if !current_by_key.contains_key(&entry.key().index_bytes()) {
                missing_entries.push(*entry);
            }
        }

        Ok(PersistBlobIndexRebuildPlan::new(
            planned_entries,
            missing_entries,
            stale_entries,
            dangling_entries,
        ))
    }

    /// Rebuilds the selected blob-index sidecar from its verified pack.
    ///
    /// This explicit maintenance operation first builds
    /// [`Self::plan_blob_index_rebuild`], then replaces the selected sidecar
    /// with the plan's newest physical pack entries. It indexes every verified
    /// newest physical record in that pack, including records that were
    /// previously unindexed, and drops sidecar entries that do not correspond
    /// to a verified physical record in the selected store. It does not choose
    /// live roots, trim pack bytes, relocate records, coordinate with raw
    /// lower-level sidecar users or unrelated maintenance writers, or implement
    /// an automatic repair policy.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexRebuildError`] if planning fails or if the
    /// selected advisory lock cannot be acquired, the same-root blob-index write
    /// lock is poisoned, or the selected sidecar cannot be replaced with the
    /// planned entries.
    pub fn rebuild_blob_index_from_pack(
        &self,
        store: PersistBlobStore,
    ) -> Result<PersistBlobIndexRebuildPlan, PersistBlobIndexRebuildError> {
        let (advisory_guard, _write_guard) = self.lock_blob_index_rebuild(store)?;
        let plan = self
            .plan_blob_index_rebuild_with_lock(store, &advisory_guard)
            .map_err(|source| PersistBlobIndexRebuildError::Plan { source })?;
        self.blob_index(store)
            .replace_entries(plan.planned_entries())
            .map_err(|source| PersistBlobIndexRebuildError::Write { source })?;
        Ok(plan)
    }

    /// Rebuilds both blob-index sidecars from their verified packs.
    ///
    /// This explicit maintenance helper runs
    /// [`Self::rebuild_blob_index_from_pack`] for `values/` and then `files/`,
    /// returning the plans that were applied to each sidecar. It is sequential
    /// and non-transactional: if the `files/` rebuild fails, the `values/`
    /// rebuild may already be committed. It does not choose live roots, trim
    /// pack bytes, relocate records, coordinate with raw lower-level sidecar
    /// users or unrelated maintenance writers, or implement an automatic repair
    /// policy. Cache-level writers opened on the same cache root share each
    /// selected store's advisory lock file and same-process blob-index write
    /// lock during its rebuild step.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexesRebuildError`] identifying the sidecar whose
    /// rebuild failed. Earlier sidecars may already have been rewritten.
    pub fn rebuild_blob_indexes_from_packs(
        &self,
    ) -> Result<PersistBlobIndexRebuild, PersistBlobIndexesRebuildError> {
        let value_blob_index = self
            .rebuild_blob_index_from_pack(PersistBlobStore::Values)
            .map_err(|source| PersistBlobIndexesRebuildError::ValueBlobIndex { source })?;
        let file_blob_index = self
            .rebuild_blob_index_from_pack(PersistBlobStore::Files)
            .map_err(|source| PersistBlobIndexesRebuildError::FileBlobIndex { source })?;
        Ok(PersistBlobIndexRebuild::new(
            value_blob_index,
            file_blob_index,
        ))
    }
}
