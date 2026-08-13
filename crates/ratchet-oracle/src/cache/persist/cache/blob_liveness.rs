//! Blob-pack live-root, liveness, and repack planning operations.

use super::repack_helpers::{
    blob_pack_repack_plan_from_liveness, blob_record_bytes, blob_record_identity,
    push_blob_index_roots,
};
use super::*;

impl PersistCache {
    fn snapshot_blob_live_roots_unlocked(
        &self,
        store: PersistBlobStore,
        advisory_guard: &AdvisoryFileLock,
    ) -> Result<Vec<PersistBlobLiveRoot>, PersistBlobLiveRootError> {
        let blob_entries = self
            .blob_index(store)
            .latest_entries()
            .map_err(|source| PersistBlobLiveRootError::BlobIndex { source })?;
        let mut roots = Vec::new();
        push_blob_index_roots(
            &mut roots,
            blob_entries,
            store,
            PersistBlobLiveRootSource::BlobIndex,
        )?;
        if store == PersistBlobStore::Files {
            roots.extend(self.root_locks.pending_file_roots()?);
            for entry in self
                .file_artifact_index
                .latest_entries()
                .map_err(|source| PersistBlobLiveRootError::FileArtifactIndex { source })?
            {
                let value = entry.value();
                roots.push(PersistBlobLiveRoot::new(
                    PersistBlobLiveRootSource::FileArtifactIndex,
                    value.blob_key(),
                    value.location(),
                ));
            }
            for entry in self
                .parse_artifact_index
                .latest_entries()
                .map_err(|source| PersistBlobLiveRootError::ParseArtifactIndex { source })?
            {
                let value = entry.value();
                roots.push(PersistBlobLiveRoot::new(
                    PersistBlobLiveRootSource::ParseArtifactIndex,
                    value.blob_key(),
                    value.location(),
                ));
            }
            roots.extend(self.root_record_blob_live_roots(advisory_guard)?);
        }
        Ok(roots)
    }

    /// Trims unindexed tail bytes from the selected blob pack.
    ///
    /// This explicit maintenance operation snapshots the selected store's
    /// latest live roots, verifies each referenced blob against the selected
    /// pack, and truncates only bytes after the highest live record. For
    /// `values/`, the roots are the value blob-index entries. For `files/`, the
    /// roots also include file-artifact mappings, parse-artifact mappings, and
    /// same-process pending artifact roots because legacy non-indexed artifact
    /// materializers can publish those values without adding a blob-index
    /// entry. This can reclaim unindexed trailing records, including blobs left
    /// behind by non-transactional append paths, but it does not relocate live
    /// records or reclaim unindexed records that precede a live record.
    /// Cache-level writers opened on the same cache root share the selected
    /// store's advisory lock file and same-process store lock while this method
    /// snapshots roots and truncates the pack; `files/` trims also share the
    /// file-artifact and parse-artifact advisory and same-root mapping locks.
    /// Raw lower-level pack or sidecar users, cross-process pending artifact
    /// publication, and unrelated maintenance writers must still be excluded by
    /// the caller.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackTrimError`] if the selected advisory lock cannot
    /// be acquired, if a same-root root-sidecar lock is poisoned, if a root
    /// sidecar cannot be snapshotted, if a blob-index entry contains a key for a
    /// different store, if any latest live blob fails verification, or if the
    /// pack cannot be inspected or truncated.
    pub fn trim_blob_pack_tail(
        &self,
        store: PersistBlobStore,
    ) -> Result<PersistBlobPackTrim, PersistBlobPackTrimError> {
        let (advisory_guard, _blob_guard) = self.lock_blob_pack_tail_trim(store)?;
        let _file_artifact_guard = if store == PersistBlobStore::Files {
            Some(
                self.lock_file_artifact_write()
                    .map_err(|source| PersistBlobPackTrimError::FileArtifactIndex { source })?,
            )
        } else {
            None
        };
        let _parse_artifact_guard = if store == PersistBlobStore::Files {
            Some(
                self.lock_parse_artifact_write()
                    .map_err(|source| PersistBlobPackTrimError::ParseArtifactIndex { source })?,
            )
        } else {
            None
        };
        // Root records root `files/` blobs too; hold their advisory lock while
        // snapshotting so a concurrent record writer cannot tear the index.
        // Always acquired after the `files/` store lock (never the reverse),
        // matching every other path that takes both.
        let _root_record_guard = if store == PersistBlobStore::Files {
            let lock_path = self.layout().root_record_lock_path();
            Some(
                AdvisoryFileLock::lock(lock_path.clone(), AdvisoryFileLockMode::Shared).map_err(
                    |source| PersistBlobPackTrimError::RootRecordLock {
                        path: lock_path,
                        source,
                    },
                )?,
            )
        } else {
            None
        };
        let roots = self
            .snapshot_blob_live_roots_unlocked(store, &advisory_guard)
            .map_err(PersistBlobPackTrimError::from)?;
        let pack = self.blob_pack(store);
        let mut live_end = PERSIST_BLOB_PACK_HEADER_LEN as u64;
        for root in &roots {
            let window = pack
                .verify_mapped_blob(&advisory_guard, root.location(), root.key().hash())
                .map_err(|source| PersistBlobPackTrimError::Read { source })?;
            live_end = live_end.max(window.payload_end());
        }
        let bytes_before = pack
            .len()
            .map_err(|source| PersistBlobPackTrimError::Trim { source })?;
        pack.trim_tail(live_end)
            .map_err(|source| PersistBlobPackTrimError::Trim { source })?;
        let bytes_after = pack
            .len()
            .map_err(|source| PersistBlobPackTrimError::Trim { source })?;
        Ok(PersistBlobPackTrim::new(
            roots.len(),
            bytes_before,
            bytes_after,
        ))
    }

    /// Plans blob-pack liveness for future repack maintenance.
    ///
    /// This read-only diagnostic snapshots the selected store's latest live
    /// roots and same-process pending artifact roots, verifies every rooted
    /// record without materializing payloads, then scans the selected pack to
    /// classify verified physical records as rooted or unrooted. For `values`,
    /// roots come from the value blob index. For `files`, roots also include
    /// file-artifact and parse-artifact mappings because legacy non-indexed
    /// artifact materializers can publish those records without a blob-index
    /// entry. The returned byte counts are sidecar/pending-root diagnostics
    /// only; node metadata references, cross-process raw writers, and the
    /// final RFC GC live-root model are outside this plan. The cache-level
    /// call holds shared advisory reader locks while inspecting sidecars and
    /// the selected pack, but it does not write sidecars, truncate packs, or
    /// relocate records.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackLivenessPlanError`] if a selected store or
    /// artifact mapping advisory read lock cannot be acquired, if a same-root
    /// root-sidecar lock is poisoned, if roots cannot be snapshotted, if a
    /// blob-index entry targets the wrong store, if any latest live root fails
    /// verification, or if the selected pack cannot be fully scanned and
    /// verified.
    pub fn plan_blob_pack_liveness(
        &self,
        store: PersistBlobStore,
    ) -> Result<PersistBlobPackLivenessPlan, PersistBlobPackLivenessPlanError> {
        let (blob_advisory_guard, _blob_guard) = self.lock_blob_liveness_plan_read(store)?;
        let _file_artifact_guard = if store == PersistBlobStore::Files {
            Some(self.lock_file_artifact_read().map_err(|source| {
                PersistBlobPackLivenessPlanError::Roots {
                    source: PersistBlobLiveRootError::FileArtifactIndex { source },
                }
            })?)
        } else {
            None
        };
        let _parse_artifact_guard = if store == PersistBlobStore::Files {
            Some(self.lock_parse_artifact_read().map_err(|source| {
                PersistBlobPackLivenessPlanError::Roots {
                    source: PersistBlobLiveRootError::ParseArtifactIndex { source },
                }
            })?)
        } else {
            None
        };
        // See `trim_blob_pack_tail`: the root-record advisory lock is held
        // (shared) while snapshotting so record writers cannot tear the index.
        let _root_record_guard = if store == PersistBlobStore::Files {
            let lock_path = self.layout().root_record_lock_path();
            Some(
                AdvisoryFileLock::lock(lock_path.clone(), AdvisoryFileLockMode::Shared).map_err(
                    |source| PersistBlobPackLivenessPlanError::Roots {
                        source: PersistBlobLiveRootError::RootRecordLock {
                            path: lock_path,
                            source,
                        },
                    },
                )?,
            )
        } else {
            None
        };
        let roots = self
            .snapshot_blob_live_roots_unlocked(store, &blob_advisory_guard)
            .map_err(|source| PersistBlobPackLivenessPlanError::Roots { source })?;
        self.plan_blob_pack_liveness_from_roots(store, roots, &blob_advisory_guard)
    }

    /// Plans liveness with the caller's locks. For the `files/` store the
    /// caller must hold the root-record advisory lock (the file-pack repack
    /// holds it exclusively) in addition to the store advisory guard.
    fn plan_blob_pack_liveness_unlocked(
        &self,
        store: PersistBlobStore,
        advisory_guard: &AdvisoryFileLock,
    ) -> Result<PersistBlobPackLivenessPlan, PersistBlobPackLivenessPlanError> {
        let roots = self
            .snapshot_blob_live_roots_unlocked(store, advisory_guard)
            .map_err(|source| PersistBlobPackLivenessPlanError::Roots { source })?;
        self.plan_blob_pack_liveness_from_roots(store, roots, advisory_guard)
    }

    fn plan_blob_pack_liveness_from_roots(
        &self,
        store: PersistBlobStore,
        roots: Vec<PersistBlobLiveRoot>,
        advisory_guard: &AdvisoryFileLock,
    ) -> Result<PersistBlobPackLivenessPlan, PersistBlobPackLivenessPlanError> {
        let pack = self.blob_pack(store);
        let mut rooted_identities = std::collections::BTreeSet::new();
        let mut live_end = PERSIST_BLOB_PACK_HEADER_LEN as u64;
        for root in &roots {
            let window = pack
                .verify_mapped_blob(advisory_guard, root.location(), root.key().hash())
                .map_err(|source| PersistBlobPackLivenessPlanError::Read { source })?;
            live_end = live_end.max(window.payload_end());
            rooted_identities.insert(blob_record_identity(root.key(), root.location()));
        }

        let bytes_before = pack
            .len()
            .map_err(|source| PersistBlobPackLivenessPlanError::Scan { source })?;
        let records = pack
            .with_mapped_records(advisory_guard, |records| records)
            .map_err(|source| PersistBlobPackLivenessPlanError::Scan { source })?;
        let mut rooted_records = Vec::new();
        let mut unrooted_records = Vec::new();
        let mut rooted_record_bytes = 0u64;
        let mut unrooted_record_bytes = 0u64;
        for record in records {
            let record_bytes = blob_record_bytes(record);
            if rooted_identities
                .contains(&blob_record_identity(record.key(store), record.location()))
            {
                rooted_record_bytes = rooted_record_bytes.saturating_add(record_bytes);
                rooted_records.push(record);
            } else {
                unrooted_record_bytes = unrooted_record_bytes.saturating_add(record_bytes);
                unrooted_records.push(record);
            }
        }
        let tail_reclaimable_bytes = bytes_before.saturating_sub(live_end);
        Ok(PersistBlobPackLivenessPlan::new(
            roots,
            rooted_records,
            unrooted_records,
            bytes_before,
            rooted_record_bytes,
            unrooted_record_bytes,
            tail_reclaimable_bytes,
        ))
    }

    /// Plans live-record relocation for a future blob-pack repack.
    ///
    /// This read-only diagnostic first builds [`Self::plan_blob_pack_liveness`],
    /// then assigns each verified rooted record a contiguous location in a
    /// fresh compacted pack while preserving current pack order. Unrooted
    /// records are reported as omitted. The cache-level call shares the
    /// liveness plan's advisory reader locks while inspecting current state,
    /// but it does not write sidecars, copy payload bytes, replace packfiles,
    /// or choose a retention policy. For `files/`, the returned plan can
    /// include same-process pending artifact roots, but applying such a
    /// relocation still requires a writer-quiescence protocol because callers
    /// with in-flight artifact index entries hold old locations.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackRepackPlanError`] if liveness planning fails
    /// or if the planned compacted pack length would overflow `u64`.
    pub fn plan_blob_pack_repack(
        &self,
        store: PersistBlobStore,
    ) -> Result<PersistBlobPackRepackPlan, PersistBlobPackRepackPlanError> {
        let liveness = self
            .plan_blob_pack_liveness(store)
            .map_err(|source| PersistBlobPackRepackPlanError::Liveness { source })?;
        blob_pack_repack_plan_from_liveness(store, liveness)
    }

    pub(super) fn plan_blob_pack_repack_unlocked(
        &self,
        store: PersistBlobStore,
        advisory_guard: &AdvisoryFileLock,
    ) -> Result<PersistBlobPackRepackPlan, PersistBlobPackRepackPlanError> {
        let liveness = self
            .plan_blob_pack_liveness_unlocked(store, advisory_guard)
            .map_err(|source| PersistBlobPackRepackPlanError::Liveness { source })?;
        blob_pack_repack_plan_from_liveness(store, liveness)
    }
}
