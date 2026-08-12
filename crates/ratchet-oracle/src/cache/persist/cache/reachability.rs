//! Blob-pack reachability planning operations.

use super::repack_helpers::{blob_record_bytes, blob_record_identity};
use super::*;

impl PersistCache {
    /// Plans node-metadata value roots for future persistent value GC.
    ///
    /// This read-only diagnostic snapshots the latest demand-node metadata
    /// records plus the latest `values/` blob-index entries, resolves each
    /// materialized value hash through that value-index snapshot, and verifies
    /// resolved pack records without materializing payloads. Metadata records
    /// without a value hash are ignored. Metadata
    /// links whose value hash is missing from the blob index are reported as
    /// missing roots. The cache-level call holds shared value-store and
    /// node-metadata advisory reader locks while inspecting the value index,
    /// value pack, and metadata sidecar, but it does not rewrite sidecars,
    /// choose a retention window, delete blobs, or relocate records.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeValueRootPlanError`] if a value-store or
    /// node-metadata advisory read lock cannot be acquired, if the same-root
    /// value-index or node-metadata lock is poisoned, if either sidecar cannot
    /// be snapshotted, or if a blob location selected by node metadata cannot
    /// be verified against the linked value hash.
    pub fn plan_node_value_roots(
        &self,
    ) -> Result<PersistNodeValueRootPlan, PersistNodeValueRootPlanError> {
        let (value_advisory_guard, _value_guard) = self.lock_node_value_root_plan_read()?;
        let (_metadata_advisory_guard, _metadata_guard) = self
            .lock_node_metadata_read()
            .map_err(|source| PersistNodeValueRootPlanError::Metadata { source })?;
        let metadata_entries = self
            .node_metadata_index
            .latest_entries()
            .map_err(|source| PersistNodeValueRootPlanError::Metadata { source })?;
        let value_entries = self
            .value_index
            .latest_entries()
            .map_err(|source| PersistNodeValueRootPlanError::BlobIndex { source })?;
        let mut value_locations = BTreeMap::new();
        for entry in value_entries {
            value_locations.insert(entry.key().index_bytes(), entry.location());
        }
        let mut resolved_roots = Vec::new();
        let mut missing_roots = Vec::new();
        for entry in metadata_entries {
            let Some(value_hash) = entry.value().materialized_value_hash() else {
                continue;
            };
            let blob_key = PersistBlobKey::for_value(value_hash);
            let Some(location) = value_locations.get(&blob_key.index_bytes()).copied() else {
                missing_roots.push(PersistMissingNodeValueRoot::new(entry.key(), value_hash));
                continue;
            };
            self.value_pack
                .verify_mapped_blob(&value_advisory_guard, location, blob_key.hash())
                .map_err(|source| PersistNodeValueRootPlanError::Read { source })?;
            resolved_roots.push(PersistNodeValueRoot::new(entry.key(), value_hash, location));
        }
        Ok(PersistNodeValueRootPlan::new(resolved_roots, missing_roots))
    }

    /// Plans physical `values/` pack reachability from current metadata/index roots.
    ///
    /// This read-only diagnostic snapshots the latest demand-node metadata and
    /// `values/` blob-index entries, verifies every latest value-index root,
    /// scans the value pack, and classifies verified physical records as
    /// node-rooted, indexed without a current node root, or absent from the
    /// latest value index. Missing node value links are reported separately.
    /// The cache-level call holds the shared value-store advisory reader lock
    /// while inspecting the value index and pack, and holds the shared
    /// node-metadata advisory reader lock while snapshotting the metadata
    /// sidecar; it does not choose a retention window, prune metadata, rewrite
    /// sidecars, delete blobs, or relocate records.
    ///
    /// # Errors
    ///
    /// Returns [`PersistValueBlobReachabilityPlanError`] if a value-store or
    /// node-metadata advisory read lock cannot be acquired, if the same-root
    /// value-index or node-metadata lock is poisoned, if either sidecar cannot
    /// be snapshotted, if the value index contains a non-value key, if an
    /// indexed value blob cannot be verified, or if the value pack cannot be
    /// fully scanned and verified.
    pub fn plan_value_blob_reachability(
        &self,
    ) -> Result<PersistValueBlobReachabilityPlan, PersistValueBlobReachabilityPlanError> {
        let (value_advisory_guard, _value_guard) = self.lock_value_blob_reachability_plan_read()?;
        let metadata_entries = {
            let (_metadata_advisory_guard, _metadata_guard) = self
                .lock_node_metadata_read()
                .map_err(|source| PersistValueBlobReachabilityPlanError::Metadata { source })?;
            self.node_metadata_index
                .latest_entries()
                .map_err(|source| PersistValueBlobReachabilityPlanError::Metadata { source })?
        };
        let value_entries = self
            .value_index
            .latest_entries()
            .map_err(|source| PersistValueBlobReachabilityPlanError::BlobIndex { source })?;
        let mut value_locations = BTreeMap::new();
        let mut index_identities = BTreeMap::new();
        for entry in value_entries {
            let key = entry.key();
            if key.store() != PersistBlobStore::Values {
                return Err(PersistValueBlobReachabilityPlanError::WrongStoreEntry {
                    actual: key.store(),
                });
            }
            self.value_pack
                .verify_mapped_blob(&value_advisory_guard, entry.location(), key.hash())
                .map_err(|source| PersistValueBlobReachabilityPlanError::Read { source })?;
            value_locations.insert(key.index_bytes(), entry.location());
            index_identities.insert(blob_record_identity(key, entry.location()), ());
        }
        let mut node_roots = Vec::new();
        let mut missing_node_roots = Vec::new();
        let mut node_root_identities = BTreeMap::new();
        for entry in metadata_entries {
            let Some(value_hash) = entry.value().materialized_value_hash() else {
                continue;
            };
            let blob_key = PersistBlobKey::for_value(value_hash);
            let Some(location) = value_locations.get(&blob_key.index_bytes()).copied() else {
                missing_node_roots.push(PersistMissingNodeValueRoot::new(entry.key(), value_hash));
                continue;
            };
            node_root_identities.insert(blob_record_identity(blob_key, location), ());
            node_roots.push(PersistNodeValueRoot::new(entry.key(), value_hash, location));
        }

        let bytes_before = self
            .value_pack
            .len()
            .map_err(|source| PersistValueBlobReachabilityPlanError::Pack { source })?;
        let records = self
            .value_pack
            .with_mapped_records(&value_advisory_guard, |records| records)
            .map_err(|source| PersistValueBlobReachabilityPlanError::Pack { source })?;
        let mut node_rooted_records = Vec::new();
        let mut indexed_unrooted_records = Vec::new();
        let mut unindexed_records = Vec::new();
        let mut node_rooted_record_bytes = 0u64;
        let mut indexed_unrooted_record_bytes = 0u64;
        let mut unindexed_record_bytes = 0u64;
        for record in records {
            let identity =
                blob_record_identity(record.key(PersistBlobStore::Values), record.location());
            let record_bytes = blob_record_bytes(record);
            if node_root_identities.contains_key(&identity) {
                node_rooted_record_bytes = node_rooted_record_bytes.saturating_add(record_bytes);
                node_rooted_records.push(record);
            } else if index_identities.contains_key(&identity) {
                indexed_unrooted_record_bytes =
                    indexed_unrooted_record_bytes.saturating_add(record_bytes);
                indexed_unrooted_records.push(record);
            } else {
                unindexed_record_bytes = unindexed_record_bytes.saturating_add(record_bytes);
                unindexed_records.push(record);
            }
        }

        Ok(PersistValueBlobReachabilityPlan {
            node_roots,
            missing_node_roots,
            node_rooted_records,
            indexed_unrooted_records,
            unindexed_records,
            bytes_before,
            node_rooted_record_bytes,
            indexed_unrooted_record_bytes,
            unindexed_record_bytes,
        })
    }

    /// Plans physical `files/` pack reachability from current artifact/index roots.
    ///
    /// This read-only diagnostic snapshots same-process pending artifact roots,
    /// latest file-artifact mappings, latest parse-artifact mappings, and the
    /// latest `files/` blob-index entries. It verifies every captured root,
    /// scans the file pack, and classifies verified physical records by the
    /// strongest root source: file artifact, parse artifact, pending artifact,
    /// blob-index-only, or unindexed. The cache-level call holds the shared
    /// file-store advisory reader lock while inspecting the file index and
    /// pack, and holds shared artifact mapping advisory reader locks while
    /// snapshotting artifact sidecars; it does not choose a retention window,
    /// rewrite sidecars, delete blobs, or relocate records.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileBlobReachabilityPlanError`] if a file-store or
    /// artifact mapping advisory read lock cannot be acquired, if the same-root
    /// file blob-index, file-artifact, or parse-artifact lock is poisoned, if
    /// roots cannot be snapshotted, if the file blob index contains a non-file
    /// key, if any captured root cannot be verified, or if the file pack cannot
    /// be fully scanned and verified.
    pub fn plan_file_blob_reachability(
        &self,
    ) -> Result<PersistFileBlobReachabilityPlan, PersistFileBlobReachabilityPlanError> {
        let (file_advisory_guard, _file_guard) = self.lock_file_blob_reachability_plan_read()?;
        let pending_artifact_roots = self
            .root_locks
            .pending_file_roots()
            .map_err(|source| PersistFileBlobReachabilityPlanError::Roots { source })?;
        let file_artifact_roots = {
            let (_file_artifact_advisory_guard, _file_artifact_guard) =
                self.lock_file_artifact_read().map_err(|source| {
                    PersistFileBlobReachabilityPlanError::FileArtifactIndex { source }
                })?;
            self.file_artifact_index
                .latest_entries()
                .map_err(
                    |source| PersistFileBlobReachabilityPlanError::FileArtifactIndex { source },
                )?
                .into_iter()
                .map(|entry| {
                    let value = entry.value();
                    PersistBlobLiveRoot::new(
                        PersistBlobLiveRootSource::FileArtifactIndex,
                        value.blob_key(),
                        value.location(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let parse_artifact_roots = {
            let (_parse_artifact_advisory_guard, _parse_artifact_guard) =
                self.lock_parse_artifact_read().map_err(|source| {
                    PersistFileBlobReachabilityPlanError::ParseArtifactIndex { source }
                })?;
            self.parse_artifact_index
                .latest_entries()
                .map_err(
                    |source| PersistFileBlobReachabilityPlanError::ParseArtifactIndex { source },
                )?
                .into_iter()
                .map(|entry| {
                    let value = entry.value();
                    PersistBlobLiveRoot::new(
                        PersistBlobLiveRootSource::ParseArtifactIndex,
                        value.blob_key(),
                        value.location(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let file_entries = self
            .file_index
            .latest_entries()
            .map_err(|source| PersistFileBlobReachabilityPlanError::BlobIndex { source })?;

        let mut blob_index_roots = Vec::new();
        let mut index_identities = BTreeMap::new();
        for entry in file_entries {
            let key = entry.key();
            if key.store() != PersistBlobStore::Files {
                return Err(PersistFileBlobReachabilityPlanError::WrongStoreEntry {
                    actual: key.store(),
                });
            }
            self.file_pack
                .verify_mapped_blob(&file_advisory_guard, entry.location(), key.hash())
                .map_err(|source| PersistFileBlobReachabilityPlanError::Read { source })?;
            blob_index_roots.push(PersistBlobLiveRoot::new(
                PersistBlobLiveRootSource::BlobIndex,
                key,
                entry.location(),
            ));
            index_identities.insert(blob_record_identity(key, entry.location()), ());
        }

        let mut file_artifact_identities = BTreeMap::new();
        for root in &file_artifact_roots {
            self.file_pack
                .verify_mapped_blob(&file_advisory_guard, root.location(), root.key().hash())
                .map_err(|source| PersistFileBlobReachabilityPlanError::Read { source })?;
            file_artifact_identities.insert(blob_live_root_identity(*root), ());
        }
        let mut parse_artifact_identities = BTreeMap::new();
        for root in &parse_artifact_roots {
            self.file_pack
                .verify_mapped_blob(&file_advisory_guard, root.location(), root.key().hash())
                .map_err(|source| PersistFileBlobReachabilityPlanError::Read { source })?;
            parse_artifact_identities.insert(blob_live_root_identity(*root), ());
        }
        let mut pending_artifact_identities = BTreeMap::new();
        for root in &pending_artifact_roots {
            self.file_pack
                .verify_mapped_blob(&file_advisory_guard, root.location(), root.key().hash())
                .map_err(|source| PersistFileBlobReachabilityPlanError::Read { source })?;
            pending_artifact_identities.insert(blob_live_root_identity(*root), ());
        }

        let bytes_before = self
            .file_pack
            .len()
            .map_err(|source| PersistFileBlobReachabilityPlanError::Pack { source })?;
        let records = self
            .file_pack
            .with_mapped_records(&file_advisory_guard, |records| records)
            .map_err(|source| PersistFileBlobReachabilityPlanError::Pack { source })?;
        let mut file_artifact_rooted_records = Vec::new();
        let mut parse_artifact_rooted_records = Vec::new();
        let mut pending_artifact_rooted_records = Vec::new();
        let mut indexed_unrooted_records = Vec::new();
        let mut unindexed_records = Vec::new();
        let mut file_artifact_rooted_record_bytes = 0u64;
        let mut parse_artifact_rooted_record_bytes = 0u64;
        let mut pending_artifact_rooted_record_bytes = 0u64;
        let mut indexed_unrooted_record_bytes = 0u64;
        let mut unindexed_record_bytes = 0u64;
        for record in records {
            let identity =
                blob_record_identity(record.key(PersistBlobStore::Files), record.location());
            let record_bytes = blob_record_bytes(record);
            if file_artifact_identities.contains_key(&identity) {
                file_artifact_rooted_record_bytes =
                    file_artifact_rooted_record_bytes.saturating_add(record_bytes);
                file_artifact_rooted_records.push(record);
            } else if parse_artifact_identities.contains_key(&identity) {
                parse_artifact_rooted_record_bytes =
                    parse_artifact_rooted_record_bytes.saturating_add(record_bytes);
                parse_artifact_rooted_records.push(record);
            } else if pending_artifact_identities.contains_key(&identity) {
                pending_artifact_rooted_record_bytes =
                    pending_artifact_rooted_record_bytes.saturating_add(record_bytes);
                pending_artifact_rooted_records.push(record);
            } else if index_identities.contains_key(&identity) {
                indexed_unrooted_record_bytes =
                    indexed_unrooted_record_bytes.saturating_add(record_bytes);
                indexed_unrooted_records.push(record);
            } else {
                unindexed_record_bytes = unindexed_record_bytes.saturating_add(record_bytes);
                unindexed_records.push(record);
            }
        }

        Ok(PersistFileBlobReachabilityPlan {
            file_artifact_roots,
            parse_artifact_roots,
            pending_artifact_roots,
            blob_index_roots,
            file_artifact_rooted_records,
            parse_artifact_rooted_records,
            pending_artifact_rooted_records,
            indexed_unrooted_records,
            unindexed_records,
            bytes_before,
            file_artifact_rooted_record_bytes,
            parse_artifact_rooted_record_bytes,
            pending_artifact_rooted_record_bytes,
            indexed_unrooted_record_bytes,
            unindexed_record_bytes,
        })
    }
}
