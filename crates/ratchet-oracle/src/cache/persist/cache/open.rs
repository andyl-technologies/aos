//! Root open and initialization for the persistent eval-cache.
//!
//! Splitting the open family out of `cache.rs` keeps that module under the
//! RFC-0007 §2 line cap. This module owns the primary-versus-secondary open
//! disposition (RFC-0007 §P4 Option C): a primary root is reconciled to the
//! process content-hash family and re-initialized on any family or
//! schema-version mismatch, while a secondary is opened non-destructively
//! under whatever family its own manifest records.

use super::*;

impl PersistCache {
    /// Opens or initializes a persistent eval-cache root as the process primary.
    ///
    /// The root is reconciled to the process content-hash family
    /// ([`cache_hash_family`], BLAKE3 by default): a matching schema version and
    /// family preserve existing payload directories, and a well-formed mismatch
    /// of either discards `nodes/`, `values/`, and `files/` before rewriting the
    /// self-describing manifest under the process family. A family-less manifest
    /// from before per-layer families is treated as the historical BLAKE3
    /// default. Malformed schema metadata is reported as an error and is not
    /// discarded.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError`] if the cache root cannot be created or
    /// canonicalized, schema metadata cannot be read, parsed, or written, cache
    /// payload directories cannot be created or discarded, the process-local
    /// root-lock registry is poisoned, the cross-process advisory open lock
    /// cannot be acquired, the same-root open lock is poisoned, or packfiles or
    /// sidecar indexes cannot be initialized.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, PersistError> {
        Self::open_with_mode(root, PersistOpenMode::Primary)
    }

    /// Opens a persistent eval-cache root as additive secondary read capacity.
    ///
    /// Unlike [`Self::open`], a secondary is opened non-destructively: it keeps
    /// whatever content-hash family its own manifest records (a family-less
    /// manifest resolves to the historical BLAKE3 default) and never discards or
    /// rewrites shared payload. The reported [`Self::hash_family`] lets a
    /// differently-configured primary decide whether the secondary is probeable
    /// under the same family. A secondary at a mismatched schema version keeps
    /// its payload too; its reads simply degrade to misses (MEMO-2 §5.4).
    ///
    /// # Errors
    ///
    /// Returns [`PersistError`] under the same conditions as [`Self::open`],
    /// except that schema-version and hash-family mismatches never discard.
    pub(crate) fn open_secondary(root: impl Into<PathBuf>) -> Result<Self, PersistError> {
        Self::open_with_mode(root, PersistOpenMode::Secondary)
    }

    fn open_with_mode(
        root: impl Into<PathBuf>,
        mode: PersistOpenMode,
    ) -> Result<Self, PersistError> {
        let layout = PersistLayout::new(root);
        ensure_root_dir(layout.root())?;
        let layout = PersistLayout::new(fs::canonicalize(layout.root()).map_err(|source| {
            PersistError::CanonicalizeRoot {
                path: layout.root().to_path_buf(),
                source,
            }
        })?);
        let root_locks = root_locks_for_root(layout.root())?;
        let open_lock_path = layout.open_lock_path();
        let _open_advisory_guard =
            AdvisoryFileLock::lock(open_lock_path.clone(), AdvisoryFileLockMode::Exclusive)
                .map_err(|source| PersistError::OpenAdvisoryLock {
                    path: open_lock_path,
                    source,
                })?;
        let open_guard = root_locks.lock_open()?;
        let record = read_schema_record(&layout)?;
        let hash_family = match mode {
            PersistOpenMode::Primary => {
                let process_family = cache_hash_family();
                match resolve_schema_open(record.as_ref(), process_family) {
                    SchemaOpenDisposition::KeepPayload => {
                        ensure_payload_dirs(&layout)?;
                    }
                    SchemaOpenDisposition::KeepPayloadRecordFamily => {
                        ensure_payload_dirs(&layout)?;
                        write_schema(&layout, process_family)?;
                    }
                    SchemaOpenDisposition::DiscardAndReinitialize => {
                        discard_payload_dirs(&layout)?;
                        ensure_payload_dirs(&layout)?;
                        write_schema(&layout, process_family)?;
                    }
                    SchemaOpenDisposition::InitializeFresh => {
                        ensure_payload_dirs(&layout)?;
                        write_schema(&layout, process_family)?;
                    }
                }
                process_family
            }
            PersistOpenMode::Secondary => {
                // Secondaries are shared, safe-to-lose read capacity: open them
                // non-destructively under their recorded family and never rewrite
                // or discard their payload (RFC-0007 §P4 Option C). A family-less
                // or absent manifest resolves to the historical BLAKE3 default.
                let recorded_family = record
                    .as_ref()
                    .and_then(|record| record.hash_family.as_deref())
                    .and_then(CacheHashFamily::from_str)
                    .unwrap_or(CacheHashFamily::Blake3);
                ensure_payload_dirs(&layout)?;
                recorded_family
            }
        };
        let value_pack_path = layout.value_packfile_path();
        let value_pack = PersistBlobPack::open(value_pack_path.clone()).map_err(|source| {
            PersistError::OpenBlobPack {
                path: value_pack_path,
                source,
            }
        })?;
        let file_pack_path = layout.file_packfile_path();
        let file_pack = PersistBlobPack::open(file_pack_path.clone()).map_err(|source| {
            PersistError::OpenBlobPack {
                path: file_pack_path,
                source,
            }
        })?;
        let value_index_path = layout.value_index_path();
        let value_index = PersistBlobIndex::open(value_index_path.clone()).map_err(|source| {
            PersistError::OpenBlobIndex {
                path: value_index_path,
                source,
            }
        })?;
        let file_index_path = layout.file_index_path();
        let file_index = PersistBlobIndex::open(file_index_path.clone()).map_err(|source| {
            PersistError::OpenBlobIndex {
                path: file_index_path,
                source,
            }
        })?;
        let file_artifact_index_path = layout.file_artifact_index_path();
        let file_artifact_index = PersistFileArtifactIndex::open(file_artifact_index_path.clone())
            .map_err(|source| PersistError::OpenFileArtifactIndex {
                path: file_artifact_index_path,
                source,
            })?;
        let parse_artifact_index_path = layout.parse_artifact_index_path();
        let parse_artifact_index = PersistParseArtifactIndex::open(
            parse_artifact_index_path.clone(),
        )
        .map_err(|source| PersistError::OpenParseArtifactIndex {
            path: parse_artifact_index_path,
            source,
        })?;
        let node_metadata_index_path = layout.node_metadata_index_path();
        let node_metadata_index = PersistNodeMetadataIndex::open(node_metadata_index_path.clone())
            .map_err(|source| PersistError::OpenNodeMetadataIndex {
                path: node_metadata_index_path,
                source,
            })?;
        let node_trace_log_path = layout.node_trace_log_path();
        let node_trace_log =
            PersistNodeTraceLog::open(node_trace_log_path.clone()).map_err(|source| {
                PersistError::OpenNodeTraceLog {
                    path: node_trace_log_path,
                    source,
                }
            })?;
        drop(open_guard);
        Ok(Self {
            layout,
            value_pack,
            file_pack,
            value_index,
            file_index,
            file_artifact_index,
            parse_artifact_index,
            node_metadata_index,
            node_trace_log,
            root_locks,
            hash_family,
            value_decode_verification: false,
            verified_node_traces: Arc::new(Mutex::new(BTreeMap::new())),
            pending_node_demands: Arc::new(Mutex::new(BTreeMap::new())),
            write_behind_values: value_write_behind::write_behind_values_from_env(),
            pending_value_blobs: Arc::new(Mutex::new(
                value_write_behind::PendingValueBatch::default(),
            )),
            pending_file_artifacts: Arc::new(Mutex::new(
                file_write_behind::PendingFileArtifactBatch::default(),
            )),
        })
    }
}
