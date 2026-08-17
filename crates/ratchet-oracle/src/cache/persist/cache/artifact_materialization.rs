//! Blob and artifact materialization operations.

use super::*;

impl PersistCache {
    /// Applies `decision` to `payload` in the packfile selected by `key`.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns
    /// [`PersistMaterialization::Skipped`] without hashing or writing
    /// `payload`. [`MaterializationDecision::Materialize`] appends the payload
    /// through [`Self::append_blob`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the selected advisory lock
    /// cannot be acquired, the selected same-root blob write lock is poisoned,
    /// the selected packfile cannot be opened, validated, or written, or when
    /// `payload` does not hash to `key.hash()`.
    pub fn materialize_blob(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
        decision: MaterializationDecision,
    ) -> Result<PersistMaterialization, PersistBlobPackError> {
        match decision {
            MaterializationDecision::Materialize => self
                .append_blob(key, payload)
                .map(PersistMaterialization::Materialized),
            MaterializationDecision::KeepInMemory => Ok(PersistMaterialization::Skipped),
        }
    }

    /// Applies `decision` to `payload` and records materialized blobs in the
    /// sidecar index.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns
    /// [`PersistMaterialization::Skipped`] without hashing or writing
    /// `payload`. [`MaterializationDecision::Materialize`] ensures the payload
    /// is present through [`Self::ensure_blob_indexed`].
    ///
    /// This helper is explicit and non-transactional: if a fresh pack append
    /// succeeds but the sidecar index write fails, the blob bytes remain in the
    /// pack without a corresponding durable index record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexedWriteError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the selected in-process
    /// materialization advisory lock cannot be acquired, the selected
    /// in-process materialization lock is poisoned, the selected packfile
    /// cannot append/verify a fresh payload, or the selected sidecar index
    /// cannot write a fresh hash-to-offset record. A sidecar lookup failure
    /// falls back to the append path.
    pub fn materialize_blob_indexed(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
        decision: MaterializationDecision,
    ) -> Result<PersistMaterialization, PersistBlobIndexedWriteError> {
        match decision {
            MaterializationDecision::Materialize => self
                .ensure_blob_indexed(key, payload)
                .map(|entry| PersistMaterialization::Materialized(entry.location())),
            MaterializationDecision::KeepInMemory => Ok(PersistMaterialization::Skipped),
        }
    }

    /// Applies materialization threshold signals to `payload`.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_blob`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] when the signals choose
    /// [`MaterializationDecision::Materialize`] and the selected advisory lock
    /// cannot be acquired, the selected same-root blob write lock is poisoned,
    /// the selected packfile cannot be opened, validated, or written, or when
    /// `payload` does not hash to `key.hash()`.
    pub fn materialize_blob_with_signals(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
        signals: MaterializationSignals,
    ) -> Result<PersistMaterialization, PersistBlobPackError> {
        self.materialize_blob(key, payload, signals.decide())
    }

    /// Applies materialization threshold signals to indexed blob materialization.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_blob_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexedWriteError`] when the signals choose
    /// [`MaterializationDecision::Materialize`] and the selected in-process
    /// materialization advisory lock cannot be acquired, the selected
    /// in-process materialization lock is poisoned, the selected packfile
    /// cannot append/verify a fresh payload, or the selected sidecar index
    /// cannot write a fresh hash-to-offset record. A sidecar lookup failure
    /// falls back to the append path.
    pub fn materialize_blob_indexed_with_signals(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
        signals: MaterializationSignals,
    ) -> Result<PersistMaterialization, PersistBlobIndexedWriteError> {
        self.materialize_blob_indexed(key, payload, signals.decide())
    }

    /// Applies `decision` to a frontend file artifact payload.
    ///
    /// The artifact mapping key is derived from `file_key` and `parse_key`.
    /// [`MaterializationDecision::KeepInMemory`] returns a skipped result
    /// without hashing or writing `payload`. [`MaterializationDecision::Materialize`]
    /// hashes `payload`, appends it to the `files/` pack, and returns the typed
    /// index value a future durable index would store. The appended record is
    /// registered as a same-process pending file-artifact root until
    /// [`Self::record_file_artifact`] publishes the mapping.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the advisory file-blob
    /// write lock cannot be acquired, the same-root file-blob write lock is
    /// poisoned, or the `files/` pack cannot be opened, validated, or written.
    pub fn materialize_file_artifact(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        payload: &[u8],
        decision: MaterializationDecision,
    ) -> Result<PersistFileArtifactMaterialization, PersistBlobPackError> {
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(file_key, parse_key);
        match decision {
            MaterializationDecision::KeepInMemory => {
                Ok(PersistFileArtifactMaterialization::Skipped { artifact_key })
            }
            MaterializationDecision::Materialize => {
                let blob_hash = PersistFileBlobHash::for_payload(payload);
                let location = self.append_pending_file_artifact_blob(
                    PersistBlobKey::for_file(blob_hash),
                    payload,
                    PersistBlobLiveRootSource::PendingFileArtifact,
                )?;
                Ok(PersistFileArtifactMaterialization::Materialized {
                    artifact_key,
                    index_value: PersistFileArtifactIndexValue::new(blob_hash, location),
                })
            }
        }
    }

    /// Applies `decision` to a frontend file artifact and records index entries.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns a skipped result
    /// without hashing or writing `payload`. [`MaterializationDecision::Materialize`]
    /// hashes `payload`, ensures it is present in the `files/` pack through
    /// [`Self::ensure_blob_indexed`], and records the file-artifact mapping
    /// through [`Self::record_file_artifact`].
    ///
    /// This helper is explicit and non-transactional: if the blob append or
    /// blob-index write succeeds but the file-artifact index write fails, the
    /// blob bytes and any blob hash-to-offset record remain without a
    /// corresponding file-artifact mapping record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexedWriteError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the `files/` blob cannot be
    /// verified/reused, appended, or indexed, or when the file-artifact mapping
    /// cannot be recorded.
    pub fn materialize_file_artifact_indexed(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        payload: &[u8],
        decision: MaterializationDecision,
    ) -> Result<PersistFileArtifactMaterialization, PersistFileArtifactIndexedWriteError> {
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(file_key, parse_key);
        match decision {
            MaterializationDecision::KeepInMemory => {
                Ok(PersistFileArtifactMaterialization::Skipped { artifact_key })
            }
            MaterializationDecision::Materialize => {
                // Write-behind (RFC-0007 §3.2(b)) buffers the whole promotion —
                // blob, blob-index, and mapping — and flushes it batched at the
                // run boundary; see `file_write_behind`.
                if self.write_behind_files_enabled() {
                    return self.buffer_file_artifact(artifact_key, payload);
                }
                let blob_hash = PersistFileBlobHash::for_payload(payload);
                let blob_entry = self
                    .ensure_blob_indexed(PersistBlobKey::for_file(blob_hash), payload)
                    .map_err(|source| PersistFileArtifactIndexedWriteError::Blob { source })?;
                let index_value =
                    PersistFileArtifactIndexValue::new(blob_hash, blob_entry.location());
                self.record_file_artifact(PersistFileArtifactIndexEntry::new(
                    artifact_key,
                    index_value,
                ))
                .map_err(|source| PersistFileArtifactIndexedWriteError::Index { source })?;
                Ok(PersistFileArtifactMaterialization::Materialized {
                    artifact_key,
                    index_value,
                })
            }
        }
    }

    /// Applies `decision` to a frontend parse artifact payload.
    ///
    /// The artifact mapping key is derived only from `parse_key`.
    /// [`MaterializationDecision::KeepInMemory`] returns a skipped result
    /// without hashing or writing `payload`. [`MaterializationDecision::Materialize`]
    /// hashes `payload`, appends it to the `files/` pack, and returns the typed
    /// index value a future durable index would store. The appended record is
    /// registered as a same-process pending parse-artifact root until
    /// [`Self::record_parse_artifact`] publishes the mapping.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the advisory file-blob
    /// write lock cannot be acquired, the same-root file-blob write lock is
    /// poisoned, or the `files/` pack cannot be opened, validated, or written.
    pub fn materialize_parse_artifact(
        &self,
        parse_key: ParseCacheKey,
        payload: &[u8],
        decision: MaterializationDecision,
    ) -> Result<PersistParseArtifactMaterialization, PersistBlobPackError> {
        let artifact_key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
        match decision {
            MaterializationDecision::KeepInMemory => {
                Ok(PersistParseArtifactMaterialization::Skipped { artifact_key })
            }
            MaterializationDecision::Materialize => {
                let blob_hash = PersistFileBlobHash::for_payload(payload);
                let location = self.append_pending_file_artifact_blob(
                    PersistBlobKey::for_file(blob_hash),
                    payload,
                    PersistBlobLiveRootSource::PendingParseArtifact,
                )?;
                Ok(PersistParseArtifactMaterialization::Materialized {
                    artifact_key,
                    index_value: PersistParseArtifactIndexValue::new(blob_hash, location),
                })
            }
        }
    }

    /// Applies `decision` to a frontend parse artifact and records index entries.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns a skipped result
    /// without hashing or writing `payload`. [`MaterializationDecision::Materialize`]
    /// hashes `payload`, ensures it is present in the `files/` pack through
    /// [`Self::ensure_blob_indexed`], and records the parse-artifact mapping
    /// through [`Self::record_parse_artifact`].
    ///
    /// This helper is explicit and non-transactional: if the blob append or
    /// blob-index write succeeds but the parse-artifact index write fails, the
    /// blob bytes and any blob hash-to-offset record remain without a
    /// corresponding parse-artifact mapping record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexedWriteError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the `files/` blob cannot be
    /// verified/reused, appended, or indexed, or when the parse-artifact mapping
    /// cannot be recorded.
    pub fn materialize_parse_artifact_indexed(
        &self,
        parse_key: ParseCacheKey,
        payload: &[u8],
        decision: MaterializationDecision,
    ) -> Result<PersistParseArtifactMaterialization, PersistParseArtifactIndexedWriteError> {
        let artifact_key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
        match decision {
            MaterializationDecision::KeepInMemory => {
                Ok(PersistParseArtifactMaterialization::Skipped { artifact_key })
            }
            MaterializationDecision::Materialize => {
                // Write-behind (RFC-0007 §3.2(b)) buffers the whole promotion —
                // blob, blob-index, and mapping — and flushes it batched at the
                // run boundary; see `file_write_behind`.
                if self.write_behind_files_enabled() {
                    return self.buffer_parse_artifact(artifact_key, payload);
                }
                let blob_hash = PersistFileBlobHash::for_payload(payload);
                let blob_entry = self
                    .ensure_blob_indexed(PersistBlobKey::for_file(blob_hash), payload)
                    .map_err(|source| PersistParseArtifactIndexedWriteError::Blob { source })?;
                let index_value =
                    PersistParseArtifactIndexValue::new(blob_hash, blob_entry.location());
                self.record_parse_artifact(PersistParseArtifactIndexEntry::new(
                    artifact_key,
                    index_value,
                ))
                .map_err(|source| PersistParseArtifactIndexedWriteError::Index { source })?;
                Ok(PersistParseArtifactMaterialization::Materialized {
                    artifact_key,
                    index_value,
                })
            }
        }
    }

    /// Applies materialization threshold signals to a frontend file artifact.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_file_artifact`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] when the signals choose
    /// [`MaterializationDecision::Materialize`] and the advisory file-blob
    /// write lock cannot be acquired, the same-root file-blob write lock is
    /// poisoned, or the `files/` pack cannot be opened, validated, or written.
    pub fn materialize_file_artifact_with_signals(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        payload: &[u8],
        signals: MaterializationSignals,
    ) -> Result<PersistFileArtifactMaterialization, PersistBlobPackError> {
        self.materialize_file_artifact(file_key, parse_key, payload, signals.decide())
    }

    /// Applies materialization threshold signals to indexed file-artifact materialization.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_file_artifact_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexedWriteError`] when the signals choose
    /// [`MaterializationDecision::Materialize`] and the `files/` blob cannot be
    /// verified/reused, appended, or indexed, or when the file-artifact mapping
    /// cannot be recorded.
    pub fn materialize_file_artifact_indexed_with_signals(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        payload: &[u8],
        signals: MaterializationSignals,
    ) -> Result<PersistFileArtifactMaterialization, PersistFileArtifactIndexedWriteError> {
        self.materialize_file_artifact_indexed(file_key, parse_key, payload, signals.decide())
    }

    /// Applies materialization threshold signals to a frontend parse artifact.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_parse_artifact`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] when the signals choose
    /// [`MaterializationDecision::Materialize`] and the advisory file-blob
    /// write lock cannot be acquired, the same-root file-blob write lock is
    /// poisoned, or the `files/` pack cannot be opened, validated, or written.
    pub fn materialize_parse_artifact_with_signals(
        &self,
        parse_key: ParseCacheKey,
        payload: &[u8],
        signals: MaterializationSignals,
    ) -> Result<PersistParseArtifactMaterialization, PersistBlobPackError> {
        self.materialize_parse_artifact(parse_key, payload, signals.decide())
    }

    /// Applies materialization threshold signals to indexed parse-artifact materialization.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_parse_artifact_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexedWriteError`] when the signals choose
    /// [`MaterializationDecision::Materialize`] and the `files/` blob cannot be
    /// appended/indexed, or when the parse-artifact mapping cannot be recorded.
    pub fn materialize_parse_artifact_indexed_with_signals(
        &self,
        parse_key: ParseCacheKey,
        payload: &[u8],
        signals: MaterializationSignals,
    ) -> Result<PersistParseArtifactMaterialization, PersistParseArtifactIndexedWriteError> {
        self.materialize_parse_artifact_indexed(parse_key, payload, signals.decide())
    }
}
