//! Blob-pack, blob-index, artifact sidecar, and advisory-lock operations.

use super::indexed_values::clone_mapped_blob_payload;
use super::*;

use ratchet_cache::file_lock::{AdvisoryFileLock, AdvisoryFileLockMode};

impl PersistCache {
    /// Returns the fixed-record blob index for `store`.
    pub const fn blob_index(&self, store: PersistBlobStore) -> &PersistBlobIndex {
        match store {
            PersistBlobStore::Values => &self.value_index,
            PersistBlobStore::Files => &self.file_index,
        }
    }

    /// Returns the immutable blob packfile for `store`.
    pub fn blob_pack(&self, store: PersistBlobStore) -> &PersistBlobPack {
        match store {
            PersistBlobStore::Values => &self.value_pack,
            PersistBlobStore::Files => &self.file_pack,
        }
    }

    pub(super) fn lock_indexed_blob_write(
        &self,
        store: PersistBlobStore,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistBlobIndexedWriteError> {
        let path = self.layout.blob_store_lock_path(store);
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistBlobIndexedWriteError::AdvisoryWriteLock {
                store,
                path,
                source,
            })?;
        let write_guard = self.root_locks.lock(store)?;
        Ok((advisory_guard, write_guard))
    }

    pub(super) fn lock_indexed_blob_read(
        &self,
        store: PersistBlobStore,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistBlobIndexedReadError> {
        let path = self.layout.blob_store_lock_path(store);
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Shared)
            .map_err(|source| PersistBlobIndexedReadError::AdvisoryReadLock {
                store,
                path,
                source,
            })?;
        let read_guard = self
            .root_locks
            .lock_blob_store(store)
            .map_err(|_| PersistBlobIndexedReadError::ReadLockPoisoned { store })?;
        Ok((advisory_guard, read_guard))
    }

    pub(super) fn lock_blob_liveness_plan_read(
        &self,
        store: PersistBlobStore,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistBlobPackLivenessPlanError> {
        let path = self.layout.blob_store_lock_path(store);
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Shared)
            .map_err(
                |source| PersistBlobPackLivenessPlanError::AdvisoryReadLock {
                    store,
                    path,
                    source,
                },
            )?;
        let read_guard = self.root_locks.lock_blob_index(store).map_err(|source| {
            PersistBlobPackLivenessPlanError::Roots {
                source: PersistBlobLiveRootError::BlobIndex { source },
            }
        })?;
        Ok((advisory_guard, read_guard))
    }

    pub(super) fn lock_node_value_root_plan_read(
        &self,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistNodeValueRootPlanError> {
        let store = PersistBlobStore::Values;
        let path = self.layout.blob_store_lock_path(store);
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Shared)
            .map_err(|source| PersistNodeValueRootPlanError::AdvisoryReadLock {
                store,
                path,
                source,
            })?;
        let read_guard = self
            .root_locks
            .lock_blob_index(store)
            .map_err(|source| PersistNodeValueRootPlanError::BlobIndex { source })?;
        Ok((advisory_guard, read_guard))
    }

    pub(super) fn lock_value_blob_reachability_plan_read(
        &self,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistValueBlobReachabilityPlanError> {
        let store = PersistBlobStore::Values;
        let path = self.layout.blob_store_lock_path(store);
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Shared)
            .map_err(
                |source| PersistValueBlobReachabilityPlanError::AdvisoryReadLock {
                    store,
                    path,
                    source,
                },
            )?;
        let read_guard = self
            .root_locks
            .lock_blob_index(store)
            .map_err(|source| PersistValueBlobReachabilityPlanError::BlobIndex { source })?;
        Ok((advisory_guard, read_guard))
    }

    pub(super) fn lock_file_blob_reachability_plan_read(
        &self,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistFileBlobReachabilityPlanError> {
        let store = PersistBlobStore::Files;
        let path = self.layout.blob_store_lock_path(store);
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Shared)
            .map_err(
                |source| PersistFileBlobReachabilityPlanError::AdvisoryReadLock {
                    store,
                    path,
                    source,
                },
            )?;
        let read_guard = self
            .root_locks
            .lock_blob_index(store)
            .map_err(|source| PersistFileBlobReachabilityPlanError::BlobIndex { source })?;
        Ok((advisory_guard, read_guard))
    }

    pub(super) fn lock_blob_pack_write(
        &self,
        store: PersistBlobStore,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistBlobPackError> {
        let path = self.layout.blob_store_lock_path(store);
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistBlobPackError::AdvisoryWriteLock {
                store,
                path,
                source,
            })?;
        let write_guard = self.root_locks.lock_blob_pack(store)?;
        Ok((advisory_guard, write_guard))
    }

    pub(super) fn lock_blob_pack_read(
        &self,
        store: PersistBlobStore,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistBlobPackError> {
        let path = self.layout.blob_store_lock_path(store);
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Shared)
            .map_err(|source| PersistBlobPackError::AdvisoryReadLock {
                store,
                path,
                source,
            })?;
        let read_guard = self
            .root_locks
            .lock_blob_store(store)
            .map_err(|_| PersistBlobPackError::ReadLockPoisoned { store })?;
        Ok((advisory_guard, read_guard))
    }

    pub(super) fn lock_blob_index_write(
        &self,
        store: PersistBlobStore,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistBlobIndexError> {
        let path = self.layout.blob_store_lock_path(store);
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistBlobIndexError::AdvisoryWriteLock {
                store,
                path,
                source,
            })?;
        let write_guard = self.root_locks.lock_blob_index(store)?;
        Ok((advisory_guard, write_guard))
    }

    pub(super) fn lock_blob_index_rebuild(
        &self,
        store: PersistBlobStore,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistBlobIndexRebuildError> {
        let path = self.layout.blob_store_lock_path(store);
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistBlobIndexRebuildError::AdvisoryWriteLock {
                store,
                path,
                source,
            })?;
        let write_guard = self
            .root_locks
            .lock_blob_store(store)
            .map_err(|_| PersistBlobIndexRebuildError::WriteLockPoisoned { store })?;
        Ok((advisory_guard, write_guard))
    }

    pub(super) fn lock_blob_pack_tail_trim(
        &self,
        store: PersistBlobStore,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistBlobPackTrimError> {
        let path = self.layout.blob_store_lock_path(store);
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistBlobPackTrimError::AdvisoryWriteLock {
                store,
                path,
                source,
            })?;
        let write_guard = self
            .root_locks
            .lock_blob_index(store)
            .map_err(|source| PersistBlobPackTrimError::BlobIndex { source })?;
        Ok((advisory_guard, write_guard))
    }

    pub(super) fn lock_value_blob_pack_repack(
        &self,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistValueBlobPackRepackError> {
        let path = self.layout.blob_store_lock_path(PersistBlobStore::Values);
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(
                |source| PersistValueBlobPackRepackError::AdvisoryWriteLock { path, source },
            )?;
        let write_guard = self
            .root_locks
            .lock_blob_store(PersistBlobStore::Values)
            .map_err(|_| PersistValueBlobPackRepackError::WriteLockPoisoned)?;
        Ok((advisory_guard, write_guard))
    }

    pub(super) fn lock_file_blob_pack_repack(
        &self,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistFileBlobPackRepackError> {
        let path = self.layout.blob_store_lock_path(PersistBlobStore::Files);
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistFileBlobPackRepackError::AdvisoryWriteLock { path, source })?;
        let write_guard = self
            .root_locks
            .lock_blob_store(PersistBlobStore::Files)
            .map_err(|_| PersistFileBlobPackRepackError::WriteLockPoisoned)?;
        Ok((advisory_guard, write_guard))
    }

    pub(super) fn lock_file_artifact_write(
        &self,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistFileArtifactIndexError> {
        let path = self.layout.file_artifact_lock_path();
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistFileArtifactIndexError::AdvisoryWriteLock { path, source })?;
        let write_guard = self.root_locks.lock_file_artifacts()?;
        Ok((advisory_guard, write_guard))
    }

    pub(super) fn lock_file_artifact_read(
        &self,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistFileArtifactIndexError> {
        let path = self.layout.file_artifact_lock_path();
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Shared)
            .map_err(|source| PersistFileArtifactIndexError::AdvisoryReadLock { path, source })?;
        let read_guard = self.root_locks.lock_file_artifacts()?;
        Ok((advisory_guard, read_guard))
    }

    pub(super) fn lock_parse_artifact_write(
        &self,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistParseArtifactIndexError> {
        let path = self.layout.parse_artifact_lock_path();
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistParseArtifactIndexError::AdvisoryWriteLock { path, source })?;
        let write_guard = self.root_locks.lock_parse_artifacts()?;
        Ok((advisory_guard, write_guard))
    }

    pub(super) fn lock_parse_artifact_read(
        &self,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistParseArtifactIndexError> {
        let path = self.layout.parse_artifact_lock_path();
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Shared)
            .map_err(|source| PersistParseArtifactIndexError::AdvisoryReadLock { path, source })?;
        let read_guard = self.root_locks.lock_parse_artifacts()?;
        Ok((advisory_guard, read_guard))
    }

    pub(super) fn lock_file_artifact_hydration_read(
        &self,
    ) -> Result<
        (
            AdvisoryFileLock,
            AdvisoryFileLock,
            MutexGuard<'_, ()>,
            MutexGuard<'_, ()>,
        ),
        PersistFileArtifactIndexedHydrationError,
    > {
        let files_path = self.layout.blob_store_lock_path(PersistBlobStore::Files);
        let files_advisory =
            AdvisoryFileLock::lock(files_path.clone(), AdvisoryFileLockMode::Shared).map_err(
                |source| PersistFileArtifactIndexedHydrationError::AdvisoryFileStoreReadLock {
                    path: files_path,
                    source,
                },
            )?;
        let artifacts_path = self.layout.file_artifact_lock_path();
        let artifacts_advisory =
            AdvisoryFileLock::lock(artifacts_path.clone(), AdvisoryFileLockMode::Shared).map_err(
                |source| PersistFileArtifactIndexedHydrationError::AdvisoryFileArtifactReadLock {
                    path: artifacts_path,
                    source,
                },
            )?;
        let file_guard = self
            .root_locks
            .lock_blob_pack(PersistBlobStore::Files)
            .map_err(|source| PersistFileArtifactIndexedHydrationError::Hydrate {
                source: PersistFileArtifactHydrationError::Read { source },
            })?;
        let artifact_guard = self
            .root_locks
            .lock_file_artifacts()
            .map_err(|source| PersistFileArtifactIndexedHydrationError::Lookup { source })?;
        Ok((
            files_advisory,
            artifacts_advisory,
            file_guard,
            artifact_guard,
        ))
    }

    pub(super) fn lock_parse_artifact_hydration_read(
        &self,
    ) -> Result<
        (
            AdvisoryFileLock,
            AdvisoryFileLock,
            MutexGuard<'_, ()>,
            MutexGuard<'_, ()>,
        ),
        PersistParseArtifactIndexedHydrationError,
    > {
        let files_path = self.layout.blob_store_lock_path(PersistBlobStore::Files);
        let files_advisory =
            AdvisoryFileLock::lock(files_path.clone(), AdvisoryFileLockMode::Shared).map_err(
                |source| PersistParseArtifactIndexedHydrationError::AdvisoryFileStoreReadLock {
                    path: files_path,
                    source,
                },
            )?;
        let artifacts_path = self.layout.parse_artifact_lock_path();
        let artifacts_advisory =
            AdvisoryFileLock::lock(artifacts_path.clone(), AdvisoryFileLockMode::Shared).map_err(
                |source| PersistParseArtifactIndexedHydrationError::AdvisoryParseArtifactReadLock {
                    path: artifacts_path,
                    source,
                },
            )?;
        let file_guard = self
            .root_locks
            .lock_blob_pack(PersistBlobStore::Files)
            .map_err(
                |source| PersistParseArtifactIndexedHydrationError::Hydrate {
                    source: PersistParseArtifactHydrationError::Read { source },
                },
            )?;
        let artifact_guard = self
            .root_locks
            .lock_parse_artifacts()
            .map_err(|source| PersistParseArtifactIndexedHydrationError::Lookup { source })?;
        Ok((
            files_advisory,
            artifacts_advisory,
            file_guard,
            artifact_guard,
        ))
    }

    pub(super) fn lock_node_metadata_write(
        &self,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistNodeMetadataIndexError> {
        let path = self.layout.node_metadata_lock_path();
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistNodeMetadataIndexError::AdvisoryWriteLock { path, source })?;
        let write_guard = self.root_locks.lock_node_metadata()?;
        Ok((advisory_guard, write_guard))
    }

    pub(super) fn lock_node_metadata_read(
        &self,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistNodeMetadataIndexError> {
        let path = self.layout.node_metadata_lock_path();
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Shared)
            .map_err(|source| PersistNodeMetadataIndexError::AdvisoryReadLock { path, source })?;
        let read_guard = self.root_locks.lock_node_metadata()?;
        Ok((advisory_guard, read_guard))
    }

    pub(super) fn lock_node_traces_write(
        &self,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistNodeTraceLogError> {
        let path = self.layout.node_traces_lock_path();
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistNodeTraceLogError::AdvisoryWriteLock { path, source })?;
        let write_guard = self.root_locks.lock_node_traces()?;
        Ok((advisory_guard, write_guard))
    }

    pub(super) fn lock_node_traces_read(
        &self,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistNodeTraceLogError> {
        let path = self.layout.node_traces_lock_path();
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Shared)
            .map_err(|source| PersistNodeTraceLogError::AdvisoryReadLock { path, source })?;
        let read_guard = self
            .root_locks
            .lock_node_traces()
            .map_err(|_| PersistNodeTraceLogError::ReadLockPoisoned)?;
        Ok((advisory_guard, read_guard))
    }

    /// Appends a blob to the packfile selected by `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the selected advisory lock cannot
    /// be acquired, the same-root blob-pack write lock is poisoned, the
    /// selected packfile cannot be opened, validated, or written, or if
    /// `payload` does not hash to `key.hash()`.
    pub fn append_blob(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
    ) -> Result<PersistBlobLocation, PersistBlobPackError> {
        let (_advisory_guard, _write_guard) = self.lock_blob_pack_write(key.store())?;
        self.append_blob_unlocked(key, payload)
    }

    pub(super) fn append_blob_unlocked(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
    ) -> Result<PersistBlobLocation, PersistBlobPackError> {
        self.blob_pack(key.store()).append_blob(key.hash(), payload)
    }

    /// Appends a blob without re-hashing the payload to verify its key.
    ///
    /// The content-addressed populate fast path: `key.hash()` is the BLAKE3 of
    /// `payload` the record was just looked up under, so the pack trusts the
    /// pairing. Skipping the verify re-hash is the cold-populate BLAKE3 tax
    /// reduction; callers without a caller-computed content address must use
    /// [`Self::append_blob_unlocked`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the selected packfile cannot be
    /// opened, validated, or written, or if `payload` is too large.
    pub(super) fn append_blob_unlocked_trusted(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
    ) -> Result<PersistBlobLocation, PersistBlobPackError> {
        self.blob_pack(key.store())
            .append_blob_trusted(key.hash(), payload)
    }

    pub(super) fn append_pending_file_artifact_blob(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
        source: PersistBlobLiveRootSource,
    ) -> Result<PersistBlobLocation, PersistBlobPackError> {
        let (_advisory_guard, _write_guard) = self.lock_blob_pack_write(PersistBlobStore::Files)?;
        let location = self.append_blob_unlocked(key, payload)?;
        self.root_locks
            .insert_pending_file_root(PersistBlobLiveRoot::new(source, key, location))?;
        Ok(location)
    }

    /// Reads a blob from the packfile selected by `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the selected advisory read lock
    /// cannot be acquired, if the same-root blob-pack read lock is poisoned, if
    /// the selected packfile cannot be opened or read, if `location` is
    /// invalid, or if record/payload hashes do not match `key.hash()`.
    pub fn read_blob(
        &self,
        key: PersistBlobKey,
        location: PersistBlobLocation,
    ) -> Result<Vec<u8>, PersistBlobPackError> {
        self.with_blob(key, location, clone_mapped_blob_payload)?
    }

    /// Visits a blob through a scoped mapped payload from the packfile selected by `key`.
    ///
    /// The callback receives verified borrowed bytes from the selected mapped
    /// packfile while the selected store's advisory read lock and same-root read
    /// lock are held. The borrowed slice cannot escape this method.
    /// Callbacks must not re-enter cache operations that need the same store
    /// lock, because those operations wait for this method to return.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the selected advisory read lock
    /// cannot be acquired, if the same-root blob-pack read lock is poisoned, if
    /// the selected packfile cannot be opened or mapped, if `location` is
    /// invalid, or if record/payload hashes do not match `key.hash()`.
    ///
    /// # Panics
    ///
    /// Panics if `visit` panics. A panic may poison the same-root read lock that
    /// is held while the callback runs.
    pub fn with_blob<R>(
        &self,
        key: PersistBlobKey,
        location: PersistBlobLocation,
        visit: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, PersistBlobPackError> {
        let (advisory_guard, _read_guard) = self.lock_blob_pack_read(key.store())?;
        self.blob_pack(key.store())
            .with_mapped_blob(&advisory_guard, location, key.hash(), visit)
    }

    /// Appends a durable file-artifact mapping entry to the sidecar index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexError`] if the advisory mapping lock
    /// cannot be acquired, if the same-root file-artifact write lock is
    /// poisoned, or if the sidecar index cannot be opened, validated, written,
    /// or flushed.
    pub fn record_file_artifact(
        &self,
        entry: PersistFileArtifactIndexEntry,
    ) -> Result<(), PersistFileArtifactIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_file_artifact_write()?;
        self.file_artifact_index.append_entry(entry)?;
        let value = entry.value();
        self.root_locks
            .remove_pending_file_root(PersistBlobLiveRoot::new(
                PersistBlobLiveRootSource::PendingFileArtifact,
                value.blob_key(),
                value.location(),
            ));
        Ok(())
    }

    /// Looks up a durable file-artifact mapping through the sidecar index.
    ///
    /// Missing index entries return `Ok(None)`. Cache-level file-artifact
    /// writers, readers, and file-pack repacks for the same cache root share the
    /// file-artifact advisory and same-root mapping locks while this sidecar is
    /// read. This is still a raw mapping lookup: callers that need the returned
    /// location to remain consistent with a following `files/` pack read must
    /// hold the file-store lock across both operations or use the higher-level
    /// hydration helpers.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexError`] if the advisory read lock
    /// cannot be acquired, if the same-root file-artifact lock is poisoned, or
    /// if the sidecar index cannot be opened, read, or decoded.
    pub fn lookup_file_artifact(
        &self,
        key: PersistFileArtifactKey,
    ) -> Result<Option<PersistFileArtifactIndexValue>, PersistFileArtifactIndexError> {
        let (_advisory_guard, _read_guard) = self.lock_file_artifact_read()?;
        self.file_artifact_index.lookup(key)
    }

    /// Appends a durable parse-artifact mapping entry to the sidecar index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexError`] if the advisory mapping lock
    /// cannot be acquired, if the same-root parse-artifact write lock is
    /// poisoned, or if the sidecar index cannot be opened, validated, written,
    /// or flushed.
    pub fn record_parse_artifact(
        &self,
        entry: PersistParseArtifactIndexEntry,
    ) -> Result<(), PersistParseArtifactIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_parse_artifact_write()?;
        self.parse_artifact_index.append_entry(entry)?;
        let value = entry.value();
        self.root_locks
            .remove_pending_file_root(PersistBlobLiveRoot::new(
                PersistBlobLiveRootSource::PendingParseArtifact,
                value.blob_key(),
                value.location(),
            ));
        Ok(())
    }

    /// Looks up a durable parse-artifact mapping through the sidecar index.
    ///
    /// Missing index entries return `Ok(None)`. Cache-level parse-artifact
    /// writers, readers, and file-pack repacks for the same cache root share the
    /// parse-artifact advisory and same-root mapping locks while this sidecar is
    /// read. This is still a raw mapping lookup: callers that need the returned
    /// location to remain consistent with a following `files/` pack read must
    /// hold the file-store lock across both operations or use the higher-level
    /// hydration helpers.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexError`] if the advisory read lock
    /// cannot be acquired, if the same-root parse-artifact lock is poisoned, or
    /// if the sidecar index cannot be opened, read, or decoded.
    pub fn lookup_parse_artifact(
        &self,
        key: PersistParseArtifactKey,
    ) -> Result<Option<PersistParseArtifactIndexValue>, PersistParseArtifactIndexError> {
        let (_advisory_guard, _read_guard) = self.lock_parse_artifact_read()?;
        self.parse_artifact_index.lookup(key)
    }

    /// Compacts file-artifact mappings to the newest entry for every known key.
    ///
    /// Cache-level writers opened on the same cache root share the
    /// file-artifact advisory lock and same-root write lock while this method
    /// rewrites the sidecar. Raw lower-level sidecar users and unrelated
    /// maintenance writers must still be excluded by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexError`] if the advisory mapping lock
    /// cannot be acquired, if the same-root file-artifact write lock is
    /// poisoned, or if the sidecar index cannot be created, opened, inspected,
    /// read, decoded, written, flushed, or renamed into place.
    pub fn compact_file_artifact_index(&self) -> Result<usize, PersistFileArtifactIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_file_artifact_write()?;
        self.file_artifact_index.compact_latest_entries()
    }

    /// Compacts parse-artifact mappings to the newest entry for every known key.
    ///
    /// Cache-level writers opened on the same cache root share the
    /// parse-artifact advisory lock and same-root write lock while this method
    /// rewrites the sidecar. Raw lower-level sidecar users and unrelated
    /// maintenance writers must still be excluded by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexError`] if the advisory mapping lock
    /// cannot be acquired, if the same-root parse-artifact write lock is
    /// poisoned, or if the sidecar index cannot be created, opened, inspected,
    /// read, decoded, written, flushed, or renamed into place.
    pub fn compact_parse_artifact_index(&self) -> Result<usize, PersistParseArtifactIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_parse_artifact_write()?;
        self.parse_artifact_index.compact_latest_entries()
    }
}
