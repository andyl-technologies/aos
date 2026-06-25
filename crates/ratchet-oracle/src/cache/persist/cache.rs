//! The opened persistent eval-cache root and its store operations.
//!
//! [`PersistCache`] ties together the per-store packfiles and indexes, routing
//! blob and file-artifact reads, writes, materialization decisions, and parse
//! artifact hydration through the on-disk layout.

use super::*;

/// An opened persistent eval-cache root.
#[derive(Clone, Debug)]
pub struct PersistCache {
    layout: PersistLayout,
    value_pack: PersistBlobPack,
    file_pack: PersistBlobPack,
    value_index: PersistBlobIndex,
    file_index: PersistBlobIndex,
    file_artifact_index: PersistFileArtifactIndex,
}

impl PersistCache {
    /// Opens or initializes a persistent eval-cache root.
    ///
    /// A matching schema preserves existing payload directories. A well-formed
    /// mismatched schema discards `nodes/`, `values/`, and `files/` before
    /// rewriting current metadata. Malformed schema metadata is reported as an
    /// error and is not discarded.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError`] if schema metadata cannot be read, parsed,
    /// written, if cache directories cannot be created or discarded, or if blob
    /// packfiles cannot be initialized.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, PersistError> {
        let layout = PersistLayout::new(root);
        match read_schema_version(&layout)? {
            Some(PERSIST_CACHE_SCHEMA_VERSION) => {
                ensure_payload_dirs(&layout)?;
            }
            Some(_) => {
                discard_payload_dirs(&layout)?;
                ensure_payload_dirs(&layout)?;
                write_schema(&layout)?;
            }
            None => {
                ensure_payload_dirs(&layout)?;
                write_schema(&layout)?;
            }
        }
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
        Ok(Self {
            layout,
            value_pack,
            file_pack,
            value_index,
            file_index,
            file_artifact_index,
        })
    }

    /// Returns this cache's filesystem layout.
    pub const fn layout(&self) -> &PersistLayout {
        &self.layout
    }

    /// Returns the immutable value blob packfile.
    pub const fn value_pack(&self) -> &PersistBlobPack {
        &self.value_pack
    }

    /// Returns the immutable file/frontend artifact blob packfile.
    pub const fn file_pack(&self) -> &PersistBlobPack {
        &self.file_pack
    }

    /// Returns the fixed-record blob index for serialized value blobs.
    pub const fn value_index(&self) -> &PersistBlobIndex {
        &self.value_index
    }

    /// Returns the fixed-record blob index for serialized file blobs.
    pub const fn file_index(&self) -> &PersistBlobIndex {
        &self.file_index
    }

    /// Returns the fixed-record index for durable file-artifact mappings.
    pub const fn file_artifact_index(&self) -> &PersistFileArtifactIndex {
        &self.file_artifact_index
    }

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

    /// Appends a blob to the packfile selected by `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the selected packfile cannot be
    /// opened, validated, or written, or if `payload` does not hash to
    /// `key.hash()`.
    pub fn append_blob(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
    ) -> Result<PersistBlobLocation, PersistBlobPackError> {
        self.blob_pack(key.store()).append_blob(key.hash(), payload)
    }

    /// Reads a blob from the packfile selected by `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the selected packfile cannot be
    /// opened or read, if `location` is invalid, or if record/payload hashes do
    /// not match `key.hash()`.
    pub fn read_blob(
        &self,
        key: PersistBlobKey,
        location: PersistBlobLocation,
    ) -> Result<Vec<u8>, PersistBlobPackError> {
        self.blob_pack(key.store()).read_blob(location, key.hash())
    }

    /// Appends a durable file-artifact mapping entry to the sidecar index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexError`] if the sidecar index cannot be
    /// opened, validated, written, or flushed.
    pub fn record_file_artifact(
        &self,
        entry: PersistFileArtifactIndexEntry,
    ) -> Result<(), PersistFileArtifactIndexError> {
        self.file_artifact_index.append_entry(entry)
    }

    /// Looks up a durable file-artifact mapping through the sidecar index.
    ///
    /// Missing index entries return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexError`] if the sidecar index cannot be
    /// opened, read, or decoded.
    pub fn lookup_file_artifact(
        &self,
        key: PersistFileArtifactKey,
    ) -> Result<Option<PersistFileArtifactIndexValue>, PersistFileArtifactIndexError> {
        self.file_artifact_index.lookup(key)
    }

    /// Looks up a blob location through the sidecar index selected by `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexError`] if the selected index cannot be
    /// opened, read, or decoded.
    pub fn lookup_blob_location(
        &self,
        key: PersistBlobKey,
    ) -> Result<Option<PersistBlobLocation>, PersistBlobIndexError> {
        self.blob_index(key.store()).lookup(key)
    }

    /// Appends a blob and records its location in the sidecar index.
    ///
    /// This helper is explicit and non-transactional: if the pack append
    /// succeeds but the sidecar index write fails, the blob bytes remain in the
    /// pack without a corresponding durable index record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexedWriteError`] if the selected packfile cannot
    /// append/verify the payload, or if the selected sidecar index cannot write
    /// the resulting hash-to-offset record.
    pub fn append_blob_indexed(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
    ) -> Result<PersistBlobIndexEntry, PersistBlobIndexedWriteError> {
        let location = self
            .append_blob(key, payload)
            .map_err(|source| PersistBlobIndexedWriteError::Append { source })?;
        let entry = PersistBlobIndexEntry::new(key, location);
        self.blob_index(key.store())
            .append_entry(entry)
            .map_err(|source| PersistBlobIndexedWriteError::Index { source })?;
        Ok(entry)
    }

    /// Reads a blob through the sidecar index selected by `key`.
    ///
    /// Missing index entries return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexedReadError`] if the selected index cannot be
    /// read/decoded or if the indexed pack location cannot be read and verified.
    pub fn read_blob_indexed(
        &self,
        key: PersistBlobKey,
    ) -> Result<Option<Vec<u8>>, PersistBlobIndexedReadError> {
        let Some(location) = self
            .lookup_blob_location(key)
            .map_err(|source| PersistBlobIndexedReadError::Lookup { source })?
        else {
            return Ok(None);
        };
        self.read_blob(key, location)
            .map(Some)
            .map_err(|source| PersistBlobIndexedReadError::Read { source })
    }

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
    /// [`MaterializationDecision::Materialize`] and the selected packfile cannot
    /// be opened, validated, or written, or when `payload` does not hash to
    /// `key.hash()`.
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
    /// `payload`. [`MaterializationDecision::Materialize`] appends the payload
    /// through [`Self::append_blob_indexed`].
    ///
    /// This helper is explicit and non-transactional: if the pack append
    /// succeeds but the sidecar index write fails, the blob bytes remain in the
    /// pack without a corresponding durable index record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexedWriteError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the selected packfile cannot
    /// append/verify the payload, or when the selected sidecar index cannot
    /// write the resulting hash-to-offset record.
    pub fn materialize_blob_indexed(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
        decision: MaterializationDecision,
    ) -> Result<PersistMaterialization, PersistBlobIndexedWriteError> {
        match decision {
            MaterializationDecision::Materialize => self
                .append_blob_indexed(key, payload)
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
    /// [`MaterializationDecision::Materialize`] and the selected packfile cannot
    /// be opened, validated, or written, or when `payload` does not hash to
    /// `key.hash()`.
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
    /// [`MaterializationDecision::Materialize`] and the selected packfile cannot
    /// append/verify the payload, or when the selected sidecar index cannot
    /// write the resulting hash-to-offset record.
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
    /// index value a future durable index would store.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the `files/` pack cannot be
    /// opened, validated, or written.
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
                let blob_hash = DurableBlake3Hash::for_bytes(payload);
                let location = self.append_blob(PersistBlobKey::for_file(blob_hash), payload)?;
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
    /// hashes `payload`, appends it to the `files/` pack through
    /// [`Self::append_blob_indexed`], and records the file-artifact mapping
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
    /// appended/indexed, or when the file-artifact mapping cannot be recorded.
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
                let blob_hash = DurableBlake3Hash::for_bytes(payload);
                let blob_entry = self
                    .append_blob_indexed(PersistBlobKey::for_file(blob_hash), payload)
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

    /// Applies materialization threshold signals to a frontend file artifact.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_file_artifact`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] when the signals choose
    /// [`MaterializationDecision::Materialize`] and the `files/` pack cannot be
    /// opened, validated, or written.
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
    /// appended/indexed, or when the file-artifact mapping cannot be recorded.
    pub fn materialize_file_artifact_indexed_with_signals(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        payload: &[u8],
        signals: MaterializationSignals,
    ) -> Result<PersistFileArtifactMaterialization, PersistFileArtifactIndexedWriteError> {
        self.materialize_file_artifact_indexed(file_key, parse_key, payload, signals.decide())
    }

    /// Reads and verifies a materialized frontend file artifact.
    ///
    /// This is a typed wrapper over [`Self::read_blob`] for values decoded from
    /// the future file-artifact index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the `files/` pack cannot be opened
    /// or read, if `index_value` points at an invalid location, or if the record
    /// or payload hash does not match `index_value`.
    pub fn read_file_artifact(
        &self,
        index_value: PersistFileArtifactIndexValue,
    ) -> Result<Vec<u8>, PersistBlobPackError> {
        self.read_blob(index_value.blob_key(), index_value.location())
    }

    /// Reads a materialized parse-artifact bundle into a parse-cache entry.
    ///
    /// This adapter consumes a caller-supplied file-artifact index value and
    /// target entry. The decoded bundle must validate against the current
    /// parse-cache schema before any entry files are written. This adapter does
    /// not perform durable index lookup or decide whether the hydrated entry
    /// should be used for a cache hit.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactHydrationError`] if the artifact cannot be
    /// read from the `files/` pack, if the payload is not a valid
    /// [`ParseArtifactBundle`], if the bundle metadata/artifact counts do not
    /// validate, or if the target entry cannot be written.
    pub fn hydrate_file_artifact_bundle(
        &self,
        index_value: PersistFileArtifactIndexValue,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistFileArtifactHydrationError> {
        let payload = self
            .read_file_artifact(index_value)
            .map_err(|source| PersistFileArtifactHydrationError::Read { source })?;
        let bundle = ParseArtifactBundle::decode(&payload)
            .map_err(|source| PersistFileArtifactHydrationError::Decode { source })?;
        bundle
            .validate_meta(PARSE_CACHE_SCHEMA_VERSION)
            .map_err(|source| PersistFileArtifactHydrationError::Validate { source })?;
        entry
            .write_artifact_bundle(&bundle)
            .map_err(|source| PersistFileArtifactHydrationError::Write { source })
    }

    /// Reads a keyed parse-artifact bundle into a parse-cache entry.
    ///
    /// The supplied `artifact_key` must match the key derived from `file_key`
    /// and `parse_key` before the `files/` pack is read. This adapter still
    /// relies on its caller to perform the durable index lookup.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactHydrationError`] if `artifact_key` does not
    /// match `file_key`/`parse_key`, if the artifact cannot be read from the
    /// `files/` pack, if the payload is not a valid [`ParseArtifactBundle`], if
    /// the bundle metadata/artifact counts do not validate, or if the target
    /// entry cannot be written.
    pub fn hydrate_file_artifact_bundle_for_key(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        artifact_key: PersistFileArtifactKey,
        index_value: PersistFileArtifactIndexValue,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistFileArtifactHydrationError> {
        let expected = PersistFileArtifactKey::from_parse_file_key(file_key, parse_key);
        if artifact_key != expected {
            return Err(PersistFileArtifactHydrationError::KeyMismatch {
                expected,
                actual: artifact_key,
            });
        }
        self.hydrate_file_artifact_bundle(index_value, entry)
    }

    /// Reads an indexed parse-artifact bundle into a parse-cache entry.
    ///
    /// This is the entry-shaped variant of
    /// [`Self::hydrate_file_artifact_bundle_for_key`]. It still relies on its
    /// caller to perform the durable index lookup that produced `index_entry`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactHydrationError`] if `index_entry.key()`
    /// does not match `file_key`/`parse_key`, if the artifact cannot be read
    /// from the `files/` pack, if the payload is not a valid
    /// [`ParseArtifactBundle`], if the bundle metadata/artifact counts do not
    /// validate, or if the target entry cannot be written.
    pub fn hydrate_file_artifact_bundle_from_entry(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        index_entry: PersistFileArtifactIndexEntry,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistFileArtifactHydrationError> {
        self.hydrate_file_artifact_bundle_for_key(
            file_key,
            parse_key,
            index_entry.key(),
            index_entry.value(),
            entry,
        )
    }

    /// Looks up and hydrates an indexed parse-artifact bundle.
    ///
    /// This is the cache-level hit adapter for the explicit file-artifact
    /// sidecar index. It derives the expected mapping key from `file_key` and
    /// `parse_key`, returns `Ok(None)` when the index has no matching entry,
    /// and otherwise validates and writes the indexed bundle into `entry`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexedHydrationError`] if the
    /// file-artifact index cannot be read, or if a matching indexed artifact
    /// cannot be read from the `files/` pack, decoded, validated, or written
    /// into `entry`.
    pub fn hydrate_file_artifact_bundle_from_index(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
    ) -> Result<Option<PersistFileArtifactIndexEntry>, PersistFileArtifactIndexedHydrationError>
    {
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(file_key, parse_key);
        let Some(index_value) = self
            .lookup_file_artifact(artifact_key)
            .map_err(|source| PersistFileArtifactIndexedHydrationError::Lookup { source })?
        else {
            return Ok(None);
        };
        let index_entry = PersistFileArtifactIndexEntry::new(artifact_key, index_value);
        self.hydrate_file_artifact_bundle_from_entry(file_key, parse_key, index_entry, entry)
            .map_err(|source| PersistFileArtifactIndexedHydrationError::Hydrate { source })?;
        Ok(Some(index_entry))
    }

    /// Derives parse identities from source bytes and hydrates the parse cache.
    ///
    /// This source-shaped adapter derives `ParseFileKey` from `realpath` and
    /// `source`, derives `ParseCacheKey` through `parse_cache`, and hydrates
    /// the parse cache's normal entry directory when the persistent
    /// file-artifact index has a matching bundle. Missing index entries return
    /// `Ok(None)`.
    ///
    /// `realpath` must already be the canonical path used for file-artifact
    /// identity; this helper does not canonicalize or read source files.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexedHydrationError`] if the
    /// file-artifact index cannot be read, or if a matching indexed artifact
    /// cannot be read from the `files/` pack, decoded, validated, or written
    /// into the parse cache entry.
    pub fn hydrate_parse_cache_entry_from_source_index(
        &self,
        parse_cache: &ParseCache,
        realpath: impl AsRef<Path>,
        source: &[u8],
    ) -> Result<Option<PersistFileArtifactIndexEntry>, PersistFileArtifactIndexedHydrationError>
    {
        let file_key = ParseFileKey::for_source(realpath.as_ref(), source);
        let parse_key = parse_cache.key_for_source(source);
        let entry = parse_cache.entry_for_key(parse_key);
        self.hydrate_file_artifact_bundle_from_index(&file_key, parse_key, &entry)
    }

    /// Canonicalizes a source path and hydrates the matching parse-cache entry.
    ///
    /// This file-shaped adapter canonicalizes `path`, reads the canonical
    /// source bytes, derives the file and parse identities from those bytes,
    /// and delegates to [`Self::hydrate_parse_cache_entry_from_source_index`].
    /// Missing file-artifact index entries return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseFileIndexedHydrationError`] if `path` cannot be
    /// canonicalized, the canonical source file cannot be read, the
    /// file-artifact index cannot be read, or a matching indexed artifact
    /// cannot be read from the `files/` pack, decoded, validated, or written
    /// into the parse cache entry.
    pub fn hydrate_parse_cache_entry_from_file_index(
        &self,
        parse_cache: &ParseCache,
        path: impl AsRef<Path>,
    ) -> Result<Option<PersistFileArtifactIndexEntry>, PersistParseFileIndexedHydrationError> {
        let requested = path.as_ref();
        let realpath = fs::canonicalize(requested).map_err(|source| {
            PersistParseFileIndexedHydrationError::CanonicalizeSource {
                path: requested.to_path_buf(),
                source,
            }
        })?;
        let source = fs::read(&realpath).map_err(|source| {
            PersistParseFileIndexedHydrationError::ReadSource {
                path: realpath.clone(),
                source,
            }
        })?;
        self.hydrate_parse_cache_entry_from_source_index(parse_cache, &realpath, &source)
            .map_err(|source| PersistParseFileIndexedHydrationError::Hydrate { source })
    }

    /// Canonicalizes a source path and loads an indexed parse-cache hit.
    ///
    /// This is an explicit load adapter over
    /// [`Self::hydrate_parse_cache_entry_from_source_index`] and
    /// [`ParseCache::load_cached_bytes`]. It canonicalizes `path`, reads the
    /// canonical source bytes, hydrates the normal parse-cache entry from the
    /// persistent file-artifact index, and returns the hydrated entry as a
    /// [`CachedParse`] hit. Missing file-artifact index entries return
    /// `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseFileIndexedLoadError`] if `path` cannot be
    /// canonicalized, the canonical source file cannot be read, the
    /// file-artifact index cannot be read, a matching indexed artifact cannot
    /// be hydrated, or the hydrated parse-cache entry cannot be read back as a
    /// [`CachedParse`].
    pub fn load_parse_cache_file_from_index(
        &self,
        parse_cache: &ParseCache,
        path: impl AsRef<Path>,
    ) -> Result<Option<CachedParse>, PersistParseFileIndexedLoadError> {
        let requested = path.as_ref();
        let realpath = fs::canonicalize(requested).map_err(|source| {
            PersistParseFileIndexedLoadError::CanonicalizeSource {
                path: requested.to_path_buf(),
                source,
            }
        })?;
        let source =
            fs::read(&realpath).map_err(|source| PersistParseFileIndexedLoadError::ReadSource {
                path: realpath.clone(),
                source,
            })?;
        if self
            .hydrate_parse_cache_entry_from_source_index(parse_cache, &realpath, &source)
            .map_err(|source| PersistParseFileIndexedLoadError::Hydrate { source })?
            .is_none()
        {
            return Ok(None);
        }
        parse_cache
            .load_cached_bytes(&source)
            .map_err(|source| PersistParseFileIndexedLoadError::Load { source })
    }

    /// Applies `decision` to an existing parse-cache artifact entry.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns a skipped result
    /// without reading or encoding `entry`. [`MaterializationDecision::Materialize`]
    /// reads the entry as a [`ParseArtifactBundle`], encodes it as one payload,
    /// and appends it through [`Self::materialize_file_artifact`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactMaterializationError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the source entry cannot be
    /// read, the bundle payload cannot be encoded, or the `files/` pack cannot
    /// be written.
    pub fn materialize_parse_artifact_entry(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
        decision: MaterializationDecision,
    ) -> Result<PersistFileArtifactMaterialization, PersistParseArtifactMaterializationError> {
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(file_key, parse_key);
        match decision {
            MaterializationDecision::KeepInMemory => {
                Ok(PersistFileArtifactMaterialization::Skipped { artifact_key })
            }
            MaterializationDecision::Materialize => {
                let bundle = entry.read_artifact_bundle().map_err(|source| {
                    PersistParseArtifactMaterializationError::ReadBundle { source }
                })?;
                let payload = bundle.encode().map_err(|source| {
                    PersistParseArtifactMaterializationError::EncodeBundle { source }
                })?;
                self.materialize_file_artifact(
                    file_key,
                    parse_key,
                    &payload,
                    MaterializationDecision::Materialize,
                )
                .map_err(|source| PersistParseArtifactMaterializationError::Write { source })
            }
        }
    }

    /// Applies `decision` to an existing parse-cache entry and records indexes.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns a skipped result
    /// without reading or encoding `entry`. [`MaterializationDecision::Materialize`]
    /// reads the entry as a [`ParseArtifactBundle`], encodes it as one payload,
    /// appends it through [`Self::materialize_file_artifact_indexed`], and
    /// records both blob and file-artifact sidecar indexes.
    ///
    /// This helper inherits the explicit non-transactional behavior of
    /// [`Self::materialize_file_artifact_indexed`]: a blob append/index write
    /// can remain even when the file-artifact mapping write fails.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactMaterializationError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the source entry cannot be
    /// read, the bundle payload cannot be encoded, the `files/` blob cannot be
    /// appended/indexed, or the file-artifact mapping cannot be recorded.
    pub fn materialize_parse_artifact_entry_indexed(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
        decision: MaterializationDecision,
    ) -> Result<PersistFileArtifactMaterialization, PersistParseArtifactMaterializationError> {
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(file_key, parse_key);
        match decision {
            MaterializationDecision::KeepInMemory => {
                Ok(PersistFileArtifactMaterialization::Skipped { artifact_key })
            }
            MaterializationDecision::Materialize => {
                let bundle = entry.read_artifact_bundle().map_err(|source| {
                    PersistParseArtifactMaterializationError::ReadBundle { source }
                })?;
                let payload = bundle.encode().map_err(|source| {
                    PersistParseArtifactMaterializationError::EncodeBundle { source }
                })?;
                self.materialize_file_artifact_indexed(
                    file_key,
                    parse_key,
                    &payload,
                    MaterializationDecision::Materialize,
                )
                .map_err(|source| PersistParseArtifactMaterializationError::WriteIndexed { source })
            }
        }
    }

    /// Applies materialization threshold signals to an existing parse-cache entry.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_parse_artifact_entry`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactMaterializationError`] when the signals
    /// choose [`MaterializationDecision::Materialize`] and the source entry
    /// cannot be read, the bundle payload cannot be encoded, or the `files/`
    /// pack cannot be written.
    pub fn materialize_parse_artifact_entry_with_signals(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
        signals: MaterializationSignals,
    ) -> Result<PersistFileArtifactMaterialization, PersistParseArtifactMaterializationError> {
        self.materialize_parse_artifact_entry(file_key, parse_key, entry, signals.decide())
    }

    /// Applies threshold signals to indexed parse-cache entry materialization.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_parse_artifact_entry_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactMaterializationError`] when the signals
    /// choose [`MaterializationDecision::Materialize`] and the source entry
    /// cannot be read, the bundle payload cannot be encoded, the `files/` blob
    /// cannot be appended/indexed, or the file-artifact mapping cannot be
    /// recorded.
    pub fn materialize_parse_artifact_entry_indexed_with_signals(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
        signals: MaterializationSignals,
    ) -> Result<PersistFileArtifactMaterialization, PersistParseArtifactMaterializationError> {
        self.materialize_parse_artifact_entry_indexed(file_key, parse_key, entry, signals.decide())
    }
}
