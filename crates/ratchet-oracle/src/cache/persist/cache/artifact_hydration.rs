//! Artifact and parse-cache hydration operations.

use super::*;
use ratchet_cache::file_lock::AdvisoryFileLock;

impl PersistCache {
    /// Reads and verifies a materialized frontend file artifact.
    ///
    /// This is a typed wrapper over [`Self::read_blob`] for values decoded from
    /// the future file-artifact index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the `files/` advisory read lock
    /// cannot be acquired, if the same-root `files/` pack read lock is
    /// poisoned, if the `files/` pack cannot be opened or read, if
    /// `index_value` points at an invalid location, or if the record or
    /// payload hash does not match `index_value`.
    pub fn read_file_artifact(
        &self,
        index_value: PersistFileArtifactIndexValue,
    ) -> Result<Vec<u8>, PersistBlobPackError> {
        self.read_blob(index_value.blob_key(), index_value.location())
    }

    fn read_file_artifact_unlocked(
        &self,
        index_value: PersistFileArtifactIndexValue,
    ) -> Result<Vec<u8>, PersistBlobPackError> {
        self.read_blob_unlocked(index_value.blob_key(), index_value.location())
    }

    /// Reads and verifies a materialized frontend parse artifact.
    ///
    /// This is a typed wrapper over [`Self::read_blob`] for values decoded from
    /// the parse-artifact index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the `files/` advisory read lock
    /// cannot be acquired, if the same-root `files/` pack read lock is
    /// poisoned, if the `files/` pack cannot be opened or read, if
    /// `index_value` points at an invalid location, or if the record or
    /// payload hash does not match `index_value`.
    pub fn read_parse_artifact(
        &self,
        index_value: PersistParseArtifactIndexValue,
    ) -> Result<Vec<u8>, PersistBlobPackError> {
        self.read_blob(index_value.blob_key(), index_value.location())
    }

    fn read_parse_artifact_unlocked(
        &self,
        index_value: PersistParseArtifactIndexValue,
    ) -> Result<Vec<u8>, PersistBlobPackError> {
        self.read_blob_unlocked(index_value.blob_key(), index_value.location())
    }

    /// Reads a materialized parse-artifact bundle into a parse-cache entry.
    ///
    /// This adapter consumes a caller-supplied parse-artifact index value and
    /// target entry. The decoded bundle must validate against the current
    /// parse-cache schema before any entry files are written. This adapter does
    /// not perform durable index lookup or decide whether the hydrated entry
    /// should be used for a cache hit.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactHydrationError`] if the artifact cannot be
    /// read from the `files/` pack, if the payload is not a valid
    /// [`ParseArtifactBundle`], if the bundle metadata/artifact counts do not
    /// validate, or if the target entry cannot be written.
    pub fn hydrate_parse_artifact_bundle(
        &self,
        index_value: PersistParseArtifactIndexValue,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistParseArtifactHydrationError> {
        let payload = {
            let (_files_advisory_guard, _files_guard) = self
                .lock_blob_pack_read(PersistBlobStore::Files)
                .map_err(|source| PersistParseArtifactHydrationError::Read { source })?;
            self.read_parse_artifact_unlocked(index_value)
                .map_err(|source| PersistParseArtifactHydrationError::Read { source })?
        };
        self.hydrate_parse_artifact_payload(&payload, entry)
    }

    fn hydrate_parse_artifact_bundle_mapped_unlocked(
        &self,
        index_value: PersistParseArtifactIndexValue,
        entry: &ParseCacheEntry,
        files_read_lease: &AdvisoryFileLock,
    ) -> Result<(), PersistParseArtifactHydrationError> {
        let blob_key = index_value.blob_key();
        let bundle = self
            .blob_pack(blob_key.store())
            .with_mapped_blob(
                files_read_lease,
                index_value.location(),
                blob_key.hash(),
                ParseArtifactBundle::decode,
            )
            .map_err(|source| PersistParseArtifactHydrationError::Read { source })?;
        let bundle =
            bundle.map_err(|source| PersistParseArtifactHydrationError::Decode { source })?;
        self.hydrate_parse_artifact_bundle_decoded(&bundle, entry)
    }

    fn hydrate_parse_artifact_payload(
        &self,
        payload: &[u8],
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistParseArtifactHydrationError> {
        let bundle = ParseArtifactBundle::decode(&payload)
            .map_err(|source| PersistParseArtifactHydrationError::Decode { source })?;
        self.hydrate_parse_artifact_bundle_decoded(&bundle, entry)
    }

    fn hydrate_parse_artifact_bundle_decoded(
        &self,
        bundle: &ParseArtifactBundle,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistParseArtifactHydrationError> {
        bundle
            .validate_meta(PARSE_CACHE_SCHEMA_VERSION)
            .map_err(|source| PersistParseArtifactHydrationError::Validate { source })?;
        entry
            .write_artifact_bundle(&bundle)
            .map_err(|source| PersistParseArtifactHydrationError::Write { source })
    }

    /// Reads a keyed parse-artifact bundle into a parse-cache entry.
    ///
    /// The supplied `artifact_key` must match the key derived from `parse_key`
    /// before the `files/` pack is read. This adapter still relies on its
    /// caller to perform the durable index lookup.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactHydrationError`] if `artifact_key` does not
    /// match `parse_key`, if the artifact cannot be read from the `files/` pack,
    /// if the payload is not a valid [`ParseArtifactBundle`], if the bundle
    /// metadata/artifact counts do not validate, or if the target entry cannot
    /// be written.
    pub fn hydrate_parse_artifact_bundle_for_key(
        &self,
        parse_key: ParseCacheKey,
        artifact_key: PersistParseArtifactKey,
        index_value: PersistParseArtifactIndexValue,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistParseArtifactHydrationError> {
        let expected = PersistParseArtifactKey::from_parse_cache_key(parse_key);
        if artifact_key != expected {
            return Err(PersistParseArtifactHydrationError::KeyMismatch {
                expected,
                actual: artifact_key,
            });
        }
        self.hydrate_parse_artifact_bundle(index_value, entry)
    }

    /// Reads an indexed parse-artifact bundle into a parse-cache entry.
    ///
    /// This is the entry-shaped variant of
    /// [`Self::hydrate_parse_artifact_bundle_for_key`]. It still relies on its
    /// caller to perform the durable index lookup that produced `index_entry`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactHydrationError`] if `index_entry.key()`
    /// does not match `parse_key`, if the artifact cannot be read from the
    /// `files/` pack, if the payload is not a valid [`ParseArtifactBundle`], if
    /// the bundle metadata/artifact counts do not validate, or if the target
    /// entry cannot be written.
    pub fn hydrate_parse_artifact_bundle_from_entry(
        &self,
        parse_key: ParseCacheKey,
        index_entry: PersistParseArtifactIndexEntry,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistParseArtifactHydrationError> {
        self.hydrate_parse_artifact_bundle_for_key(
            parse_key,
            index_entry.key(),
            index_entry.value(),
            entry,
        )
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
        let payload = {
            let (_files_advisory_guard, _files_guard) = self
                .lock_blob_pack_read(PersistBlobStore::Files)
                .map_err(|source| PersistFileArtifactHydrationError::Read { source })?;
            self.read_file_artifact_unlocked(index_value)
                .map_err(|source| PersistFileArtifactHydrationError::Read { source })?
        };
        self.hydrate_file_artifact_payload(&payload, entry)
    }

    fn hydrate_file_artifact_bundle_mapped_unlocked(
        &self,
        index_value: PersistFileArtifactIndexValue,
        entry: &ParseCacheEntry,
        files_read_lease: &AdvisoryFileLock,
    ) -> Result<(), PersistFileArtifactHydrationError> {
        let blob_key = index_value.blob_key();
        let bundle = self
            .blob_pack(blob_key.store())
            .with_mapped_blob(
                files_read_lease,
                index_value.location(),
                blob_key.hash(),
                ParseArtifactBundle::decode,
            )
            .map_err(|source| PersistFileArtifactHydrationError::Read { source })?;
        let bundle =
            bundle.map_err(|source| PersistFileArtifactHydrationError::Decode { source })?;
        self.hydrate_file_artifact_bundle_decoded(&bundle, entry)
    }

    fn hydrate_file_artifact_payload(
        &self,
        payload: &[u8],
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistFileArtifactHydrationError> {
        let bundle = ParseArtifactBundle::decode(&payload)
            .map_err(|source| PersistFileArtifactHydrationError::Decode { source })?;
        self.hydrate_file_artifact_bundle_decoded(&bundle, entry)
    }

    fn hydrate_file_artifact_bundle_decoded(
        &self,
        bundle: &ParseArtifactBundle,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistFileArtifactHydrationError> {
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

    /// Looks up and hydrates an indexed file-artifact bundle.
    ///
    /// This is the cache-level hit adapter for the explicit file-artifact
    /// sidecar index. It derives the expected mapping key from `file_key` and
    /// `parse_key`, returns `Ok(None)` when the index has no matching entry,
    /// and otherwise validates and writes the indexed bundle into `entry`. The
    /// selected store and file-artifact advisory locks plus same-root file
    /// store and file-artifact locks are held across lookup and pack read so
    /// cooperating writers and same-process repacks cannot expose a split
    /// sidecar/pack view.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexedHydrationError`] if the
    /// advisory lock cannot be acquired for the `files/` store or
    /// file-artifact mapping, if the file-artifact index cannot be read, or if
    /// a matching indexed artifact cannot be read from the `files/` pack,
    /// decoded, validated, or written into `entry`.
    pub fn hydrate_file_artifact_bundle_from_index(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
    ) -> Result<Option<PersistFileArtifactIndexEntry>, PersistFileArtifactIndexedHydrationError>
    {
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(file_key, parse_key);
        let (
            files_advisory_guard,
            _file_artifact_advisory_guard,
            _file_guard,
            _file_artifact_guard,
        ) = self.lock_file_artifact_hydration_read()?;
        let Some(index_value) = self
            .file_artifact_index
            .lookup(artifact_key)
            .map_err(|source| PersistFileArtifactIndexedHydrationError::Lookup { source })?
        else {
            return Ok(None);
        };
        let index_entry = PersistFileArtifactIndexEntry::new(artifact_key, index_value);
        self.hydrate_file_artifact_bundle_mapped_unlocked(
            index_value,
            entry,
            &files_advisory_guard,
        )
        .map_err(|source| PersistFileArtifactIndexedHydrationError::Hydrate { source })?;
        Ok(Some(index_entry))
    }

    /// Looks up and hydrates an indexed parse-artifact bundle.
    ///
    /// This is the cache-level hit adapter for the parse-artifact sidecar
    /// index. It derives the expected mapping key from `parse_key`, returns
    /// `Ok(None)` when the index has no matching entry, and otherwise validates
    /// and writes the indexed bundle into `entry`. The selected store and
    /// parse-artifact advisory locks plus same-root file store and
    /// parse-artifact locks are held across lookup and pack read so cooperating
    /// writers and same-process repacks cannot expose a split sidecar/pack
    /// view.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexedHydrationError`] if the
    /// advisory lock cannot be acquired for the `files/` store or
    /// parse-artifact mapping, if the parse-artifact index cannot be read, or
    /// if a matching indexed artifact cannot be read from the `files/` pack,
    /// decoded, validated, or written into `entry`.
    pub fn hydrate_parse_artifact_bundle_from_index(
        &self,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
    ) -> Result<Option<PersistParseArtifactIndexEntry>, PersistParseArtifactIndexedHydrationError>
    {
        let artifact_key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
        let (
            files_advisory_guard,
            _parse_artifact_advisory_guard,
            _file_guard,
            _parse_artifact_guard,
        ) = self.lock_parse_artifact_hydration_read()?;
        let Some(index_value) = self
            .parse_artifact_index
            .lookup(artifact_key)
            .map_err(|source| PersistParseArtifactIndexedHydrationError::Lookup { source })?
        else {
            return Ok(None);
        };
        let index_entry = PersistParseArtifactIndexEntry::new(artifact_key, index_value);
        self.hydrate_parse_artifact_bundle_mapped_unlocked(
            index_value,
            entry,
            &files_advisory_guard,
        )
        .map_err(|source| PersistParseArtifactIndexedHydrationError::Hydrate { source })?;
        Ok(Some(index_entry))
    }

    /// Derives parse identity from source bytes and hydrates the parse cache.
    ///
    /// This source-shaped adapter derives `ParseCacheKey` through
    /// `parse_cache` and hydrates the parse cache's normal entry directory when
    /// the persistent parse-artifact index has a matching bundle. Missing index
    /// entries return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexedHydrationError`] if the
    /// parse-artifact index cannot be read, or if a matching indexed artifact
    /// cannot be read from the `files/` pack, decoded, validated, or written
    /// into the parse cache entry.
    pub fn hydrate_parse_cache_entry_from_parse_index(
        &self,
        parse_cache: &ParseCache,
        source: &[u8],
    ) -> Result<Option<PersistParseArtifactIndexEntry>, PersistParseArtifactIndexedHydrationError>
    {
        let parse_key = parse_cache.key_for_source(source);
        let entry = parse_cache.entry_for_key(parse_key);
        self.hydrate_parse_artifact_bundle_from_index(parse_key, &entry)
    }

    /// Loads an indexed parse-cache hit for caller-supplied source bytes.
    ///
    /// This is a source-shaped load adapter over
    /// [`Self::hydrate_parse_cache_entry_from_parse_index`] and
    /// [`ParseCache::load_cached_bytes`]. It derives identity from `source`
    /// bytes alone, hydrates the normal parse-cache entry from the persistent
    /// parse-artifact index, and returns the hydrated entry as a
    /// [`CachedParse`] hit. Missing parse-artifact index entries return
    /// `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseBytesIndexedLoadError`] if the parse-artifact
    /// index cannot be read, a matching indexed artifact cannot be hydrated, or
    /// the hydrated parse-cache entry cannot be read back as a [`CachedParse`].
    pub fn load_parse_cache_bytes_from_index(
        &self,
        parse_cache: &ParseCache,
        source: &[u8],
    ) -> Result<Option<CachedParse>, PersistParseBytesIndexedLoadError> {
        if self
            .hydrate_parse_cache_entry_from_parse_index(parse_cache, source)
            .map_err(|source| PersistParseBytesIndexedLoadError::Hydrate { source })?
            .is_none()
        {
            return Ok(None);
        }
        parse_cache
            .load_cached_bytes(source)
            .map_err(|source| PersistParseBytesIndexedLoadError::Load { source })
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

    /// Loads an indexed parse-cache hit for caller-supplied source bytes.
    ///
    /// This is a source-shaped load adapter over
    /// [`Self::hydrate_parse_cache_entry_from_source_index`] and
    /// [`ParseCache::load_cached_bytes`]. It derives both identities from the
    /// same canonical `realpath` and `source` bytes, hydrates the normal
    /// parse-cache entry from the persistent file-artifact index, and returns
    /// the hydrated entry as a [`CachedParse`] hit. Missing file-artifact index
    /// entries return `Ok(None)`.
    ///
    /// `realpath` must already be the canonical path used for file-artifact
    /// identity; this helper does not canonicalize or read source files.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseSourceIndexedLoadError`] if the file-artifact index
    /// cannot be read, a matching indexed artifact cannot be hydrated, or the
    /// hydrated parse-cache entry cannot be read back as a [`CachedParse`].
    pub fn load_parse_cache_source_from_index(
        &self,
        parse_cache: &ParseCache,
        realpath: impl AsRef<Path>,
        source: &[u8],
    ) -> Result<Option<CachedParse>, PersistParseSourceIndexedLoadError> {
        if self
            .hydrate_parse_cache_entry_from_source_index(parse_cache, realpath, source)
            .map_err(|source| PersistParseSourceIndexedLoadError::Hydrate { source })?
            .is_none()
        {
            return Ok(None);
        }
        parse_cache
            .load_cached_bytes(source)
            .map_err(|source| PersistParseSourceIndexedLoadError::Load { source })
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
}
