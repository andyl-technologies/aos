//! Indexed blob, cached-expression value, and node-linked value operations.
//!
//! # Decode verification knob
//!
//! Indexed value blobs are content-addressed and the blob pack verifies its
//! per-record integrity header on every read. Decoding a value therefore trusts
//! the content address by default and does not recompute the decoded payload's
//! [`ValueHash`]. Setting [`PersistCache::with_value_decode_verification`] (wired
//! to the `AOS_NIX_CACHE_VERIFY` environment knob) restores the fully defensive
//! path that re-hashes every decoded payload and rejects any mismatch.
//!
//! # Trace-hit verification
//!
//! Trace-verified node hits are established without decoding dependency values.
//! Only the top-level request decodes its own value; each memo-read dependency
//! is verified from its metadata value hash, trace record, input revalidation,
//! and an O(1) value-blob existence probe. Dependencies proven valid this run
//! are memoized on the handle's run-scoped verified-node table so a shared
//! dependency is verified once per run rather than once per dependent.

use super::*;
use std::collections::BTreeSet;

/// A trace-verified node-linked cached expression payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PersistCachedExpressionNodeValueTraceHit {
    value: CachedExpressionValue,
    memo_read_dependencies: Vec<PersistNodeMetadataKey>,
}

impl PersistCachedExpressionNodeValueTraceHit {
    fn new(
        value: CachedExpressionValue,
        memo_read_dependencies: Vec<PersistNodeMetadataKey>,
    ) -> Self {
        Self {
            value,
            memo_read_dependencies,
        }
    }

    /// Returns the sorted durable memo-read dependency keys recorded with the trace.
    pub(crate) fn memo_read_dependencies(&self) -> &[PersistNodeMetadataKey] {
        &self.memo_read_dependencies
    }

    /// Consumes this hit into its cached expression payload.
    pub(crate) fn into_value(self) -> CachedExpressionValue {
        self.value
    }
}

/// A trace-verified node identity produced during hit verification.
///
/// Dependency checks carry only the verified value hash; the top-level request
/// additionally carries the sorted memo-read dependency keys the caller records
/// with the decoded hit.
struct PersistVerifiedNodeTrace {
    value_hash: ValueHash,
    memo_read_dependencies: Vec<PersistNodeMetadataKey>,
}

impl PersistVerifiedNodeTrace {
    /// Builds a verified dependency identity with no dependency list.
    fn dependency(value_hash: ValueHash) -> Self {
        Self {
            value_hash,
            memo_read_dependencies: Vec::new(),
        }
    }

    /// Builds a verified top-level identity carrying its memo-read dependencies.
    fn top_level(
        value_hash: ValueHash,
        memo_read_dependencies: Vec<PersistNodeMetadataKey>,
    ) -> Self {
        Self {
            value_hash,
            memo_read_dependencies,
        }
    }
}

impl PersistCache {
    /// Appends a blob and records its location in the sidecar index.
    ///
    /// This helper is explicit and non-transactional: if the pack append
    /// succeeds but the sidecar index write fails, the blob bytes remain in the
    /// pack without a corresponding durable index record. Same-process writers
    /// opened on the same cache root share the selected store's blob-store write
    /// lock while this method writes the pack and sidecar; cooperating
    /// cross-process writers share the selected store's advisory lock file.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexedWriteError`] if the selected advisory lock
    /// cannot be acquired, the same-root blob-store write lock is poisoned, if
    /// the selected packfile cannot append/verify the payload, or if the
    /// selected sidecar index cannot write the resulting hash-to-offset record.
    pub fn append_blob_indexed(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
    ) -> Result<PersistBlobIndexEntry, PersistBlobIndexedWriteError> {
        let (_advisory_guard, _write_guard) = self.lock_indexed_blob_write(key.store())?;
        self.append_blob_indexed_unlocked(key, payload)
    }

    fn append_blob_indexed_unlocked(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
    ) -> Result<PersistBlobIndexEntry, PersistBlobIndexedWriteError> {
        let location = self
            .append_blob_unlocked(key, payload)
            .map_err(|source| PersistBlobIndexedWriteError::Append { source })?;
        let entry = PersistBlobIndexEntry::new(key, location);
        self.blob_index(key.store())
            .append_entry(entry)
            .map_err(|source| PersistBlobIndexedWriteError::Index { source })?;
        Ok(entry)
    }

    /// Reads a blob through the sidecar index selected by `key`.
    ///
    /// Missing index entries return `Ok(None)`. Same-root writers opened on
    /// the same cache root and cooperating cross-process writers share the
    /// selected store lock while this method reads the sidecar index and then
    /// maps, verifies, and clones the referenced pack record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexedReadError`] if the selected advisory lock
    /// cannot be acquired, the same-root store lock is poisoned, if the
    /// selected index cannot be read/decoded, or if the indexed pack location
    /// cannot be read and verified.
    pub fn read_blob_indexed(
        &self,
        key: PersistBlobKey,
    ) -> Result<Option<Vec<u8>>, PersistBlobIndexedReadError> {
        let Some(payload) = self.with_blob_indexed(key, clone_mapped_blob_payload)? else {
            return Ok(None);
        };
        payload
            .map(Some)
            .map_err(|source| PersistBlobIndexedReadError::Read { source })
    }

    /// Visits a blob through the sidecar index selected by `key`.
    ///
    /// Missing index entries return `Ok(None)`. Present entries are mapped and
    /// verified while the selected store's advisory read lock and same-root read
    /// lock are held. The callback receives borrowed packfile bytes that cannot
    /// escape this method. Callbacks must not re-enter cache operations that
    /// need the same store lock, because those operations wait for this method
    /// to return.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexedReadError`] if the selected advisory lock
    /// cannot be acquired, the same-root store lock is poisoned, if the selected
    /// index cannot be read/decoded, or if the indexed pack location cannot be
    /// mapped and verified.
    ///
    /// # Panics
    ///
    /// Panics if `visit` panics on an indexed hit. A panic may poison the
    /// same-root read lock that is held while the callback runs.
    pub fn with_blob_indexed<R>(
        &self,
        key: PersistBlobKey,
        visit: impl FnOnce(&[u8]) -> R,
    ) -> Result<Option<R>, PersistBlobIndexedReadError> {
        self.read_blob_indexed_mapped_with(key, visit)
    }

    fn read_blob_indexed_mapped_with<R>(
        &self,
        key: PersistBlobKey,
        visit: impl FnOnce(&[u8]) -> R,
    ) -> Result<Option<R>, PersistBlobIndexedReadError> {
        let (advisory_guard, _read_guard) = self.lock_indexed_blob_read(key.store())?;
        let Some(location) = self
            .lookup_blob_location(key)
            .map_err(|source| PersistBlobIndexedReadError::Lookup { source })?
        else {
            return Ok(None);
        };
        self.blob_pack(key.store())
            .with_mapped_blob(&advisory_guard, location, key.hash(), visit)
            .map(Some)
            .map_err(|source| PersistBlobIndexedReadError::Read { source })
    }

    /// Ensures a blob is present in the selected pack and sidecar index.
    ///
    /// If the sidecar index can be read and already points at a pack record
    /// that verifies for `key` and exactly matches `payload`, the existing
    /// location is reused without appending duplicate bytes or index records.
    /// Missing, stale, mismatching, or unreadable indexed records append a fresh
    /// blob and record a newer sidecar entry while holding the selected store's
    /// advisory and same-root write locks.
    ///
    /// This helper is explicit and non-transactional: if a fresh pack append
    /// succeeds but the sidecar index write fails, the blob bytes remain in the
    /// pack without a corresponding durable index record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexedWriteError`] if the selected advisory lock
    /// cannot be acquired, the selected in-process materialization lock is
    /// poisoned, if the selected packfile cannot append or verify a fresh
    /// payload, or if the selected sidecar index cannot write a fresh
    /// hash-to-offset record. A lookup failure falls back to the append path so
    /// this helper preserves append-first failure semantics.
    pub fn ensure_blob_indexed(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
    ) -> Result<PersistBlobIndexEntry, PersistBlobIndexedWriteError> {
        let (_advisory_guard, _write_guard) = self.lock_indexed_blob_write(key.store())?;
        if let Ok(Some(location)) = self.lookup_blob_location(key) {
            let pack = self.blob_pack(key.store());
            if matches!(
                pack.payload_matches(location, key.hash(), payload),
                Ok(true)
            ) {
                return Ok(PersistBlobIndexEntry::new(key, location));
            }
        }
        self.append_blob_indexed_unlocked(key, payload)
    }

    /// Materializes a cached expression payload into the indexed `values/` pack.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns
    /// [`PersistMaterialization::Skipped`] without hashing, encoding, or
    /// writing `value`. [`MaterializationDecision::Materialize`] encodes the
    /// payload as canonical value-store bytes, uses the payload's
    /// [`ValueHash`] as the `values/` content address, and records the pack
    /// location in the sidecar blob index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionValueIndexedWriteError`] when
    /// materialization is requested and the payload cannot be hashed, encoded,
    /// appended, or indexed.
    pub fn materialize_cached_expression_value_indexed(
        &self,
        value: &CachedExpressionValue,
        decision: MaterializationDecision,
    ) -> Result<PersistMaterialization, PersistCachedExpressionValueIndexedWriteError> {
        let MaterializationDecision::Materialize = decision else {
            return Ok(PersistMaterialization::Skipped);
        };
        let value_hash = value
            .value_hash()
            .map_err(|source| PersistCachedExpressionValueIndexedWriteError::Hash { source })?;
        let payload = value
            .encode_persistent_payload()
            .map_err(|source| PersistCachedExpressionValueIndexedWriteError::Encode { source })?;
        let key = PersistBlobKey::for_value(value_hash);
        self.materialize_blob_indexed(key, &payload, MaterializationDecision::Materialize)
            .map_err(|source| PersistCachedExpressionValueIndexedWriteError::Write { source })
    }

    /// Applies materialization threshold signals to a cached expression payload.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through
    /// [`Self::materialize_cached_expression_value_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionValueIndexedWriteError`] when the
    /// signals choose materialization and the payload cannot be hashed,
    /// encoded, appended, or indexed.
    pub fn materialize_cached_expression_value_indexed_with_signals(
        &self,
        value: &CachedExpressionValue,
        signals: MaterializationSignals,
    ) -> Result<PersistMaterialization, PersistCachedExpressionValueIndexedWriteError> {
        self.materialize_cached_expression_value_indexed(value, signals.decide())
    }

    /// Loads a cached expression payload from the indexed `values/` pack.
    ///
    /// Missing index entries return `Ok(None)`. Present entries are read by
    /// `value_hash`, verified by the blob pack, and decoded as a cached
    /// expression payload. When decode verification is enabled the decoded value
    /// is hashed again and must match `value_hash` before being returned;
    /// otherwise the content-addressed pack read is trusted and the re-hash is
    /// skipped (see [`PersistCache::with_value_decode_verification`]).
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionValueIndexedLoadError`] if the sidecar
    /// index cannot be read, the indexed blob cannot be verified, the bytes
    /// are not a supported cached-expression payload, or (when verification is
    /// enabled) the decoded payload's value hash does not match `value_hash`.
    pub fn load_cached_expression_value_indexed(
        &self,
        value_hash: ValueHash,
    ) -> Result<Option<CachedExpressionValue>, PersistCachedExpressionValueIndexedLoadError> {
        self.decode_cached_expression_value_indexed(value_hash)
    }

    /// Visits a cached expression payload from the indexed `values/` pack.
    ///
    /// Missing index entries return `Ok(None)`. Present entries are mapped,
    /// verified, decoded, and (when decode verification is enabled) rehashed
    /// before the callback receives a reference to the decoded owned value. The
    /// callback runs after the mapped payload and value-store locks have been
    /// released.
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionValueIndexedLoadError`] if the sidecar
    /// index cannot be read, the indexed blob cannot be verified, the bytes are
    /// not a supported cached-expression payload, or the decoded payload's value
    /// hash does not match `value_hash`.
    ///
    /// # Panics
    ///
    /// Panics if `visit` panics on an indexed hit.
    pub fn with_cached_expression_value_indexed<R>(
        &self,
        value_hash: ValueHash,
        visit: impl FnOnce(&CachedExpressionValue) -> R,
    ) -> Result<Option<R>, PersistCachedExpressionValueIndexedLoadError> {
        let Some(value) = self.decode_cached_expression_value_indexed(value_hash)? else {
            return Ok(None);
        };
        Ok(Some(visit(&value)))
    }

    fn decode_cached_expression_value_indexed(
        &self,
        value_hash: ValueHash,
    ) -> Result<Option<CachedExpressionValue>, PersistCachedExpressionValueIndexedLoadError> {
        let key = PersistBlobKey::for_value(value_hash);
        let verify = self.value_decode_verification();
        let Some(value) = self
            .read_blob_indexed_mapped_with(key, |payload| {
                let value = CachedExpressionValue::decode_persistent_payload(payload).map_err(
                    |source| PersistCachedExpressionValueIndexedLoadError::Decode { source },
                )?;
                // The blob pack is content-addressed and verifies its integrity
                // header on read, so the structural re-hash is skipped unless the
                // `AOS_NIX_CACHE_VERIFY` knob asks for the fully defensive path.
                if verify {
                    let actual = value.value_hash().map_err(|source| {
                        PersistCachedExpressionValueIndexedLoadError::Hash { source }
                    })?;
                    if actual != value_hash {
                        return Err(
                            PersistCachedExpressionValueIndexedLoadError::ValueHashMismatch {
                                expected: value_hash,
                                actual,
                            },
                        );
                    }
                }
                Ok(value)
            })
            .map_err(|source| PersistCachedExpressionValueIndexedLoadError::Read { source })?
        else {
            return Ok(None);
        };
        value.map(Some)
    }

    /// Materializes a cached expression payload and links it from node metadata.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns
    /// [`PersistMaterialization::Skipped`] without hashing, encoding, writing,
    /// or updating node metadata. [`MaterializationDecision::Materialize`]
    /// writes the payload through the indexed `values/` pack and then records
    /// the resulting [`ValueHash`] in the demand-node metadata sidecar while
    /// preserving existing reuse counters for `node_key`.
    ///
    /// This helper is explicit and non-transactional: if the value-pack write
    /// succeeds but the node metadata write fails, the indexed value remains
    /// addressable by value hash but is not linked from `node_key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionNodeValueIndexedWriteError`] when
    /// materialization is requested and the payload cannot be hashed, encoded,
    /// indexed, or linked from node metadata.
    pub fn materialize_cached_expression_node_value_indexed(
        &self,
        node_key: PersistNodeMetadataKey,
        value: &CachedExpressionValue,
        decision: MaterializationDecision,
    ) -> Result<PersistMaterialization, PersistCachedExpressionNodeValueIndexedWriteError> {
        let MaterializationDecision::Materialize = decision else {
            return Ok(PersistMaterialization::Skipped);
        };
        let value_hash = value
            .value_hash()
            .map_err(|source| PersistCachedExpressionNodeValueIndexedWriteError::Hash { source })?;
        let payload = value.encode_persistent_payload().map_err(|source| {
            PersistCachedExpressionNodeValueIndexedWriteError::Encode { source }
        })?;
        let blob_key = PersistBlobKey::for_value(value_hash);
        let materialization = self
            .materialize_blob_indexed(blob_key, &payload, MaterializationDecision::Materialize)
            .map_err(
                |source| PersistCachedExpressionNodeValueIndexedWriteError::Write { source },
            )?;
        self.record_node_materialized_value_hash(node_key, value_hash)
            .map_err(
                |source| PersistCachedExpressionNodeValueIndexedWriteError::Metadata { source },
            )?;
        Ok(materialization)
    }

    /// Applies materialization threshold signals to a node-linked payload write.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through
    /// [`Self::materialize_cached_expression_node_value_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionNodeValueIndexedWriteError`] when the
    /// signals choose materialization and the payload cannot be hashed,
    /// encoded, indexed, or linked from node metadata.
    pub fn materialize_cached_expression_node_value_indexed_with_signals(
        &self,
        node_key: PersistNodeMetadataKey,
        value: &CachedExpressionValue,
        signals: MaterializationSignals,
    ) -> Result<PersistMaterialization, PersistCachedExpressionNodeValueIndexedWriteError> {
        self.materialize_cached_expression_node_value_indexed(node_key, value, signals.decide())
    }

    /// Loads a cached expression payload through one demand-node metadata key.
    ///
    /// Missing node metadata, metadata without a materialized value hash, and
    /// missing indexed value blobs all return `Ok(None)`. Present value blobs
    /// are decoded and rehashed by [`Self::load_cached_expression_value_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionNodeValueIndexedLoadError`] if node
    /// metadata cannot be read or the linked value payload cannot be loaded.
    pub fn load_cached_expression_node_value_indexed(
        &self,
        node_key: PersistNodeMetadataKey,
    ) -> Result<Option<CachedExpressionValue>, PersistCachedExpressionNodeValueIndexedLoadError>
    {
        let Some(value_hash) =
            self.lookup_node_materialized_value_hash(node_key)
                .map_err(
                    |source| PersistCachedExpressionNodeValueIndexedLoadError::Metadata { source },
                )?
        else {
            return Ok(None);
        };
        self.load_cached_expression_value_indexed(value_hash)
            .map_err(|source| PersistCachedExpressionNodeValueIndexedLoadError::Value { source })
    }

    /// Visits a cached expression payload through one demand-node metadata key.
    ///
    /// Missing node metadata, metadata without a materialized value hash, and
    /// missing indexed value blobs all return `Ok(None)`. Present value blobs
    /// are mapped, decoded, and rehashed by
    /// [`Self::with_cached_expression_value_indexed`]. The callback receives a
    /// reference to the decoded owned value after node-metadata lookup, mapped
    /// value payload access, and value-store locks have completed.
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionNodeValueIndexedLoadError`] if node
    /// metadata cannot be read or the linked value payload cannot be loaded.
    ///
    /// # Panics
    ///
    /// Panics if `visit` panics on a node-linked hit.
    pub fn with_cached_expression_node_value_indexed<R>(
        &self,
        node_key: PersistNodeMetadataKey,
        visit: impl FnOnce(&CachedExpressionValue) -> R,
    ) -> Result<Option<R>, PersistCachedExpressionNodeValueIndexedLoadError> {
        let Some(value_hash) =
            self.lookup_node_materialized_value_hash(node_key)
                .map_err(
                    |source| PersistCachedExpressionNodeValueIndexedLoadError::Metadata { source },
                )?
        else {
            return Ok(None);
        };
        self.with_cached_expression_value_indexed(value_hash, visit)
            .map_err(|source| PersistCachedExpressionNodeValueIndexedLoadError::Value { source })
    }

    /// Loads a node-linked payload after value-associated trace revalidation.
    ///
    /// This helper is for trace-backed durable hit selection. Missing node
    /// metadata, missing trace records, trace records whose associated
    /// [`ValueHash`] differs from the current node metadata link, tombstone
    /// trace records, stale input observations, and missing indexed value blobs
    /// all return `Ok(None)`. The revalidator is called only after the node
    /// metadata value hash and trace-record value hash match.
    ///
    /// This does not insert the value into the in-memory demand graph or choose
    /// evaluator hits; it only proves that the persistent node metadata, trace,
    /// and value payload agree at this cache boundary.
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionNodeValueTraceLoadError`] if node
    /// metadata, the trace log, or the linked value payload cannot be read.
    pub fn load_cached_expression_node_value_with_trace_revalidation<R>(
        &self,
        node_key: PersistNodeMetadataKey,
        revalidator: &mut R,
    ) -> Result<Option<CachedExpressionValue>, PersistCachedExpressionNodeValueTraceLoadError>
    where
        R: ImpureInputRevalidator + ?Sized,
    {
        Ok(self
            .load_cached_expression_node_value_trace_hit_with_revalidation(node_key, revalidator)?
            .map(PersistCachedExpressionNodeValueTraceHit::into_value))
    }

    /// Visits a node-linked payload after value-associated trace revalidation.
    ///
    /// This is the callback-shaped counterpart to
    /// [`Self::load_cached_expression_node_value_with_trace_revalidation`].
    /// Missing node metadata, missing or stale trace records, tombstone trace
    /// records, stale input observations, dependency mismatches, and missing
    /// indexed value blobs all return `Ok(None)`. The callback receives a
    /// reference to the decoded owned value plus the sorted durable memo-read
    /// dependency keys after node metadata, node-trace, and mapped value payload
    /// reads have completed for the selected node and its memo-read
    /// dependencies.
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionNodeValueTraceLoadError`] if node
    /// metadata, the trace log, or the linked value payload cannot be read.
    ///
    /// # Panics
    ///
    /// Panics if `revalidator` panics while revalidating persisted inputs, or if
    /// `visit` panics on a trace-verified hit.
    pub fn with_cached_expression_node_value_with_trace_revalidation<Revalidator, Output>(
        &self,
        node_key: PersistNodeMetadataKey,
        revalidator: &mut Revalidator,
        visit: impl FnOnce(&CachedExpressionValue, &[PersistNodeMetadataKey]) -> Output,
    ) -> Result<Option<Output>, PersistCachedExpressionNodeValueTraceLoadError>
    where
        Revalidator: ImpureInputRevalidator + ?Sized,
    {
        let Some(hit) = self
            .load_cached_expression_node_value_trace_hit_with_revalidation(node_key, revalidator)?
        else {
            return Ok(None);
        };
        Ok(Some(visit(&hit.value, hit.memo_read_dependencies())))
    }

    pub(crate) fn load_cached_expression_node_value_trace_hit_with_revalidation<R>(
        &self,
        node_key: PersistNodeMetadataKey,
        revalidator: &mut R,
    ) -> Result<
        Option<PersistCachedExpressionNodeValueTraceHit>,
        PersistCachedExpressionNodeValueTraceLoadError,
    >
    where
        R: ImpureInputRevalidator + ?Sized,
    {
        let mut active = BTreeSet::new();
        let Some(verified) = self.verify_cached_expression_node_trace_active(
            node_key,
            None,
            revalidator,
            &mut active,
        )?
        else {
            return Ok(None);
        };
        // The top-level request always needs its decoded value; a missing value
        // blob is an ordinary miss, matching the pre-verification behavior.
        let Some(value) = self
            .load_cached_expression_value_indexed(verified.value_hash)
            .map_err(|source| PersistCachedExpressionNodeValueTraceLoadError::Value { source })?
        else {
            return Ok(None);
        };
        // A decoded top-level value proves the node and its subtree are a valid
        // hit this run, so record it for reuse by later dependents.
        self.remember_verified_node_trace(node_key, verified.value_hash);
        Ok(Some(PersistCachedExpressionNodeValueTraceHit::new(
            value,
            verified.memo_read_dependencies,
        )))
    }

    /// Verifies a node's trace-backed hit without decoding dependency values.
    ///
    /// The top-level request (`expected_value_hash` is `None`) returns the
    /// node's value hash together with its sorted memo-read dependency keys so
    /// the caller can decode the value. Dependency checks (`expected_value_hash`
    /// is `Some`) return only the verified value hash and an empty dependency
    /// list: they establish validity from the O(1) metadata, trace,
    /// input-revalidation, and blob-existence checks alone and never decode the
    /// dependency's value. A dependency whose other checks pass but whose value
    /// blob is absent misses exactly as the previous decode-based path did.
    ///
    /// Successful dependency verifications are recorded in the run-scoped
    /// verified-node memo so a dependency shared by many dependents is verified
    /// once per run instead of once per dependent.
    fn verify_cached_expression_node_trace_active<R>(
        &self,
        node_key: PersistNodeMetadataKey,
        expected_value_hash: Option<ValueHash>,
        revalidator: &mut R,
        active: &mut BTreeSet<PersistNodeMetadataKey>,
    ) -> Result<Option<PersistVerifiedNodeTrace>, PersistCachedExpressionNodeValueTraceLoadError>
    where
        R: ImpureInputRevalidator + ?Sized,
    {
        if let Some(expected) = expected_value_hash {
            if self.verified_node_trace_is_cached(node_key, expected) {
                return Ok(Some(PersistVerifiedNodeTrace::dependency(expected)));
            }
        }
        if !active.insert(node_key) {
            return Ok(None);
        }
        let result = (|| {
            let Some(value_hash) = self
                .lookup_node_materialized_value_hash(node_key)
                .map_err(|source| {
                    PersistCachedExpressionNodeValueTraceLoadError::Metadata { source }
                })?
            else {
                return Ok(None);
            };
            if expected_value_hash.is_some_and(|expected| expected != value_hash) {
                return Ok(None);
            }
            let Some(trace) = self.lookup_node_trace(node_key).map_err(|source| {
                PersistCachedExpressionNodeValueTraceLoadError::Trace { source }
            })?
            else {
                return Ok(None);
            };
            if trace.value_hash() != value_hash {
                return Ok(None);
            }
            if trace.payload().is_tombstone() {
                return Ok(None);
            }
            if !revalidate_persist_node_trace_payload(trace.payload(), revalidator) {
                return Ok(None);
            }
            for (dependency, dependency_value_hash) in
                trace.payload().memo_read_dependency_records()
            {
                if active.contains(&dependency) {
                    return Ok(None);
                }
                let Some(dependency_value_hash) = dependency_value_hash else {
                    return Ok(None);
                };
                if self
                    .verify_cached_expression_node_trace_active(
                        dependency,
                        Some(dependency_value_hash),
                        revalidator,
                        active,
                    )?
                    .is_none()
                {
                    return Ok(None);
                }
            }
            if expected_value_hash.is_some() {
                // Dependency check: prove the value blob exists without decoding
                // it. An absent blob is the same miss the decode path produced.
                if !self.value_blob_is_present(value_hash)? {
                    return Ok(None);
                }
                return Ok(Some(PersistVerifiedNodeTrace::dependency(value_hash)));
            }
            let dependencies = trace.payload().memo_read_dependencies().to_vec();
            Ok(Some(PersistVerifiedNodeTrace::top_level(
                value_hash,
                dependencies,
            )))
        })();
        active.remove(&node_key);
        if expected_value_hash.is_some() {
            if let Ok(Some(verified)) = &result {
                self.remember_verified_node_trace(node_key, verified.value_hash);
            }
        }
        result
    }

    /// Returns whether an indexed value blob exists for `value_hash`.
    ///
    /// This is an O(1) sidecar-index existence probe used to accept dependency
    /// trace hits without decoding the dependency's value. A missing index entry
    /// reports `Ok(false)` (an ordinary miss); an index read failure propagates.
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionNodeValueTraceLoadError::Value`] if the
    /// value blob index cannot be read or decoded.
    fn value_blob_is_present(
        &self,
        value_hash: ValueHash,
    ) -> Result<bool, PersistCachedExpressionNodeValueTraceLoadError> {
        let key = PersistBlobKey::for_value(value_hash);
        self.lookup_blob_location(key)
            .map(|location| location.is_some())
            .map_err(|source| PersistCachedExpressionNodeValueTraceLoadError::Value {
                source: PersistCachedExpressionValueIndexedLoadError::Read {
                    source: PersistBlobIndexedReadError::Lookup { source },
                },
            })
    }
}

pub(super) fn clone_mapped_blob_payload(payload: &[u8]) -> Result<Vec<u8>, PersistBlobPackError> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(payload.len())
        .map_err(|_| PersistBlobPackError::PayloadTooLarge {
            payload_len: payload.len() as u128,
        })?;
    owned.extend_from_slice(payload);
    Ok(owned)
}

fn revalidate_persist_node_trace_payload<R>(
    payload: &PersistNodeTracePayload,
    revalidator: &mut R,
) -> bool
where
    R: ImpureInputRevalidator + ?Sized,
{
    if payload.is_tombstone() {
        return false;
    }
    for expected in payload.inputs() {
        let Some(fresh) = revalidator.revalidate_impure_input(expected.identity()) else {
            return false;
        };
        let Some(fresh) = fresh.as_cacheable() else {
            return false;
        };
        if fresh.identity() != expected.identity() {
            return false;
        }
        if fresh.observation_hash() != expected.observation_hash() {
            return false;
        }
    }
    true
}
