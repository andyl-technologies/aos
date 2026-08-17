//! Stable on-disk encoding for one persisted node verifying trace payload.
//!
//! Owns [`PersistNodeTracePayload`] and its versioned little-endian codec:
//! cacheable impure-input fingerprints, sorted memo-read dependency keys and
//! pinned supplier value hashes, and tombstones. The append log adapter that
//! persists these payloads lives in the sibling `log` module.

use super::super::*;

/// A stable payload for one persisted node verifying trace.
///
/// Ordinary payloads preserve evaluator trace order and store only cacheable
/// impure-input fingerprints: each record carries the typed input identity
/// parts plus the observed-result hash. Version 4 payloads additionally carry
/// sorted memo-read dependency keys. Version 5 dependency records also pin the
/// supplier value hash that the parent observed, so durable-hit revalidation can
/// reject parents whose suppliers advanced to a different value. Tombstone
/// payloads carry no inputs or dependencies and explicitly invalidate older
/// trace records for the same node. The eventual persistent demand-graph sidecar
/// can attach ordinary payload bytes to an expression node and replay the
/// fingerprints during durable-hit revalidation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistNodeTracePayload {
    inputs: Vec<CacheableInputFingerprint>,
    memo_read_dependencies: Vec<PersistNodeMetadataKey>,
    memo_read_dependency_value_hashes: Vec<Option<ValueHash>>,
    tombstone: bool,
}

impl PersistNodeTracePayload {
    /// Creates a tombstone payload that invalidates older trace records for a node.
    pub fn tombstone() -> Self {
        Self {
            inputs: Vec::new(),
            memo_read_dependencies: Vec::new(),
            memo_read_dependency_value_hashes: Vec::new(),
            tombstone: true,
        }
    }

    /// Creates a node trace payload from cacheable input fingerprints.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTracePayloadError`] if storage for the input list
    /// cannot be reserved.
    pub fn from_cacheable_inputs<I>(inputs: I) -> Result<Self, PersistNodeTracePayloadError>
    where
        I: IntoIterator<Item = CacheableInputFingerprint>,
    {
        Self::from_cacheable_inputs_and_memo_reads(
            inputs,
            std::iter::empty::<PersistNodeMetadataKey>(),
        )
    }

    /// Creates a node trace payload from input fingerprints and memo-read keys.
    ///
    /// Memo-read dependency keys are sorted and deduplicated before encoding so
    /// semantically identical dependency sets have stable bytes regardless of
    /// caller iteration order.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTracePayloadError`] if storage for either list
    /// cannot be reserved.
    pub fn from_cacheable_inputs_and_memo_reads<I, D>(
        inputs: I,
        dependencies: D,
    ) -> Result<Self, PersistNodeTracePayloadError>
    where
        I: IntoIterator<Item = CacheableInputFingerprint>,
        D: IntoIterator<Item = PersistNodeMetadataKey>,
    {
        let inputs = inputs.into_iter();
        let (minimum, _) = inputs.size_hint();
        let mut stored = Vec::new();
        stored
            .try_reserve_exact(minimum)
            .map_err(|_| PersistNodeTracePayloadError::InputAllocationFailed { inputs: minimum })?;
        for input in inputs {
            if stored.len() == stored.capacity() {
                let requested = stored.len().saturating_add(1);
                stored.try_reserve_exact(1).map_err(|_| {
                    PersistNodeTracePayloadError::InputAllocationFailed { inputs: requested }
                })?;
            }
            stored.push(input);
        }
        let memo_read_dependencies = collect_memo_read_dependencies(dependencies)?;
        Ok(Self {
            inputs: stored,
            memo_read_dependency_value_hashes: vec![None; memo_read_dependencies.len()],
            memo_read_dependencies,
            tombstone: false,
        })
    }

    /// Creates a node trace payload from an evaluator impure-input trace.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTracePayloadError`] if the trace contains an
    /// uncacheable input or if storage for the input list cannot be reserved.
    pub fn from_impure_trace<'a, I>(trace: I) -> Result<Self, PersistNodeTracePayloadError>
    where
        I: IntoIterator<Item = &'a ImpureInputFingerprint>,
    {
        let trace = trace.into_iter();
        let (minimum, _) = trace.size_hint();
        let mut inputs = Vec::new();
        inputs
            .try_reserve_exact(minimum)
            .map_err(|_| PersistNodeTracePayloadError::InputAllocationFailed { inputs: minimum })?;
        for fingerprint in trace {
            match fingerprint {
                ImpureInputFingerprint::Cacheable(input) => {
                    if inputs.len() == inputs.capacity() {
                        let requested = inputs.len().saturating_add(1);
                        inputs.try_reserve_exact(1).map_err(|_| {
                            PersistNodeTracePayloadError::InputAllocationFailed {
                                inputs: requested,
                            }
                        })?;
                    }
                    inputs.push(input.clone());
                }
                ImpureInputFingerprint::Uncacheable(input) => {
                    return Err(PersistNodeTracePayloadError::UncacheableInput { input: *input });
                }
            }
        }
        Ok(Self {
            inputs,
            memo_read_dependencies: Vec::new(),
            memo_read_dependency_value_hashes: Vec::new(),
            tombstone: false,
        })
    }

    /// Returns this payload with the supplied memo-read dependency keys.
    ///
    /// Keys are sorted and deduplicated before being stored.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTracePayloadError`] if storage for the dependency
    /// list cannot be reserved.
    pub fn with_memo_read_dependencies<D>(
        mut self,
        dependencies: D,
    ) -> Result<Self, PersistNodeTracePayloadError>
    where
        D: IntoIterator<Item = PersistNodeMetadataKey>,
    {
        if self.tombstone {
            self.memo_read_dependencies.clear();
            self.memo_read_dependency_value_hashes.clear();
        } else {
            self.memo_read_dependencies = collect_memo_read_dependencies(dependencies)?;
            self.memo_read_dependency_value_hashes = vec![None; self.memo_read_dependencies.len()];
        }
        Ok(self)
    }

    /// Returns this payload with supplied memo-read dependency keys and value hashes.
    ///
    /// Records are sorted by key and deduplicated before storage.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTracePayloadError`] if storage for the dependency
    /// list cannot be reserved.
    pub fn with_memo_read_dependency_records<D>(
        mut self,
        dependencies: D,
    ) -> Result<Self, PersistNodeTracePayloadError>
    where
        D: IntoIterator<Item = (PersistNodeMetadataKey, ValueHash)>,
    {
        if self.tombstone {
            self.memo_read_dependencies.clear();
            self.memo_read_dependency_value_hashes.clear();
        } else {
            let dependencies = collect_memo_read_dependency_records(dependencies)?;
            self.memo_read_dependencies = dependencies.iter().map(|(key, _)| *key).collect();
            self.memo_read_dependency_value_hashes = dependencies
                .into_iter()
                .map(|(_, value_hash)| Some(value_hash))
                .collect();
        }
        Ok(self)
    }

    /// Returns whether this payload tombstones older traces for the same node.
    pub const fn is_tombstone(&self) -> bool {
        self.tombstone
    }

    /// Returns the cacheable input fingerprints in trace order.
    pub fn inputs(&self) -> &[CacheableInputFingerprint] {
        &self.inputs
    }

    /// Returns the sorted memo-read dependency metadata keys.
    pub fn memo_read_dependencies(&self) -> &[PersistNodeMetadataKey] {
        &self.memo_read_dependencies
    }

    /// Returns the sorted memo-read dependency metadata keys and pinned value hashes.
    pub fn memo_read_dependency_records(
        &self,
    ) -> impl Iterator<Item = (PersistNodeMetadataKey, Option<ValueHash>)> + '_ {
        self.memo_read_dependencies
            .iter()
            .copied()
            .zip(self.memo_read_dependency_value_hashes.iter().copied())
    }

    /// Encodes this node trace payload as stable little-endian bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTracePayloadError`] if an input or dependency count
    /// or any subject length cannot be represented in the on-disk format, or if
    /// encoded output storage cannot be reserved.
    pub fn encode(&self) -> Result<Vec<u8>, PersistNodeTracePayloadError> {
        let count = if self.tombstone {
            PERSIST_NODE_TRACE_PAYLOAD_TOMBSTONE_COUNT
        } else {
            u64::try_from(self.inputs.len()).map_err(|_| {
                PersistNodeTracePayloadError::EncodedInputCountOverflow {
                    inputs: self.inputs.len(),
                }
            })?
        };
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN)
            .map_err(|_| PersistNodeTracePayloadError::PayloadAllocationFailed {
                len: PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN,
            })?;
        bytes.extend_from_slice(&PERSIST_NODE_TRACE_PAYLOAD_MAGIC);
        bytes.extend_from_slice(&PERSIST_NODE_TRACE_PAYLOAD_VERSION.to_le_bytes());
        bytes.extend_from_slice(&count.to_le_bytes());

        if self.tombstone {
            return Ok(bytes);
        }

        for input in &self.inputs {
            let identity = input.identity();
            let subject = identity.subject();
            let subject_len = u64::try_from(subject.len()).map_err(|_| {
                PersistNodeTracePayloadError::EncodedSubjectLengthOverflow { len: subject.len() }
            })?;
            let record_len = PERSIST_NODE_TRACE_INPUT_FIXED_LEN
                .checked_add(subject.len())
                .ok_or(PersistNodeTracePayloadError::PayloadAllocationFailed { len: usize::MAX })?;
            bytes.try_reserve_exact(record_len).map_err(|_| {
                PersistNodeTracePayloadError::PayloadAllocationFailed { len: record_len }
            })?;
            bytes.push(node_trace_input_kind_tag(identity.kind()));
            bytes.push(node_trace_input_mode_tag(identity.mode()));
            bytes.extend_from_slice(&subject_len.to_le_bytes());
            bytes.extend_from_slice(&input.observation_hash().as_durable_hash().as_bytes());
            bytes.extend_from_slice(subject);
        }

        let dependency_count = u64::try_from(self.memo_read_dependencies.len()).map_err(|_| {
            PersistNodeTracePayloadError::EncodedDependencyCountOverflow {
                dependencies: self.memo_read_dependencies.len(),
            }
        })?;
        let dependency_bytes_len = PERSIST_NODE_METADATA_INDEX_KEY_LEN
            .checked_mul(self.memo_read_dependencies.len())
            .and_then(|len| {
                PERSIST_NODE_METADATA_VALUE_HASH_LEN
                    .checked_mul(self.memo_read_dependencies.len())
                    .and_then(|hashes_len| len.checked_add(hashes_len))
            })
            .and_then(|len| len.checked_add(8))
            .ok_or(PersistNodeTracePayloadError::PayloadAllocationFailed { len: usize::MAX })?;
        bytes.try_reserve_exact(dependency_bytes_len).map_err(|_| {
            PersistNodeTracePayloadError::PayloadAllocationFailed {
                len: dependency_bytes_len,
            }
        })?;
        bytes.extend_from_slice(&dependency_count.to_le_bytes());
        for (dependency, value_hash) in self.memo_read_dependency_records() {
            bytes.extend_from_slice(&dependency.index_bytes());
            match value_hash {
                Some(value_hash) => {
                    bytes.push(PERSIST_NODE_METADATA_VALUE_HASH_PRESENT_TAG);
                    bytes.extend_from_slice(&value_hash.as_durable_hash().as_bytes());
                }
                None => {
                    bytes.push(PERSIST_NODE_METADATA_VALUE_HASH_NONE_TAG);
                    bytes.extend_from_slice(&[0; 32]);
                }
            }
        }

        Ok(bytes)
    }

    /// Decodes a stable node trace payload.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTracePayloadError`] if `bytes` has the wrong magic
    /// or version, contains malformed input or dependency records, contains
    /// trailing bytes, or cannot reconstruct an input fingerprint or dependency
    /// key.
    pub fn decode(bytes: &[u8]) -> Result<Self, PersistNodeTracePayloadError> {
        if bytes.len() < PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN {
            return Err(PersistNodeTracePayloadError::ShortPayload {
                expected: PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN,
                actual: bytes.len(),
            });
        }

        let mut magic = [0; 16];
        magic.copy_from_slice(&bytes[..16]);
        if magic != PERSIST_NODE_TRACE_PAYLOAD_MAGIC {
            return Err(PersistNodeTracePayloadError::InvalidMagic { actual: magic });
        }

        let version = read_u32(&bytes[16..20]);
        if !(PERSIST_NODE_TRACE_PAYLOAD_MIN_VERSION..=PERSIST_NODE_TRACE_PAYLOAD_VERSION)
            .contains(&version)
        {
            return Err(PersistNodeTracePayloadError::UnsupportedVersion { version });
        }

        let count = read_u64(&bytes[20..28]);
        if count == PERSIST_NODE_TRACE_PAYLOAD_TOMBSTONE_COUNT {
            if version < 2 {
                return Err(PersistNodeTracePayloadError::InputCountOverflow { count });
            }
            if bytes.len() != PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN {
                return Err(PersistNodeTracePayloadError::TrailingBytes {
                    remaining: bytes.len() - PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN,
                });
            }
            return Ok(Self::tombstone());
        }
        let count_usize = usize::try_from(count)
            .map_err(|_| PersistNodeTracePayloadError::InputCountOverflow { count })?;
        let fixed_records_len = count_usize
            .checked_mul(PERSIST_NODE_TRACE_INPUT_FIXED_LEN)
            .ok_or(PersistNodeTracePayloadError::ShortPayload {
                expected: usize::MAX,
                actual: bytes.len(),
            })?;
        let minimum_len = PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN
            .checked_add(fixed_records_len)
            .ok_or(PersistNodeTracePayloadError::ShortPayload {
                expected: usize::MAX,
                actual: bytes.len(),
            })?;
        if minimum_len > bytes.len() {
            return Err(PersistNodeTracePayloadError::ShortPayload {
                expected: minimum_len,
                actual: bytes.len(),
            });
        }

        let mut inputs = Vec::new();
        inputs.try_reserve_exact(count_usize).map_err(|_| {
            PersistNodeTracePayloadError::InputAllocationFailed {
                inputs: count_usize,
            }
        })?;

        let mut cursor = PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN;
        for _ in 0..count_usize {
            let fixed_end = cursor
                .checked_add(PERSIST_NODE_TRACE_INPUT_FIXED_LEN)
                .ok_or(PersistNodeTracePayloadError::ShortPayload {
                    expected: usize::MAX,
                    actual: bytes.len(),
                })?;
            if fixed_end > bytes.len() {
                return Err(PersistNodeTracePayloadError::ShortPayload {
                    expected: fixed_end,
                    actual: bytes.len(),
                });
            }

            let kind = node_trace_input_kind_from_tag(bytes[cursor])?;
            let mode = node_trace_input_mode_from_tag(version, bytes[cursor + 1])?;
            let subject_len = read_u64(&bytes[cursor + 2..cursor + 10]);
            let mut observation_hash = [0; 32];
            observation_hash.copy_from_slice(&bytes[cursor + 10..cursor + 42]);
            cursor = fixed_end;

            let subject_len = usize::try_from(subject_len).map_err(|_| {
                PersistNodeTracePayloadError::SubjectLengthOverflow { len: subject_len }
            })?;
            let subject_end = cursor.checked_add(subject_len).ok_or(
                PersistNodeTracePayloadError::ShortPayload {
                    expected: usize::MAX,
                    actual: bytes.len(),
                },
            )?;
            if subject_end > bytes.len() {
                return Err(PersistNodeTracePayloadError::ShortPayload {
                    expected: subject_end,
                    actual: bytes.len(),
                });
            }
            let input = CacheableInputFingerprint::from_observation_hash(
                kind,
                mode,
                &bytes[cursor..subject_end],
                DurableBlake3Hash::from_bytes(observation_hash),
            )
            .map_err(|source| PersistNodeTracePayloadError::Input { source })?;
            inputs.push(input);
            cursor = subject_end;
        }

        if cursor != bytes.len() {
            if version < 4 {
                return Err(PersistNodeTracePayloadError::TrailingBytes {
                    remaining: bytes.len() - cursor,
                });
            }
        }

        let (memo_read_dependencies, memo_read_dependency_value_hashes) = if version >= 4 {
            let count_end =
                cursor
                    .checked_add(8)
                    .ok_or(PersistNodeTracePayloadError::ShortPayload {
                        expected: usize::MAX,
                        actual: bytes.len(),
                    })?;
            if count_end > bytes.len() {
                return Err(PersistNodeTracePayloadError::ShortPayload {
                    expected: count_end,
                    actual: bytes.len(),
                });
            }
            let dependency_count = read_u64(&bytes[cursor..count_end]);
            cursor = count_end;
            let dependency_count_usize = usize::try_from(dependency_count).map_err(|_| {
                PersistNodeTracePayloadError::DependencyCountOverflow {
                    count: dependency_count,
                }
            })?;
            let dependency_record_len = if version >= 5 {
                PERSIST_NODE_TRACE_DEPENDENCY_FIXED_LEN
            } else {
                PERSIST_NODE_METADATA_INDEX_KEY_LEN
            };
            let dependencies_len = dependency_count_usize
                .checked_mul(dependency_record_len)
                .ok_or(PersistNodeTracePayloadError::ShortPayload {
                    expected: usize::MAX,
                    actual: bytes.len(),
                })?;
            let dependencies_end = cursor.checked_add(dependencies_len).ok_or(
                PersistNodeTracePayloadError::ShortPayload {
                    expected: usize::MAX,
                    actual: bytes.len(),
                },
            )?;
            if dependencies_end > bytes.len() {
                return Err(PersistNodeTracePayloadError::ShortPayload {
                    expected: dependencies_end,
                    actual: bytes.len(),
                });
            }
            let mut dependencies = Vec::new();
            dependencies
                .try_reserve_exact(dependency_count_usize)
                .map_err(
                    |_| PersistNodeTracePayloadError::DependencyAllocationFailed {
                        dependencies: dependency_count_usize,
                    },
                )?;
            while cursor < dependencies_end {
                let key_end = cursor + PERSIST_NODE_METADATA_INDEX_KEY_LEN;
                let key = PersistNodeMetadataKey::decode_index_bytes(&bytes[cursor..key_end])
                    .map_err(|source| PersistNodeTracePayloadError::Dependency { source })?;
                cursor = key_end;
                let value_hash = if version >= 5 {
                    let value_hash_end = cursor + PERSIST_NODE_METADATA_VALUE_HASH_LEN;
                    let value_hash = decode_dependency_value_hash(&bytes[cursor..value_hash_end])?;
                    cursor = value_hash_end;
                    value_hash
                } else {
                    None
                };
                dependencies.push((key, value_hash));
            }
            collect_decoded_memo_read_dependencies(dependencies)?
        } else {
            (Vec::new(), Vec::new())
        };

        if cursor != bytes.len() {
            return Err(PersistNodeTracePayloadError::TrailingBytes {
                remaining: bytes.len() - cursor,
            });
        }

        Ok(Self {
            inputs,
            memo_read_dependencies,
            memo_read_dependency_value_hashes,
            tombstone: false,
        })
    }
}

fn decode_dependency_value_hash(
    bytes: &[u8],
) -> Result<Option<ValueHash>, PersistNodeTracePayloadError> {
    let value_hash_payload = &bytes[1..PERSIST_NODE_METADATA_VALUE_HASH_LEN];
    match bytes[0] {
        PERSIST_NODE_METADATA_VALUE_HASH_NONE_TAG => {
            if value_hash_payload.iter().any(|byte| *byte != 0) {
                return Err(PersistNodeTracePayloadError::NonZeroDependencyValueHashPadding);
            }
            Ok(None)
        }
        PERSIST_NODE_METADATA_VALUE_HASH_PRESENT_TAG => {
            let mut hash = [0; 32];
            hash.copy_from_slice(value_hash_payload);
            Ok(Some(ValueHash::from_canonical_value_hash(
                DurableBlake3Hash::from_bytes(hash),
            )))
        }
        tag => Err(PersistNodeTracePayloadError::InvalidDependencyValueHashTag { tag }),
    }
}

fn collect_memo_read_dependencies<D>(
    dependencies: D,
) -> Result<Vec<PersistNodeMetadataKey>, PersistNodeTracePayloadError>
where
    D: IntoIterator<Item = PersistNodeMetadataKey>,
{
    let dependencies = dependencies.into_iter();
    let (minimum, _) = dependencies.size_hint();
    let mut stored = Vec::new();
    stored.try_reserve_exact(minimum).map_err(|_| {
        PersistNodeTracePayloadError::DependencyAllocationFailed {
            dependencies: minimum,
        }
    })?;
    for dependency in dependencies {
        if stored.len() == stored.capacity() {
            let requested = stored.len().saturating_add(1);
            stored.try_reserve_exact(1).map_err(|_| {
                PersistNodeTracePayloadError::DependencyAllocationFailed {
                    dependencies: requested,
                }
            })?;
        }
        stored.push(dependency);
    }
    stored.sort_unstable();
    stored.dedup();
    Ok(stored)
}

fn collect_memo_read_dependency_records<D>(
    dependencies: D,
) -> Result<Vec<(PersistNodeMetadataKey, ValueHash)>, PersistNodeTracePayloadError>
where
    D: IntoIterator<Item = (PersistNodeMetadataKey, ValueHash)>,
{
    let dependencies = dependencies.into_iter();
    let (minimum, _) = dependencies.size_hint();
    let mut stored = Vec::new();
    stored.try_reserve_exact(minimum).map_err(|_| {
        PersistNodeTracePayloadError::DependencyAllocationFailed {
            dependencies: minimum,
        }
    })?;
    for dependency in dependencies {
        if stored.len() == stored.capacity() {
            let requested = stored.len().saturating_add(1);
            stored.try_reserve_exact(1).map_err(|_| {
                PersistNodeTracePayloadError::DependencyAllocationFailed {
                    dependencies: requested,
                }
            })?;
        }
        stored.push(dependency);
    }
    stored.sort_unstable_by_key(|(key, _)| *key);
    stored.dedup_by_key(|(key, _)| *key);
    Ok(stored)
}

fn collect_decoded_memo_read_dependencies<D>(
    dependencies: D,
) -> Result<(Vec<PersistNodeMetadataKey>, Vec<Option<ValueHash>>), PersistNodeTracePayloadError>
where
    D: IntoIterator<Item = (PersistNodeMetadataKey, Option<ValueHash>)>,
{
    let dependencies = dependencies.into_iter();
    let (minimum, _) = dependencies.size_hint();
    let mut stored = Vec::new();
    stored.try_reserve_exact(minimum).map_err(|_| {
        PersistNodeTracePayloadError::DependencyAllocationFailed {
            dependencies: minimum,
        }
    })?;
    for dependency in dependencies {
        if stored.len() == stored.capacity() {
            let requested = stored.len().saturating_add(1);
            stored.try_reserve_exact(1).map_err(|_| {
                PersistNodeTracePayloadError::DependencyAllocationFailed {
                    dependencies: requested,
                }
            })?;
        }
        stored.push(dependency);
    }
    stored.sort_unstable_by_key(|(key, _)| *key);
    stored.dedup_by_key(|(key, _)| *key);
    let mut keys = Vec::new();
    let mut value_hashes = Vec::new();
    keys.try_reserve_exact(stored.len()).map_err(|_| {
        PersistNodeTracePayloadError::DependencyAllocationFailed {
            dependencies: stored.len(),
        }
    })?;
    value_hashes.try_reserve_exact(stored.len()).map_err(|_| {
        PersistNodeTracePayloadError::DependencyAllocationFailed {
            dependencies: stored.len(),
        }
    })?;
    for (key, value_hash) in stored {
        keys.push(key);
        value_hashes.push(value_hash);
    }
    Ok((keys, value_hashes))
}

fn node_trace_input_kind_tag(kind: ImpureInputKind) -> u8 {
    match kind {
        ImpureInputKind::Import => 1,
        ImpureInputKind::ReadFile => 2,
        ImpureInputKind::ReadDir => 3,
        ImpureInputKind::ReadFileType => 4,
        ImpureInputKind::PathExists => 5,
        ImpureInputKind::GetEnv => 6,
        ImpureInputKind::HashFile => 7,
    }
}

fn node_trace_input_kind_from_tag(
    tag: u8,
) -> Result<ImpureInputKind, PersistNodeTracePayloadError> {
    match tag {
        1 => Ok(ImpureInputKind::Import),
        2 => Ok(ImpureInputKind::ReadFile),
        3 => Ok(ImpureInputKind::ReadDir),
        4 => Ok(ImpureInputKind::ReadFileType),
        5 => Ok(ImpureInputKind::PathExists),
        6 => Ok(ImpureInputKind::GetEnv),
        7 => Ok(ImpureInputKind::HashFile),
        _ => Err(PersistNodeTracePayloadError::InvalidInputKindTag { tag }),
    }
}

fn node_trace_input_mode_tag(mode: ImpureInputMode) -> u8 {
    match mode {
        ImpureInputMode::Default => 1,
        ImpureInputMode::RequireDirectory => 2,
        ImpureInputMode::FindFileCandidate => 3,
    }
}

fn node_trace_input_mode_from_tag(
    version: u32,
    tag: u8,
) -> Result<ImpureInputMode, PersistNodeTracePayloadError> {
    match tag {
        1 => Ok(ImpureInputMode::Default),
        2 => Ok(ImpureInputMode::RequireDirectory),
        3 if version >= 3 => Ok(ImpureInputMode::FindFileCandidate),
        _ => Err(PersistNodeTracePayloadError::InvalidInputModeTag { tag }),
    }
}
