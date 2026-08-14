//! Content-addressed DAG storage and temporal-graph storage records.

use super::*;

/// A stable content address used by the execution-model spine.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct ContentHash {
    /// The canonical hash bytes for the addressed content.
    pub bytes: [u8; 32],
}

impl ContentHash {
    /// Computes the RFC-0010 DAG-store key for raw object bytes.
    ///
    /// This is the portable `DagStore` key function: equal bytes produce equal
    /// BLAKE3-backed keys across every backend.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let digest = blake3::hash(bytes);
        Self {
            bytes: *digest.as_bytes(),
        }
    }

    /// Computes the RFC-0010 DAG-store key from a raw object byte stream.
    /// # Errors
    /// Returns an I/O error when the reader cannot supply the complete object.
    pub fn from_reader(mut reader: impl std::io::Read) -> Result<Self, std::io::Error> {
        let mut hasher = blake3::Hasher::new();
        std::io::copy(&mut reader, &mut hasher)?;
        Ok(Self {
            bytes: *hasher.finalize().as_bytes(),
        })
    }

    /// Computes a stable content hash from canonical material.
    ///
    /// `domain` separates independently versioned material streams, and
    /// `material` is the canonical byte representation of the addressed
    /// content.
    #[must_use]
    pub fn from_canonical_material(domain: &str, material: &str) -> Self {
        canonical::content_hash_from_canonical_material(domain, material)
    }

    /// Renders this content address as 64 lowercase hexadecimal characters.
    #[must_use]
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(self.bytes.len() * 2);
        for byte in self.bytes {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    }
}

/// A portable blob reference allowed in serialized scenario forms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentAddressedBlobRef {
    hash: ContentHash,
}

impl ContentAddressedBlobRef {
    /// Parses a `blake3:<64-lower-hex>` content-addressed blob reference.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioImageReferenceNotContentAddressed`] when
    /// `value` is not a BLAKE3 content-addressed reference.
    pub fn parse(field: &'static str, value: &str) -> Result<Self, EngineError> {
        parse_content_addressed_blob_ref(field, value)
    }

    /// Builds a blob reference from an already-computed content hash.
    #[must_use]
    pub const fn from_hash(hash: ContentHash) -> Self {
        Self { hash }
    }

    /// Returns the referenced blob hash.
    #[must_use]
    pub const fn hash(self) -> ContentHash {
        self.hash
    }

    /// Renders the reference as `blake3:<64-lower-hex>`.
    #[must_use]
    pub fn to_uri(self) -> String {
        format_content_hash_ref(self.hash)
    }
}

/// Error returned by a [`DagStore`] backend.
#[derive(Debug)]
pub enum DagStoreError {
    /// No object exists at the requested key.
    NotFound {
        /// The missing content-addressed key.
        key: ContentHash,
    },
    /// Stored bytes did not hash to the key they were read through.
    ContentMismatch {
        /// The key requested by the caller.
        expected: ContentHash,
        /// The key computed from the retrieved bytes.
        actual: ContentHash,
    },
    /// A local store lock was poisoned.
    StorePoisoned {
        /// The operation that needed the poisoned lock.
        operation: &'static str,
    },
    /// A local checkpoint lookup sidecar was malformed or self-inconsistent.
    CorruptIndex {
        /// The checkpoint whose lookup index was being read.
        checkpoint: ContentHash,
        /// Human-readable corruption reason.
        reason: String,
    },
    /// The backend could not complete a filesystem operation.
    Io {
        /// The operation being performed.
        operation: &'static str,
        /// The path involved in the failed operation.
        path: PathBuf,
        /// The underlying I/O error.
        source: io::Error,
    },
}

impl fmt::Display for DagStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { .. } => f.write_str("DAG store object was not found"),
            Self::ContentMismatch { .. } => {
                f.write_str("DAG store object content did not match its key")
            }
            Self::StorePoisoned { operation } => {
                write!(f, "DAG store lock was poisoned during {operation}")
            }
            Self::CorruptIndex { checkpoint, reason } => {
                write!(
                    f,
                    "DAG store checkpoint index for {} is corrupt: {reason}",
                    ContentAddressedBlobRef::from_hash(*checkpoint).to_uri()
                )
            }
            Self::Io {
                operation, path, ..
            } => {
                write!(
                    f,
                    "DAG store filesystem operation {operation} failed for {}",
                    path.display()
                )
            }
        }
    }
}

impl Error for DagStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::NotFound { .. }
            | Self::ContentMismatch { .. }
            | Self::StorePoisoned { .. }
            | Self::CorruptIndex { .. } => None,
        }
    }
}

/// Backend-agnostic content-addressed store for temporal-graph objects.
///
/// The store keys raw object bytes with [`ContentHash::from_bytes`]. Equal
/// bytes therefore produce the same key, and `put` is idempotent across local
/// and future remote backends.
pub trait DagStore: Send + Sync {
    /// Stores `bytes` and returns their content-addressed key.
    ///
    /// Re-inserting the same bytes returns the same key without creating a
    /// duplicate logical object.
    ///
    /// # Errors
    ///
    /// Returns [`DagStoreError`] when the backend cannot persist or validate
    /// the object.
    fn put(&self, bytes: &[u8]) -> Result<ContentHash, DagStoreError>;

    /// Retrieves the bytes addressed by `key`.
    ///
    /// # Errors
    ///
    /// Returns [`DagStoreError::NotFound`] when the object is absent, or another
    /// [`DagStoreError`] when the backend cannot read or validate it.
    fn get(&self, key: &ContentHash) -> Result<Vec<u8>, DagStoreError>;

    /// Returns whether a valid object for `key` is present.
    ///
    /// Backends may answer this from metadata when the store guarantees object
    /// integrity. Backends that can observe local corruption may validate bytes
    /// and report [`DagStoreError::ContentMismatch`].
    ///
    /// # Errors
    ///
    /// Returns [`DagStoreError`] when the backend cannot query the object.
    fn exists(&self, key: &ContentHash) -> Result<bool, DagStoreError>;

    /// Deletes the object addressed by `key`.
    ///
    /// Returns `Ok(true)` when an object existed and was removed, and
    /// `Ok(false)` when no object was present.
    ///
    /// # Errors
    ///
    /// Returns [`DagStoreError`] when the backend cannot delete the object.
    fn delete(&self, key: &ContentHash) -> Result<bool, DagStoreError>;
}

/// In-memory [`DagStore`] implementation used by model tests and adapters.
#[derive(Debug, Default)]
pub struct MemoryDagStore {
    objects: Mutex<BTreeMap<ContentHash, Vec<u8>>>,
}

impl MemoryDagStore {
    /// Builds an empty in-memory DAG store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of unique objects currently held by the store.
    ///
    /// # Errors
    ///
    /// Returns [`DagStoreError::StorePoisoned`] if a prior panic poisoned the
    /// store lock.
    pub fn object_count(&self) -> Result<usize, DagStoreError> {
        let objects = self
            .objects
            .lock()
            .map_err(|_| DagStoreError::StorePoisoned {
                operation: "object-count",
            })?;
        Ok(objects.len())
    }
}

impl DagStore for MemoryDagStore {
    fn put(&self, bytes: &[u8]) -> Result<ContentHash, DagStoreError> {
        let key = ContentHash::from_bytes(bytes);
        let mut objects = self
            .objects
            .lock()
            .map_err(|_| DagStoreError::StorePoisoned { operation: "put" })?;
        match objects.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(bytes.to_vec());
            }
            Entry::Occupied(_) => {}
        }
        Ok(key)
    }

    fn get(&self, key: &ContentHash) -> Result<Vec<u8>, DagStoreError> {
        let objects = self
            .objects
            .lock()
            .map_err(|_| DagStoreError::StorePoisoned { operation: "get" })?;
        objects
            .get(key)
            .cloned()
            .ok_or(DagStoreError::NotFound { key: *key })
    }

    fn exists(&self, key: &ContentHash) -> Result<bool, DagStoreError> {
        let objects = self
            .objects
            .lock()
            .map_err(|_| DagStoreError::StorePoisoned {
                operation: "exists",
            })?;
        Ok(objects.contains_key(key))
    }

    fn delete(&self, key: &ContentHash) -> Result<bool, DagStoreError> {
        let mut objects = self
            .objects
            .lock()
            .map_err(|_| DagStoreError::StorePoisoned {
                operation: "delete",
            })?;
        Ok(objects.remove(key).is_some())
    }
}

mod local;

pub use local::{LocalCheckpointClosureIndex, LocalDagStore};

/// Reproduction artifact expressed only as DAG-store keys.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DagStoreReproductionArtifact {
    /// Store key for the scenario definition bytes.
    pub scenario_def: ContentHash,
    /// Store key for the baked genesis snapshot bytes.
    pub genesis_snapshot: ContentHash,
    /// Store keys for the schedule-delta bytes needed to reconstruct the run.
    pub schedule_deltas: Vec<ContentHash>,
    /// Store keys for retained event-log segments used as debugging/fork metadata.
    pub event_log_segments: Vec<ContentHash>,
}

impl DagStoreReproductionArtifact {
    /// Builds a store-key reproduction artifact.
    #[must_use]
    pub fn new(
        scenario_def: ContentHash,
        genesis_snapshot: ContentHash,
        schedule_deltas: Vec<ContentHash>,
    ) -> Self {
        Self::with_event_log_segments(scenario_def, genesis_snapshot, schedule_deltas, Vec::new())
    }

    /// Builds a store-key reproduction artifact with shared event-log segment refs.
    #[must_use]
    pub fn with_event_log_segments(
        scenario_def: ContentHash,
        genesis_snapshot: ContentHash,
        schedule_deltas: Vec<ContentHash>,
        event_log_segments: Vec<ContentHash>,
    ) -> Self {
        Self {
            scenario_def,
            genesis_snapshot,
            schedule_deltas,
            event_log_segments: sorted_unique_hashes(event_log_segments),
        }
    }

    /// Returns this artifact with shared-store event-log segment keys attached.
    #[must_use]
    pub fn with_event_log_segment_keys(mut self, event_log_segments: Vec<ContentHash>) -> Self {
        self.event_log_segments = sorted_unique_hashes(event_log_segments);
        self
    }

    /// Returns the deduplicated store-key closure named by the artifact.
    #[must_use]
    pub fn store_keys(&self) -> BTreeSet<ContentHash> {
        let mut keys = BTreeSet::from([self.scenario_def, self.genesis_snapshot]);
        keys.extend(self.schedule_deltas.iter().copied());
        keys.extend(self.event_log_segments.iter().copied());
        keys
    }
}

/// Store keys produced when a temporal-graph closure is persisted.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TemporalGraphStoreKeys {
    /// Mapping from checkpoint graph identity to the stored checkpoint-node bytes.
    pub checkpoint_nodes: BTreeMap<ContentHash, ContentHash>,
    /// Mapping from checkpoint graph identity to stored fat cached-snapshot bytes.
    pub cached_snapshots: BTreeMap<ContentHash, ContentHash>,
    /// Mapping from typed CoW delta identity to the stored delta descriptor bytes.
    pub cow_deltas: BTreeMap<CowDeltaRef, ContentHash>,
    /// Reproduction artifact expressed as portable DAG-store keys.
    pub reproduction_artifact: DagStoreReproductionArtifact,
}

impl TemporalGraphStoreKeys {
    /// Returns the deduplicated store-key closure for this persisted graph slice.
    #[must_use]
    pub fn store_keys(&self) -> BTreeSet<ContentHash> {
        let mut keys = self.reproduction_artifact.store_keys();
        keys.extend(self.checkpoint_nodes.values().copied());
        keys.extend(self.cached_snapshots.values().copied());
        keys.extend(self.cow_deltas.values().copied());
        keys
    }
}

/// Root set used by temporal-graph garbage collection.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TemporalGraphGcRoots {
    /// Checkpoint ids currently held by live sessions, counted by holder.
    pub live_tips: BTreeMap<ContentHash, usize>,
    /// Saved checkpoint ids that must remain replay-realizable, counted by pin.
    pub pinned_checkpoints: BTreeMap<ContentHash, usize>,
}

impl TemporalGraphGcRoots {
    /// Builds an empty explicit root set.
    ///
    /// Baked genesis checkpoints are implicit roots supplied by the graph during
    /// every GC pass.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a live session tip root.
    #[must_use]
    pub fn with_live_tip(mut self, checkpoint: ContentHash) -> Self {
        *self.live_tips.entry(checkpoint).or_insert(0) += 1;
        self
    }

    /// Adds a saved or pinned checkpoint root.
    #[must_use]
    pub fn with_pinned_checkpoint(mut self, checkpoint: ContentHash) -> Self {
        *self.pinned_checkpoints.entry(checkpoint).or_insert(0) += 1;
        self
    }
}

/// Reference counts computed for the live temporal-graph closure.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TemporalGraphReferenceCounts {
    /// Live references to checkpoint DAG nodes.
    pub checkpoint_nodes: BTreeMap<ContentHash, usize>,
    /// Live references to fat cached snapshots attached to live checkpoint ids.
    pub cached_snapshots: BTreeMap<ContentHash, usize>,
    /// Live references to typed CoW delta objects.
    pub cow_deltas: BTreeMap<CowDeltaRef, usize>,
}

impl TemporalGraphReferenceCounts {
    fn increment_checkpoint(&mut self, checkpoint: ContentHash) {
        *self.checkpoint_nodes.entry(checkpoint).or_insert(0) += 1;
    }

    fn increment_cached_snapshot(&mut self, checkpoint: ContentHash) {
        *self.cached_snapshots.entry(checkpoint).or_insert(0) += 1;
    }

    fn increment_cow_delta(&mut self, cow_ref: CowDeltaRef) {
        *self.cow_deltas.entry(cow_ref).or_insert(0) += 1;
    }
}

/// Result of one temporal-graph garbage-collection pass.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TemporalGraphGcReport {
    /// Explicit roots used for the pass; baked genesis checkpoints are implicit.
    pub roots: TemporalGraphGcRoots,
    /// Checkpoint ids retained by root-to-genesis reachability.
    pub live_checkpoints: BTreeSet<ContentHash>,
    /// Reference counts for the retained closure.
    pub live_reference_counts: TemporalGraphReferenceCounts,
    /// Thin checkpoint DAG nodes removed because no root reaches them.
    pub collected_checkpoints: BTreeSet<ContentHash>,
    /// Fat cached snapshots removed because their checkpoint id is unreachable.
    pub collected_cached_snapshots: BTreeSet<ContentHash>,
    /// Recorded configurations removed with unreachable checkpoint nodes.
    pub collected_configurations: BTreeSet<ContentHash>,
    /// Typed CoW objects no longer referenced by any retained checkpoint or cache.
    pub collectible_cow_deltas: BTreeSet<CowDeltaRef>,
    /// DAG-store keys still referenced by the retained graph closure.
    pub live_store_keys: BTreeSet<ContentHash>,
    /// DAG-store keys no longer referenced by the retained graph closure.
    pub collectible_store_keys: BTreeSet<ContentHash>,
    /// DAG-store keys actually deleted by a store-backed GC pass.
    pub deleted_store_keys: BTreeSet<ContentHash>,
    /// Collectible DAG-store keys that were already absent during store-backed GC.
    pub missing_store_keys: BTreeSet<ContentHash>,
}

/// Error returned while persisting temporal-graph objects into a [`DagStore`].
#[derive(Debug)]
pub enum TemporalGraphStoreError {
    /// The graph could not derive a valid checkpoint closure.
    Engine {
        /// The graph operation being performed.
        operation: &'static str,
        /// The engine-spine error.
        source: Box<EngineError>,
    },
    /// The DAG store rejected or failed a persistence operation.
    Store {
        /// The store operation being performed.
        operation: &'static str,
        /// The backend error.
        source: DagStoreError,
    },
}
