//! Content-addressed execution-model vocabulary.
//!
//! This module owns the pure, content-addressed data contracts shared by the
//! scheduler, temporal graph, checkpoint cache, fault engine, assertions, and
//! event log. It deliberately contains no backend-specific driver state.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::ops;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crucible_sim::{
    DECISION_RNG_LINK_STREAM_DOMAIN, DECISION_RNG_NAME_HASH_DOMAIN,
    DECISION_RNG_NODE_STREAM_DOMAIN, DecisionRng, DecisionStream,
};
use serde::{Deserialize, Serialize};

mod canonical;

static LOCAL_DAG_STORE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
/// Minimum one-way logical link latency in virtual nanoseconds.
pub const MIN_LINK_LATENCY: SimDuration = SimDuration { nanos: 1 };
const MAX_LINK_LOSS_MILLIONTHS: u32 = 1_000_000;
const MAX_FAMILY_FAULT_DENSITY_MILLIONTHS: u32 = 1_000_000;
const MAX_SCENARIO_FAMILY_SEEDS: u32 = 1_000_000;
const MAX_SCENARIO_FAMILY_TOPOLOGY_SIZE: u32 = 256;
const FAMILY_FAULT_STEP_TICKS: u64 = 20;
const FAMILY_FAULT_HEAL_DELAY_TICKS: u64 = 5;
const REPLAY_ORACLE_SEARCH_SAMPLING_DOMAIN: &[u8] = b"crucible.replay-oracle.search-sampling.v1";
const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x00000100000001b3;

/// A stable content address used by the execution-model spine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
            Self::NotFound { .. } | Self::ContentMismatch { .. } | Self::StorePoisoned { .. } => {
                None
            }
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

/// Filesystem-backed [`DagStore`] using the RFC-0010 two-level layout.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LocalDagStore {
    root: PathBuf,
}

impl LocalDagStore {
    /// Builds a local DAG store rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the store root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the two-level object path for `key`.
    ///
    /// The layout is `{root}/{first 2 hex chars}/{full hex hash}`.
    #[must_use]
    pub fn object_path(&self, key: &ContentHash) -> PathBuf {
        let hex = key.to_hex();
        self.root.join(&hex[0..2]).join(hex)
    }
}

impl DagStore for LocalDagStore {
    fn put(&self, bytes: &[u8]) -> Result<ContentHash, DagStoreError> {
        let key = ContentHash::from_bytes(bytes);
        let path = self.object_path(&key);
        let replace_existing = match fs::read(&path) {
            Ok(existing) => {
                if ContentHash::from_bytes(&existing) == key && existing == bytes {
                    return Ok(key);
                }
                true
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(source) => {
                return Err(DagStoreError::Io {
                    operation: "read",
                    path,
                    source,
                });
            }
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| DagStoreError::Io {
                operation: "create-dir",
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let temp_path = local_store_temp_path(&path, &key);
        fs::write(&temp_path, bytes).map_err(|source| DagStoreError::Io {
            operation: "write",
            path: temp_path.clone(),
            source,
        })?;
        if replace_existing {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(source) => {
                    let _ = fs::remove_file(&temp_path);
                    return Err(DagStoreError::Io {
                        operation: "remove",
                        path,
                        source,
                    });
                }
            }
        }
        if let Err(source) = fs::rename(&temp_path, &path) {
            if let Ok(existing) = fs::read(&path) {
                if ContentHash::from_bytes(&existing) == key && existing == bytes {
                    let _ = fs::remove_file(&temp_path);
                    return Ok(key);
                }
            }
            let _ = fs::remove_file(&temp_path);
            return Err(DagStoreError::Io {
                operation: "rename",
                path,
                source,
            });
        }
        Ok(key)
    }

    fn get(&self, key: &ContentHash) -> Result<Vec<u8>, DagStoreError> {
        let path = self.object_path(key);
        let bytes = fs::read(&path).map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                DagStoreError::NotFound { key: *key }
            } else {
                DagStoreError::Io {
                    operation: "read",
                    path: path.clone(),
                    source,
                }
            }
        })?;
        let actual = ContentHash::from_bytes(&bytes);
        if actual != *key {
            return Err(DagStoreError::ContentMismatch {
                expected: *key,
                actual,
            });
        }
        Ok(bytes)
    }

    fn exists(&self, key: &ContentHash) -> Result<bool, DagStoreError> {
        match self.get(key) {
            Ok(_) => Ok(true),
            Err(DagStoreError::NotFound { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn delete(&self, key: &ContentHash) -> Result<bool, DagStoreError> {
        let path = self.object_path(key);
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(DagStoreError::Io {
                operation: "delete",
                path,
                source,
            }),
        }
    }
}

/// Reproduction artifact expressed only as DAG-store keys.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DagStoreReproductionArtifact {
    /// Store key for the scenario definition bytes.
    pub scenario_def: ContentHash,
    /// Store key for the baked genesis snapshot bytes.
    pub genesis_snapshot: ContentHash,
    /// Store keys for the schedule-delta bytes needed to reconstruct the run.
    pub schedule_deltas: Vec<ContentHash>,
}

impl DagStoreReproductionArtifact {
    /// Builds a store-key reproduction artifact.
    #[must_use]
    pub fn new(
        scenario_def: ContentHash,
        genesis_snapshot: ContentHash,
        schedule_deltas: Vec<ContentHash>,
    ) -> Self {
        Self {
            scenario_def,
            genesis_snapshot,
            schedule_deltas,
        }
    }

    /// Returns the deduplicated store-key closure named by the artifact.
    #[must_use]
    pub fn store_keys(&self) -> BTreeSet<ContentHash> {
        let mut keys = BTreeSet::from([self.scenario_def, self.genesis_snapshot]);
        keys.extend(self.schedule_deltas.iter().copied());
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
        source: EngineError,
    },
    /// The DAG store rejected or failed a persistence operation.
    Store {
        /// The store operation being performed.
        operation: &'static str,
        /// The backend error.
        source: DagStoreError,
    },
}

impl fmt::Display for TemporalGraphStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine { operation, .. } => {
                write!(f, "temporal graph operation {operation} failed")
            }
            Self::Store { operation, .. } => {
                write!(f, "temporal graph store operation {operation} failed")
            }
        }
    }
}

impl Error for TemporalGraphStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Engine { source, .. } => Some(source),
            Self::Store { source, .. } => Some(source),
        }
    }
}

/// A handle to an immutable scenario definition.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScenarioDef {
    /// The content address of the scenario definition.
    id: ContentHash,
    /// The root entropy carried by this scenario definition.
    seed: Seed,
}

impl ScenarioDef {
    /// Returns the content address of this scenario definition.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        self.id
    }

    /// Returns the root entropy carried by this scenario definition.
    #[must_use]
    pub fn seed(&self) -> Seed {
        self.seed
    }

    /// Builds a scenario definition from canonical material.
    ///
    /// This helper is the engine-side content-addressing entry point for
    /// backend-produced canonical material.
    #[must_use]
    pub fn from_canonical_material(domain: &str, material: &str) -> Self {
        Self::from_canonical_material_with_seed(domain, material, Seed::default())
    }

    /// Builds a scenario definition from canonical material and root seed.
    ///
    /// This helper is the compatibility entry point for backend-produced
    /// canonical material when the caller also has the scenario seed component.
    /// The seed is included in the returned content address so it cannot drift
    /// from scenario identity.
    #[must_use]
    pub fn from_canonical_material_with_seed(domain: &str, material: &str, seed: Seed) -> Self {
        let material = format!("{material}\n{}", seed_material(seed));
        Self {
            id: ContentHash::from_canonical_material(domain, &material),
            seed,
        }
    }
}

impl World {
    /// Builds an opaque world handle from an already-computed content address.
    ///
    /// This is the compatibility path for backend tests and adapters that do
    /// not yet carry full spatial-graph node material.
    #[must_use]
    pub fn from_content_hash(id: ContentHash) -> Self {
        Self {
            id,
            nodes: Vec::new(),
            links: Vec::new(),
        }
    }

    /// Builds a world from an already-recorded identity and validated topology.
    ///
    /// This compatibility path lets adapters preserve an external world handle
    /// while still enforcing the same static topology invariants as
    /// [`World::from_nodes_and_links`]. Non-empty logical worlds derive
    /// [`ScenarioDef`] and bake identity from their node/link material rather
    /// than this recorded handle.
    ///
    /// # Errors
    ///
    /// Returns the same topology and ready-point validation errors as
    /// [`World::from_nodes_and_links`].
    pub fn from_recorded_parts(
        id: ContentHash,
        nodes: Vec<WorldNode>,
        links: Vec<LinkDef>,
    ) -> Result<Self, EngineError> {
        let nodes = canonical_world_nodes(&nodes);
        let links = canonical_world_links(&links);
        validate_world_nodes(&nodes)?;
        validate_world_links(&nodes, &links)?;
        Ok(Self { id, nodes, links })
    }

    /// Returns the world content address carried by this handle.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        self.id
    }

    /// Returns this world's immutable node topology.
    #[must_use]
    pub fn nodes(&self) -> &[WorldNode] {
        &self.nodes
    }

    /// Returns this world's immutable logical links.
    #[must_use]
    pub fn links(&self) -> &[LinkDef] {
        &self.links
    }

    /// Builds a canonical world from node ready-point configuration.
    ///
    /// Nodes are sorted by [`NodeId`] before hashing so authoring order does not
    /// affect the world identity.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DuplicateWorldNodeId`] when a node id appears
    /// more than once, or [`EngineError::WhiteBoxReadyPointWithoutOptIn`] when
    /// a node selects [`ReadyPoint::AgentSignal`] without enabling
    /// [`WhiteBoxPolicy::Enabled`].
    pub fn from_nodes(nodes: Vec<WorldNode>) -> Result<Self, EngineError> {
        Self::from_nodes_and_links(nodes, Vec::new())
    }

    /// Builds a canonical world from node and link topology.
    ///
    /// Nodes are sorted by [`NodeId`] and links are sorted by endpoint pair
    /// before hashing so authoring order does not affect world identity.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DuplicateWorldNodeId`] when a node id appears
    /// more than once, [`EngineError::WhiteBoxReadyPointWithoutOptIn`] when a
    /// node selects [`ReadyPoint::AgentSignal`] without enabling
    /// [`WhiteBoxPolicy::Enabled`], [`EngineError::WorldLinkUnknownNode`] when
    /// a link references an undeclared node, [`EngineError::WorldLinkSelfLoop`]
    /// when a link's endpoints are equal, or [`EngineError::DuplicateWorldLink`]
    /// when a canonical endpoint pair appears more than once. Returns
    /// [`EngineError::WorldLinkLatencyBelowFloor`] or
    /// [`EngineError::WorldLinkJitterBelowLatencyFloor`] when a link's
    /// transport configuration violates the latency floor.
    pub fn from_nodes_and_links(
        nodes: Vec<WorldNode>,
        links: Vec<LinkDef>,
    ) -> Result<Self, EngineError> {
        let nodes = canonical_world_nodes(&nodes);
        let links = canonical_world_links(&links);
        validate_world_nodes(&nodes)?;
        validate_world_links(&nodes, &links)?;
        Ok(Self {
            id: ContentHash::from_canonical_material(
                "crucible.model.world.v1",
                &world_material(&nodes, &links),
            ),
            nodes,
            links,
        })
    }

    /// Validates the world's ready-point policy configuration.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DuplicateWorldNodeId`] when a node id appears
    /// more than once, [`EngineError::WhiteBoxReadyPointWithoutOptIn`] when a
    /// node selects [`ReadyPoint::AgentSignal`] without enabling
    /// [`WhiteBoxPolicy::Enabled`], or a link validation error from
    /// [`World::validate_topology`].
    pub fn validate_ready_point_policies(&self) -> Result<(), EngineError> {
        self.validate_topology()
    }

    /// Validates the world's canonical node/link topology.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DuplicateWorldNodeId`] when a node id appears
    /// more than once, [`EngineError::WhiteBoxReadyPointWithoutOptIn`] when a
    /// node selects [`ReadyPoint::AgentSignal`] without enabling
    /// [`WhiteBoxPolicy::Enabled`], [`EngineError::WorldLinkUnknownNode`] when
    /// a link references an undeclared node, [`EngineError::WorldLinkSelfLoop`]
    /// when a link's endpoints are equal, or [`EngineError::DuplicateWorldLink`]
    /// when a canonical endpoint pair appears more than once. Returns
    /// [`EngineError::WorldLinkLatencyBelowFloor`] or
    /// [`EngineError::WorldLinkJitterBelowLatencyFloor`] when a link's
    /// transport configuration violates the latency floor.
    pub fn validate_topology(&self) -> Result<(), EngineError> {
        validate_world_nodes(&self.nodes)?;
        validate_world_links(&self.nodes, &self.links)
    }

    /// Derives the static topology products that are fixed by this world.
    ///
    /// The returned participant set, per-entity decision-RNG streams,
    /// scheduler-lookahead graph, and bake-node set are functions only of the
    /// world's node/link topology. They do not take a [`Schedule`] and therefore
    /// cannot vary with a schedule prefix.
    #[must_use]
    pub fn static_topology(&self) -> WorldStaticTopology {
        WorldStaticTopology {
            participants: world_participants(self),
            rng_streams: world_rng_streams(self),
            lookahead_graph: world_lookahead_edges(self),
            bake_nodes: world_bake_nodes(self),
        }
    }

    /// Builds the canonical genesis scenario definition for this world, empty plan,
    /// empty properties, and the default seed.
    ///
    /// Later builder work provides the explicit authoring surface; until then
    /// this helper composes the independently hashed `World`, empty [`Plan`],
    /// empty [`Properties`], and default [`Seed`] components.
    #[must_use]
    pub fn scenario_def(&self) -> ScenarioDef {
        self.scenario_def_from_components(&Plan::empty(), &Properties::empty(), Seed::default())
    }

    /// Builds the canonical scenario definition for this world, plan, and empty
    /// properties.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::PlanFaultUnknownNode`],
    /// [`EngineError::PlanFaultUnknownLink`],
    /// [`EngineError::PlanHealUnknownTag`],
    /// [`EngineError::PlanHealBeforeActivate`], or
    /// [`EngineError::PlanNotYetJoinedAfterStart`] when `plan` cannot be
    /// layered over this world's static topology.
    pub fn scenario_def_with_plan(&self, plan: &Plan) -> Result<ScenarioDef, EngineError> {
        plan.validate_for_world(self)?;
        Ok(self.scenario_def_from_components(plan, &Properties::empty(), Seed::default()))
    }

    /// Builds the canonical scenario definition for this world, empty plan, and
    /// properties.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::PropertyDuplicateAssertionId`],
    /// [`EngineError::PropertyPredicateUnknownNode`], or
    /// [`EngineError::PropertyPredicateEmptyCompound`] when `properties` cannot
    /// be layered over this world's static topology.
    pub fn scenario_def_with_properties(
        &self,
        properties: &Properties,
    ) -> Result<ScenarioDef, EngineError> {
        properties.validate_for_world(self)?;
        Ok(self.scenario_def_from_components(&Plan::empty(), properties, Seed::default()))
    }

    /// Builds the canonical scenario definition for this world, plan, and
    /// properties, using the default seed.
    ///
    /// # Errors
    ///
    /// Returns a plan validation error when `plan` cannot be layered over this
    /// world's static topology, or a property validation error when `properties`
    /// names undeclared predicate nodes or otherwise violates the declarative
    /// property model.
    pub fn scenario_def_with_plan_and_properties(
        &self,
        plan: &Plan,
        properties: &Properties,
    ) -> Result<ScenarioDef, EngineError> {
        plan.validate_for_world(self)?;
        properties.validate_for_world(self)?;
        Ok(self.scenario_def_from_components(plan, properties, Seed::default()))
    }

    /// Builds the canonical scenario definition for this world, empty plan,
    /// empty properties, and `seed`.
    #[must_use]
    pub fn scenario_def_with_seed(&self, seed: Seed) -> ScenarioDef {
        self.scenario_def_from_components(&Plan::empty(), &Properties::empty(), seed)
    }

    /// Builds the canonical scenario definition for this world, plan,
    /// properties, and seed.
    ///
    /// # Errors
    ///
    /// Returns a plan validation error when `plan` cannot be layered over this
    /// world's static topology, or a property validation error when `properties`
    /// names undeclared predicate nodes or otherwise violates the declarative
    /// property model.
    pub fn scenario_def_with_plan_properties_and_seed(
        &self,
        plan: &Plan,
        properties: &Properties,
        seed: Seed,
    ) -> Result<ScenarioDef, EngineError> {
        plan.validate_for_world(self)?;
        properties.validate_for_world(self)?;
        Ok(self.scenario_def_from_components(plan, properties, seed))
    }

    /// Derives this world's per-entity decision-RNG stream seeds from `seed`.
    #[must_use]
    pub fn seeded_rng_streams(&self, seed: Seed) -> Vec<SeededRngStream> {
        self.static_topology()
            .rng_streams
            .into_iter()
            .map(|stream| SeededRngStream {
                seed: seed.stream_seed(&stream),
                stream,
            })
            .collect()
    }

    /// Serializes this world component as deterministic TOML.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] if the TOML renderer rejects
    /// the internal DTO shape.
    pub fn to_canonical_toml(&self) -> Result<String, EngineError> {
        toml::to_string(&world_to_toml(self)).map_err(|source| {
            scenario_serialization_error(format!("serialize world TOML: {source}"))
        })
    }

    /// Parses and validates a deterministic TOML world component.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed TOML or an id
    /// mismatch, or a world validation error for invalid topology.
    pub fn from_canonical_toml(input: &str) -> Result<Self, EngineError> {
        validate_no_host_path_image_refs_in_toml(input)?;
        let toml = toml::from_str::<WorldToml>(input).map_err(|source| {
            scenario_serialization_error(format!("parse world TOML: {source}"))
        })?;
        world_from_toml(toml)
    }

    /// Serializes this world component as compact binary.
    #[must_use]
    pub fn to_compact_binary(&self) -> Vec<u8> {
        let mut writer = ScenarioBinaryWriter::new(WORLD_BINARY_MAGIC);
        write_world_binary(self, &mut writer);
        writer.finish()
    }

    /// Parses and validates a compact binary world component.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed binary input
    /// or an id mismatch, or a world validation error for invalid topology.
    pub fn from_compact_binary(bytes: &[u8]) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, WORLD_BINARY_MAGIC)?;
        let world = read_world_binary(&mut reader)?;
        reader.finish()?;
        Ok(world)
    }

    /// Returns the canonical bytes used to compute this world's content address.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        world_material(
            &canonical_world_nodes(&self.nodes),
            &canonical_world_links(&self.links),
        )
        .into_bytes()
    }

    fn scenario_def_from_components(
        &self,
        plan: &Plan,
        properties: &Properties,
        seed: Seed,
    ) -> ScenarioDef {
        let material = scenario_world_plan_properties_seed_material(self, plan, properties, seed);
        ScenarioDef {
            id: ContentHash::from_canonical_material(
                "crucible.model.world-plan-properties-seed-scenario.v1",
                &material,
            ),
            seed,
        }
    }
}

/// Reusable node settings for code-first scenario authoring.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NodeTemplate {
    ready_point: ReadyPoint,
    white_box: WhiteBoxPolicy,
    kernel: Option<ContentAddressedBlobRef>,
    root_image: Option<ContentAddressedBlobRef>,
    initrd: Option<ContentAddressedBlobRef>,
}

impl NodeTemplate {
    /// Builds a node template with the supplied ready point and white-box disabled.
    #[must_use]
    pub fn new(ready_point: ReadyPoint) -> Self {
        Self {
            ready_point,
            white_box: WhiteBoxPolicy::Disabled,
            kernel: None,
            root_image: None,
            initrd: None,
        }
    }

    /// Builds a template for a fixed-instruction ready point.
    #[must_use]
    pub fn fixed_icount(icount: Icount) -> Self {
        Self::new(ReadyPoint::FixedIcount { icount })
    }

    /// Builds a template for a network-idle ready point.
    #[must_use]
    pub fn network_idle(window: SimDuration) -> Self {
        Self::new(ReadyPoint::NetworkIdle { window })
    }

    /// Builds a template for a console-marker ready point.
    #[must_use]
    pub fn console_marker(marker: impl Into<String>) -> Self {
        Self::new(ReadyPoint::ConsoleMarker {
            marker: marker.into(),
        })
    }

    /// Builds a template for an agent-signal ready point with white-box opt-in.
    #[must_use]
    pub fn agent_signal() -> Self {
        Self {
            ready_point: ReadyPoint::AgentSignal,
            white_box: WhiteBoxPolicy::Enabled,
            kernel: None,
            root_image: None,
            initrd: None,
        }
    }

    /// Builds a node template by copying another world node's settings.
    #[must_use]
    pub fn from_world_node(node: &WorldNode) -> Self {
        Self {
            ready_point: node.ready_point.clone(),
            white_box: node.white_box,
            kernel: node.kernel,
            root_image: node.root_image,
            initrd: node.initrd,
        }
    }

    /// Replaces the template ready point.
    #[must_use]
    pub fn ready_point(mut self, ready_point: ReadyPoint) -> Self {
        self.ready_point = ready_point;
        self
    }

    /// Replaces the template white-box policy.
    #[must_use]
    pub fn white_box(mut self, white_box: WhiteBoxPolicy) -> Self {
        self.white_box = white_box;
        self
    }

    /// Replaces the template kernel blob reference.
    #[must_use]
    pub fn kernel(mut self, kernel: ContentAddressedBlobRef) -> Self {
        self.kernel = Some(kernel);
        self
    }

    /// Replaces the template root-image blob reference.
    #[must_use]
    pub fn root_image(mut self, root_image: ContentAddressedBlobRef) -> Self {
        self.root_image = Some(root_image);
        self
    }

    /// Replaces the template initrd blob reference.
    #[must_use]
    pub fn initrd(mut self, initrd: ContentAddressedBlobRef) -> Self {
        self.initrd = Some(initrd);
        self
    }

    fn instantiate(&self, id: NodeId) -> WorldNode {
        WorldNode {
            id,
            ready_point: self.ready_point.clone(),
            white_box: self.white_box,
            kernel: self.kernel,
            root_image: self.root_image,
            initrd: self.initrd,
        }
    }
}

impl From<WorldNode> for NodeTemplate {
    fn from(node: WorldNode) -> Self {
        Self::from_world_node(&node)
    }
}

/// Code-first scenario authoring surface for the four orthogonal scenario layers.
#[derive(Clone, Debug, Default)]
pub struct ScenarioBuilder {
    nodes: Vec<PendingScenarioNode>,
    links: Vec<PendingScenarioLink>,
    plan: Option<Plan>,
    plan_entries: Vec<PlanEntry>,
    properties: Option<Properties>,
    assertions: Vec<AssertionDef>,
    seed: Seed,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum PendingScenarioNode {
    Concrete(WorldNode),
    Like { id: NodeId, template: NodeId },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum PendingScenarioLink {
    Default {
        left: NodeId,
        right: NodeId,
    },
    Transport {
        left: NodeId,
        right: NodeId,
        latency: SimDuration,
        jitter: SimDuration,
        loss: LinkLossProbability,
        bandwidth_bps: Option<u64>,
    },
    Concrete(LinkDef),
}

impl ScenarioBuilder {
    /// Starts an empty scenario builder with empty plan/properties and default seed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Copies a complete world into the builder's world layer.
    #[must_use]
    pub fn world(mut self, world: &World) -> Self {
        self.nodes.extend(
            world
                .nodes()
                .iter()
                .cloned()
                .map(PendingScenarioNode::Concrete),
        );
        self.links.extend(
            world
                .links()
                .iter()
                .cloned()
                .map(PendingScenarioLink::Concrete),
        );
        self
    }

    /// Adds a concrete node from a reusable node template.
    #[must_use]
    pub fn node(mut self, name: impl Into<String>, template: NodeTemplate) -> Self {
        let id = NodeId { name: name.into() };
        self.nodes
            .push(PendingScenarioNode::Concrete(template.instantiate(id)));
        self
    }

    /// Adds a node by copying another declared node's template settings at build time.
    #[must_use]
    pub fn node_like(mut self, name: impl Into<String>, template: impl Into<String>) -> Self {
        self.nodes.push(PendingScenarioNode::Like {
            id: NodeId { name: name.into() },
            template: NodeId {
                name: template.into(),
            },
        });
        self
    }

    /// Adds a default logical world link between two node names.
    #[must_use]
    pub fn link(mut self, left: impl Into<String>, right: impl Into<String>) -> Self {
        self.links.push(PendingScenarioLink::Default {
            left: NodeId { name: left.into() },
            right: NodeId { name: right.into() },
        });
        self
    }

    /// Adds a logical world link with explicit transport characteristics.
    #[must_use]
    pub fn link_with_transport(
        mut self,
        left: impl Into<String>,
        right: impl Into<String>,
        latency: SimDuration,
        jitter: SimDuration,
        loss: LinkLossProbability,
        bandwidth_bps: Option<u64>,
    ) -> Self {
        self.links.push(PendingScenarioLink::Transport {
            left: NodeId { name: left.into() },
            right: NodeId { name: right.into() },
            latency,
            jitter,
            loss,
            bandwidth_bps,
        });
        self
    }

    /// Adds an already-constructed logical world link.
    #[must_use]
    pub fn link_def(mut self, link: LinkDef) -> Self {
        self.links.push(PendingScenarioLink::Concrete(link));
        self
    }

    /// Sets the complete plan layer.
    #[must_use]
    pub fn plan(mut self, plan: Plan) -> Self {
        self.plan = Some(plan);
        self.plan_entries.clear();
        self
    }

    /// Adds one plan entry to the plan layer.
    #[must_use]
    pub fn plan_entry(mut self, entry: PlanEntry) -> Self {
        self.plan = None;
        self.plan_entries.push(entry);
        self
    }

    /// Sets the complete properties layer.
    #[must_use]
    pub fn properties(mut self, properties: Properties) -> Self {
        self.properties = Some(properties);
        self.assertions.clear();
        self
    }

    /// Adds one assertion to the properties layer.
    #[must_use]
    pub fn property(mut self, assertion: AssertionDef) -> Self {
        self.properties = None;
        self.assertions.push(assertion);
        self
    }

    /// Sets the scenario root entropy.
    #[must_use]
    pub fn seed(mut self, seed: Seed) -> Self {
        self.seed = seed;
        self
    }

    /// Builds, validates, canonicalizes, and content-addresses the scenario.
    ///
    /// # Errors
    ///
    /// Returns world validation errors for invalid node/link topology, plan
    /// validation errors when plan entries cannot layer over the static world,
    /// property validation errors when assertions reference undeclared nodes or
    /// malformed compound predicates, or
    /// [`EngineError::ScenarioBuilderUnknownNodeTemplate`] when a `node_like`
    /// entry names no concrete node template.
    pub fn build(self) -> Result<ScenarioDef, EngineError> {
        let world = World::from_nodes_and_links(self.build_nodes()?, self.build_links()?)?;
        let plan = self.build_plan(&world)?;
        let properties = self.build_properties(&world)?;
        world.scenario_def_with_plan_properties_and_seed(&plan, &properties, self.seed)
    }

    fn build_nodes(&self) -> Result<Vec<WorldNode>, EngineError> {
        let mut templates = BTreeMap::new();
        let mut nodes = Vec::with_capacity(self.nodes.len());

        for pending in &self.nodes {
            if let PendingScenarioNode::Concrete(node) = pending {
                templates.insert(node.id.clone(), NodeTemplate::from_world_node(node));
                nodes.push(node.clone());
            }
        }

        for pending in &self.nodes {
            if let PendingScenarioNode::Like { id, template } = pending {
                let node_template = templates.get(template).ok_or_else(|| {
                    EngineError::ScenarioBuilderUnknownNodeTemplate {
                        node: id.clone(),
                        template: template.clone(),
                    }
                })?;
                nodes.push(node_template.instantiate(id.clone()));
            }
        }

        Ok(nodes)
    }

    fn build_links(&self) -> Result<Vec<LinkDef>, EngineError> {
        self.links
            .iter()
            .map(|pending| match pending {
                PendingScenarioLink::Default { left, right } => {
                    LinkDef::new(left.clone(), right.clone())
                }
                PendingScenarioLink::Transport {
                    left,
                    right,
                    latency,
                    jitter,
                    loss,
                    bandwidth_bps,
                } => LinkDef::with_transport(
                    left.clone(),
                    right.clone(),
                    *latency,
                    *jitter,
                    *loss,
                    *bandwidth_bps,
                ),
                PendingScenarioLink::Concrete(link) => Ok(link.clone()),
            })
            .collect()
    }

    fn build_plan(&self, world: &World) -> Result<Plan, EngineError> {
        if let Some(plan) = &self.plan {
            plan.validate_for_world(world)?;
            return Ok(plan.clone());
        }

        if self.plan_entries.is_empty() {
            Ok(Plan::empty())
        } else {
            Plan::from_entries_for_world(world, self.plan_entries.clone())
        }
    }

    fn build_properties(&self, world: &World) -> Result<Properties, EngineError> {
        if let Some(properties) = &self.properties {
            properties.validate_for_world(world)?;
            return Ok(properties.clone());
        }

        if self.assertions.is_empty() {
            Ok(Properties::empty())
        } else {
            Properties::from_assertions_for_world(world, self.assertions.clone())
        }
    }
}

/// A deterministic fixed-point fault density for [`ScenarioFamily`] generation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FaultDensity {
    millionths: u32,
}

impl FaultDensity {
    /// The density that generates no family faults.
    pub const ZERO: Self = Self { millionths: 0 };

    /// The density that selects every deterministic fault candidate.
    pub const ONE: Self = Self {
        millionths: MAX_FAMILY_FAULT_DENSITY_MILLIONTHS,
    };

    /// Builds a density from millionths in the closed range `[0, 1_000_000]`.
    ///
    /// `0` means no generated faults, and `1_000_000` means every candidate fault
    /// for the generated topology. The fixed-point representation avoids
    /// floating-point ambiguity in family parameter points.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::FaultDensityOutOfRange`] when `millionths` is greater
    /// than `1_000_000`.
    pub fn from_millionths(millionths: u32) -> Result<Self, EngineError> {
        if millionths > MAX_FAMILY_FAULT_DENSITY_MILLIONTHS {
            return Err(EngineError::FaultDensityOutOfRange {
                millionths,
                maximum: MAX_FAMILY_FAULT_DENSITY_MILLIONTHS,
            });
        }

        Ok(Self { millionths })
    }

    /// Returns this density as millionths in the closed range `[0, 1_000_000]`.
    #[must_use]
    pub fn millionths(self) -> u32 {
        self.millionths
    }

    fn scaled_count(self, candidates: usize) -> usize {
        if self.millionths == 0 || candidates == 0 {
            return 0;
        }

        let numerator = (candidates as u128) * u128::from(self.millionths);
        let denominator = u128::from(MAX_FAMILY_FAULT_DENSITY_MILLIONTHS);
        ((numerator + denominator - 1) / denominator) as usize
    }
}

/// Inclusive finite range of family fault-density values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FaultDensityRange {
    min: FaultDensity,
    max: FaultDensity,
}

impl FaultDensityRange {
    /// Builds an inclusive fault-density range.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyInvalidSpace`] when `min > max`.
    pub fn new(min: FaultDensity, max: FaultDensity) -> Result<Self, EngineError> {
        if min > max {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "fault density range minimum exceeds maximum",
            });
        }

        Ok(Self { min, max })
    }

    /// Returns the minimum density in the range.
    #[must_use]
    pub fn min(self) -> FaultDensity {
        self.min
    }

    /// Returns the maximum density in the range.
    #[must_use]
    pub fn max(self) -> FaultDensity {
        self.max
    }

    /// Returns whether `density` is in this range.
    #[must_use]
    pub fn contains(self, density: FaultDensity) -> bool {
        self.min <= density && density <= self.max
    }

    fn len(self) -> u64 {
        u64::from(self.max.millionths - self.min.millionths) + 1
    }

    fn at(self, index: u64) -> Result<FaultDensity, EngineError> {
        if index >= self.len() {
            return Err(EngineError::ScenarioFamilyParameterOutOfSpace {
                parameter: "fault_density",
            });
        }
        FaultDensity::from_millionths(self.min.millionths + index as u32)
    }
}

/// Inclusive finite range of generated family topology sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TopologySizeRange {
    min: u32,
    max: u32,
}

impl TopologySizeRange {
    /// Builds an inclusive topology-size range.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyInvalidSpace`] when the range is empty,
    /// starts at zero, or exceeds the implementation's bounded generation limit.
    pub fn new(min: u32, max: u32) -> Result<Self, EngineError> {
        if min == 0 {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "topology size range must start above zero",
            });
        }
        if min > max {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "topology size range minimum exceeds maximum",
            });
        }
        if max > MAX_SCENARIO_FAMILY_TOPOLOGY_SIZE {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "topology size range exceeds family generation limit",
            });
        }

        Ok(Self { min, max })
    }

    /// Returns the minimum generated node count.
    #[must_use]
    pub fn min(self) -> u32 {
        self.min
    }

    /// Returns the maximum generated node count.
    #[must_use]
    pub fn max(self) -> u32 {
        self.max
    }

    /// Returns whether `size` is in this range.
    #[must_use]
    pub fn contains(self, size: u32) -> bool {
        self.min <= size && size <= self.max
    }

    fn len(self) -> u64 {
        u64::from(self.max - self.min) + 1
    }

    fn at(self, index: u64) -> Result<u32, EngineError> {
        if index >= self.len() {
            return Err(EngineError::ScenarioFamilyParameterOutOfSpace {
                parameter: "topology_size",
            });
        }
        Ok(self.min + index as u32)
    }
}

/// Topology shape axis for [`ScenarioFamily`] generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TopologyShape {
    /// Connect each node to its successor, wrapping the last node to the first.
    Ring,
    /// Connect every non-center node to `node-0`.
    Star,
    /// Connect every node pair.
    Mesh,
    /// Build a deterministic seed-derived connected graph.
    Random,
}

/// Finite seed axis for [`ScenarioFamily`] generation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SeedSpace {
    kind: SeedSpaceKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum SeedSpaceKind {
    Explicit(Vec<Seed>),
    Generated { meta_seed: Seed, count: u32 },
}

impl SeedSpace {
    /// Builds a seed space from an explicit set of seeds.
    ///
    /// The stored set is sorted for deterministic sampling.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyInvalidSpace`] when `seeds` is empty,
    /// too large, or contains duplicates.
    pub fn explicit(seeds: Vec<Seed>) -> Result<Self, EngineError> {
        if seeds.is_empty() {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "seed space must not be empty",
            });
        }
        if seeds.len() > MAX_SCENARIO_FAMILY_SEEDS as usize {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "seed space exceeds family generation limit",
            });
        }

        let mut seeds = seeds;
        seeds.sort();
        if seeds.windows(2).any(|window| window[0] == window[1]) {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "seed space contains duplicate seeds",
            });
        }

        Ok(Self {
            kind: SeedSpaceKind::Explicit(seeds),
        })
    }

    /// Builds a finite seed space deterministically derived from `meta_seed`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyInvalidSpace`] when `count` is zero or
    /// exceeds the implementation's bounded generation limit.
    pub fn generated(meta_seed: Seed, count: u32) -> Result<Self, EngineError> {
        if count == 0 {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "generated seed space must not be empty",
            });
        }
        if count > MAX_SCENARIO_FAMILY_SEEDS {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "seed space exceeds family generation limit",
            });
        }

        Ok(Self {
            kind: SeedSpaceKind::Generated { meta_seed, count },
        })
    }

    /// Returns the number of seeds in this finite seed space.
    #[must_use]
    pub fn len(&self) -> u64 {
        match &self.kind {
            SeedSpaceKind::Explicit(seeds) => seeds.len() as u64,
            SeedSpaceKind::Generated { count, .. } => u64::from(*count),
        }
    }

    /// Returns whether this seed space is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the seed at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyParameterOutOfSpace`] when `index` is
    /// outside this finite seed space.
    pub fn seed_at(&self, index: u64) -> Result<Seed, EngineError> {
        if index >= self.len() {
            return Err(EngineError::ScenarioFamilyParameterOutOfSpace { parameter: "seed" });
        }

        match &self.kind {
            SeedSpaceKind::Explicit(seeds) => Ok(seeds[index as usize]),
            SeedSpaceKind::Generated { meta_seed, .. } => Ok(derive_family_seed(*meta_seed, index)),
        }
    }

    fn contains(&self, seed: Seed) -> bool {
        match &self.kind {
            SeedSpaceKind::Explicit(seeds) => seeds.binary_search(&seed).is_ok(),
            SeedSpaceKind::Generated { count, meta_seed } => {
                (0..u64::from(*count)).any(|index| derive_family_seed(*meta_seed, index) == seed)
            }
        }
    }
}

/// The deterministic parameter space a [`ScenarioFamily`] ranges over.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FamilySpace {
    seeds: SeedSpace,
    fault_density: FaultDensityRange,
    topology_size: TopologySizeRange,
    topology_shapes: Vec<TopologyShape>,
}

impl FamilySpace {
    /// Builds a finite family parameter space.
    ///
    /// Shapes are sorted and deduplicated so sampling is deterministic regardless
    /// of authoring order.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyInvalidSpace`] when `topology_shapes`
    /// is empty.
    pub fn new(
        seeds: SeedSpace,
        fault_density: FaultDensityRange,
        topology_size: TopologySizeRange,
        topology_shapes: Vec<TopologyShape>,
    ) -> Result<Self, EngineError> {
        if topology_shapes.is_empty() {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "topology shape set must not be empty",
            });
        }

        let mut topology_shapes = topology_shapes;
        topology_shapes.sort();
        topology_shapes.dedup();

        Ok(Self {
            seeds,
            fault_density,
            topology_size,
            topology_shapes,
        })
    }

    /// Returns this space's seed axis.
    #[must_use]
    pub fn seeds(&self) -> &SeedSpace {
        &self.seeds
    }

    /// Returns this space's fault-density axis.
    #[must_use]
    pub fn fault_density(&self) -> FaultDensityRange {
        self.fault_density
    }

    /// Returns this space's topology-size axis.
    #[must_use]
    pub fn topology_size(&self) -> TopologySizeRange {
        self.topology_size
    }

    /// Returns this space's canonical topology-shape axis.
    #[must_use]
    pub fn topology_shapes(&self) -> &[TopologyShape] {
        &self.topology_shapes
    }

    /// Returns whether `params` lies inside this space.
    #[must_use]
    pub fn contains(&self, params: FamilyParams) -> bool {
        self.seeds.contains(params.seed)
            && self.fault_density.contains(params.fault_density)
            && self.topology_size.contains(params.topology_size)
            && self
                .topology_shapes
                .binary_search(&params.topology_shape)
                .is_ok()
    }

    /// Returns the finite cardinality of this family space.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyInvalidSpace`] if the finite space size
    /// overflows `u64`.
    pub fn cardinality(&self) -> Result<u64, EngineError> {
        let seed_count = self.seeds.len();
        let shape_count = self.topology_shapes.len() as u64;
        let size_count = self.topology_size.len();
        let density_count = self.fault_density.len();
        let total = seed_count
            .checked_mul(shape_count)
            .and_then(|count| count.checked_mul(size_count))
            .and_then(|count| count.checked_mul(density_count))
            .ok_or(EngineError::ScenarioFamilyInvalidSpace {
                reason: "family space cardinality overflows u64",
            })?;
        if total == 0 {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "family space must not be empty",
            });
        }

        Ok(total)
    }

    /// Deterministically samples one parameter point by cartesian index.
    ///
    /// The finite axes are traversed in seed, shape, size, then density order.
    /// Callers that want an unbounded fuzz counter should explicitly wrap by
    /// [`Self::cardinality`] so exhaustive enumeration can still reject an
    /// out-of-space index.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyParameterOutOfSpace`] when `index` is
    /// greater than or equal to [`Self::cardinality`].
    pub fn sample(&self, index: u64) -> Result<FamilyParams, EngineError> {
        let total = self.cardinality()?;
        if index >= total {
            return Err(EngineError::ScenarioFamilyParameterOutOfSpace {
                parameter: "sample_index",
            });
        }

        let seed_count = self.seeds.len();
        let shape_count = self.topology_shapes.len() as u64;
        let size_count = self.topology_size.len();
        let density_count = self.fault_density.len();
        let mut index = index;
        let seed = self.seeds.seed_at(index % seed_count)?;
        index /= seed_count;
        let topology_shape = self.topology_shapes[(index % shape_count) as usize];
        index /= shape_count;
        let topology_size = self.topology_size.at(index % size_count)?;
        index /= size_count;
        let fault_density = self.fault_density.at(index % density_count)?;

        Ok(FamilyParams {
            seed,
            fault_density,
            topology_size,
            topology_shape,
        })
    }

    fn validate_params(&self, params: FamilyParams) -> Result<(), EngineError> {
        if !self.seeds.contains(params.seed) {
            return Err(EngineError::ScenarioFamilyParameterOutOfSpace { parameter: "seed" });
        }
        if !self.fault_density.contains(params.fault_density) {
            return Err(EngineError::ScenarioFamilyParameterOutOfSpace {
                parameter: "fault_density",
            });
        }
        if !self.topology_size.contains(params.topology_size) {
            return Err(EngineError::ScenarioFamilyParameterOutOfSpace {
                parameter: "topology_size",
            });
        }
        if self
            .topology_shapes
            .binary_search(&params.topology_shape)
            .is_err()
        {
            return Err(EngineError::ScenarioFamilyParameterOutOfSpace {
                parameter: "topology_shape",
            });
        }

        Ok(())
    }
}

/// One concrete point sampled from a [`ScenarioFamily`] parameter space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FamilyParams {
    /// Concrete root seed for the pinned scenario.
    pub seed: Seed,
    /// Concrete exact fault density used to generate the plan.
    pub fault_density: FaultDensity,
    /// Concrete generated node count.
    pub topology_size: u32,
    /// Concrete generated topology shape.
    pub topology_shape: TopologyShape,
}

/// Parametric generator over concrete, validated scenario definitions.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScenarioFamily {
    space: FamilySpace,
    node_template: NodeTemplate,
    assertions: Vec<AssertionDef>,
}

impl ScenarioFamily {
    /// Builds a scenario family from a parameter space and reusable node template.
    #[must_use]
    pub fn new(space: FamilySpace, node_template: NodeTemplate) -> Self {
        Self {
            space,
            node_template,
            assertions: Vec::new(),
        }
    }

    /// Returns the parameter space this family ranges over.
    #[must_use]
    pub fn space(&self) -> &FamilySpace {
        &self.space
    }

    /// Adds one assertion to every generated scenario's properties layer.
    #[must_use]
    pub fn property(mut self, assertion: AssertionDef) -> Self {
        self.assertions.push(assertion);
        self
    }

    /// Instantiates a concrete validated scenario at `params`.
    ///
    /// The returned [`PinnedScenario`] contains the concrete [`ScenarioDefForm`]
    /// used by execution and reproduction. It carries no reference back to this
    /// family, so callers can only run the pinned scenario definition.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyParameterOutOfSpace`] when `params`
    /// does not lie in the family space, or the usual world/plan/properties
    /// validation errors if the generated scenario is invalid.
    pub fn instantiate(&self, params: FamilyParams) -> Result<PinnedScenario, EngineError> {
        self.space.validate_params(params)?;
        let world = self.build_world(params)?;
        let plan = self.build_plan(&world, params)?;
        let properties = Properties::from_assertions_for_world(&world, self.assertions.clone())?;
        let form = ScenarioDefForm::from_components(&world, &plan, &properties, params.seed)?;
        Ok(PinnedScenario { params, form })
    }

    /// Samples and instantiates one deterministic parameter point.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`FamilySpace::sample`] or [`Self::instantiate`].
    pub fn instantiate_sample(&self, index: u64) -> Result<PinnedScenario, EngineError> {
        let params = self.space.sample(index)?;
        self.instantiate(params)
    }

    fn build_world(&self, params: FamilyParams) -> Result<World, EngineError> {
        let nodes = (0..params.topology_size)
            .map(|index| self.node_template.instantiate(family_node_id(index)))
            .collect::<Vec<_>>();
        let links = family_links(params)?;
        World::from_nodes_and_links(nodes, links)
    }

    fn build_plan(&self, world: &World, params: FamilyParams) -> Result<Plan, EngineError> {
        let candidates = family_fault_candidates(world);
        let fault_count = params.fault_density.scaled_count(candidates.len());
        let mut entries = Vec::with_capacity(fault_count.saturating_mul(2));
        for (index, candidate) in candidates.into_iter().take(fault_count).enumerate() {
            let activate_at = VirtualTime {
                ticks: FAMILY_FAULT_STEP_TICKS
                    .checked_mul(index as u64 + 1)
                    .ok_or(EngineError::ScenarioFamilyInvalidSpace {
                        reason: "generated family fault time overflows u64",
                    })?,
            };
            let heal_at = VirtualTime {
                ticks: activate_at
                    .ticks
                    .checked_add(FAMILY_FAULT_HEAL_DELAY_TICKS)
                    .ok_or(EngineError::ScenarioFamilyInvalidSpace {
                        reason: "generated family heal time overflows u64",
                    })?,
            };
            let tag = FaultTag::from_name(format!("family-fault-{index}"));
            entries.push(PlanEntry::Activate {
                at: activate_at,
                tag: tag.clone(),
                fault: candidate.into_fault(),
            });
            entries.push(PlanEntry::Heal { at: heal_at, tag });
        }

        Plan::from_entries_for_world(world, entries)
    }
}

/// A concrete scenario pinned from a [`ScenarioFamily`] parameter point.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PinnedScenario {
    params: FamilyParams,
    form: ScenarioDefForm,
}

impl PinnedScenario {
    /// Returns the family parameters that produced this pinned instance.
    #[must_use]
    pub fn params(&self) -> FamilyParams {
        self.params
    }

    /// Returns the materialized concrete scenario form.
    #[must_use]
    pub fn form(&self) -> &ScenarioDefForm {
        &self.form
    }

    /// Consumes this pinned instance and returns its concrete scenario form.
    #[must_use]
    pub fn into_form(self) -> ScenarioDefForm {
        self.form
    }

    /// Reconstructs the concrete scenario definition used by execution.
    #[must_use]
    pub fn scenario_def(&self) -> ScenarioDef {
        self.form.scenario_def()
    }

    /// Builds the genesis execution configuration while retaining the concrete form.
    #[must_use]
    pub fn genesis_configuration(&self) -> PinnedConfiguration {
        PinnedConfiguration {
            scenario: self.form.clone(),
            configuration: Configuration::genesis(self.scenario_def()),
        }
    }

    /// Returns the concrete scenario id.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        self.form.id()
    }
}

/// A run configuration pinned to a concrete materialized scenario form.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PinnedConfiguration {
    scenario: ScenarioDefForm,
    configuration: Configuration,
}

impl PinnedConfiguration {
    /// Returns the concrete materialized scenario form for reproduction.
    #[must_use]
    pub fn scenario_form(&self) -> &ScenarioDefForm {
        &self.scenario
    }

    /// Returns the executable configuration handle for the pinned scenario.
    #[must_use]
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    /// Consumes this pinned configuration into its concrete parts.
    #[must_use]
    pub fn into_parts(self) -> (ScenarioDefForm, Configuration) {
        (self.scenario, self.configuration)
    }
}

/// A self-contained `(seed, scenario, schedule)` reproduction bundle.
///
/// The seed is not stored as a drifting side channel: it is the embedded
/// [`ScenarioDefForm`]'s own seed. The artifact carries only the complete
/// validated scenario form and recorded schedule, so its identity is exactly the
/// RFC tuple `(seed, scenario, schedule)` without a parent family or host path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReproductionArtifact {
    id: ContentHash,
    scenario: ScenarioDefForm,
    schedule: Schedule,
}

impl ReproductionArtifact {
    /// Captures an artifact by reducing `schedule` from `scenario`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] if the reduction function rejects the supplied
    /// scenario/schedule pair.
    pub fn capture(scenario: &ScenarioDefForm, schedule: &Schedule) -> Result<Self, EngineError> {
        let artifact = Self::from_recorded_parts(scenario.clone(), schedule.clone());
        let _ = artifact.replay()?;
        Ok(artifact)
    }

    /// Captures an artifact from an executable pinned configuration.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] if replaying the pinned configuration's scenario
    /// and schedule cannot derive a reduced state.
    pub fn from_pinned_configuration(pinned: &PinnedConfiguration) -> Result<Self, EngineError> {
        Self::capture(pinned.scenario_form(), &pinned.configuration().schedule)
    }

    /// Rebuilds an artifact from already-recorded self-contained parts.
    #[must_use]
    pub fn from_recorded_parts(scenario: ScenarioDefForm, schedule: Schedule) -> Self {
        let id =
            ContentHash::from_bytes(&reproduction_artifact_canonical_bytes(&scenario, &schedule));
        Self {
            id,
            scenario,
            schedule,
        }
    }

    /// Parses a compact canonical artifact representation.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed artifact,
    /// scenario, or schedule bytes.
    pub fn from_compact_binary(bytes: &[u8]) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, REPRODUCTION_ARTIFACT_BINARY_MAGIC)?;
        let scenario_bytes = reader.read_binary_blob("reproduction-artifact.scenario")?;
        let schedule_bytes = reader.read_binary_blob("reproduction-artifact.schedule")?;
        reader.finish()?;

        let scenario = ScenarioDefForm::from_compact_binary(scenario_bytes)?;
        let schedule = Schedule::from_compact_binary(schedule_bytes)?;
        Ok(Self::from_recorded_parts(scenario, schedule))
    }

    /// Returns the BLAKE3 content address over this artifact's canonical bytes.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        self.id
    }

    /// Returns the concrete serialized scenario form carried by this artifact.
    #[must_use]
    pub fn scenario_form(&self) -> &ScenarioDefForm {
        &self.scenario
    }

    /// Reconstructs the immutable scenario definition carried by this artifact.
    #[must_use]
    pub fn scenario_def(&self) -> ScenarioDef {
        self.scenario.scenario_def()
    }

    /// Returns the scenario definition's root seed.
    #[must_use]
    pub fn seed(&self) -> Seed {
        self.scenario.seed()
    }

    /// Returns the recorded schedule carried by this artifact.
    #[must_use]
    pub fn schedule(&self) -> &Schedule {
        &self.schedule
    }

    /// Returns the canonical byte serialization hashed by [`Self::id`].
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        reproduction_artifact_canonical_bytes(&self.scenario, &self.schedule)
    }

    /// Serializes this artifact as compact canonical bytes.
    #[must_use]
    pub fn to_compact_binary(&self) -> Vec<u8> {
        self.canonical_bytes()
    }

    /// Replays the artifact through the reduction oracle.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] if the reduction function rejects the embedded
    /// scenario/schedule pair.
    pub fn replay(&self) -> Result<ReproductionReplay, EngineError> {
        let state = reduce(&self.scenario_def(), &self.schedule)?;
        Ok(ReproductionReplay {
            artifact: self.id,
            scenario: self.scenario.id(),
            schedule: self.schedule.content_hash(),
            state: state.id,
        })
    }

    /// Replays the artifact and compares the result with an external target state.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReproductionArtifactReplayMismatch`] when the
    /// embedded scenario and schedule reduce to a state other than `expected`.
    /// Returns other [`EngineError`] variants if the reduction itself fails.
    pub fn verify_replay(&self, expected: ContentHash) -> Result<ReproductionReplay, EngineError> {
        let replay = self.replay()?;
        if replay.state != expected {
            return Err(EngineError::ReproductionArtifactReplayMismatch {
                artifact: self.id,
                expected,
                actual: replay.state,
            });
        }
        Ok(replay)
    }
}

/// Successful replay-oracle verification of a reproduction artifact.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReproductionReplay {
    /// The artifact whose replay was verified.
    pub artifact: ContentHash,
    /// The embedded scenario definition id used for replay.
    pub scenario: ContentHash,
    /// The embedded recorded-schedule id used for replay.
    pub schedule: ContentHash,
    /// The reduced state reached by replay.
    pub state: ContentHash,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum FamilyFaultCandidate {
    Crash(NodeId),
    Partition {
        endpoint_a: NodeId,
        endpoint_b: NodeId,
    },
}

impl FamilyFaultCandidate {
    fn into_fault(self) -> MembershipFault {
        match self {
            Self::Crash(node) => MembershipFault::Crash {
                node,
                restart: RestartPolicy::FromReadyPoint,
            },
            Self::Partition {
                endpoint_a,
                endpoint_b,
            } => MembershipFault::Partition {
                endpoint_a,
                endpoint_b,
                direction: PartitionDirection::Bidirectional,
            },
        }
    }
}

/// A fully materialized scenario definition form for storage and exchange.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScenarioDefForm {
    world: World,
    plan: Plan,
    properties: Properties,
    seed: Seed,
}

impl ScenarioDefForm {
    /// Builds a serialized-form scenario from independently addressed components.
    ///
    /// The constructor validates that the plan and properties layer over `world`
    /// before the form can be serialized.
    ///
    /// # Errors
    ///
    /// Returns a world identity error when `world` carries non-canonical identity,
    /// a plan validation error when `plan` cannot layer over the static world, or a
    /// properties validation error when `properties` references undeclared nodes.
    pub fn from_components(
        world: &World,
        plan: &Plan,
        properties: &Properties,
        seed: Seed,
    ) -> Result<Self, EngineError> {
        validate_world_serialized_identity(world)?;
        plan.validate_for_world(world)?;
        properties.validate_for_world(world)?;
        Ok(Self {
            world: world.clone(),
            plan: plan.clone(),
            properties: properties.clone(),
            seed,
        })
    }

    /// Returns the serialized world component.
    #[must_use]
    pub fn world(&self) -> &World {
        &self.world
    }

    /// Returns the serialized plan component.
    #[must_use]
    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    /// Returns the serialized properties component.
    #[must_use]
    pub fn properties(&self) -> &Properties {
        &self.properties
    }

    /// Returns the serialized scenario seed component.
    #[must_use]
    pub fn seed(&self) -> Seed {
        self.seed
    }

    /// Reconstructs the immutable scenario definition handle.
    #[must_use]
    pub fn scenario_def(&self) -> ScenarioDef {
        self.world
            .scenario_def_from_components(&self.plan, &self.properties, self.seed)
    }

    /// Returns the content address of the reconstructed scenario definition.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        self.scenario_def().id()
    }

    /// Serializes this form as deterministic TOML.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] if the TOML renderer rejects
    /// the internal DTO shape.
    pub fn to_canonical_toml(&self) -> Result<String, EngineError> {
        toml::to_string(&scenario_form_to_toml(self)).map_err(|source| {
            scenario_serialization_error(format!("serialize scenario TOML: {source}"))
        })
    }

    /// Parses and validates a deterministic TOML scenario form.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed TOML or id
    /// mismatches, [`EngineError::PlanNegativeTime`],
    /// [`EngineError::PlanFaultUnknownDirection`], or
    /// [`EngineError::PlanFaultUnsupportedParam`] for localized serialized plan
    /// validation failures, or the same validation errors as the component
    /// constructors when the parsed world, plan, or properties are invalid.
    pub fn from_canonical_toml(input: &str) -> Result<Self, EngineError> {
        validate_no_host_path_image_refs_in_toml(input)?;
        validate_plan_entries_in_toml(input)?;
        let toml = toml::from_str::<ScenarioDefToml>(input).map_err(|source| {
            scenario_serialization_error(format!("parse scenario TOML: {source}"))
        })?;
        scenario_form_from_toml(toml)
    }

    /// Serializes this form as the compact canonical binary representation.
    #[must_use]
    pub fn to_compact_binary(&self) -> Vec<u8> {
        let mut writer = ScenarioBinaryWriter::new(SCENARIO_FORM_BINARY_MAGIC);
        write_scenario_form_binary(self, &mut writer);
        writer.finish()
    }

    /// Parses and validates a compact binary scenario form.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed binary input or
    /// id mismatches, or the same validation errors as the component constructors
    /// when the parsed world, plan, or properties are invalid.
    pub fn from_compact_binary(bytes: &[u8]) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, SCENARIO_FORM_BINARY_MAGIC)?;
        let form = read_scenario_form_binary(&mut reader)?;
        reader.finish()?;
        Ok(form)
    }

    /// Returns the canonical bytes used to compute this scenario definition's id.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        scenario_world_plan_properties_seed_material(
            &self.world,
            &self.plan,
            &self.properties,
            self.seed,
        )
        .into_bytes()
    }
}

/// The only identity-bearing execution configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Configuration {
    /// The immutable definition of the run.
    pub def: ScenarioDef,
    /// The ordered decisions already taken for this definition.
    pub schedule: Schedule,
}

impl Configuration {
    /// Builds the genesis configuration for `def`.
    #[must_use]
    pub fn genesis(def: ScenarioDef) -> Self {
        Self {
            def,
            schedule: Schedule::empty(),
        }
    }

    /// Returns whether this configuration has an empty schedule.
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        self.schedule.is_empty()
    }

    /// Computes the canonical identity of this configuration.
    ///
    /// The configuration identity is a pure function of the immutable scenario
    /// definition and the recorded schedule prefix. Runtime caches and
    /// materialized checkpoints do not contribute to this identity.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        canonical::configuration_hash(self)
    }

    /// Computes the RFC-named content-addressed configuration id.
    ///
    /// This is an alias for [`Configuration::content_hash`]. It exists so the
    /// execution model exposes the `Configuration::id()` API named in RFC-0010.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        self.content_hash()
    }
}

/// One resolved nondeterministic choice at a scheduling point.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Decision {
    /// A deterministic or recorded ordering of events at one virtual time.
    DeliveryOrder(DeliveryOrderDecision),
    /// The recorded outcome of a probabilistic fault.
    FaultFires(FaultDecision),
    /// A raw draw from a named deterministic decision stream.
    RngDraw(RngDecision),
    /// A search or fuzzing override at a scheduling point.
    Override(OverrideDecision),
    /// A vCPU switch or interrupt-preemption decision.
    Preemption(PreemptionDecision),
    /// A served application-requested random value.
    AppRandom(AppRandomDecision),
}

impl Decision {
    /// Returns the set of nodes this decision is known to touch.
    ///
    /// `None` means the current model cannot prove the decision is node-local,
    /// so search reductions must treat it as dependent on other decisions.
    #[must_use]
    pub fn touched_nodes(&self) -> Option<BTreeSet<NodeId>> {
        decision_touched_nodes(self)
    }

    /// Returns whether `policy` proves this decision independent from `other`.
    ///
    /// Independence requires an explicit unordered-pair proof, known disjoint
    /// node sets, and no shared ordered decision resource. Unknown/global
    /// decision kinds are treated as dependent.
    #[must_use]
    pub fn is_independent_from(&self, other: &Self, policy: &PartialOrderReductionPolicy) -> bool {
        decisions_are_independent(self, other, policy)
    }

    /// Returns the deterministic ordering key used by partial-order reduction.
    ///
    /// Search uses this key only to pick one representative interleaving for
    /// decisions already proven independent; it is not part of configuration
    /// identity.
    #[must_use]
    pub fn reduction_order_key(&self) -> ContentHash {
        decision_reduction_order_key(self)
    }
}

/// A totally ordered sequence of [`Decision`] values.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Schedule {
    decisions: Vec<Decision>,
}

impl Schedule {
    /// Builds an empty schedule.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            decisions: Vec::new(),
        }
    }

    /// Returns whether the schedule has no decisions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.decisions.is_empty()
    }

    /// Returns the number of decisions in this schedule.
    #[must_use]
    pub fn len(&self) -> usize {
        self.decisions.len()
    }

    /// Returns the decisions in their canonical order.
    #[must_use]
    pub fn decisions(&self) -> &[Decision] {
        &self.decisions
    }

    /// Returns a schedule containing the first `len` decisions.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleError::PrefixTooLong`] when `len` is greater than the
    /// number of decisions in this schedule.
    pub fn prefix(&self, len: usize) -> Result<Self, ScheduleError> {
        if len > self.decisions.len() {
            return Err(ScheduleError::PrefixTooLong {
                requested: len,
                available: self.decisions.len(),
            });
        }

        Ok(Self {
            decisions: self.decisions[..len].to_vec(),
        })
    }

    /// Returns the suffix after the first `len` decisions.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleError::PrefixTooLong`] when `len` is greater than the
    /// number of decisions in this schedule.
    pub fn suffix_from(&self, len: usize) -> Result<Self, ScheduleError> {
        if len > self.decisions.len() {
            return Err(ScheduleError::PrefixTooLong {
                requested: len,
                available: self.decisions.len(),
            });
        }

        Ok(Self {
            decisions: self.decisions[len..].to_vec(),
        })
    }

    /// Returns a new schedule with `decision` appended.
    #[must_use]
    pub fn appended(&self, decision: Decision) -> Self {
        let mut decisions = self.decisions.clone();
        decisions.push(decision);
        Self { decisions }
    }

    /// Computes the canonical identity of this schedule.
    ///
    /// The hash includes every decision in order and changes when a decision is
    /// reordered, inserted, or modified.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        canonical::schedule_hash(self)
    }

    /// Serializes this schedule as compact canonical bytes.
    #[must_use]
    pub fn to_compact_binary(&self) -> Vec<u8> {
        let mut writer = ScenarioBinaryWriter::new(SCHEDULE_BINARY_MAGIC);
        write_schedule_binary(self, &mut writer);
        writer.finish()
    }

    /// Parses and validates a compact binary schedule.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed binary input
    /// or a schedule id mismatch.
    pub fn from_compact_binary(bytes: &[u8]) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, SCHEDULE_BINARY_MAGIC)?;
        let schedule = read_schedule_binary(&mut reader)?;
        reader.finish()?;
        Ok(schedule)
    }
}

/// An error produced by schedule shape helpers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScheduleError {
    /// The requested prefix is longer than the schedule.
    PrefixTooLong {
        /// The requested prefix length.
        requested: usize,
        /// The number of available decisions.
        available: usize,
    },
}

impl fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrefixTooLong {
                requested,
                available,
            } => write!(
                f,
                "schedule prefix length {requested} exceeds available length {available}"
            ),
        }
    }
}

impl Error for ScheduleError {}

/// A virtual time value used by the execution-model signatures.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtualTime {
    /// The canonical virtual-time tick.
    pub ticks: u64,
}

/// An instruction-count value used by backend and preemption signatures.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Icount {
    /// The retired-instruction count.
    pub retired: u64,
}

impl Icount {
    /// Converts this instruction count into a virtual-time point.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidShift`] when `shift` cannot name a
    /// `u64` power-of-two scale, or [`TimeConversionError::VirtualTimeOverflow`]
    /// when `retired << shift` cannot be represented as `u64` virtual
    /// nanoseconds.
    pub fn to_virtual(self, shift: Shift) -> Result<VirtualInstant, TimeConversionError> {
        let scale = scale_for_shift(shift)?;
        let nanos =
            self.retired
                .checked_mul(scale)
                .ok_or(TimeConversionError::VirtualTimeOverflow {
                    icount: self,
                    shift,
                })?;
        Ok(VirtualInstant { nanos })
    }
}

/// A monotone per-node counter projected onto the shared virtual timeline.
///
/// VM nodes construct this from retired guest instructions; deterministic I/O
/// sub-nodes construct it from their model-owned completion counter. Both use
/// the same `counter << shift` projection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeCounter {
    /// The node-local counter value.
    pub ticks: u64,
}

impl NodeCounter {
    /// Converts a VM retired-instruction count into a scheduler node counter.
    #[must_use]
    pub fn from_icount(icount: Icount) -> Self {
        Self {
            ticks: icount.retired,
        }
    }

    /// Converts this node-local counter into a shared virtual-time point.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidShift`] when `shift` cannot name a
    /// `u64` power-of-two scale, or [`TimeConversionError::VirtualTimeOverflow`]
    /// when `ticks << shift` cannot be represented as `u64` virtual
    /// nanoseconds.
    pub fn to_virtual(self, shift: Shift) -> Result<VirtualInstant, TimeConversionError> {
        Icount {
            retired: self.ticks,
        }
        .to_virtual(shift)
    }
}

/// The fixed `-icount shift=N` scale.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Shift {
    /// The number of low-order virtual-nanosecond bits per instruction.
    pub bits: u8,
}

impl Shift {
    /// Builds a fixed icount shift.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidShift`] when `bits >= 64`, because
    /// that shift cannot be represented as a `u64` power-of-two scale.
    pub fn new(bits: u8) -> Result<Self, TimeConversionError> {
        let shift = Self { bits };
        let _ = scale_for_shift(shift)?;
        Ok(shift)
    }
}

/// A point on the shared virtual timeline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtualInstant {
    /// Virtual nanoseconds since Crucible's fixed virtual epoch.
    pub nanos: u64,
}

impl VirtualInstant {
    /// The fixed virtual-time epoch.
    pub const EPOCH: Self = Self { nanos: 0 };

    /// Converts this virtual-time point to the containing instruction count.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidShift`] when `shift` cannot name a
    /// `u64` power-of-two scale.
    pub fn to_icount_floor(self, shift: Shift) -> Result<Icount, TimeConversionError> {
        let scale = scale_for_shift(shift)?;
        Ok(Icount {
            retired: self.nanos / scale,
        })
    }

    /// Converts this virtual-time point to the first instruction boundary at or after it.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidShift`] when `shift` cannot name a
    /// `u64` power-of-two scale.
    pub fn to_icount_ceil(self, shift: Shift) -> Result<Icount, TimeConversionError> {
        let scale = scale_for_shift(shift)?;
        let quotient = self.nanos / scale;
        let remainder = self.nanos % scale;
        Ok(Icount {
            retired: quotient + u64::from(remainder != 0),
        })
    }

    /// Returns the saturating non-negative span since `earlier`.
    #[must_use]
    pub fn duration_since(self, earlier: Self) -> SimDuration {
        SimDuration {
            nanos: self.nanos.saturating_sub(earlier.nanos),
        }
    }

    /// Applies a signed virtual-time offset, saturating at the virtual epoch.
    #[must_use]
    pub fn with_skew(self, offset: SimOffset) -> Self {
        let shifted = i128::from(self.nanos) + i128::from(offset.nanos);
        if shifted <= 0 {
            Self::EPOCH
        } else if shifted > i128::from(u64::MAX) {
            Self { nanos: u64::MAX }
        } else {
            Self {
                nanos: shifted as u64,
            }
        }
    }
}

impl ops::Add<SimDuration> for VirtualInstant {
    type Output = Self;

    fn add(self, duration: SimDuration) -> Self::Output {
        Self {
            nanos: self.nanos.saturating_add(duration.nanos),
        }
    }
}

/// Alias for the shared-timeline reading of a point.
pub type SimInstant = VirtualInstant;

/// An unsigned virtual-time span.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SimDuration {
    /// Virtual nanoseconds in the span.
    pub nanos: u64,
}

impl ops::Add for SimDuration {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            nanos: self.nanos.saturating_add(rhs.nanos),
        }
    }
}

impl ops::Mul<u64> for SimDuration {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self::Output {
        Self {
            nanos: self.nanos.saturating_mul(rhs),
        }
    }
}

/// A signed virtual-time offset used for configured clock skew.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SimOffset {
    /// Signed virtual nanoseconds in the offset.
    pub nanos: i64,
}

/// A fixed-point clock drift rate applied to guest-visible time reads.
///
/// The rate is stored as an exact rational `numerator / denominator`. Applying
/// the rate uses multiply-then-divide integer arithmetic and rounds down toward
/// zero, matching RFC-0010 TIME-17.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClockDriftRate {
    /// The drift-rate numerator.
    pub numerator: u64,
    /// The drift-rate denominator.
    pub denominator: u64,
}

impl ClockDriftRate {
    /// The perfect no-drift rate.
    pub const ONE: Self = Self {
        numerator: 1,
        denominator: 1,
    };

    /// Builds a fixed-point clock drift rate.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidDriftRate`] when `denominator` is
    /// zero.
    pub fn new(numerator: u64, denominator: u64) -> Result<Self, TimeConversionError> {
        let drift_rate = Self {
            numerator,
            denominator,
        };
        if denominator == 0 {
            Err(TimeConversionError::InvalidDriftRate { drift_rate })
        } else {
            Ok(drift_rate)
        }
    }

    /// Applies the fixed-point drift rate with floor rounding.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidDriftRate`] when the denominator is
    /// zero, or [`TimeConversionError::GuestVisibleTimeOverflow`] when the
    /// drifted virtual time cannot fit in `u64` nanoseconds.
    pub fn apply_floor(
        self,
        virtual_time: VirtualInstant,
    ) -> Result<VirtualInstant, TimeConversionError> {
        if self.denominator == 0 {
            return Err(TimeConversionError::InvalidDriftRate { drift_rate: self });
        }

        let drifted = u128::from(virtual_time.nanos) * u128::from(self.numerator);
        let drifted = drifted / u128::from(self.denominator);
        let nanos =
            u64::try_from(drifted).map_err(|_| TimeConversionError::GuestVisibleTimeOverflow {
                virtual_time,
                drift_rate: self,
            })?;
        Ok(VirtualInstant { nanos })
    }

    /// Returns whether this rate is exactly one.
    #[must_use]
    pub fn is_one(self) -> bool {
        self.denominator != 0 && self.numerator == self.denominator
    }
}

impl Default for ClockDriftRate {
    fn default() -> Self {
        Self::ONE
    }
}

/// Deterministic clock skew applied only to guest-visible clock reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeClockSkew {
    /// The signed guest-visible offset in virtual nanoseconds.
    pub offset: SimOffset,
    /// The fixed-point drift rate.
    pub drift_rate: ClockDriftRate,
}

impl NodeClockSkew {
    /// The default perfect clock, byte-identical to omitting skew.
    pub const PERFECT: Self = Self {
        offset: SimOffset { nanos: 0 },
        drift_rate: ClockDriftRate::ONE,
    };

    /// Applies skew to an unskewed scheduler virtual-time point.
    ///
    /// The returned value is guest-visible only. The input point remains the
    /// unskewed scheduling axis used for horizon computation, cross-node
    /// ordering, and delivery-icount conversion.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError`] when the drift rate is invalid or the
    /// drifted guest-visible time cannot fit in `u64` nanoseconds.
    pub fn guest_visible_time(
        self,
        scheduler_time: VirtualInstant,
    ) -> Result<VirtualInstant, TimeConversionError> {
        let drifted = self.drift_rate.apply_floor(scheduler_time)?;
        let shifted = i128::from(drifted.nanos) + i128::from(self.offset.nanos);
        if shifted <= 0 {
            Ok(VirtualInstant::EPOCH)
        } else {
            let nanos = u64::try_from(shifted).map_err(|_| {
                TimeConversionError::GuestVisibleTimeOffsetOverflow {
                    virtual_time: drifted,
                    offset: self.offset,
                }
            })?;
            Ok(VirtualInstant { nanos })
        }
    }

    /// Returns whether this skew leaves guest-visible time unchanged.
    #[must_use]
    pub fn is_perfect(self) -> bool {
        self.offset.nanos == 0 && self.drift_rate.is_one()
    }

    /// Returns canonical scenario material for non-perfect skew.
    ///
    /// The perfect clock returns `None`, so omitting skew and explicitly using
    /// the default remain byte-identical at the scenario material layer.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidDriftRate`] when public-field
    /// construction supplied a zero denominator.
    pub fn scenario_hash_material(self) -> Result<Option<String>, TimeConversionError> {
        if self.drift_rate.denominator == 0 {
            return Err(TimeConversionError::InvalidDriftRate {
                drift_rate: self.drift_rate,
            });
        }

        Ok((!self.is_perfect()).then(|| {
            [
                format!("clock_skew_offset_ns={}", self.offset.nanos),
                format!(
                    "clock_drift_rate={}/{}",
                    self.drift_rate.numerator, self.drift_rate.denominator
                ),
                "clock_drift_rounding=floor".to_owned(),
                "clock_skew_applies_to=guest-visible-only".to_owned(),
                "clock_skew_scheduling_axis=unskewed-icount-derived".to_owned(),
            ]
            .join("\n")
        }))
    }
}

impl Default for NodeClockSkew {
    fn default() -> Self {
        Self::PERFECT
    }
}

/// A virtual-time conversion error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeConversionError {
    /// The shift cannot name a `u64` power-of-two scale.
    InvalidShift {
        /// The invalid shift.
        shift: Shift,
    },
    /// The converted virtual-time point would overflow `u64`.
    VirtualTimeOverflow {
        /// The input instruction count.
        icount: Icount,
        /// The fixed shift.
        shift: Shift,
    },
    /// The drift rate is invalid.
    InvalidDriftRate {
        /// The invalid drift rate.
        drift_rate: ClockDriftRate,
    },
    /// The guest-visible time conversion overflowed.
    GuestVisibleTimeOverflow {
        /// The input unskewed scheduler time.
        virtual_time: VirtualInstant,
        /// The drift rate being applied.
        drift_rate: ClockDriftRate,
    },
    /// Guest-visible offset application overflowed.
    GuestVisibleTimeOffsetOverflow {
        /// The drifted guest-visible time before offset application.
        virtual_time: VirtualInstant,
        /// The offset being applied.
        offset: SimOffset,
    },
}

impl fmt::Display for TimeConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidShift { shift } => {
                write!(
                    f,
                    "icount shift {} cannot be represented as u64",
                    shift.bits
                )
            }
            Self::VirtualTimeOverflow { icount, shift } => write!(
                f,
                "virtual time overflow for icount {} with shift {}",
                icount.retired, shift.bits
            ),
            Self::InvalidDriftRate { drift_rate } => write!(
                f,
                "clock drift rate {}/{} is invalid",
                drift_rate.numerator, drift_rate.denominator
            ),
            Self::GuestVisibleTimeOverflow {
                virtual_time,
                drift_rate,
            } => write!(
                f,
                "guest-visible time overflow for virtual time {} with drift rate {}/{}",
                virtual_time.nanos, drift_rate.numerator, drift_rate.denominator
            ),
            Self::GuestVisibleTimeOffsetOverflow {
                virtual_time,
                offset,
            } => write!(
                f,
                "guest-visible time overflow for virtual time {} with offset {}",
                virtual_time.nanos, offset.nanos
            ),
        }
    }
}

impl Error for TimeConversionError {}

fn scale_for_shift(shift: Shift) -> Result<u64, TimeConversionError> {
    1_u64
        .checked_shl(u32::from(shift.bits))
        .ok_or(TimeConversionError::InvalidShift { shift })
}

/// A node identifier inside a scenario definition.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId {
    /// The canonical node name.
    pub name: String,
}

/// One node's model-level ready-point configuration inside a [`World`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WorldNode {
    /// Stable node identity within the world.
    pub id: NodeId,
    /// The deterministic point where this node reaches `t = 0`.
    pub ready_point: ReadyPoint,
    /// Whether this node opts into the white-box guest-host channel.
    pub white_box: WhiteBoxPolicy,
    /// Optional content-addressed guest kernel blob.
    pub kernel: Option<ContentAddressedBlobRef>,
    /// Optional content-addressed read-only root-image blob.
    pub root_image: Option<ContentAddressedBlobRef>,
    /// Optional content-addressed initrd blob.
    pub initrd: Option<ContentAddressedBlobRef>,
}

/// One logical symmetric link between two nodes in a [`World`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LinkDef {
    endpoint_a: NodeId,
    endpoint_b: NodeId,
    latency: SimDuration,
    jitter: SimDuration,
    loss: LinkLossProbability,
    bandwidth_bps: Option<u64>,
}

/// A deterministic fixed-point link loss probability.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkLossProbability {
    millionths: u32,
}

impl LinkLossProbability {
    /// The lossless probability value.
    pub const ZERO: Self = Self { millionths: 0 };

    /// The always-drop probability value.
    pub const ONE: Self = Self {
        millionths: MAX_LINK_LOSS_MILLIONTHS,
    };

    /// Builds a probability from millionths in the closed range `[0, 1_000_000]`.
    ///
    /// `0` represents `0.0`, and `1_000_000` represents `1.0`. The fixed-point
    /// representation avoids floating-point ambiguity in canonical link
    /// material.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::LinkLossProbabilityOutOfRange`] when
    /// `millionths` is greater than `1_000_000`.
    pub fn from_millionths(millionths: u32) -> Result<Self, EngineError> {
        if millionths > MAX_LINK_LOSS_MILLIONTHS {
            return Err(EngineError::LinkLossProbabilityOutOfRange {
                millionths,
                maximum: MAX_LINK_LOSS_MILLIONTHS,
            });
        }

        Ok(Self { millionths })
    }

    /// Returns this probability as millionths in the closed range `[0, 1_000_000]`.
    #[must_use]
    pub fn millionths(self) -> u32 {
        self.millionths
    }
}

impl LinkDef {
    /// Builds a link with a canonical endpoint ordering.
    ///
    /// `LinkDef::new(a, b)` and `LinkDef::new(b, a)` produce equal links. A
    /// self-loop is rejected because a world link must reference exactly two
    /// distinct node endpoints. The link uses the minimum legal latency, no
    /// jitter, lossless delivery, and no bandwidth cap.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::WorldLinkSelfLoop`] when both endpoints name the
    /// same node.
    pub fn new(left: NodeId, right: NodeId) -> Result<Self, EngineError> {
        Self::with_transport(
            left,
            right,
            MIN_LINK_LATENCY,
            SimDuration::default(),
            LinkLossProbability::ZERO,
            None,
        )
    }

    /// Builds a link with explicit transport characteristics.
    ///
    /// Endpoints are canonically ordered before validation. `latency` is the
    /// one-way base latency; `jitter` is the maximum subtractive jitter allowed
    /// by the model; `loss` is a fixed-point probability; and `bandwidth_bps`
    /// is an optional bits-per-virtual-second cap.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::WorldLinkSelfLoop`] when both endpoints name the
    /// same node, [`EngineError::WorldLinkLatencyBelowFloor`] when `latency` is
    /// below [`MIN_LINK_LATENCY`], or
    /// [`EngineError::WorldLinkJitterBelowLatencyFloor`] when
    /// `latency - jitter` could fall below [`MIN_LINK_LATENCY`].
    pub fn with_transport(
        left: NodeId,
        right: NodeId,
        latency: SimDuration,
        jitter: SimDuration,
        loss: LinkLossProbability,
        bandwidth_bps: Option<u64>,
    ) -> Result<Self, EngineError> {
        if left == right {
            return Err(EngineError::WorldLinkSelfLoop { node: left });
        }

        let link = if left <= right {
            Self {
                endpoint_a: left,
                endpoint_b: right,
                latency,
                jitter,
                loss,
                bandwidth_bps,
            }
        } else {
            Self {
                endpoint_a: right,
                endpoint_b: left,
                latency,
                jitter,
                loss,
                bandwidth_bps,
            }
        };

        validate_link_transport(&link)?;
        Ok(link)
    }

    /// Returns the canonical endpoint pair.
    #[must_use]
    pub fn endpoints(&self) -> (&NodeId, &NodeId) {
        (&self.endpoint_a, &self.endpoint_b)
    }

    /// Returns the one-way base latency for this link.
    #[must_use]
    pub fn latency(&self) -> SimDuration {
        self.latency
    }

    /// Returns the maximum deterministic latency jitter for this link.
    #[must_use]
    pub fn jitter(&self) -> SimDuration {
        self.jitter
    }

    /// Returns the fixed-point frame-loss probability for this link.
    #[must_use]
    pub fn loss(&self) -> LinkLossProbability {
        self.loss
    }

    /// Returns the optional bits-per-virtual-second bandwidth cap for this link.
    #[must_use]
    pub fn bandwidth_bps(&self) -> Option<u64> {
        self.bandwidth_bps
    }
}

/// The deterministic ready-point policy used by `bake`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ReadyPoint {
    /// Snapshot after retiring exactly this many guest instructions.
    FixedIcount {
        /// The target retired-instruction count.
        icount: Icount,
    },
    /// Snapshot after the first network-idle quiescence window.
    NetworkIdle {
        /// Required idle span before the node is considered ready.
        window: SimDuration,
    },
    /// Snapshot when a marker appears on the guest console.
    ConsoleMarker {
        /// Marker matched on the guest console stream.
        marker: String,
    },
    /// Snapshot when the optional in-guest agent signals readiness.
    AgentSignal,
}

/// Whether a node opts into the white-box guest-host channel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum WhiteBoxPolicy {
    /// The guest-host channel is disabled.
    #[default]
    Disabled,
    /// The guest-host channel is enabled.
    Enabled,
}

impl WhiteBoxPolicy {
    /// Returns whether this policy enables the white-box channel.
    #[must_use]
    pub fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

/// A homogeneous content-addressed VM-state reference for one node.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NodeBlobRef {
    /// The baked ready-point VM blob for a node in the world's genesis.
    Baked(ContentHash),
    /// A copy-on-write delta layered over a parent VM blob.
    CowDelta {
        /// The parent VM blob content address.
        parent: ContentHash,
        /// The delta content address.
        delta: ContentHash,
        /// The resolved VM-state content address after applying `delta`.
        resolved: ContentHash,
    },
}

impl NodeBlobRef {
    /// Builds a baked ready-point VM blob reference.
    #[must_use]
    pub fn baked(blob: ContentHash) -> Self {
        Self::Baked(blob)
    }

    /// Builds a copy-on-write delta VM blob reference.
    #[must_use]
    pub fn cow_delta(parent: ContentHash, delta: ContentHash, resolved: ContentHash) -> Self {
        Self::CowDelta {
            parent,
            delta,
            resolved,
        }
    }

    /// Returns the resolved VM-state content address denoted by this blob reference.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        match self {
            Self::Baked(blob) => *blob,
            Self::CowDelta { resolved, .. } => *resolved,
        }
    }

    /// Returns the stored CoW delta object, when this blob is layered.
    #[must_use]
    pub fn cow_delta_ref(&self) -> Option<CowDeltaRef> {
        match self {
            Self::Baked(_) => None,
            Self::CowDelta { delta, .. } => Some(CowDeltaRef::new(CowDeltaKind::VmMemory, *delta)),
        }
    }
}

/// A vCPU identifier within one node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VcpuId {
    /// The zero-based vCPU index.
    pub index: u32,
}

/// An interrupt vector identifier.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IrqVector {
    /// The interrupt vector number.
    pub vector: u32,
}

/// A deterministic event-key placeholder for delivery-order decisions.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventKey {
    /// The event sequence key.
    pub sequence: u64,
}

/// A fault identifier inside a scenario plan.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FaultId {
    /// The canonical fault name.
    pub name: String,
}

/// A stable tag used to activate and heal a planned fault.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FaultTag {
    /// The canonical tag name.
    pub name: String,
}

impl FaultTag {
    /// Builds a fault tag from a canonical name.
    #[must_use]
    pub fn from_name(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// Restart behavior used when a crash fault heals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RestartPolicy {
    /// Reboot the node from its baked ready-point checkpoint.
    FromReadyPoint,
    /// Resume the node from its most recent pre-crash checkpoint.
    FromLastCheckpoint,
    /// Keep the node stopped until a later explicit start command.
    StayDown,
}

/// Direction for a planned partition over a declared link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PartitionDirection {
    /// Suppress delivery in both directions.
    Bidirectional,
    /// Suppress delivery from `endpoint_a` to `endpoint_b`.
    EndpointAToEndpointB,
    /// Suppress delivery from `endpoint_b` to `endpoint_a`.
    EndpointBToEndpointA,
}

/// A membership-dynamics fault layered over a static [`World`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MembershipFault {
    /// Stop a declared node until the fault heals or its restart policy acts.
    Crash {
        /// The declared node that stops.
        node: NodeId,
        /// How the node restarts when the crash heals.
        restart: RestartPolicy,
    },
    /// Suppress delivery on a declared link without removing it from the world.
    Partition {
        /// One declared endpoint of the partitioned link.
        endpoint_a: NodeId,
        /// The other declared endpoint of the partitioned link.
        endpoint_b: NodeId,
        /// Direction of delivery suppression.
        direction: PartitionDirection,
    },
    /// Suppress all links incident to a declared node without removing the node.
    Isolate {
        /// The declared node held isolated.
        node: NodeId,
    },
    /// Hold a declared node inactive until a later heal/rejoin event.
    NotYetJoined {
        /// The declared participant that starts inactive.
        node: NodeId,
    },
}

/// One entry in the declarative membership-fault plan.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PlanEntry {
    /// Activate a membership fault at an exact virtual time.
    Activate {
        /// Virtual time when the fault activates.
        at: VirtualTime,
        /// Stable tag used by a later heal.
        tag: FaultTag,
        /// Membership fault to layer over the static world.
        fault: MembershipFault,
    },
    /// Heal, restart, or rejoin a previously activated fault tag at an exact virtual time.
    Heal {
        /// Virtual time when the fault heals.
        at: VirtualTime,
        /// Stable tag naming the fault to heal.
        tag: FaultTag,
    },
}

/// A declarative fault plan layered over a static [`World`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Plan {
    /// The independently content-addressed plan identity.
    id: ContentHash,
    entries: Vec<PlanEntry>,
}

impl Default for Plan {
    fn default() -> Self {
        Self::empty()
    }
}

impl Plan {
    /// Builds an empty plan.
    #[must_use]
    pub fn empty() -> Self {
        let entries = Vec::new();
        Self::from_canonical_entries(entries)
    }

    /// Builds a plan after validating every entry against `world`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::PlanFaultUnknownNode`] when a membership fault
    /// names a node that is not declared by `world`,
    /// [`EngineError::PlanFaultUnknownLink`] when a partition names no declared
    /// link, [`EngineError::PlanHealUnknownTag`] when a heal names no activated
    /// fault tag in the plan, [`EngineError::PlanHealBeforeActivate`] when a
    /// heal is not after its activation, or
    /// [`EngineError::PlanNotYetJoinedAfterStart`] when an initial join hold is
    /// scheduled after `t = 0`.
    pub fn from_entries_for_world(
        world: &World,
        entries: Vec<PlanEntry>,
    ) -> Result<Self, EngineError> {
        validate_plan_entries_for_world(world, &entries)?;
        Ok(Self::from_canonical_entries(canonical_plan_entries(
            &entries,
        )))
    }

    /// Returns plan entries in their canonical order.
    #[must_use]
    pub fn entries(&self) -> &[PlanEntry] {
        &self.entries
    }

    /// Computes the canonical identity of this plan.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        self.id
    }

    /// Serializes this plan component as deterministic TOML.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] if the TOML renderer rejects
    /// the internal DTO shape.
    pub fn to_canonical_toml(&self) -> Result<String, EngineError> {
        toml::to_string(&plan_to_toml(self)).map_err(|source| {
            scenario_serialization_error(format!("serialize plan TOML: {source}"))
        })
    }

    /// Parses and validates a deterministic TOML plan component for `world`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed TOML or an id
    /// mismatch, [`EngineError::PlanNegativeTime`],
    /// [`EngineError::PlanFaultUnknownDirection`], or
    /// [`EngineError::PlanFaultUnsupportedParam`] for localized serialized plan
    /// validation failures, or a plan validation error when the parsed entries do
    /// not layer over `world`.
    pub fn from_canonical_toml_for_world(world: &World, input: &str) -> Result<Self, EngineError> {
        validate_plan_entries_in_toml(input)?;
        let toml = toml::from_str::<PlanToml>(input)
            .map_err(|source| scenario_serialization_error(format!("parse plan TOML: {source}")))?;
        plan_from_toml(world, toml)
    }

    /// Serializes this plan component as compact binary.
    #[must_use]
    pub fn to_compact_binary(&self) -> Vec<u8> {
        let mut writer = ScenarioBinaryWriter::new(PLAN_BINARY_MAGIC);
        write_plan_binary(self, &mut writer);
        writer.finish()
    }

    /// Parses and validates a compact binary plan component for `world`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed binary input
    /// or an id mismatch, or a plan validation error when the parsed entries do
    /// not layer over `world`.
    pub fn from_compact_binary_for_world(world: &World, bytes: &[u8]) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, PLAN_BINARY_MAGIC)?;
        let plan = read_plan_binary(world, &mut reader)?;
        reader.finish()?;
        Ok(plan)
    }

    /// Returns the canonical bytes used to compute this plan's content address.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        plan_material(&self.entries).into_bytes()
    }

    /// Validates this plan against `world`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::PlanFaultUnknownNode`],
    /// [`EngineError::PlanFaultUnknownLink`],
    /// [`EngineError::PlanHealUnknownTag`],
    /// [`EngineError::PlanHealBeforeActivate`], or
    /// [`EngineError::PlanNotYetJoinedAfterStart`] when an entry cannot be
    /// layered over the static world topology.
    pub fn validate_for_world(&self, world: &World) -> Result<(), EngineError> {
        validate_plan_entries_for_world(world, &self.entries)
    }

    fn from_canonical_entries(entries: Vec<PlanEntry>) -> Self {
        Self {
            id: ContentHash::from_canonical_material(
                "crucible.model.plan.v1",
                &plan_material(&entries),
            ),
            entries,
        }
    }
}

/// A stable assertion identifier inside a [`Properties`] bundle.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssertionId {
    /// The canonical assertion name.
    pub name: String,
}

impl AssertionId {
    /// Builds an assertion id from a canonical name.
    #[must_use]
    pub fn from_name(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// A stable white-box marker identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MarkerId {
    /// The canonical marker name.
    pub name: String,
}

impl MarkerId {
    /// Builds a marker id from a canonical name.
    #[must_use]
    pub fn from_name(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// Disposition for an ordinary reachable marker that is never reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReachableDisposition {
    /// Report a coverage warning when the marker is never reached.
    Warn,
    /// Treat the never-reached marker as a property failure.
    Fail,
}

/// Reachability expectation and never-reached policy for a coverage property.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReachabilityExpectation {
    /// The predicate is expected to become true at least once.
    Reachable {
        /// Disposition when the predicate is never reached.
        on_unreached: ReachableDisposition,
    },
    /// The predicate is expected to remain false throughout the run.
    Unreachable,
}

/// The declarative predicate vocabulary used by properties.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Predicate {
    /// A named host-side predicate resolved by the harness and event log.
    Named {
        /// Stable predicate name.
        name: String,
        /// Declared nodes the predicate references.
        nodes: Vec<NodeId>,
    },
    /// A named white-box marker emitted by the optional guest-host channel.
    GuestMarker {
        /// Stable marker identity.
        marker: MarkerId,
    },
    /// Logical conjunction over sub-predicates.
    AllOf {
        /// Predicates that must all hold.
        predicates: Vec<Predicate>,
    },
    /// Logical disjunction over sub-predicates.
    AnyOf {
        /// Predicates where at least one must hold.
        predicates: Vec<Predicate>,
    },
    /// Latching predicate that remains true once its inner predicate holds.
    Once {
        /// Predicate being latched.
        predicate: Box<Predicate>,
    },
    /// Logical negation of an inner predicate.
    Not {
        /// Predicate being negated.
        predicate: Box<Predicate>,
    },
}

/// A temporal property declaration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Property {
    /// Invariant checked at every relevant evaluation point.
    Always {
        /// Predicate that must always hold.
        predicate: Predicate,
    },
    /// Liveness witness that must hold at least once.
    Sometimes {
        /// Predicate that must eventually be seen.
        predicate: Predicate,
    },
    /// Bounded liveness property armed by a trigger predicate.
    Eventually {
        /// Predicate that opens the bounded obligation.
        trigger: Predicate,
        /// Predicate that must hold within the deadline.
        property: Predicate,
        /// Virtual-time deadline measured from the trigger instant.
        deadline: VirtualTime,
    },
    /// End-state property checked once at quiescence or run limit.
    AfterQuiescence {
        /// Predicate that must hold at the terminal evaluation point.
        predicate: Predicate,
    },
    /// Coverage-style property over a predicate that may or may not be reached.
    Reachable {
        /// Predicate whose reachability is recorded.
        predicate: Predicate,
        /// Whether the predicate is expected to be reached, with never-reached
        /// disposition, or expected to remain unreachable.
        expectation: ReachabilityExpectation,
    },
}

/// One named property assertion in a [`Properties`] bundle.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AssertionDef {
    /// Stable assertion id used for canonical ordering and reports.
    pub id: AssertionId,
    /// Human-readable failure or coverage message.
    pub message: String,
    /// Temporal property definition.
    pub property: Property,
}

/// A declarative assertion bundle layered over a static [`World`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Properties {
    /// The independently content-addressed properties identity.
    id: ContentHash,
    assertions: Vec<AssertionDef>,
}

impl Default for Properties {
    fn default() -> Self {
        Self::empty()
    }
}

impl Properties {
    /// Builds an empty properties bundle.
    #[must_use]
    pub fn empty() -> Self {
        let assertions = Vec::new();
        Self::from_canonical_assertions(assertions)
    }

    /// Builds a properties bundle after validating every predicate against `world`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::PropertyDuplicateAssertionId`] when two
    /// assertions share an id, [`EngineError::PropertyPredicateUnknownNode`]
    /// when a predicate names a node that is not declared by `world`, or
    /// [`EngineError::PropertyPredicateEmptyCompound`] when an `AllOf` or
    /// `AnyOf` predicate has no children.
    pub fn from_assertions_for_world(
        world: &World,
        assertions: Vec<AssertionDef>,
    ) -> Result<Self, EngineError> {
        validate_properties_for_world(world, &assertions)?;
        Ok(Self::from_canonical_assertions(canonical_assertions(
            &assertions,
        )))
    }

    /// Returns property assertions in their canonical order.
    #[must_use]
    pub fn assertions(&self) -> &[AssertionDef] {
        &self.assertions
    }

    /// Computes the canonical identity of this properties bundle.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        self.id
    }

    /// Serializes this properties component as deterministic TOML.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] if the TOML renderer rejects
    /// the internal DTO shape.
    pub fn to_canonical_toml(&self) -> Result<String, EngineError> {
        toml::to_string(&properties_to_toml(self)).map_err(|source| {
            scenario_serialization_error(format!("serialize properties TOML: {source}"))
        })
    }

    /// Parses and validates a deterministic TOML properties component for `world`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed TOML or an id
    /// mismatch, or a property validation error when the parsed assertions do not
    /// layer over `world`.
    pub fn from_canonical_toml_for_world(world: &World, input: &str) -> Result<Self, EngineError> {
        let toml = toml::from_str::<PropertiesToml>(input).map_err(|source| {
            scenario_serialization_error(format!("parse properties TOML: {source}"))
        })?;
        properties_from_toml(world, toml)
    }

    /// Serializes this properties component as compact binary.
    #[must_use]
    pub fn to_compact_binary(&self) -> Vec<u8> {
        let mut writer = ScenarioBinaryWriter::new(PROPERTIES_BINARY_MAGIC);
        write_properties_binary(self, &mut writer);
        writer.finish()
    }

    /// Parses and validates a compact binary properties component for `world`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed binary input
    /// or an id mismatch, or a property validation error when the parsed assertions
    /// do not layer over `world`.
    pub fn from_compact_binary_for_world(world: &World, bytes: &[u8]) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, PROPERTIES_BINARY_MAGIC)?;
        let properties = read_properties_binary(world, &mut reader)?;
        reader.finish()?;
        Ok(properties)
    }

    /// Returns the canonical bytes used to compute this properties bundle's content address.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        properties_material(&self.assertions).into_bytes()
    }

    /// Validates this properties bundle against `world`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::PropertyDuplicateAssertionId`],
    /// [`EngineError::PropertyPredicateUnknownNode`], or
    /// [`EngineError::PropertyPredicateEmptyCompound`] when an assertion cannot
    /// be layered over the static world topology.
    pub fn validate_for_world(&self, world: &World) -> Result<(), EngineError> {
        validate_properties_for_world(world, &self.assertions)
    }

    fn from_canonical_assertions(assertions: Vec<AssertionDef>) -> Self {
        Self {
            id: ContentHash::from_canonical_material(
                "crucible.model.properties.v1",
                &properties_material(&assertions),
            ),
            assertions,
        }
    }
}

/// The 256-bit root entropy component of a scenario definition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Seed {
    bytes: [u8; 32],
}

impl Seed {
    /// Builds a seed from canonical root-entropy bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Builds a seed from a small deterministic integer.
    ///
    /// This is a convenience constructor for examples and tests. The integer is
    /// encoded into the low eight bytes of the 256-bit seed; all remaining bytes
    /// are zero.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        Self { bytes }
    }

    /// Returns this seed's canonical 256-bit byte representation.
    #[must_use]
    pub fn bytes(self) -> [u8; 32] {
        self.bytes
    }

    /// Renders this seed as 64 lowercase hexadecimal characters.
    #[must_use]
    pub fn to_hex(self) -> String {
        bytes_hex(&self.bytes)
    }

    /// Builds the deterministic decision RNG rooted at this seed.
    #[must_use]
    pub fn decision_rng(self) -> DecisionRng {
        DecisionRng::new(self.decision_rng_root_seed())
    }

    /// Returns the deterministic fork seed for `stream`.
    #[must_use]
    pub fn stream_seed(self, stream: &RngStreamId) -> u64 {
        self.decision_rng()
            .stream_seed_in_domain(&stream.domain, &stream.name)
    }

    /// Forks a deterministic decision stream for `stream`.
    #[must_use]
    pub fn fork_stream(self, stream: &RngStreamId) -> DecisionStream {
        self.decision_rng()
            .fork_in_domain(&stream.domain, &stream.name)
    }

    /// Serializes this seed component as deterministic TOML.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] if the TOML renderer rejects
    /// the internal DTO shape.
    pub fn to_canonical_toml(self) -> Result<String, EngineError> {
        toml::to_string(&seed_to_toml(self)).map_err(|source| {
            scenario_serialization_error(format!("serialize seed TOML: {source}"))
        })
    }

    /// Parses a deterministic TOML seed component.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] when the TOML is malformed or
    /// the seed is not `0x` plus 64 lowercase hexadecimal characters.
    pub fn from_canonical_toml(input: &str) -> Result<Self, EngineError> {
        let toml = toml::from_str::<SeedToml>(input)
            .map_err(|source| scenario_serialization_error(format!("parse seed TOML: {source}")))?;
        seed_from_toml(&toml)
    }

    /// Serializes this seed component as compact binary.
    #[must_use]
    pub fn to_compact_binary(self) -> Vec<u8> {
        let mut writer = ScenarioBinaryWriter::new(SEED_BINARY_MAGIC);
        writer.write_seed(self);
        writer.finish()
    }

    /// Parses a compact binary seed component.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] when the binary input is not
    /// the fixed seed component encoding.
    pub fn from_compact_binary(bytes: &[u8]) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, SEED_BINARY_MAGIC)?;
        let seed = reader.read_seed()?;
        reader.finish()?;
        Ok(seed)
    }

    /// Returns the canonical bytes used when this seed participates in identities.
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        seed_material(self).into_bytes()
    }

    fn decision_rng_root_seed(self) -> u64 {
        let hash = ContentHash::from_canonical_material(
            "crucible.model.seed-decision-rng-root.v1",
            &seed_material(self),
        );
        let mut root = [0; 8];
        root.copy_from_slice(&hash.bytes[..8]);
        u64::from_le_bytes(root)
    }
}

/// One world-declared decision-RNG stream after forking from a scenario seed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SeededRngStream {
    /// The declared per-entity stream id.
    pub stream: RngStreamId,
    /// The deterministic stream seed derived from [`Seed`] and stream name-hash.
    pub seed: u64,
}

/// A deterministic decision-stream identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RngStreamId {
    /// The stable stream domain.
    pub domain: String,
    /// The canonical stream name.
    pub name: String,
}

impl RngStreamId {
    /// Builds a stream id in the default decision-RNG name-hash domain.
    #[must_use]
    pub fn from_name(name: impl Into<String>) -> Self {
        Self::new(DECISION_RNG_NAME_HASH_DOMAIN, name)
    }

    /// Builds a node-scoped stream id.
    #[must_use]
    pub fn for_node(name: impl Into<String>) -> Self {
        Self::new(DECISION_RNG_NODE_STREAM_DOMAIN, name)
    }

    /// Builds a link-scoped stream id.
    #[must_use]
    pub fn for_link(name: impl Into<String>) -> Self {
        Self::new(DECISION_RNG_LINK_STREAM_DOMAIN, name)
    }

    /// Builds a stream id in a caller-supplied stable domain.
    #[must_use]
    pub fn new(domain: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            name: name.into(),
        }
    }
}

/// A scheduling point identifier used by override decisions.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchedulingPoint {
    /// The canonical scheduling-point key.
    pub key: String,
}

/// An override choice identifier used by exploration.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChoiceTag {
    /// The canonical choice name.
    pub name: String,
}

/// A delivery-order decision payload.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeliveryOrderDecision {
    /// The virtual time at which the ordering was resolved.
    pub at: VirtualTime,
    /// The ordered event keys.
    pub order: Vec<EventKey>,
}

/// A probabilistic fault decision payload.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FaultDecision {
    /// The virtual time at which the fault was resolved.
    pub at: VirtualTime,
    /// The fault whose outcome was resolved.
    pub fault: FaultId,
    /// Whether the fault fired.
    pub fired: bool,
}

/// A decision-stream draw payload.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RngDecision {
    /// The stream that produced the value.
    pub stream: RngStreamId,
    /// The drawn value.
    pub value: u64,
}

/// A search or fuzzing override payload.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OverrideDecision {
    /// The scheduling point being overridden.
    pub point: SchedulingPoint,
    /// The selected override choice.
    pub choice: ChoiceTag,
}

/// A vCPU-switch or interrupt-preemption payload.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PreemptionDecision {
    /// The node whose execution is preempted.
    pub node: NodeId,
    /// The instruction count where the preemption occurs.
    pub at: Icount,
    /// The kind of preemption.
    pub kind: PreemptionKind,
}

/// The kind of a preemption decision.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PreemptionKind {
    /// A multi-vCPU round-robin switch.
    VcpuSwitch {
        /// The previously running vCPU.
        from_vcpu: VcpuId,
        /// The newly selected vCPU.
        to_vcpu: VcpuId,
    },
    /// A timer or external interrupt at a chosen instruction count.
    InterruptAt {
        /// The vCPU receiving the interrupt.
        target_vcpu: VcpuId,
        /// The interrupt vector delivered.
        irq: IrqVector,
    },
}

/// An application-requested random draw payload.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AppRandomDecision {
    /// The requesting node.
    pub node: NodeId,
    /// The decision stream used to serve the request.
    pub stream: RngStreamId,
    /// The per-stream request identifier.
    pub request_id: u64,
    /// The requested bit width.
    pub width: u8,
    /// The served random value.
    pub value: u64,
}

/// A per-VM snapshot reference captured by a fat checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VmSnapshotRef {
    /// The content-addressed VM-state blob or CoW delta.
    pub blob: NodeBlobRef,
    /// The retired-instruction count at which the snapshot was taken.
    pub icount: Icount,
}

impl VmSnapshotRef {
    /// Builds a VM snapshot reference from a blob ref and snapshot icount.
    #[must_use]
    pub fn new(blob: NodeBlobRef, icount: Icount) -> Self {
        Self { blob, icount }
    }
}

/// A device or I/O sub-node identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId {
    /// The canonical device name.
    pub name: String,
}

/// A deterministic RNG stream cursor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RngStreamPosition {
    /// Number of draws already consumed from the stream.
    pub draws: u64,
}

impl RngStreamPosition {
    /// Builds a deterministic RNG stream cursor.
    #[must_use]
    pub fn new(draws: u64) -> Self {
        Self { draws }
    }
}

/// The deterministic RNG state owned by one device overlay.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DeviceRngState {
    /// Per-stream cursor positions for device-local randomness.
    pub streams: BTreeMap<RngStreamId, RngStreamPosition>,
}

impl DeviceRngState {
    /// Builds an empty device RNG state.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            streams: BTreeMap::new(),
        }
    }
}

/// A per-device copy-on-write overlay delta captured by a checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeviceOverlayDelta {
    /// Parent overlay or read-only base content address.
    pub parent: ContentHash,
    /// Dirty-page delta content address.
    pub delta: ContentHash,
    /// Resolved overlay content address after applying `delta`.
    pub resolved: ContentHash,
    /// Device-local deterministic RNG state at this checkpoint.
    pub rng: DeviceRngState,
}

impl DeviceOverlayDelta {
    /// Builds a device overlay delta from content-addressed pieces.
    #[must_use]
    pub fn new(
        parent: ContentHash,
        delta: ContentHash,
        resolved: ContentHash,
        rng: DeviceRngState,
    ) -> Self {
        Self {
            parent,
            delta,
            resolved,
            rng,
        }
    }

    /// Returns the stored CoW object for this device overlay delta.
    #[must_use]
    pub fn cow_delta_ref(&self) -> CowDeltaRef {
        CowDeltaRef::new(CowDeltaKind::DeviceOverlay, self.delta)
    }
}

/// A pending cross-node frame captured in scheduler state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PendingFrame {
    /// The source node that produced the frame.
    pub source: NodeId,
    /// Stable source-local frame sequence.
    pub sequence: u64,
    /// Delivery instruction count selected by the scheduler.
    pub delivery_icount: Icount,
    /// Content-addressed payload reference.
    pub payload: ContentHash,
}

/// A timer identifier inside the scheduler state.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimerId {
    /// The canonical timer name.
    pub name: String,
}

/// An armed timer captured by the scheduler state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TimerState {
    /// The node that owns the timer.
    pub owner: NodeId,
    /// Virtual time when the timer was armed.
    pub armed_at: VirtualTime,
    /// Virtual time when the timer should fire.
    pub fire_at: VirtualTime,
    /// Instruction count corresponding to the fire point.
    pub fire_icount: Icount,
}

/// The set of armed timers captured by a materialized checkpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TimerRegistry {
    /// Timers keyed by stable timer id.
    pub timers: BTreeMap<TimerId, TimerState>,
}

impl TimerRegistry {
    /// Builds an empty timer registry.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            timers: BTreeMap::new(),
        }
    }
}

/// An active fault captured in scheduler state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FaultState {
    /// Virtual time at which the fault became active.
    pub active_since: VirtualTime,
    /// Optional virtual time when the fault should heal.
    pub heal_at: Option<VirtualTime>,
}

/// Authoritative scheduler state needed to resume a fat checkpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SchedulerState {
    /// Per-node scheduler horizons.
    pub horizons: BTreeMap<NodeId, VirtualTime>,
    /// Pending frame queues with deterministic delivery counts.
    pub pending_frames: BTreeMap<NodeId, Vec<PendingFrame>>,
    /// Armed timer registry.
    pub timers: TimerRegistry,
    /// Faults currently active in the scheduler.
    pub active_faults: BTreeMap<FaultId, FaultState>,
}

impl SchedulerState {
    /// Builds an empty scheduler state.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            horizons: BTreeMap::new(),
            pending_frames: BTreeMap::new(),
            timers: TimerRegistry::empty(),
            active_faults: BTreeMap::new(),
        }
    }
}

/// Harness decision-RNG cursor state captured at a checkpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DecisionRngState {
    /// Per-stream cursor positions.
    pub positions: BTreeMap<RngStreamId, RngStreamPosition>,
}

impl DecisionRngState {
    /// Builds an empty decision-RNG state.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            positions: BTreeMap::new(),
        }
    }
}

/// The shared event-log prefix position for a checkpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct EventLogOffset {
    /// Content address of the shared event-log prefix.
    pub prefix: ContentHash,
    /// Content address of the segment appended after the parent checkpoint.
    pub appended_segment: Option<ContentHash>,
    /// Byte offset at which resume continues appending.
    pub bytes: u64,
    /// Event count at which resume continues appending.
    pub events: u64,
}

impl EventLogOffset {
    /// Builds an event-log offset from prefix, byte offset, and event count.
    #[must_use]
    pub fn new(prefix: ContentHash, bytes: u64, events: u64) -> Self {
        Self {
            prefix,
            appended_segment: None,
            bytes,
            events,
        }
    }

    /// Builds an event-log offset with an appended segment delta.
    #[must_use]
    pub fn with_appended_segment(
        prefix: ContentHash,
        bytes: u64,
        events: u64,
        appended_segment: ContentHash,
    ) -> Self {
        Self {
            prefix,
            appended_segment: Some(appended_segment),
            bytes,
            events,
        }
    }

    /// Returns the stored event-log segment delta, when one was appended.
    #[must_use]
    pub fn cow_delta_ref(self) -> Option<CowDeltaRef> {
        self.appended_segment
            .map(|segment| CowDeltaRef::new(CowDeltaKind::EventLogSegment, segment))
    }
}

/// The CoW namespace for a content-addressed delta object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CowDeltaKind {
    /// Dirty VM memory or device-state pages for one node.
    VmMemory,
    /// Dirty block/9p overlay pages for one device.
    DeviceOverlay,
    /// Decisions appended after a checkpoint parent.
    ScheduleDelta,
    /// Event-log bytes appended after a checkpoint parent.
    EventLogSegment,
}

/// A typed content-addressed CoW delta object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CowDeltaRef {
    /// The delta namespace.
    pub kind: CowDeltaKind,
    /// The canonical content hash of the stored delta bytes.
    pub content: ContentHash,
}

impl CowDeltaRef {
    /// Builds a typed CoW delta reference.
    #[must_use]
    pub fn new(kind: CowDeltaKind, content: ContentHash) -> Self {
        Self { kind, content }
    }
}

/// CoW sharing accounting for a checkpoint set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CowSharingStats {
    /// Total logical references to CoW objects before content-address dedup.
    pub logical_references: usize,
    /// Unique typed content hashes that must be stored.
    pub unique_objects: usize,
}

impl CowSharingStats {
    /// Computes sharing stats from logical CoW references.
    #[must_use]
    pub fn from_refs<I>(refs: I) -> Self
    where
        I: IntoIterator<Item = CowDeltaRef>,
    {
        let mut logical_references = 0;
        let mut unique_refs = BTreeSet::new();
        for cow_ref in refs {
            logical_references += 1;
            unique_refs.insert(cow_ref);
        }
        Self {
            logical_references,
            unique_objects: unique_refs.len(),
        }
    }

    /// Returns references eliminated by content-addressed sharing.
    #[must_use]
    pub fn deduped_references(&self) -> usize {
        self.logical_references.saturating_sub(self.unique_objects)
    }
}

/// The cached realization carried by a fat checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MaterializedState {
    /// Content address of the materialized runtime/cache payload.
    pub id: ContentHash,
    /// Per-VM snapshot refs and the icount at which each was taken.
    pub vm_snapshots: BTreeMap<NodeId, VmSnapshotRef>,
    /// Per-device CoW overlay deltas and device RNG state.
    pub device_overlays: BTreeMap<DeviceId, DeviceOverlayDelta>,
    /// Scheduler state required to resume cross-node ordering.
    pub scheduler: SchedulerState,
    /// Harness decision-RNG cursor positions.
    pub decision_rng: DecisionRngState,
    /// Event-log prefix position at this checkpoint.
    pub event_log: EventLogOffset,
}

impl MaterializedState {
    /// Builds a legacy materialized-state handle from an existing content address.
    ///
    /// The resulting value is not sufficient for a loadable fat checkpoint
    /// unless `id` is the canonical hash of the empty component set. Use
    /// [`Self::from_components`] for loadable checkpoint state.
    #[must_use]
    pub fn from_content_hash(id: ContentHash) -> Self {
        Self {
            id,
            vm_snapshots: BTreeMap::new(),
            device_overlays: BTreeMap::new(),
            scheduler: SchedulerState::empty(),
            decision_rng: DecisionRngState::empty(),
            event_log: EventLogOffset::default(),
        }
    }

    /// Builds a materialized state from content-addressed components.
    #[must_use]
    pub fn from_components(
        vm_snapshots: BTreeMap<NodeId, VmSnapshotRef>,
        device_overlays: BTreeMap<DeviceId, DeviceOverlayDelta>,
        scheduler: SchedulerState,
        decision_rng: DecisionRngState,
        event_log: EventLogOffset,
    ) -> Self {
        let id = canonical::materialized_state_hash(
            &vm_snapshots,
            &device_overlays,
            &scheduler,
            &decision_rng,
            event_log,
        );
        Self {
            id,
            vm_snapshots,
            device_overlays,
            scheduler,
            decision_rng,
            event_log,
        }
    }

    /// Builds an empty structured materialized state.
    #[must_use]
    pub fn empty() -> Self {
        Self::from_components(
            BTreeMap::new(),
            BTreeMap::new(),
            SchedulerState::empty(),
            DecisionRngState::empty(),
            EventLogOffset::default(),
        )
    }

    /// Builds a materialized state from checkpoint VM refs.
    #[must_use]
    pub fn from_checkpoint_parts(
        node_icounts: &BTreeMap<NodeId, Icount>,
        node_blobs: &BTreeMap<NodeId, NodeBlobRef>,
    ) -> Self {
        Self::from_components(
            materialized_vm_snapshots(node_icounts, node_blobs),
            BTreeMap::new(),
            SchedulerState::empty(),
            DecisionRngState::empty(),
            EventLogOffset::default(),
        )
    }

    /// Enumerates logical CoW delta refs stored by this materialized state.
    #[must_use]
    pub fn cow_delta_refs(&self) -> Vec<CowDeltaRef> {
        let mut refs = Vec::new();
        refs.extend(
            self.vm_snapshots
                .values()
                .filter_map(|snapshot| snapshot.blob.cow_delta_ref()),
        );
        refs.extend(
            self.device_overlays
                .values()
                .map(DeviceOverlayDelta::cow_delta_ref),
        );
        if let Some(event_log) = self.event_log.cow_delta_ref() {
            refs.push(event_log);
        }
        refs
    }
}

/// Identity-irrelevant checkpoint metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CheckpointMeta {
    /// Human/debug annotations that must not affect [`Checkpoint::id`].
    pub labels: BTreeMap<String, String>,
}

impl CheckpointMeta {
    /// Builds empty checkpoint metadata.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            labels: BTreeMap::new(),
        }
    }

    /// Builds checkpoint metadata from key/value annotations.
    #[must_use]
    pub fn from_labels(labels: BTreeMap<String, String>) -> Self {
        Self { labels }
    }
}

/// A checkpoint handle in the temporal graph.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Checkpoint {
    /// The checkpoint content address.
    pub id: ContentHash,
    /// The configuration this checkpoint materializes.
    pub configuration: ContentHash,
    /// The scenario definition this checkpoint belongs to.
    pub scenario_ref: ContentHash,
    /// The parent checkpoint id, or `None` for genesis.
    pub parent: Option<ContentHash>,
    /// The decisions appended after `parent` to reach this checkpoint.
    pub schedule_delta: Schedule,
    /// The shared virtual-time coordinate at this checkpoint.
    pub virtual_time: VirtualTime,
    /// Per-node instruction counters at this checkpoint.
    pub node_icounts: BTreeMap<NodeId, Icount>,
    /// The materialized state, when this is a fat checkpoint.
    pub state: Option<MaterializedState>,
    /// Observation-only coverage fingerprint for this checkpoint.
    pub coverage_fingerprint: ContentHash,
    /// Identity-irrelevant metadata for humans and cache policy.
    pub metadata: CheckpointMeta,
    /// Per-node VM-state blob references.
    pub node_blobs: BTreeMap<NodeId, NodeBlobRef>,
    /// Whether this is a fat or thin checkpoint.
    pub kind: CheckpointKind,
}

impl Checkpoint {
    /// Builds a checkpoint handle with no recorded VM blob references.
    #[must_use]
    pub fn new(id: ContentHash, configuration: ContentHash, kind: CheckpointKind) -> Self {
        Self::with_node_blobs(id, configuration, kind, BTreeMap::new())
    }

    /// Builds the recorded checkpoint node for `configuration`.
    ///
    /// The checkpoint node identity is the recorded [`Configuration::id`].
    /// `parent` and `schedule_delta` are derived from the supplied parent
    /// configuration and must reconstruct the same configuration identity.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointTopologyMismatch`] when a non-genesis
    /// checkpoint has no parent, a genesis checkpoint has a parent, the parent
    /// belongs to another scenario, or the parent schedule is not a prefix of
    /// the checkpoint schedule. Returns [`EngineError::SchedulePrefix`] when
    /// the schedule prefix/suffix cannot be constructed.
    pub fn from_recorded_configuration(
        configuration: &Configuration,
        parent: Option<&Configuration>,
        virtual_time: VirtualTime,
        node_icounts: BTreeMap<NodeId, Icount>,
        kind: CheckpointKind,
        node_blobs: BTreeMap<NodeId, NodeBlobRef>,
    ) -> Result<Self, EngineError> {
        let (parent, schedule_delta) = checkpoint_edge(configuration, parent)?;
        Ok(Self {
            id: configuration.id(),
            configuration: configuration.id(),
            scenario_ref: configuration.def.id,
            parent,
            schedule_delta,
            virtual_time,
            state: materialized_state_for_kind(kind, &node_icounts, &node_blobs),
            node_icounts,
            coverage_fingerprint: ContentHash::default(),
            metadata: CheckpointMeta::empty(),
            node_blobs,
            kind,
        })
    }

    /// Builds a checkpoint handle with explicit per-node VM blob references.
    #[must_use]
    pub fn with_node_blobs(
        id: ContentHash,
        configuration: ContentHash,
        kind: CheckpointKind,
        node_blobs: BTreeMap<NodeId, NodeBlobRef>,
    ) -> Self {
        Self {
            id,
            configuration,
            scenario_ref: ContentHash::default(),
            parent: None,
            schedule_delta: Schedule::empty(),
            virtual_time: VirtualTime::default(),
            node_icounts: BTreeMap::new(),
            state: materialized_state_for_kind(kind, &BTreeMap::new(), &node_blobs),
            coverage_fingerprint: ContentHash::default(),
            metadata: CheckpointMeta::empty(),
            node_blobs,
            kind,
        }
    }

    /// Replaces the optional materialized state without changing identity.
    #[must_use]
    pub fn with_materialized_state(mut self, state: Option<MaterializedState>) -> Self {
        self.kind = if state.is_some() {
            CheckpointKind::Fat
        } else {
            CheckpointKind::Thin
        };
        self.state = state;
        self
    }

    /// Replaces the observation-only coverage fingerprint without changing identity.
    #[must_use]
    pub fn with_coverage_fingerprint(mut self, coverage_fingerprint: ContentHash) -> Self {
        self.coverage_fingerprint = coverage_fingerprint;
        self
    }

    /// Replaces identity-irrelevant metadata without changing identity.
    #[must_use]
    pub fn with_metadata(mut self, metadata: CheckpointMeta) -> Self {
        self.metadata = metadata;
        self
    }

    /// Returns the VM-state blob reference for `node`, when one is recorded.
    #[must_use]
    pub fn node_blob(&self, node: &NodeId) -> Option<&NodeBlobRef> {
        self.node_blobs.get(node)
    }

    /// Returns the canonical-relabeling fingerprint used by symmetry reduction.
    ///
    /// Checkpoints with no observed coverage fingerprint, no loadable
    /// materialized state, no explicit symmetry classes, or ambiguous canonical
    /// relabeling return `None`, forcing search to explore rather than assume
    /// equivalence.
    #[must_use]
    pub fn symmetry_reduction_key(
        &self,
        classes: &SymmetryReductionClasses,
    ) -> Option<SymmetryReductionKey> {
        checkpoint_symmetry_reduction_key(self, classes)
    }

    /// Enumerates logical CoW delta refs stored by this checkpoint.
    #[must_use]
    pub fn cow_delta_refs(&self) -> Vec<CowDeltaRef> {
        let mut refs = Vec::new();
        if !self.schedule_delta.is_empty() {
            refs.push(CowDeltaRef::new(
                CowDeltaKind::ScheduleDelta,
                self.schedule_delta.content_hash(),
            ));
        }
        if let Some(state) = &self.state {
            refs.extend(state.cow_delta_refs());
        }
        refs
    }
}

/// The storage shape of a checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CheckpointKind {
    /// A self-contained materialized checkpoint.
    Fat,
    /// A checkpoint represented by ancestor plus schedule delta.
    Thin,
}

/// Why a checkpoint is being considered for materialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MaterializationTrigger {
    /// The checkpoint is repeatedly used as a fork source.
    RepeatedForkSource,
    /// The checkpoint is on a replay path shared by many descendants.
    SharedReplayPath,
    /// The checkpoint is the target of an interactive session.
    InteractiveTarget,
    /// The checkpoint is cold and should remain thin unless explicitly saved.
    Cold,
}

impl MaterializationTrigger {
    /// Returns whether this trigger identifies a hot node.
    #[must_use]
    pub const fn is_hot(self) -> bool {
        matches!(
            self,
            Self::RepeatedForkSource | Self::SharedReplayPath | Self::InteractiveTarget
        )
    }
}

/// Advisory budget for turning thin checkpoints into fat cache entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MaterializationPolicy {
    /// Maximum number of non-genesis fat checkpoint cache entries to keep.
    pub max_fat_checkpoints: usize,
}

impl MaterializationPolicy {
    /// Builds a policy that permits at most `max_fat_checkpoints` fat caches.
    #[must_use]
    pub const fn with_budget(max_fat_checkpoints: usize) -> Self {
        Self {
            max_fat_checkpoints,
        }
    }

    /// Builds a policy that keeps every ordinary checkpoint thin.
    #[must_use]
    pub const fn thin_only() -> Self {
        Self::with_budget(0)
    }

    /// Returns whether a new fat cache entry should be created.
    #[must_use]
    pub const fn should_materialize(
        self,
        current_fat_checkpoints: usize,
        trigger: MaterializationTrigger,
    ) -> bool {
        trigger.is_hot() && current_fat_checkpoints < self.max_fat_checkpoints
    }
}

/// Deterministic replay-oracle sampling policy for active graph search.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SearchReplayOracleSamplingConfig {
    numerator: u64,
    denominator: u64,
    seed_tag: String,
}

impl SearchReplayOracleSamplingConfig {
    /// Builds a deterministic sampling-rate configuration.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::InvalidSearchReplayOracleSamplingConfig`] when the
    /// denominator is zero, numerator is zero, numerator exceeds denominator, or
    /// the seed tag is empty.
    pub fn new(
        numerator: u64,
        denominator: u64,
        seed_tag: impl Into<String>,
    ) -> Result<Self, EngineError> {
        if denominator == 0 {
            return Err(EngineError::InvalidSearchReplayOracleSamplingConfig {
                reason: "sampling denominator must be non-zero",
            });
        }
        if numerator == 0 {
            return Err(EngineError::InvalidSearchReplayOracleSamplingConfig {
                reason: "sampling numerator must be non-zero",
            });
        }
        if numerator > denominator {
            return Err(EngineError::InvalidSearchReplayOracleSamplingConfig {
                reason: "sampling numerator cannot exceed denominator",
            });
        }
        let seed_tag = seed_tag.into();
        if seed_tag.is_empty() {
            return Err(EngineError::InvalidSearchReplayOracleSamplingConfig {
                reason: "sampling seed tag must be non-empty",
            });
        }

        Ok(Self {
            numerator,
            denominator,
            seed_tag,
        })
    }

    /// Returns the sampling-rate numerator.
    #[must_use]
    pub const fn numerator(&self) -> u64 {
        self.numerator
    }

    /// Returns the sampling-rate denominator.
    #[must_use]
    pub const fn denominator(&self) -> u64 {
        self.denominator
    }

    /// Returns the deterministic sampling seed tag.
    #[must_use]
    pub fn seed_tag(&self) -> &str {
        &self.seed_tag
    }

    fn samples(&self, sequence: u64, checkpoint: ContentHash) -> bool {
        search_replay_oracle_sampling_score(&self.seed_tag, sequence, checkpoint) % self.denominator
            < self.numerator
    }
}

/// Policy for hedging incomplete backend `savevm` coverage.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SavevmCompletenessHedge {
    fat_snapshot_default: bool,
    unreliable_devices: BTreeSet<DeviceId>,
}

impl SavevmCompletenessHedge {
    /// Builds a hedge that permits fat snapshots after full replay-oracle proof.
    #[must_use]
    pub fn verified() -> Self {
        Self {
            fat_snapshot_default: true,
            unreliable_devices: BTreeSet::new(),
        }
    }

    /// Builds the conservative fallback adopted until full S3 is green.
    #[must_use]
    pub fn thin_replay_until_full_s3() -> Self {
        Self {
            fat_snapshot_default: false,
            unreliable_devices: BTreeSet::new(),
        }
    }

    /// Builds a hedge that keeps checkpoints touching `devices` thin.
    #[must_use]
    pub fn with_unreliable_devices<I>(devices: I) -> Self
    where
        I: IntoIterator<Item = DeviceId>,
    {
        Self {
            fat_snapshot_default: true,
            unreliable_devices: devices.into_iter().collect(),
        }
    }

    /// Returns whether fat snapshots are usable by default.
    #[must_use]
    pub const fn fat_snapshot_default(&self) -> bool {
        self.fat_snapshot_default
    }

    /// Returns the devices whose materialized snapshots must stay thin.
    #[must_use]
    pub fn unreliable_devices(&self) -> &BTreeSet<DeviceId> {
        &self.unreliable_devices
    }

    /// Returns whether `state` is eligible to be cached as a fat snapshot.
    #[must_use]
    pub fn allows_materialized_state(&self, state: &MaterializedState) -> bool {
        self.fat_snapshot_default
            && state
                .device_overlays
                .keys()
                .all(|device| !self.unreliable_devices.contains(device))
    }

    /// Returns whether `checkpoint` is eligible to be cached as a fat snapshot.
    #[must_use]
    pub fn allows_checkpoint(&self, checkpoint: &Checkpoint) -> bool {
        checkpoint
            .state
            .as_ref()
            .is_some_and(|state| self.allows_materialized_state(state))
    }
}

/// A baked genesis checkpoint handle.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GenesisCheckpoint {
    /// The checkpoint content address.
    pub checkpoint: Checkpoint,
}

/// A world handle used by the `bake` signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct World {
    /// The world content address.
    pub id: ContentHash,
    nodes: Vec<WorldNode>,
    links: Vec<LinkDef>,
}

/// Static topology products derived from a [`World`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WorldStaticTopology {
    /// The node participants declared by the world.
    pub participants: Vec<NodeId>,
    /// The per-entity decision-RNG streams declared by the world.
    pub rng_streams: Vec<RngStreamId>,
    /// The directed scheduler-lookahead edges declared by the world.
    pub lookahead_graph: Vec<WorldLookaheadEdge>,
    /// The node set that `bake` must prepare for this world.
    pub bake_nodes: Vec<NodeId>,
}

/// One directed edge in the scheduler lookahead graph derived from a [`World`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorldLookaheadEdge {
    /// The peer that can send a future network event.
    pub from: NodeId,
    /// The peer that can receive that future network event.
    pub to: NodeId,
    /// The minimum one-way latency that bounds conservative lookahead.
    pub minimum_latency: SimDuration,
}

/// An abstract reduced state handle.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct State {
    /// The reduced state's content address.
    pub id: ContentHash,
}

/// A temporal graph handle used by the `instantiate` signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TemporalGraph {
    /// The temporal graph content address.
    pub id: ContentHash,
    recorded_configurations: BTreeMap<ContentHash, Configuration>,
    checkpoint_nodes: BTreeMap<ContentHash, Checkpoint>,
    cached_snapshots: BTreeMap<ContentHash, Checkpoint>,
    baked_genesis: BTreeMap<ContentHash, GenesisCheckpoint>,
}

impl TemporalGraph {
    /// Builds an empty temporal graph cache with `id`.
    #[must_use]
    pub fn new(id: ContentHash) -> Self {
        Self {
            id,
            recorded_configurations: BTreeMap::new(),
            checkpoint_nodes: BTreeMap::new(),
            cached_snapshots: BTreeMap::new(),
            baked_genesis: BTreeMap::new(),
        }
    }

    /// Builds an empty temporal graph cache with the default test identity.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(ContentHash::default())
    }

    /// Returns a graph with a loadable snapshot registered for `configuration`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointConfigurationMismatch`] when the
    /// checkpoint does not name `configuration`, or
    /// [`EngineError::CheckpointNotLoadable`] when `checkpoint` is not fat.
    /// Returns [`EngineError::GenesisSnapshotMustBeBaked`] when
    /// `configuration` is the scenario genesis.
    pub fn with_cached_snapshot(
        mut self,
        configuration: &Configuration,
        checkpoint: Checkpoint,
    ) -> Result<Self, EngineError> {
        self.cache_snapshot(configuration, checkpoint)?;
        Ok(self)
    }

    /// Registers a loadable snapshot for `configuration`.
    ///
    /// When the graph has the scenario's baked genesis, this also records the
    /// thin checkpoint closure for `configuration` and keeps that thin node as
    /// the source of truth. The supplied fat checkpoint is stored only as the
    /// loadable cache entry.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointConfigurationMismatch`] when the
    /// checkpoint does not name `configuration`, or
    /// [`EngineError::CheckpointNotLoadable`] when `checkpoint` is not fat.
    /// Returns [`EngineError::GenesisSnapshotMustBeBaked`] when
    /// `configuration` is the scenario genesis.
    pub fn cache_snapshot(
        &mut self,
        configuration: &Configuration,
        checkpoint: Checkpoint,
    ) -> Result<(), EngineError> {
        if configuration.is_genesis() {
            return Err(EngineError::GenesisSnapshotMustBeBaked {
                configuration: configuration.id(),
            });
        }
        validate_loadable_checkpoint(&checkpoint, configuration)?;
        if self.genesis_snapshot(&configuration.def).is_some() {
            self.record_checkpoint_closure(configuration)?;
        }
        self.record_configuration(configuration.clone());
        self.cached_snapshots.insert(configuration.id(), checkpoint);
        Ok(())
    }

    /// Registers `checkpoint` only when the savevm hedge allows fat caching.
    ///
    /// If the hedge marks the snapshot unreliable, the graph records and
    /// returns the thin source-of-truth checkpoint instead of inserting the fat
    /// cache entry.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointConfigurationMismatch`] or related
    /// checkpoint-validation errors when the supplied fat checkpoint metadata is
    /// invalid. Returns [`EngineError::MissingBakedGenesis`] when the hedge
    /// rejects the fat checkpoint but no baked root exists to support thin
    /// replay.
    pub fn cache_snapshot_with_savevm_hedge(
        &mut self,
        configuration: &Configuration,
        checkpoint: Checkpoint,
        hedge: &SavevmCompletenessHedge,
    ) -> Result<Checkpoint, EngineError> {
        validate_loadable_checkpoint(&checkpoint, configuration)?;
        if hedge.allows_checkpoint(&checkpoint) {
            self.cache_snapshot(configuration, checkpoint.clone())?;
            Ok(checkpoint)
        } else {
            self.evict_fat_checkpoint_to_thin(configuration)
        }
    }

    /// Returns a graph with the baked genesis checkpoint registered for `def`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointConfigurationMismatch`] when the baked
    /// checkpoint does not name the genesis configuration for `def`, or
    /// [`EngineError::CheckpointNotLoadable`] when the baked checkpoint is not
    /// fat.
    pub fn with_baked_genesis(
        mut self,
        def: &ScenarioDef,
        genesis: GenesisCheckpoint,
    ) -> Result<Self, EngineError> {
        self.cache_baked_genesis(def, genesis)?;
        Ok(self)
    }

    /// Registers the baked genesis checkpoint for `def`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointConfigurationMismatch`] when the baked
    /// checkpoint does not name the genesis configuration for `def`, or
    /// [`EngineError::CheckpointNotLoadable`] when the baked checkpoint is not
    /// fat.
    pub fn cache_baked_genesis(
        &mut self,
        def: &ScenarioDef,
        genesis: GenesisCheckpoint,
    ) -> Result<(), EngineError> {
        let genesis_config = Configuration::genesis(def.clone());
        validate_loadable_checkpoint(&genesis.checkpoint, &genesis_config)?;
        self.record_configuration(genesis_config);
        self.checkpoint_nodes
            .insert(genesis.checkpoint.id, genesis.checkpoint.clone());
        self.baked_genesis.insert(def.id, genesis);
        Ok(())
    }

    /// Records `configuration` as a thin checkpoint source-of-truth node.
    ///
    /// Descendants are recorded with `state = None`; the baked genesis remains
    /// the materialized root because there is no cold-boot checkpoint in the
    /// temporal graph.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when the graph has no baked
    /// root for the scenario. Returns other [`EngineError`] variants if the
    /// parent/delta edge cannot be represented as a valid checkpoint.
    pub fn record_thin_checkpoint(
        &mut self,
        configuration: &Configuration,
    ) -> Result<Checkpoint, EngineError> {
        self.record_checkpoint_closure(configuration)?;
        self.checkpoint_node(configuration.id()).cloned().ok_or(
            EngineError::CheckpointNotRecorded {
                checkpoint: configuration.id(),
            },
        )
    }

    /// Materializes `configuration` as a fat checkpoint cache entry.
    ///
    /// The thin checkpoint remains the canonical DAG node whenever the graph
    /// has a baked genesis root. The returned fat checkpoint is validated by
    /// replaying the same configuration through the thin ancestor path before
    /// it is inserted into the exact-snapshot cache.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when no exact or ancestor
    /// cache can realize the configuration. Returns other [`EngineError`]
    /// variants when replay validation or checkpoint metadata validation fails.
    pub fn materialize_checkpoint(
        &mut self,
        configuration: &Configuration,
    ) -> Result<Checkpoint, EngineError> {
        self.record_configuration(configuration.clone());
        if configuration.is_genesis() {
            let genesis = self.genesis_snapshot(&configuration.def).ok_or(
                EngineError::MissingBakedGenesis {
                    scenario: configuration.def.id,
                },
            )?;
            return Ok(genesis.checkpoint.clone());
        }
        if self.genesis_snapshot(&configuration.def).is_some() {
            self.record_thin_checkpoint(configuration)?;
        }
        if self.cached_snapshot(configuration).is_some() {
            if self.has_replay_oracle_path(configuration)? {
                self.replay_oracle_admit_cached_snapshot(configuration)?;
            }
            if let Some(checkpoint) = self.cached_snapshot(configuration) {
                return Ok(checkpoint.clone());
            }
        }
        if self.has_replay_oracle_path(configuration)? {
            self.replay_oracle_admit_cached_ancestors(configuration)?;
        }

        let runtime = instantiate(self, configuration)?;
        let checkpoint = materialized_checkpoint_for_runtime(configuration, runtime)?;
        self.replay_checkpoint(configuration, &checkpoint)?;
        self.cache_snapshot(configuration, checkpoint.clone())?;
        Ok(checkpoint)
    }

    /// Materializes `configuration` only when the savevm hedge permits it.
    ///
    /// The thin checkpoint is returned when fat snapshots are disabled or when
    /// the materialized state touches a device whose snapshot is unreliable.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when the graph cannot
    /// record or replay the thin source-of-truth path. Returns other
    /// [`EngineError`] variants from checkpoint validation or replay-oracle
    /// validation.
    pub fn materialize_checkpoint_with_savevm_hedge(
        &mut self,
        configuration: &Configuration,
        hedge: &SavevmCompletenessHedge,
    ) -> Result<Checkpoint, EngineError> {
        self.record_configuration(configuration.clone());
        if configuration.is_genesis() {
            let genesis = self.genesis_snapshot(&configuration.def).ok_or(
                EngineError::MissingBakedGenesis {
                    scenario: configuration.def.id,
                },
            )?;
            return Ok(genesis.checkpoint.clone());
        }
        if self.genesis_snapshot(&configuration.def).is_some() {
            self.record_thin_checkpoint(configuration)?;
        }
        if self.cached_snapshot(configuration).is_some()
            && self.has_replay_oracle_path(configuration)?
        {
            self.replay_oracle_admit_cached_snapshot(configuration)?;
        }
        if let Some(checkpoint) = self.cached_snapshot(configuration).cloned() {
            if hedge.allows_checkpoint(&checkpoint) {
                return Ok(checkpoint);
            }
            return self.evict_fat_checkpoint_to_thin(configuration);
        }
        if !hedge.fat_snapshot_default() {
            return self.record_thin_checkpoint(configuration);
        }
        if self.has_replay_oracle_path(configuration)? {
            self.replay_oracle_admit_cached_ancestors(configuration)?;
        }

        let runtime = instantiate(self, configuration)?;
        let checkpoint = materialized_checkpoint_for_runtime(configuration, runtime)?;
        self.replay_checkpoint(configuration, &checkpoint)?;
        if hedge.allows_checkpoint(&checkpoint) {
            self.cache_snapshot(configuration, checkpoint.clone())?;
            Ok(checkpoint)
        } else {
            self.record_thin_checkpoint(configuration)
        }
    }

    /// Applies the hot-node materialization policy to `configuration`.
    ///
    /// Hot nodes within budget are materialized through
    /// [`Self::materialize_checkpoint`]. Cold or over-budget nodes are kept as
    /// thin DAG checkpoints and returned in that form.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when a thin checkpoint
    /// cannot be recorded or a requested materialization cannot be realized.
    /// Returns other [`EngineError`] variants from checkpoint validation.
    pub fn materialize_hot_checkpoint(
        &mut self,
        configuration: &Configuration,
        policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
    ) -> Result<Checkpoint, EngineError> {
        if self.cached_snapshot(configuration).is_some() {
            if self.has_replay_oracle_path(configuration)? {
                self.replay_oracle_admit_cached_snapshot(configuration)?;
            }
            if let Some(checkpoint) = self.cached_snapshot(configuration) {
                return Ok(checkpoint.clone());
            }
        }
        if policy.should_materialize(self.cached_snapshot_count(), trigger) {
            self.materialize_checkpoint(configuration)
        } else {
            self.record_thin_checkpoint(configuration)
        }
    }

    /// Applies both hot-node policy and the savevm-completeness hedge.
    ///
    /// Even hot nodes remain thin when fat snapshots are globally disabled or
    /// their materialized state contains an unreliable device snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when the graph cannot
    /// record or replay the thin source-of-truth path. Returns other
    /// [`EngineError`] variants from checkpoint validation.
    pub fn materialize_hot_checkpoint_with_savevm_hedge(
        &mut self,
        configuration: &Configuration,
        policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
        hedge: &SavevmCompletenessHedge,
    ) -> Result<Checkpoint, EngineError> {
        if self.cached_snapshot(configuration).is_some()
            && self.has_replay_oracle_path(configuration)?
        {
            self.replay_oracle_admit_cached_snapshot(configuration)?;
        }
        if let Some(checkpoint) = self.cached_snapshot(configuration).cloned() {
            if hedge.allows_checkpoint(&checkpoint) {
                return Ok(checkpoint);
            }
            return self.evict_fat_checkpoint_to_thin(configuration);
        }
        if policy.should_materialize(self.cached_snapshot_count(), trigger) {
            self.materialize_checkpoint_with_savevm_hedge(configuration, hedge)
        } else {
            self.record_thin_checkpoint(configuration)
        }
    }

    /// Evicts an ordinary fat checkpoint cache entry back to its thin node.
    ///
    /// The checkpoint identity and denoted configuration are unchanged. The
    /// exact-snapshot cache entry is dropped, and future realization must use
    /// ancestor replay until the node is materialized again. Baked genesis is
    /// not an ordinary cache entry and remains the graph root.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when the thin source node
    /// cannot be recorded. Returns [`EngineError::CheckpointNotRecorded`] if
    /// the thin node is still absent after closure recording.
    pub fn evict_fat_checkpoint_to_thin(
        &mut self,
        configuration: &Configuration,
    ) -> Result<Checkpoint, EngineError> {
        if configuration.is_genesis() {
            return self
                .genesis_snapshot(&configuration.def)
                .map(|genesis| genesis.checkpoint.clone())
                .ok_or(EngineError::MissingBakedGenesis {
                    scenario: configuration.def.id,
                });
        }
        if self.checkpoint_node(configuration.id()).is_none() {
            self.record_checkpoint_closure(configuration)?;
        }
        self.cached_snapshots.remove(&configuration.id());
        self.checkpoint_node(configuration.id()).cloned().ok_or(
            EngineError::CheckpointNotRecorded {
                checkpoint: configuration.id(),
            },
        )
    }

    /// Saves `configuration` as a fat checkpoint in the temporal graph.
    ///
    /// The checkpoint cache key is the configuration's content address. Saving
    /// the same configuration repeatedly is idempotent and returns the existing
    /// checkpoint instead of re-materializing a duplicate node.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when materialization reaches
    /// genesis without a baked genesis checkpoint. Returns other
    /// [`EngineError`] variants when cached checkpoint metadata is invalid.
    pub fn save_checkpoint(
        &mut self,
        configuration: &Configuration,
    ) -> Result<Checkpoint, EngineError> {
        self.materialize_checkpoint(configuration)
    }

    /// Saves `configuration` as a graph checkpoint and persists its DAG-store closure.
    ///
    /// This is the user-facing save operation expressed on the temporal graph:
    /// it realizes the configuration via [`instantiate`], validates the fat
    /// checkpoint against thin replay, keeps the thin checkpoint as the DAG
    /// source of truth, and writes the content-addressed closure through
    /// `store`.
    ///
    /// # Errors
    ///
    /// Returns [`TemporalGraphStoreError::Engine`] when materialization or
    /// replay-oracle validation fails. Returns [`TemporalGraphStoreError::Store`]
    /// when `store` cannot persist an object.
    pub fn save<S>(
        &mut self,
        store: &S,
        configuration: &Configuration,
    ) -> Result<TemporalGraphSave, TemporalGraphStoreError>
    where
        S: DagStore + ?Sized,
    {
        let checkpoint = self.save_checkpoint(configuration).map_err(|source| {
            TemporalGraphStoreError::Engine {
                operation: "save-checkpoint",
                source,
            }
        })?;
        let store_keys = self.persist_checkpoint_closure(store, configuration)?;
        Ok(TemporalGraphSave {
            configuration: configuration.id(),
            checkpoint: checkpoint.id,
            checkpoint_kind: checkpoint.kind,
            store_keys,
        })
    }

    /// Resumes `tip` by instantiating it through the temporal graph.
    ///
    /// The graph records the thin checkpoint closure before calling
    /// [`instantiate`], so resume uses the same exact-snapshot, cached-ancestor,
    /// or baked-genesis path as every other operation.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when no baked root can
    /// realize the configuration, or another [`EngineError`] if checkpoint
    /// metadata is invalid.
    pub fn resume(&mut self, tip: &Configuration) -> Result<TemporalGraphRuntime, EngineError> {
        self.record_checkpoint_closure(tip)?;
        let runtime = instantiate(self, tip)?;
        Ok(TemporalGraphRuntime {
            configuration: tip.id(),
            checkpoint: tip.id(),
            runtime,
        })
    }

    /// Forks from `base` by instantiating it and appending `decisions`.
    ///
    /// The returned branch is recorded as a thin checkpoint in the same DAG.
    /// Forking therefore creates no state representation outside the temporal
    /// graph; later save or search operations may materialize the branch through
    /// the usual replay-oracle-checked path.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when `base` cannot be instantiated or the branch
    /// cannot be recorded as a valid checkpoint edge.
    pub fn fork<I>(
        &mut self,
        base: &Configuration,
        decisions: I,
    ) -> Result<TemporalGraphFork, EngineError>
    where
        I: IntoIterator<Item = Decision>,
    {
        let base_runtime = self.resume(base)?;
        let mut branch = base.clone();
        for decision in decisions {
            branch = step(&branch, decision);
        }
        let branch_checkpoint = self.record_thin_checkpoint(&branch)?;
        Ok(TemporalGraphFork {
            base: base_runtime,
            branch,
            branch_checkpoint,
        })
    }

    /// Replays the stored fat checkpoint for `configuration` on demand.
    ///
    /// The operation checks the exact cached snapshot, or baked genesis for the
    /// genesis configuration, against the independent thin replay path.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointNotRecorded`] when no stored fat
    /// checkpoint exists for `configuration`. Returns replay-oracle validation
    /// errors from [`Self::replay_checkpoint`] when the fat and thin paths do
    /// not match.
    pub fn replay(&self, configuration: &Configuration) -> Result<ReplayOracleCheck, EngineError> {
        let checkpoint = if configuration.is_genesis() {
            self.genesis_snapshot(&configuration.def)
                .map(|genesis| genesis.checkpoint.clone())
        } else {
            self.cached_snapshot(configuration).cloned()
        }
        .ok_or(EngineError::CheckpointNotRecorded {
            checkpoint: configuration.id(),
        })?;
        self.replay_checkpoint(configuration, &checkpoint)
    }

    /// Searches one frontier by reducing, deduplicating, and materializing children.
    ///
    /// Frontier expansion uses [`Self::enumerate_frontier_reduced`]. Every
    /// explored child is then passed through [`Self::materialize_hot_checkpoint`]
    /// with the supplied materialization policy and trigger; covered children
    /// are reported but never materialized.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the frontier cannot be recorded, a child
    /// checkpoint cannot be represented, or a requested hot materialization
    /// cannot be replay-oracle validated.
    pub fn search<I>(
        &mut self,
        frontier: &Configuration,
        decisions: I,
        reduction_policy: FrontierReductionPolicy,
        materialization_policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
    ) -> Result<TemporalGraphSearch, EngineError>
    where
        I: IntoIterator<Item = Decision>,
    {
        self.search_inner(
            frontier,
            decisions,
            reduction_policy,
            materialization_policy,
            trigger,
            None,
        )
    }

    /// Searches one frontier while sampling fat checkpoints through the replay oracle.
    ///
    /// Each explored child is materialized according to `materialization_policy`.
    /// Every returned fat checkpoint is considered for deterministic sampling;
    /// sampled fat checkpoints are immediately reconstructed through thin replay
    /// and compared before search returns.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::SearchReplayOracleMismatch`] when a sampled fat
    /// checkpoint differs from its thin reconstruction. Other graph,
    /// materialization, or replay-oracle validation errors are returned as
    /// [`EngineError`].
    pub fn search_with_replay_oracle_sampling<I>(
        &mut self,
        frontier: &Configuration,
        decisions: I,
        reduction_policy: FrontierReductionPolicy,
        materialization_policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
        sampling_config: &SearchReplayOracleSamplingConfig,
    ) -> Result<TemporalGraphSearch, EngineError>
    where
        I: IntoIterator<Item = Decision>,
    {
        self.search_inner(
            frontier,
            decisions,
            reduction_policy,
            materialization_policy,
            trigger,
            Some(sampling_config),
        )
    }

    fn search_inner<I>(
        &mut self,
        frontier: &Configuration,
        decisions: I,
        reduction_policy: FrontierReductionPolicy,
        materialization_policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
        sampling_config: Option<&SearchReplayOracleSamplingConfig>,
    ) -> Result<TemporalGraphSearch, EngineError>
    where
        I: IntoIterator<Item = Decision>,
    {
        let frontier_id = frontier.id();
        let frontier_report =
            self.enumerate_frontier_reduced(frontier, decisions, reduction_policy)?;
        let mut materialized = Vec::new();
        let mut replay_oracle_sampling =
            sampling_config.map(|_| SearchReplayOracleSamplingReport::default());
        for (sequence, child) in frontier_report.explored.iter().enumerate() {
            let sequence = sequence as u64;
            let checkpoint = match self.materialize_hot_checkpoint(
                &child.configuration,
                materialization_policy,
                trigger,
            ) {
                Ok(checkpoint) => checkpoint,
                Err(error) => {
                    return Err(match sampling_config {
                        Some(config) => sampled_search_replay_oracle_error(sequence, config, error),
                        None => error,
                    });
                }
            };

            if let (Some(config), Some(report)) = (sampling_config, replay_oracle_sampling.as_mut())
            {
                sample_search_replay_oracle_checkpoint(
                    self,
                    &child.configuration,
                    &checkpoint,
                    sequence,
                    config,
                    report,
                )?;
            }

            materialized.push(checkpoint);
        }

        Ok(TemporalGraphSearch {
            frontier: frontier_id,
            frontier_report,
            materialized,
            replay_oracle_sampling,
        })
    }

    /// Admits an exact cached snapshot only if it matches thin replay.
    ///
    /// Cached ancestors are admitted from genesis outward before the target is
    /// checked, so a corrupt ancestor cannot make a corrupt descendant appear
    /// valid. The exact target snapshot is never used to validate itself. On a
    /// replay mismatch or incomplete materialized state, the fat cache entry is
    /// evicted back to its thin checkpoint before the error is returned.
    ///
    /// # Errors
    ///
    /// Returns replay-oracle validation errors from [`Self::replay_checkpoint`].
    /// Returns eviction errors if a corrupt cache entry cannot be converted
    /// back to a thin checkpoint.
    pub fn replay_oracle_admit_cached_snapshot(
        &mut self,
        configuration: &Configuration,
    ) -> Result<Option<ReplayOracleCheck>, EngineError> {
        let Some(checkpoint) = self.cached_snapshot(configuration).cloned() else {
            return Ok(None);
        };
        if let Err(error) = self.replay_oracle_admit_cached_ancestors(configuration) {
            if replay_oracle_failure_rejects_cache(&error) {
                self.evict_fat_checkpoint_to_thin(configuration)?;
            }
            return Err(error);
        }

        match self.replay_checkpoint(configuration, &checkpoint) {
            Ok(check) => Ok(Some(check)),
            Err(error) => {
                if replay_oracle_failure_rejects_cache(&error) {
                    self.evict_fat_checkpoint_to_thin(configuration)?;
                }
                Err(error)
            }
        }
    }

    /// Validates every cached fat snapshot as a replay-oracle invariant.
    ///
    /// Cached checkpoints are admitted from shortest schedule to longest so a
    /// corrupt ancestor is rejected before descendants can use it. The first
    /// mismatch is surfaced and no later cache entry is silently repaired.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when a cached checkpoint has
    /// no independent thin replay path. Returns replay-oracle validation errors
    /// from [`Self::replay_oracle_admit_cached_snapshot`].
    pub fn validate_cached_snapshots_with_replay_oracle(
        &mut self,
    ) -> Result<Vec<ReplayOracleCheck>, EngineError> {
        let mut configurations = self.cached_snapshot_configurations()?;
        configurations
            .sort_by_key(|configuration| (configuration.schedule.len(), configuration.id()));

        let mut checks = Vec::new();
        for configuration in configurations {
            if let Some(check) = self.replay_oracle_admit_cached_snapshot(&configuration)? {
                checks.push(check);
            }
        }
        Ok(checks)
    }

    /// Checks a stored fat checkpoint against its thin replay derivation.
    ///
    /// This is the on-demand replay operation: the supplied fat checkpoint is
    /// validated, the same configuration is reconstructed from an ancestor or
    /// baked genesis without using the target exact snapshot, and both
    /// checkpoint identities are compared.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointConfigurationMismatch`] or
    /// [`EngineError::CheckpointNotLoadable`] when the fat checkpoint metadata
    /// is invalid. Returns [`EngineError::ReplayOracleMismatch`] when the thin
    /// derivation does not reproduce the fat checkpoint identity.
    pub fn replay_checkpoint(
        &self,
        configuration: &Configuration,
        checkpoint: &Checkpoint,
    ) -> Result<ReplayOracleCheck, EngineError> {
        validate_loadable_checkpoint(checkpoint, configuration)?;
        let thin_runtime = instantiate_thin_replay(self, configuration)?;
        let thin_checkpoint = if configuration.is_genesis() {
            self.genesis_snapshot(&configuration.def)
                .ok_or(EngineError::MissingBakedGenesis {
                    scenario: configuration.def.id,
                })?
                .checkpoint
                .clone()
        } else {
            materialized_checkpoint_for_runtime(configuration, thin_runtime)?
        };
        validate_loadable_checkpoint(&thin_checkpoint, configuration)?;
        let fat_state = checkpoint.state.as_ref().ok_or(
            EngineError::CheckpointMaterializedStateIncomplete {
                checkpoint: checkpoint.id,
                reason: "missing-state",
            },
        )?;
        let thin_state = thin_checkpoint.state.as_ref().ok_or(
            EngineError::CheckpointMaterializedStateIncomplete {
                checkpoint: thin_checkpoint.id,
                reason: "missing-state",
            },
        )?;
        if checkpoint.id != thin_checkpoint.id
            || checkpoint.node_blobs != thin_checkpoint.node_blobs
            || checkpoint.node_icounts != thin_checkpoint.node_icounts
            || fat_state.id != thin_state.id
        {
            return Err(EngineError::ReplayOracleMismatch {
                checkpoint: checkpoint.id,
                expected: thin_state.id,
                actual: fat_state.id,
            });
        }

        Ok(ReplayOracleCheck {
            configuration: configuration.id(),
            fat_checkpoint: checkpoint.id,
            thin_checkpoint: thin_checkpoint.id,
        })
    }

    /// Enumerates frontier checkpoint children by applying decisions with `step`.
    ///
    /// The temporal graph records the frontier and each unique child in the
    /// baked-genesis-rooted checkpoint DAG. Duplicate child configurations are
    /// returned once, in stable content-address order, and previously recorded
    /// children are marked so a search driver can avoid re-materializing them.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when the scenario has no
    /// baked root. Returns other [`EngineError`] variants if the frontier or a
    /// child cannot be represented as a valid checkpoint edge.
    pub fn enumerate_frontier<I>(
        &mut self,
        frontier: &Configuration,
        decisions: I,
    ) -> Result<Vec<FrontierChild>, EngineError>
    where
        I: IntoIterator<Item = Decision>,
    {
        self.record_checkpoint_closure(frontier)?;
        let mut children = BTreeMap::new();
        for decision in decisions {
            let configuration = step(frontier, decision.clone());
            children.entry(configuration.id()).or_insert(FrontierChild {
                decision,
                configuration,
                already_recorded: false,
            });
        }

        let mut result = Vec::new();
        for mut child in children.into_values() {
            child.already_recorded = !self.record_checkpoint_closure(&child.configuration)?;
            result.push(child);
        }
        Ok(result)
    }

    /// Enumerates frontier children while applying graph-level reductions.
    ///
    /// Partial-order reduction is applied before recording a child only when an
    /// explicit independence proof covers the frontier's last decision and the
    /// candidate decision, the canonical representative ordering is already in
    /// the graph, and the candidate appears in non-canonical order. Symmetry
    /// reduction uses explicit interchangeable-node classes plus a loadable
    /// checkpoint's canonicalized materialized state; candidates without such
    /// proof material are explored.
    ///
    /// The reductions never rewrite a child configuration. Explored children
    /// remain ordinary content-addressed DAG nodes, and covered children carry
    /// the representative configuration id that justified skipping expansion.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when the scenario has no
    /// baked root. Returns other [`EngineError`] variants if the frontier or an
    /// explored child cannot be represented as a valid checkpoint edge.
    pub fn enumerate_frontier_reduced<I>(
        &mut self,
        frontier: &Configuration,
        decisions: I,
        policy: FrontierReductionPolicy,
    ) -> Result<FrontierReductionReport, EngineError>
    where
        I: IntoIterator<Item = Decision>,
    {
        self.record_checkpoint_closure(frontier)?;
        let mut children = BTreeMap::new();
        let mut covered = Vec::new();
        for decision in decisions {
            let configuration = step(frontier, decision.clone());
            if let Some(cover) = partial_order_cover(
                self,
                frontier,
                decision.clone(),
                configuration.clone(),
                &policy,
            ) {
                covered.push(cover);
                continue;
            }
            children.entry(configuration.id()).or_insert(FrontierChild {
                decision,
                configuration,
                already_recorded: false,
            });
        }

        let mut explored = Vec::new();
        let mut symmetry_representatives = BTreeMap::new();
        for mut child in children.into_values() {
            if let Some(key) =
                self.symmetry_reduction_key(&child.configuration, &policy.symmetry_classes)
            {
                match symmetry_representatives.entry(key) {
                    Entry::Vacant(entry) => {
                        entry.insert(child.configuration.id());
                    }
                    Entry::Occupied(entry) => {
                        covered.push(FrontierCoveredChild {
                            decision: child.decision,
                            configuration: child.configuration,
                            representative: *entry.get(),
                            reason: FrontierReductionReason::Symmetry,
                            reduction_key: key.fingerprint,
                        });
                        continue;
                    }
                }
            }
            child.already_recorded = !self.record_checkpoint_closure(&child.configuration)?;
            explored.push(child);
        }

        Ok(FrontierReductionReport { explored, covered })
    }

    /// Records one `step` edge in the checkpoint DAG.
    ///
    /// The graph must already contain the baked genesis checkpoint for the
    /// scenario. The returned checkpoint is a thin recorded child unless an
    /// identical configuration was already present, in which case the existing
    /// checkpoint node is returned.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when the scenario has no
    /// baked root. Returns other [`EngineError`] variants if the parent/delta
    /// edge cannot be represented as a valid checkpoint.
    pub fn record_step(
        &mut self,
        parent: &Configuration,
        decision: Decision,
    ) -> Result<Checkpoint, EngineError> {
        self.record_checkpoint_closure(parent)?;
        let child = step(parent, decision);
        self.record_checkpoint_closure(&child)?;
        self.checkpoint_node(child.id())
            .cloned()
            .ok_or(EngineError::CheckpointNotRecorded {
                checkpoint: child.id(),
            })
    }

    /// Returns a recorded checkpoint DAG node by id.
    #[must_use]
    pub fn checkpoint_node(&self, checkpoint: ContentHash) -> Option<&Checkpoint> {
        self.checkpoint_nodes.get(&checkpoint)
    }

    /// Returns the symmetry-reduction key for a recorded configuration.
    ///
    /// Exact cached snapshots are preferred because they carry the richest
    /// per-node material. If neither a cached snapshot nor a checkpoint node has
    /// explicit coverage, a loadable materialized state, and an unambiguous
    /// class-based canonical relabeling, `None` is returned and search must
    /// explore the candidate.
    #[must_use]
    pub fn symmetry_reduction_key(
        &self,
        configuration: &Configuration,
        classes: &SymmetryReductionClasses,
    ) -> Option<SymmetryReductionKey> {
        self.cached_snapshots
            .get(&configuration.id())
            .or_else(|| self.checkpoint_nodes.get(&configuration.id()))
            .and_then(|checkpoint| checkpoint.symmetry_reduction_key(classes))
    }

    /// Returns the number of deduplicated checkpoint DAG nodes.
    #[must_use]
    pub fn checkpoint_node_count(&self) -> usize {
        self.checkpoint_nodes.len()
    }

    /// Returns the root-to-target parent chain for `checkpoint`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointNotRecorded`] when the target or one of
    /// its parents is absent from the graph.
    pub fn checkpoint_parent_chain(
        &self,
        checkpoint: ContentHash,
    ) -> Result<Vec<Checkpoint>, EngineError> {
        let mut current = checkpoint;
        let mut reversed = Vec::new();
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert(current) {
                return Err(EngineError::CheckpointTopologyMismatch {
                    checkpoint: current,
                    reason: "parent-cycle",
                });
            }
            let node = self
                .checkpoint_node(current)
                .ok_or(EngineError::CheckpointNotRecorded {
                    checkpoint: current,
                })?;
            reversed.push(node.clone());
            let Some(parent) = node.parent else {
                break;
            };
            current = parent;
        }
        reversed.reverse();
        Ok(reversed)
    }

    /// Persists the root-to-frontier checkpoint closure into `store`.
    ///
    /// The returned keys include checkpoint-node descriptors, typed CoW delta
    /// descriptors, and a reproduction artifact whose scenario, genesis, and
    /// schedule-delta fields are all portable [`DagStore`] keys. VM/device/log
    /// byte streams are owned by lower layers; the pure model persists their
    /// typed content references here so the graph records the same closure shape
    /// that those layers populate with raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TemporalGraphStoreError::Engine`] when the graph cannot derive a
    /// valid baked-genesis-rooted checkpoint closure. Returns
    /// [`TemporalGraphStoreError::Store`] when `store` cannot persist an object.
    pub fn persist_checkpoint_closure<S>(
        &mut self,
        store: &S,
        frontier: &Configuration,
    ) -> Result<TemporalGraphStoreKeys, TemporalGraphStoreError>
    where
        S: DagStore + ?Sized,
    {
        self.record_checkpoint_closure(frontier).map_err(|source| {
            TemporalGraphStoreError::Engine {
                operation: "record-checkpoint-closure",
                source,
            }
        })?;
        let chain = self
            .checkpoint_parent_chain(frontier.id())
            .map_err(|source| TemporalGraphStoreError::Engine {
                operation: "checkpoint-parent-chain",
                source,
            })?;
        let genesis = self.genesis_snapshot(&frontier.def).ok_or_else(|| {
            TemporalGraphStoreError::Engine {
                operation: "load-genesis-snapshot",
                source: EngineError::MissingBakedGenesis {
                    scenario: frontier.def.id,
                },
            }
        })?;

        let scenario_def = store
            .put(&scenario_def_store_bytes(&frontier.def))
            .map_err(|source| TemporalGraphStoreError::Store {
                operation: "put-scenario-def",
                source,
            })?;
        let genesis_snapshot = store
            .put(&checkpoint_store_bytes(&genesis.checkpoint))
            .map_err(|source| TemporalGraphStoreError::Store {
                operation: "put-genesis-snapshot",
                source,
            })?;

        let mut checkpoint_nodes = BTreeMap::new();
        let mut cached_snapshots = BTreeMap::new();
        let mut cow_deltas = BTreeMap::new();
        let mut schedule_deltas = Vec::new();
        for checkpoint in &chain {
            let checkpoint_key =
                store
                    .put(&checkpoint_store_bytes(checkpoint))
                    .map_err(|source| TemporalGraphStoreError::Store {
                        operation: "put-checkpoint-node",
                        source,
                    })?;
            checkpoint_nodes.insert(checkpoint.id, checkpoint_key);

            persist_checkpoint_cow_deltas(
                store,
                checkpoint,
                &mut cow_deltas,
                &mut schedule_deltas,
            )?;

            if let Some(snapshot) = self.cached_snapshots.get(&checkpoint.id) {
                let snapshot_key =
                    store
                        .put(&checkpoint_store_bytes(snapshot))
                        .map_err(|source| TemporalGraphStoreError::Store {
                            operation: "put-cached-snapshot",
                            source,
                        })?;
                cached_snapshots.insert(snapshot.id, snapshot_key);
                persist_checkpoint_cow_deltas(
                    store,
                    snapshot,
                    &mut cow_deltas,
                    &mut schedule_deltas,
                )?;
            }
        }

        Ok(TemporalGraphStoreKeys {
            checkpoint_nodes,
            cached_snapshots,
            cow_deltas,
            reproduction_artifact: DagStoreReproductionArtifact::new(
                scenario_def,
                genesis_snapshot,
                schedule_deltas,
            ),
        })
    }

    /// Computes reference counts for objects reachable from `roots`.
    ///
    /// Baked genesis checkpoints are implicit roots. A live or pinned checkpoint
    /// roots its parent chain, cached snapshot when present, and all typed CoW
    /// deltas referenced by the retained checkpoint/cache closure.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointNotRecorded`] when a live or pinned root
    /// is absent from the checkpoint DAG. Returns
    /// [`EngineError::CheckpointTopologyMismatch`] when a parent chain is
    /// malformed.
    pub fn reference_counts(
        &self,
        roots: &TemporalGraphGcRoots,
    ) -> Result<TemporalGraphReferenceCounts, EngineError> {
        let live_checkpoints = self.mark_live_checkpoints(roots)?;
        Ok(self.reference_counts_for_live_checkpoints(roots, &live_checkpoints))
    }

    /// Runs mark-and-sweep garbage collection over the temporal graph.
    ///
    /// The sweep is rooted at live session tips, pinned checkpoints, and every
    /// baked genesis checkpoint. Unreachable thin checkpoint nodes and exact
    /// cached snapshots are removed; reachable fat cache entries stay cache
    /// entries because they are still referenced by a live identity. Use
    /// [`Self::collect_cached_snapshot`] to explicitly collect a reachable fat
    /// cache entry without deleting its checkpoint identity.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointNotRecorded`] when a live or pinned root
    /// is absent from the checkpoint DAG. Returns
    /// [`EngineError::CheckpointTopologyMismatch`] when a parent chain is
    /// malformed.
    pub fn garbage_collect(
        &mut self,
        roots: &TemporalGraphGcRoots,
    ) -> Result<TemporalGraphGcReport, EngineError> {
        let before_checkpoints = self
            .checkpoint_nodes
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let before_cached_snapshots = self
            .cached_snapshots
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let before_configurations = self
            .recorded_configurations
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let before_cow_deltas = self.cow_delta_ref_set();
        let before_store_keys = self.store_keys_for_checkpoint_ids(&self.store_checkpoint_ids());
        let live_checkpoints = self.mark_live_checkpoints(roots)?;
        let live_reference_counts =
            self.reference_counts_for_live_checkpoints(roots, &live_checkpoints);
        let live_store_keys = self.store_keys_for_checkpoint_ids(&live_checkpoints);

        self.checkpoint_nodes
            .retain(|checkpoint, _| live_checkpoints.contains(checkpoint));
        self.cached_snapshots
            .retain(|checkpoint, _| live_checkpoints.contains(checkpoint));
        self.recorded_configurations
            .retain(|configuration, _| live_checkpoints.contains(configuration));

        let retained_checkpoints = self
            .checkpoint_nodes
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let retained_cached_snapshots = self
            .cached_snapshots
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let retained_configurations = self
            .recorded_configurations
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let retained_cow_deltas = live_reference_counts
            .cow_deltas
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();

        Ok(TemporalGraphGcReport {
            roots: roots.clone(),
            live_checkpoints,
            live_reference_counts,
            collected_checkpoints: before_checkpoints
                .difference(&retained_checkpoints)
                .copied()
                .collect(),
            collected_cached_snapshots: before_cached_snapshots
                .difference(&retained_cached_snapshots)
                .copied()
                .collect(),
            collected_configurations: before_configurations
                .difference(&retained_configurations)
                .copied()
                .collect(),
            collectible_cow_deltas: before_cow_deltas
                .difference(&retained_cow_deltas)
                .copied()
                .collect(),
            live_store_keys: live_store_keys.clone(),
            collectible_store_keys: before_store_keys
                .difference(&live_store_keys)
                .copied()
                .collect(),
            deleted_store_keys: BTreeSet::new(),
            missing_store_keys: BTreeSet::new(),
        })
    }

    /// Runs mark-and-sweep GC and deletes swept objects from `store`.
    ///
    /// The graph first computes the pre-sweep and retained content-addressed
    /// store-key closures. After unreachable graph/cache/configuration entries
    /// are removed, every store key unique to the swept closure is deleted from
    /// `store`.
    ///
    /// # Errors
    ///
    /// Returns [`TemporalGraphStoreError::Engine`] when root reachability cannot
    /// be computed. Returns [`TemporalGraphStoreError::Store`] when `store`
    /// rejects a delete operation. A store error may occur after the graph maps
    /// have been swept.
    pub fn garbage_collect_store<S>(
        &mut self,
        store: &S,
        roots: &TemporalGraphGcRoots,
    ) -> Result<TemporalGraphGcReport, TemporalGraphStoreError>
    where
        S: DagStore + ?Sized,
    {
        let mut report =
            self.garbage_collect(roots)
                .map_err(|source| TemporalGraphStoreError::Engine {
                    operation: "garbage-collect",
                    source,
                })?;
        delete_collectible_store_keys(store, &mut report)?;
        Ok(report)
    }

    /// Collects a reachable fat cache entry without deleting its checkpoint.
    ///
    /// This is the cache-not-identity GC rule: the exact snapshot is removed,
    /// and the checkpoint remains as a thin DAG node that can be replayed from
    /// its retained ancestor chain.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when the graph cannot record
    /// the thin source node for `configuration`. Returns
    /// [`EngineError::CheckpointNotRecorded`] if the thin node is absent after
    /// closure recording.
    pub fn collect_cached_snapshot(
        &mut self,
        configuration: &Configuration,
    ) -> Result<Option<Checkpoint>, EngineError> {
        if self.cached_snapshot(configuration).is_none() {
            return Ok(None);
        }
        self.evict_fat_checkpoint_to_thin(configuration).map(Some)
    }

    /// Collects a reachable fat cache entry and deletes its now-unreferenced store keys.
    ///
    /// This is the store-backed form of [`Self::collect_cached_snapshot`]. The
    /// thin checkpoint identity remains in the graph, while the persisted
    /// cached-snapshot descriptor and any cache-only CoW descriptor keys are
    /// removed from `store`.
    ///
    /// # Errors
    ///
    /// Returns [`TemporalGraphStoreError::Engine`] when the graph cannot evict
    /// the fat cache entry to its thin source node. Returns
    /// [`TemporalGraphStoreError::Store`] when `store` rejects a delete
    /// operation.
    pub fn collect_cached_snapshot_store<S>(
        &mut self,
        store: &S,
        configuration: &Configuration,
    ) -> Result<Option<TemporalGraphGcReport>, TemporalGraphStoreError>
    where
        S: DagStore + ?Sized,
    {
        if self.cached_snapshot(configuration).is_none() {
            return Ok(None);
        }

        let before_store_keys = self.store_keys_for_checkpoint_ids(&self.store_checkpoint_ids());
        let before_cow_deltas = self.cow_delta_ref_set();
        self.collect_cached_snapshot(configuration)
            .map_err(|source| TemporalGraphStoreError::Engine {
                operation: "collect-cached-snapshot",
                source,
            })?;
        let live_checkpoints = self
            .checkpoint_nodes
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let live_store_keys = self.store_keys_for_checkpoint_ids(&self.store_checkpoint_ids());
        let retained_cow_deltas = self.cow_delta_ref_set();
        let mut report = TemporalGraphGcReport {
            roots: TemporalGraphGcRoots::new(),
            live_checkpoints,
            live_reference_counts: TemporalGraphReferenceCounts::default(),
            collected_checkpoints: BTreeSet::new(),
            collected_cached_snapshots: BTreeSet::from([configuration.id()]),
            collected_configurations: BTreeSet::new(),
            collectible_cow_deltas: before_cow_deltas
                .difference(&retained_cow_deltas)
                .copied()
                .collect(),
            live_store_keys: live_store_keys.clone(),
            collectible_store_keys: before_store_keys
                .difference(&live_store_keys)
                .copied()
                .collect(),
            deleted_store_keys: BTreeSet::new(),
            missing_store_keys: BTreeSet::new(),
        };
        delete_collectible_store_keys(store, &mut report)?;
        Ok(Some(report))
    }

    /// Returns whether `configuration` is recorded in the temporal graph.
    #[must_use]
    pub fn contains_configuration(&self, configuration: &Configuration) -> bool {
        self.recorded_configurations
            .contains_key(&configuration.id())
    }

    /// Returns the number of deduplicated configurations recorded by the graph.
    #[must_use]
    pub fn recorded_configuration_count(&self) -> usize {
        self.recorded_configurations.len()
    }

    /// Returns the number of saved non-genesis fat checkpoints in the graph.
    #[must_use]
    pub fn cached_snapshot_count(&self) -> usize {
        self.cached_snapshots.len()
    }

    /// Returns CoW sharing stats for recorded DAG nodes and exact-snapshot cache entries.
    #[must_use]
    pub fn cow_sharing_stats(&self) -> CowSharingStats {
        CowSharingStats::from_refs(self.cow_delta_refs())
    }

    /// Returns how many new CoW objects `checkpoint` would add to this graph.
    ///
    /// Existing objects are matched by typed content hash, so a sibling fork
    /// that dirties the same VM page, device overlay page, or event-log segment
    /// pays no additional storage for that already-present delta object.
    #[must_use]
    pub fn marginal_fork_cow_delta_objects(&self, checkpoint: &Checkpoint) -> usize {
        let existing = self.cow_delta_ref_set();
        checkpoint
            .cow_delta_refs()
            .into_iter()
            .filter(|cow_ref| !existing.contains(cow_ref))
            .collect::<BTreeSet<_>>()
            .len()
    }

    fn record_configuration(&mut self, configuration: Configuration) -> bool {
        let id = configuration.id();
        match self.recorded_configurations.entry(id) {
            Entry::Vacant(entry) => {
                entry.insert(configuration);
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    fn cow_delta_refs(&self) -> Vec<CowDeltaRef> {
        let mut refs = Vec::new();
        for checkpoint in self.checkpoint_nodes.values() {
            refs.extend(checkpoint.cow_delta_refs());
        }
        for checkpoint in self.cached_snapshots.values() {
            refs.extend(checkpoint.cow_delta_refs());
        }
        refs
    }

    fn cow_delta_ref_set(&self) -> BTreeSet<CowDeltaRef> {
        self.cow_delta_refs().into_iter().collect()
    }

    fn mark_live_checkpoints(
        &self,
        roots: &TemporalGraphGcRoots,
    ) -> Result<BTreeSet<ContentHash>, EngineError> {
        let mut live = BTreeSet::new();
        for root in self.gc_root_checkpoint_ids(roots) {
            let chain = self.checkpoint_parent_chain(root)?;
            live.extend(chain.into_iter().map(|checkpoint| checkpoint.id));
        }
        Ok(live)
    }

    fn gc_root_checkpoint_ids(&self, roots: &TemporalGraphGcRoots) -> BTreeSet<ContentHash> {
        let mut root_ids = BTreeSet::new();
        root_ids.extend(
            roots
                .live_tips
                .iter()
                .filter(|(_, count)| **count > 0)
                .map(|(checkpoint, _)| *checkpoint),
        );
        root_ids.extend(
            roots
                .pinned_checkpoints
                .iter()
                .filter(|(_, count)| **count > 0)
                .map(|(checkpoint, _)| *checkpoint),
        );
        root_ids.extend(
            self.baked_genesis
                .values()
                .map(|genesis| genesis.checkpoint.id),
        );
        root_ids
    }

    fn reference_counts_for_live_checkpoints(
        &self,
        roots: &TemporalGraphGcRoots,
        live_checkpoints: &BTreeSet<ContentHash>,
    ) -> TemporalGraphReferenceCounts {
        let mut counts = TemporalGraphReferenceCounts::default();
        for (root, refcount) in self.gc_root_refcounts(roots) {
            if live_checkpoints.contains(&root) {
                for _ in 0..refcount {
                    counts.increment_checkpoint(root);
                }
            }
        }
        for checkpoint_id in live_checkpoints {
            let Some(checkpoint) = self.checkpoint_nodes.get(checkpoint_id) else {
                continue;
            };
            if let Some(parent) = checkpoint.parent
                && live_checkpoints.contains(&parent)
            {
                counts.increment_checkpoint(parent);
            }
            for cow_ref in checkpoint.cow_delta_refs() {
                counts.increment_cow_delta(cow_ref);
            }
            if let Some(snapshot) = self.cached_snapshots.get(checkpoint_id) {
                counts.increment_cached_snapshot(*checkpoint_id);
                for cow_ref in snapshot.cow_delta_refs() {
                    counts.increment_cow_delta(cow_ref);
                }
            }
        }
        counts
    }

    fn gc_root_refcounts(&self, roots: &TemporalGraphGcRoots) -> BTreeMap<ContentHash, usize> {
        let mut refcounts = BTreeMap::new();
        for (checkpoint, count) in &roots.live_tips {
            if *count == 0 {
                continue;
            }
            *refcounts.entry(*checkpoint).or_insert(0) += *count;
        }
        for (checkpoint, count) in &roots.pinned_checkpoints {
            if *count == 0 {
                continue;
            }
            *refcounts.entry(*checkpoint).or_insert(0) += *count;
        }
        for genesis in self.baked_genesis.values() {
            *refcounts.entry(genesis.checkpoint.id).or_insert(0) += 1;
        }
        refcounts
    }

    fn store_checkpoint_ids(&self) -> BTreeSet<ContentHash> {
        let mut checkpoints = self
            .checkpoint_nodes
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        checkpoints.extend(self.cached_snapshots.keys().copied());
        checkpoints
    }

    fn store_keys_for_checkpoint_ids(
        &self,
        checkpoints: &BTreeSet<ContentHash>,
    ) -> BTreeSet<ContentHash> {
        let mut keys = BTreeSet::new();
        for configuration in self.recorded_configurations.values() {
            if checkpoints.contains(&configuration.id()) {
                keys.insert(ContentHash::from_bytes(&scenario_def_store_bytes(
                    &configuration.def,
                )));
                if let Some(genesis) = self.genesis_snapshot(&configuration.def) {
                    keys.insert(ContentHash::from_bytes(&checkpoint_store_bytes(
                        &genesis.checkpoint,
                    )));
                }
            }
        }
        for checkpoint_id in checkpoints {
            if let Some(checkpoint) = self.checkpoint_nodes.get(checkpoint_id) {
                insert_checkpoint_store_keys(checkpoint, &mut keys);
            }
            if let Some(snapshot) = self.cached_snapshots.get(checkpoint_id) {
                insert_checkpoint_store_keys(snapshot, &mut keys);
            }
        }
        keys
    }

    fn has_replay_oracle_path(&self, configuration: &Configuration) -> Result<bool, EngineError> {
        if configuration.is_genesis() {
            return Ok(self.genesis_snapshot(&configuration.def).is_some());
        }
        Ok(self.genesis_snapshot(&configuration.def).is_some())
    }

    fn replay_oracle_admit_cached_ancestors(
        &mut self,
        configuration: &Configuration,
    ) -> Result<(), EngineError> {
        let ancestors = self.cached_ancestor_configurations(configuration)?;
        for ancestor in ancestors {
            self.replay_oracle_admit_cached_snapshot(&ancestor)?;
        }
        Ok(())
    }

    fn cached_ancestor_configurations(
        &self,
        configuration: &Configuration,
    ) -> Result<Vec<Configuration>, EngineError> {
        let mut ancestors = Vec::new();
        for prefix_len in 0..configuration.schedule.len() {
            let schedule = configuration
                .schedule
                .prefix(prefix_len)
                .map_err(EngineError::SchedulePrefix)?;
            let ancestor = Configuration {
                def: configuration.def.clone(),
                schedule,
            };
            if self.cached_snapshot(&ancestor).is_some() {
                ancestors.push(ancestor);
            }
        }
        Ok(ancestors)
    }

    fn cached_snapshot_configurations(&self) -> Result<Vec<Configuration>, EngineError> {
        let mut configurations = Vec::new();
        for checkpoint in self.cached_snapshots.keys() {
            let configuration = self.recorded_configurations.get(checkpoint).ok_or(
                EngineError::CheckpointNotRecorded {
                    checkpoint: *checkpoint,
                },
            )?;
            configurations.push(configuration.clone());
        }
        Ok(configurations)
    }

    fn record_checkpoint_closure(
        &mut self,
        configuration: &Configuration,
    ) -> Result<bool, EngineError> {
        if self.checkpoint_nodes.contains_key(&configuration.id()) {
            self.record_configuration(configuration.clone());
            return Ok(false);
        }
        if configuration.is_genesis() {
            let checkpoint = self
                .genesis_snapshot(&configuration.def)
                .ok_or(EngineError::MissingBakedGenesis {
                    scenario: configuration.def.id,
                })?
                .checkpoint
                .clone();
            self.record_configuration(configuration.clone());
            self.checkpoint_nodes.insert(configuration.id(), checkpoint);
            return Ok(true);
        }

        let parent = immediate_parent_configuration(configuration)?.ok_or(
            EngineError::CheckpointTopologyMismatch {
                checkpoint: configuration.id(),
                reason: "descendant-missing-parent",
            },
        )?;
        self.record_checkpoint_closure(&parent)?;
        let checkpoint = Checkpoint::from_recorded_configuration(
            configuration,
            Some(&parent),
            VirtualTime::default(),
            BTreeMap::new(),
            CheckpointKind::Thin,
            BTreeMap::new(),
        )?;
        self.record_configuration(configuration.clone());
        self.checkpoint_nodes.insert(configuration.id(), checkpoint);
        Ok(true)
    }

    /// Returns the exact loadable snapshot for `configuration`, if one exists.
    #[must_use]
    pub fn cached_snapshot(&self, configuration: &Configuration) -> Option<&Checkpoint> {
        self.cached_snapshots.get(&configuration.id())
    }

    /// Returns the baked genesis snapshot for `def`, if one exists.
    #[must_use]
    pub fn genesis_snapshot(&self, def: &ScenarioDef) -> Option<&GenesisCheckpoint> {
        self.baked_genesis.get(&def.id)
    }

    /// Returns the nearest cached ancestor of `configuration`, excluding itself.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] if a schedule prefix cannot be constructed.
    pub fn nearest_cached_ancestor(
        &self,
        configuration: &Configuration,
    ) -> Result<Option<Configuration>, EngineError> {
        for prefix_len in (0..configuration.schedule.len()).rev() {
            let schedule = configuration
                .schedule
                .prefix(prefix_len)
                .map_err(EngineError::SchedulePrefix)?;
            let ancestor = Configuration {
                def: configuration.def.clone(),
                schedule,
            };
            if self.cached_snapshot(&ancestor).is_some() {
                return Ok(Some(ancestor));
            }
        }

        Ok(None)
    }
}

/// Result of an on-demand replay-oracle check.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReplayOracleCheck {
    /// Configuration whose fat and thin checkpoint identities were compared.
    pub configuration: ContentHash,
    /// Content address of the supplied fat checkpoint.
    pub fat_checkpoint: ContentHash,
    /// Content address of the checkpoint reconstructed by thin replay.
    pub thin_checkpoint: ContentHash,
}

/// Bisection requested after an active-search replay-oracle mismatch.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SearchReplayOracleBisectionRequest {
    /// Stable search materialization sequence where the mismatch was observed.
    pub sequence: u64,
    /// Fat checkpoint whose sampled replay-oracle comparison failed.
    pub checkpoint: ContentHash,
    /// Stable reason for the bisection request.
    pub reason: &'static str,
}

/// Deterministic sampling report for active graph-search replay-oracle checks.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SearchReplayOracleSamplingReport {
    /// Number of fat search materializations considered.
    pub considered: usize,
    /// Number of fat search materializations replay-oracle checked.
    pub sampled: usize,
    /// Number of fat search materializations not sampled.
    pub skipped: usize,
    /// Checkpoints selected by the deterministic sampler.
    pub sampled_checkpoints: Vec<ContentHash>,
}

/// One unique child produced by frontier decision enumeration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FrontierChild {
    /// Decision applied to the frontier configuration.
    pub decision: Decision,
    /// Child configuration produced by `step`.
    pub configuration: Configuration,
    /// Whether the child was already present in the temporal graph.
    pub already_recorded: bool,
}

/// Proof-carrying policy for graph-level frontier reductions.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct FrontierReductionPolicy {
    /// Interchangeable node classes used for canonical-relabeling symmetry.
    pub symmetry_classes: SymmetryReductionClasses,
    /// Explicit independent decision pairs used for partial-order reduction.
    pub partial_order: PartialOrderReductionPolicy,
}

impl FrontierReductionPolicy {
    /// Builds a policy that explores every candidate.
    #[must_use]
    pub fn none() -> Self {
        Self {
            symmetry_classes: SymmetryReductionClasses::new(),
            partial_order: PartialOrderReductionPolicy::new(),
        }
    }

    /// Replaces the symmetry classes used for canonical relabeling.
    #[must_use]
    pub fn with_symmetry_classes(mut self, classes: SymmetryReductionClasses) -> Self {
        self.symmetry_classes = classes;
        self
    }

    /// Replaces the partial-order independence proof set.
    #[must_use]
    pub fn with_partial_order(mut self, partial_order: PartialOrderReductionPolicy) -> Self {
        self.partial_order = partial_order;
        self
    }
}

/// Why a frontier candidate was covered by a representative.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrontierReductionReason {
    /// A prior frontier child had the same canonical-relabeling fingerprint.
    Symmetry,
    /// The candidate is the non-canonical ordering of independent decisions.
    PartialOrder,
}

/// A frontier child skipped because a representative already covers it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FrontierCoveredChild {
    /// Decision that would have produced the covered child.
    pub decision: Decision,
    /// Covered child configuration produced by `step`.
    pub configuration: Configuration,
    /// Configuration id of the representative explored instead.
    pub representative: ContentHash,
    /// Reduction that justified the skip.
    pub reason: FrontierReductionReason,
    /// Content-addressed proof key for the reduction decision.
    pub reduction_key: ContentHash,
}

/// Reduced frontier enumeration result.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct FrontierReductionReport {
    /// Children the search should explore.
    pub explored: Vec<FrontierChild>,
    /// Children covered by explored representatives.
    pub covered: Vec<FrontierCoveredChild>,
}

/// Result of a graph-level save operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TemporalGraphSave {
    /// Configuration saved by the operation.
    pub configuration: ContentHash,
    /// Checkpoint identity saved for the configuration.
    pub checkpoint: ContentHash,
    /// Storage shape of the saved checkpoint.
    pub checkpoint_kind: CheckpointKind,
    /// DAG-store keys persisted for the saved closure.
    pub store_keys: TemporalGraphStoreKeys,
}

/// Result of a graph-level runtime realization.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TemporalGraphRuntime {
    /// Configuration realized by [`instantiate`].
    pub configuration: ContentHash,
    /// Checkpoint identity used as the graph operation target.
    pub checkpoint: ContentHash,
    /// Runtime state returned by [`instantiate`].
    pub runtime: RuntimeState,
}

/// Result of a graph-level fork operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TemporalGraphFork {
    /// Runtime produced for the fork base.
    pub base: TemporalGraphRuntime,
    /// Branch configuration produced by appending fork decisions.
    pub branch: Configuration,
    /// Thin checkpoint recorded for the branch.
    pub branch_checkpoint: Checkpoint,
}

/// Result of a graph-level search frontier expansion.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TemporalGraphSearch {
    /// Frontier configuration expanded by the operation.
    pub frontier: ContentHash,
    /// Reduced frontier enumeration report.
    pub frontier_report: FrontierReductionReport,
    /// Checkpoints returned by hot/cold materialization policy for explored children.
    pub materialized: Vec<Checkpoint>,
    /// Replay-oracle sampling report when active search sampling was enabled.
    pub replay_oracle_sampling: Option<SearchReplayOracleSamplingReport>,
}

/// Canonical-relabeling fingerprint for symmetry reduction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymmetryReductionKey {
    /// Hash of coverage plus node-local state under canonical node relabeling.
    pub fingerprint: ContentHash,
}

/// A caller-provided class of interchangeable nodes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymmetryClassId {
    /// Stable class name within one scenario.
    pub name: String,
}

/// Explicit interchangeable-node classes for symmetry reduction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SymmetryReductionClasses {
    /// Node-to-class mapping. Nodes absent from this map retain their identity.
    pub classes: BTreeMap<NodeId, SymmetryClassId>,
}

impl SymmetryReductionClasses {
    /// Builds an empty class map, which disables symmetry reduction.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `node` to an interchangeable class.
    #[must_use]
    pub fn with_node_class(mut self, node: NodeId, class: SymmetryClassId) -> Self {
        self.classes.insert(node, class);
        self
    }

    /// Returns whether no interchangeable classes are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }
}

/// Canonical ordering fingerprint for one independent decision pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartialOrderReductionKey {
    /// Hash of the canonical representative interleaving.
    pub fingerprint: ContentHash,
}

/// Explicit proof that one unordered pair of decisions is independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartialOrderIndependenceProof {
    /// Lower deterministic decision key.
    pub first: ContentHash,
    /// Higher deterministic decision key.
    pub second: ContentHash,
}

impl PartialOrderIndependenceProof {
    /// Builds an unordered independence proof for two decisions.
    #[must_use]
    pub fn new(left: &Decision, right: &Decision) -> Self {
        let left = left.reduction_order_key();
        let right = right.reduction_order_key();
        if left <= right {
            Self {
                first: left,
                second: right,
            }
        } else {
            Self {
                first: right,
                second: left,
            }
        }
    }
}

/// Explicit independence proofs for partial-order reduction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct PartialOrderReductionPolicy {
    /// Proven independent unordered decision pairs.
    pub independent_pairs: BTreeSet<PartialOrderIndependenceProof>,
}

impl PartialOrderReductionPolicy {
    /// Builds an empty proof set, which disables partial-order skips.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an unordered independent decision pair proof.
    #[must_use]
    pub fn with_independent_pair(mut self, left: &Decision, right: &Decision) -> Self {
        self.independent_pairs
            .insert(PartialOrderIndependenceProof::new(left, right));
        self
    }

    /// Returns whether this policy proves `left` and `right` independent.
    #[must_use]
    pub fn proves_independent(&self, left: &Decision, right: &Decision) -> bool {
        self.independent_pairs
            .contains(&PartialOrderIndependenceProof::new(left, right))
    }
}

/// A live runtime-state handle produced by `instantiate`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RuntimeState {
    /// The runtime state's content address.
    pub id: ContentHash,
    /// The configuration materialized by this runtime state.
    pub configuration: ContentHash,
    /// Per-node VM-state refs available to a fat checkpoint materialization.
    pub node_blobs: BTreeMap<NodeId, NodeBlobRef>,
    /// Per-node retired instruction counters at the materialization point.
    pub node_icounts: BTreeMap<NodeId, Icount>,
}

/// Appends one decision to a configuration without materializing runtime state.
#[must_use]
pub fn step(config: &Configuration, decision: Decision) -> Configuration {
    Configuration {
        def: config.def.clone(),
        schedule: config.schedule.appended(decision),
    }
}

/// Computes the abstract state denoted by `def` and `schedule`.
///
/// # Errors
///
/// This reducer is total for the current pure execution spine and therefore
/// does not currently return an error. The `Result` shape is retained for later
/// semantic validation as richer `Decision` variants become executable.
pub fn reduce(def: &ScenarioDef, schedule: &Schedule) -> Result<State, EngineError> {
    Ok(State {
        id: canonical::reduced_state_hash(def, schedule),
    })
}

/// Materializes `config` into a live runtime through `graph`.
///
/// Exact cached snapshots are checked against the replay oracle before they are
/// loaded whenever the graph has a baked genesis root for the scenario.
///
/// # Errors
///
/// Returns [`EngineError::MissingBakedGenesis`] when materialization reaches
/// genesis and the graph has no baked genesis checkpoint for the scenario.
/// Returns other [`EngineError`] variants when cached checkpoint metadata is
/// invalid or suffix replay does not reconstruct the requested configuration.
pub fn instantiate(
    graph: &TemporalGraph,
    config: &Configuration,
) -> Result<RuntimeState, EngineError> {
    if config.is_genesis() {
        let genesis =
            graph
                .genesis_snapshot(&config.def)
                .ok_or(EngineError::MissingBakedGenesis {
                    scenario: config.def.id,
                })?;
        return load_snapshot(config, &genesis.checkpoint);
    }

    if let Some(snapshot) = graph.cached_snapshot(config) {
        if graph.has_replay_oracle_path(config)? {
            graph.replay_checkpoint(config, snapshot)?;
        }
        return load_snapshot(config, snapshot);
    }

    if let Some(ancestor) = graph.nearest_cached_ancestor(config)? {
        let ancestor_runtime = instantiate(graph, &ancestor)?;
        let suffix = config
            .schedule
            .suffix_from(ancestor.schedule.len())
            .map_err(EngineError::SchedulePrefix)?;
        return replay_suffix(ancestor_runtime, &ancestor, &suffix, config);
    }

    let genesis = Configuration::genesis(config.def.clone());
    let genesis_runtime = instantiate(graph, &genesis)?;
    let suffix = config
        .schedule
        .suffix_from(genesis.schedule.len())
        .map_err(EngineError::SchedulePrefix)?;
    replay_suffix(genesis_runtime, &genesis, &suffix, config)
}

/// Produces the genesis checkpoint for `world`.
///
/// # Errors
///
/// This pure model helper is total for a content-addressed [`World`] handle.
/// Backend-specific bake implementations may still return backend errors while
/// starting guests to their ready point and saving VM state.
pub fn bake(world: &World) -> Result<GenesisCheckpoint, EngineError> {
    world.validate_ready_point_policies()?;
    let def = world.scenario_def();
    let genesis = Configuration::genesis(def);

    let checkpoint = Checkpoint::from_recorded_configuration(
        &genesis,
        None,
        VirtualTime::default(),
        baked_node_icounts(world),
        CheckpointKind::Fat,
        baked_node_blobs(world),
    )?;

    Ok(GenesisCheckpoint { checkpoint })
}

/// An engine-spine error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineError {
    /// The operation's signature is fixed but its behavior is not implemented.
    NotImplemented {
        /// The operation whose implementation is deferred.
        operation: &'static str,
    },
    /// A cached checkpoint is not a fat loadable snapshot.
    CheckpointNotLoadable {
        /// The checkpoint that cannot be loaded.
        checkpoint: ContentHash,
        /// The checkpoint storage kind.
        kind: CheckpointKind,
    },
    /// A cached checkpoint names a different configuration than requested.
    CheckpointConfigurationMismatch {
        /// The checkpoint whose metadata was invalid.
        checkpoint: ContentHash,
        /// The requested configuration id.
        expected: ContentHash,
        /// The configuration id recorded by the checkpoint.
        actual: ContentHash,
    },
    /// A checkpoint's recorded node id does not match its configuration id.
    CheckpointIdentityMismatch {
        /// The checkpoint whose identity was invalid.
        checkpoint: ContentHash,
        /// The expected checkpoint id.
        expected: ContentHash,
        /// The actual checkpoint id.
        actual: ContentHash,
    },
    /// A checkpoint's parent/delta/scenario fields do not match its configuration.
    CheckpointTopologyMismatch {
        /// The checkpoint whose topology was invalid.
        checkpoint: ContentHash,
        /// Stable reason for the topology rejection.
        reason: &'static str,
    },
    /// A fat checkpoint does not carry enough materialized state for `loadvm`.
    CheckpointMaterializedStateIncomplete {
        /// The checkpoint whose materialized state is incomplete.
        checkpoint: ContentHash,
        /// Stable reason for the state rejection.
        reason: &'static str,
    },
    /// A checkpoint DAG node was requested before it was recorded.
    CheckpointNotRecorded {
        /// The absent checkpoint id.
        checkpoint: ContentHash,
    },
    /// No baked genesis checkpoint exists for the scenario.
    MissingBakedGenesis {
        /// The scenario id missing a baked genesis checkpoint.
        scenario: ContentHash,
    },
    /// A genesis snapshot was registered through the ordinary snapshot cache.
    GenesisSnapshotMustBeBaked {
        /// The genesis configuration that must use the baked genesis cache.
        configuration: ContentHash,
    },
    /// A world contains duplicate node identifiers.
    DuplicateWorldNodeId {
        /// The duplicate node id.
        node: NodeId,
    },
    /// A world link connects a node to itself.
    WorldLinkSelfLoop {
        /// The repeated endpoint node.
        node: NodeId,
    },
    /// A world link references a node that is not declared in the world.
    WorldLinkUnknownNode {
        /// The invalid link.
        link: LinkDef,
        /// The undeclared endpoint.
        node: NodeId,
    },
    /// A world contains duplicate canonical links.
    DuplicateWorldLink {
        /// The duplicated link.
        link: LinkDef,
    },
    /// A link's one-way base latency is below the model floor.
    WorldLinkLatencyBelowFloor {
        /// The invalid link.
        link: LinkDef,
        /// The configured one-way base latency.
        latency: SimDuration,
        /// The minimum legal link latency.
        minimum: SimDuration,
    },
    /// A link's configured jitter can drive effective latency below the floor.
    WorldLinkJitterBelowLatencyFloor {
        /// The invalid link.
        link: LinkDef,
        /// The configured one-way base latency.
        latency: SimDuration,
        /// The configured maximum jitter.
        jitter: SimDuration,
        /// The minimum legal effective link latency.
        minimum: SimDuration,
    },
    /// A fixed-point link loss probability is outside `[0.0, 1.0]`.
    LinkLossProbabilityOutOfRange {
        /// The invalid probability in millionths.
        millionths: u32,
        /// The maximum legal probability in millionths.
        maximum: u32,
    },
    /// A fixed-point family fault density is outside `[0.0, 1.0]`.
    FaultDensityOutOfRange {
        /// The invalid density in millionths.
        millionths: u32,
        /// The maximum legal density in millionths.
        maximum: u32,
    },
    /// An agent-signal ready point was configured without white-box opt-in.
    WhiteBoxReadyPointWithoutOptIn {
        /// The node whose ready-point configuration is invalid.
        node: NodeId,
    },
    /// A plan membership fault references an undeclared node.
    PlanFaultUnknownNode {
        /// The undeclared node.
        node: NodeId,
    },
    /// A plan partition references no declared world link.
    PlanFaultUnknownLink {
        /// One endpoint requested by the plan fault.
        endpoint_a: NodeId,
        /// The other endpoint requested by the plan fault.
        endpoint_b: NodeId,
    },
    /// A plan heal references no activated fault tag.
    PlanHealUnknownTag {
        /// The unknown heal tag.
        tag: FaultTag,
    },
    /// A plan heal is not after the tag activation it heals.
    PlanHealBeforeActivate {
        /// The invalid heal tag.
        tag: FaultTag,
        /// Virtual time when the tag activates.
        activate_at: VirtualTime,
        /// Virtual time when the tag was healed.
        heal_at: VirtualTime,
    },
    /// A not-yet-joined membership hold was scheduled after the run starts.
    PlanNotYetJoinedAfterStart {
        /// The node that would be held inactive too late.
        node: NodeId,
        /// Virtual time when the hold was scheduled.
        at: VirtualTime,
    },
    /// A serialized plan entry carries a negative virtual time.
    PlanNegativeTime {
        /// Zero-based index of the serialized plan entry.
        entry: usize,
        /// The invalid signed tick value.
        at_ticks: i64,
    },
    /// A serialized plan partition uses an unknown direction.
    PlanFaultUnknownDirection {
        /// Zero-based index of the serialized plan entry.
        entry: usize,
        /// The invalid direction spelling.
        direction: String,
    },
    /// A serialized membership fault carries a parameter the model does not support.
    PlanFaultUnsupportedParam {
        /// Zero-based index of the serialized plan entry.
        entry: usize,
        /// The unsupported fault parameter name.
        field: String,
    },
    /// A properties bundle contains duplicate assertion identifiers.
    PropertyDuplicateAssertionId {
        /// The duplicated assertion id.
        id: AssertionId,
    },
    /// A property predicate references an undeclared node.
    PropertyPredicateUnknownNode {
        /// The undeclared node.
        node: NodeId,
    },
    /// A compound property predicate has no child predicates.
    PropertyPredicateEmptyCompound {
        /// Stable name of the empty compound predicate kind.
        kind: &'static str,
    },
    /// A scenario-builder node template reference names no concrete node.
    ScenarioBuilderUnknownNodeTemplate {
        /// The node that requested a copied template.
        node: NodeId,
        /// The missing template node name.
        template: NodeId,
    },
    /// A serialized scenario form is malformed.
    ScenarioSerialization {
        /// Stable reason for the serialization failure.
        reason: String,
    },
    /// A serialized image/kernel/initrd reference is not content-addressed.
    ScenarioImageReferenceNotContentAddressed {
        /// The serialized field being validated.
        field: &'static str,
        /// The non-portable reference value.
        value: String,
    },
    /// A serialized content address did not match the parsed component content.
    ScenarioSerializedIdMismatch {
        /// The component whose serialized id was invalid.
        component: &'static str,
        /// The content address carried in the serialized form.
        expected: ContentHash,
        /// The content address recomputed from parsed content.
        actual: ContentHash,
    },
    /// A scenario family has an invalid finite parameter space.
    ScenarioFamilyInvalidSpace {
        /// Stable reason for the parameter-space rejection.
        reason: &'static str,
    },
    /// A requested family parameter point is outside the family space.
    ScenarioFamilyParameterOutOfSpace {
        /// Stable parameter axis name.
        parameter: &'static str,
    },
    /// A runtime was replayed from a configuration it does not materialize.
    RuntimeConfigurationMismatch {
        /// The runtime-state id whose metadata was invalid.
        runtime: ContentHash,
        /// The configuration expected by the replay start.
        expected: ContentHash,
        /// The configuration recorded by the runtime state.
        actual: ContentHash,
    },
    /// Replaying a suffix did not reconstruct the requested configuration.
    ReplayTargetMismatch {
        /// The requested target configuration.
        expected: ContentHash,
        /// The configuration produced by replaying the suffix.
        actual: ContentHash,
    },
    /// A fat checkpoint did not match its thin replay derivation.
    ReplayOracleMismatch {
        /// The fat checkpoint under test.
        checkpoint: ContentHash,
        /// The materialized-state identity reconstructed by thin replay.
        expected: ContentHash,
        /// The supplied fat checkpoint's materialized-state identity.
        actual: ContentHash,
    },
    /// A sampled search materialization failed the replay oracle and needs bisection.
    SearchReplayOracleMismatch {
        /// Bisection request for the fat/thin reconstruction pair.
        bisection: SearchReplayOracleBisectionRequest,
        /// The fat checkpoint under test.
        checkpoint: ContentHash,
        /// The materialized-state identity reconstructed by thin replay.
        expected: ContentHash,
        /// The supplied fat checkpoint's materialized-state identity.
        actual: ContentHash,
    },
    /// A self-contained reproduction artifact did not replay to its recorded state.
    ReproductionArtifactReplayMismatch {
        /// The artifact whose replay failed.
        artifact: ContentHash,
        /// The reduced state recorded in the artifact.
        expected: ContentHash,
        /// The reduced state reached by replaying the embedded scenario/schedule.
        actual: ContentHash,
    },
    /// Active-search replay-oracle sampling was configured with an invalid rate.
    InvalidSearchReplayOracleSamplingConfig {
        /// Stable reason for the validation failure.
        reason: &'static str,
    },
    /// A schedule prefix or suffix could not be constructed.
    SchedulePrefix(
        /// The schedule prefix error.
        ScheduleError,
    ),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented { operation } => {
                write!(f, "{operation} is not implemented yet")
            }
            Self::CheckpointNotLoadable { kind, .. } => {
                write!(
                    f,
                    "checkpoint is not loadable because it is {}",
                    checkpoint_kind_label(*kind)
                )
            }
            Self::CheckpointConfigurationMismatch { .. } => {
                f.write_str("checkpoint configuration does not match requested configuration")
            }
            Self::CheckpointIdentityMismatch { .. } => {
                f.write_str("checkpoint id does not match requested configuration")
            }
            Self::CheckpointTopologyMismatch { reason, .. } => {
                write!(f, "checkpoint topology is invalid: {reason}")
            }
            Self::CheckpointMaterializedStateIncomplete { reason, .. } => {
                write!(f, "checkpoint materialized state is incomplete: {reason}")
            }
            Self::CheckpointNotRecorded { .. } => {
                f.write_str("checkpoint is not recorded in the temporal graph")
            }
            Self::MissingBakedGenesis { .. } => {
                f.write_str("missing baked genesis checkpoint for scenario")
            }
            Self::GenesisSnapshotMustBeBaked { .. } => {
                f.write_str("genesis snapshots must be registered as baked genesis checkpoints")
            }
            Self::DuplicateWorldNodeId { .. } => f.write_str("world contains a duplicate node id"),
            Self::WorldLinkSelfLoop { .. } => f.write_str("world link endpoints must be distinct"),
            Self::WorldLinkUnknownNode { .. } => {
                f.write_str("world link references an undeclared node")
            }
            Self::DuplicateWorldLink { .. } => {
                f.write_str("world contains a duplicate canonical link")
            }
            Self::WorldLinkLatencyBelowFloor { .. } => {
                f.write_str("world link latency is below the minimum floor")
            }
            Self::WorldLinkJitterBelowLatencyFloor { .. } => {
                f.write_str("world link jitter can drive latency below the minimum floor")
            }
            Self::LinkLossProbabilityOutOfRange { .. } => {
                f.write_str("world link loss probability is outside the legal range")
            }
            Self::FaultDensityOutOfRange { .. } => {
                f.write_str("scenario family fault density is outside the legal range")
            }
            Self::WhiteBoxReadyPointWithoutOptIn { .. } => {
                f.write_str("agent-signal ready point requires white-box opt-in")
            }
            Self::PlanFaultUnknownNode { .. } => {
                f.write_str("plan membership fault references an undeclared node")
            }
            Self::PlanFaultUnknownLink { .. } => {
                f.write_str("plan partition references no declared world link")
            }
            Self::PlanHealUnknownTag { .. } => {
                f.write_str("plan heal references no activated fault tag")
            }
            Self::PlanHealBeforeActivate { .. } => {
                f.write_str("plan heal is not after its fault activation")
            }
            Self::PlanNotYetJoinedAfterStart { .. } => {
                f.write_str("not-yet-joined fault must be active at run start")
            }
            Self::PlanNegativeTime { .. } => {
                f.write_str("plan entry virtual time must be non-negative")
            }
            Self::PlanFaultUnknownDirection { .. } => {
                f.write_str("plan partition direction is unknown")
            }
            Self::PlanFaultUnsupportedParam { field, .. } => {
                write!(f, "plan membership fault parameter {field} is unsupported")
            }
            Self::PropertyDuplicateAssertionId { .. } => {
                f.write_str("properties bundle contains a duplicate assertion id")
            }
            Self::PropertyPredicateUnknownNode { .. } => {
                f.write_str("property predicate references an undeclared node")
            }
            Self::PropertyPredicateEmptyCompound { kind } => {
                write!(f, "property predicate compound {kind} has no children")
            }
            Self::ScenarioBuilderUnknownNodeTemplate { .. } => {
                f.write_str("scenario builder node template is unknown")
            }
            Self::ScenarioSerialization { reason } => {
                write!(f, "scenario serialized form is invalid: {reason}")
            }
            Self::ScenarioImageReferenceNotContentAddressed { field, .. } => {
                write!(
                    f,
                    "scenario serialized {field} reference is not content-addressed"
                )
            }
            Self::ScenarioSerializedIdMismatch { component, .. } => {
                write!(
                    f,
                    "scenario serialized {component} id does not match parsed content"
                )
            }
            Self::ScenarioFamilyInvalidSpace { reason } => {
                write!(f, "scenario family parameter space is invalid: {reason}")
            }
            Self::ScenarioFamilyParameterOutOfSpace { parameter } => {
                write!(
                    f,
                    "scenario family parameter {parameter} is outside the space"
                )
            }
            Self::RuntimeConfigurationMismatch { .. } => {
                f.write_str("runtime configuration does not match replay start configuration")
            }
            Self::ReplayTargetMismatch { .. } => {
                f.write_str("replayed suffix did not produce requested configuration")
            }
            Self::ReplayOracleMismatch { .. } => {
                f.write_str("replay oracle mismatch between fat checkpoint and thin derivation")
            }
            Self::SearchReplayOracleMismatch { .. } => {
                f.write_str("sampled search checkpoint does not match thin replay derivation")
            }
            Self::ReproductionArtifactReplayMismatch { .. } => {
                f.write_str("reproduction artifact did not replay to its recorded state")
            }
            Self::InvalidSearchReplayOracleSamplingConfig { reason } => {
                write!(f, "invalid search replay-oracle sampling config: {reason}")
            }
            Self::SchedulePrefix(error) => write!(f, "schedule prefix failed: {error}"),
        }
    }
}

impl Error for EngineError {}

fn load_snapshot(
    configuration: &Configuration,
    checkpoint: &Checkpoint,
) -> Result<RuntimeState, EngineError> {
    validate_loadable_checkpoint(checkpoint, configuration)?;
    runtime_for_configuration(
        configuration,
        checkpoint.node_blobs.clone(),
        checkpoint.node_icounts.clone(),
    )
}

fn runtime_for_configuration(
    configuration: &Configuration,
    node_blobs: BTreeMap<NodeId, NodeBlobRef>,
    node_icounts: BTreeMap<NodeId, Icount>,
) -> Result<RuntimeState, EngineError> {
    Ok(RuntimeState {
        id: reduce(&configuration.def, &configuration.schedule)?.id,
        configuration: configuration.id(),
        node_blobs,
        node_icounts,
    })
}

fn replay_suffix(
    runtime: RuntimeState,
    start: &Configuration,
    suffix: &Schedule,
    target: &Configuration,
) -> Result<RuntimeState, EngineError> {
    if runtime.configuration != start.id() {
        return Err(EngineError::RuntimeConfigurationMismatch {
            runtime: runtime.id,
            expected: start.id(),
            actual: runtime.configuration,
        });
    }

    let mut replayed = start.clone();
    for decision in suffix.decisions() {
        replayed = step(&replayed, decision.clone());
    }

    if replayed.id() != target.id() {
        return Err(EngineError::ReplayTargetMismatch {
            expected: target.id(),
            actual: replayed.id(),
        });
    }

    let node_blobs = replayed_node_blobs(&runtime.node_blobs, start, suffix, target);
    let node_icounts = replayed_node_icounts(&runtime.node_icounts, suffix);
    runtime_for_configuration(&replayed, node_blobs, node_icounts)
}

fn instantiate_thin_replay(
    graph: &TemporalGraph,
    config: &Configuration,
) -> Result<RuntimeState, EngineError> {
    if config.is_genesis() {
        let genesis =
            graph
                .genesis_snapshot(&config.def)
                .ok_or(EngineError::MissingBakedGenesis {
                    scenario: config.def.id,
                })?;
        return load_snapshot(config, &genesis.checkpoint);
    }

    if let Some(ancestor) = graph.nearest_cached_ancestor(config)? {
        let ancestor_runtime = instantiate(graph, &ancestor)?;
        let suffix = config
            .schedule
            .suffix_from(ancestor.schedule.len())
            .map_err(EngineError::SchedulePrefix)?;
        return replay_suffix(ancestor_runtime, &ancestor, &suffix, config);
    }

    let genesis = Configuration::genesis(config.def.clone());
    let genesis_runtime = instantiate(graph, &genesis)?;
    let suffix = config
        .schedule
        .suffix_from(genesis.schedule.len())
        .map_err(EngineError::SchedulePrefix)?;
    replay_suffix(genesis_runtime, &genesis, &suffix, config)
}

fn materialized_checkpoint_for_runtime(
    configuration: &Configuration,
    runtime: RuntimeState,
) -> Result<Checkpoint, EngineError> {
    if runtime.configuration != configuration.id() {
        return Err(EngineError::RuntimeConfigurationMismatch {
            runtime: runtime.id,
            expected: configuration.id(),
            actual: runtime.configuration,
        });
    }
    let parent = immediate_parent_configuration(configuration)?;
    Checkpoint::from_recorded_configuration(
        configuration,
        parent.as_ref(),
        VirtualTime::default(),
        runtime.node_icounts,
        CheckpointKind::Fat,
        runtime.node_blobs,
    )
}

fn validate_loadable_checkpoint(
    checkpoint: &Checkpoint,
    configuration: &Configuration,
) -> Result<(), EngineError> {
    if checkpoint.kind != CheckpointKind::Fat {
        return Err(EngineError::CheckpointNotLoadable {
            checkpoint: checkpoint.id,
            kind: checkpoint.kind,
        });
    }
    if checkpoint.configuration != configuration.id() {
        return Err(EngineError::CheckpointConfigurationMismatch {
            checkpoint: checkpoint.id,
            expected: configuration.id(),
            actual: checkpoint.configuration,
        });
    }
    if checkpoint.id != configuration.id() {
        return Err(EngineError::CheckpointIdentityMismatch {
            checkpoint: checkpoint.id,
            expected: configuration.id(),
            actual: checkpoint.id,
        });
    }
    if checkpoint.scenario_ref != configuration.def.id {
        return Err(EngineError::CheckpointTopologyMismatch {
            checkpoint: checkpoint.id,
            reason: "scenario-ref-mismatch",
        });
    }

    let expected_parent_config = immediate_parent_configuration(configuration)?;
    let (expected_parent, expected_delta) =
        checkpoint_edge(configuration, expected_parent_config.as_ref())?;
    if checkpoint.parent != expected_parent {
        return Err(EngineError::CheckpointTopologyMismatch {
            checkpoint: checkpoint.id,
            reason: "parent-mismatch",
        });
    }
    if checkpoint.schedule_delta != expected_delta {
        return Err(EngineError::CheckpointTopologyMismatch {
            checkpoint: checkpoint.id,
            reason: "schedule-delta-mismatch",
        });
    }
    validate_materialized_state(checkpoint)?;

    Ok(())
}

fn replay_oracle_failure_rejects_cache(error: &EngineError) -> bool {
    !matches!(error, EngineError::MissingBakedGenesis { .. })
}

fn sample_search_replay_oracle_checkpoint(
    graph: &TemporalGraph,
    configuration: &Configuration,
    checkpoint: &Checkpoint,
    sequence: u64,
    config: &SearchReplayOracleSamplingConfig,
    report: &mut SearchReplayOracleSamplingReport,
) -> Result<(), EngineError> {
    if checkpoint.kind != CheckpointKind::Fat {
        return Ok(());
    }

    report.considered += 1;
    if !config.samples(sequence, checkpoint.id) {
        report.skipped += 1;
        return Ok(());
    }

    report.sampled += 1;
    report.sampled_checkpoints.push(checkpoint.id);
    graph
        .replay_checkpoint(configuration, checkpoint)
        .map(|_| ())
        .map_err(|error| search_replay_oracle_error(sequence, error))
}

fn search_replay_oracle_error(sequence: u64, error: EngineError) -> EngineError {
    match error {
        EngineError::ReplayOracleMismatch {
            checkpoint,
            expected,
            actual,
        } => EngineError::SearchReplayOracleMismatch {
            bisection: SearchReplayOracleBisectionRequest {
                sequence,
                checkpoint,
                reason: "sampled fat checkpoint differs from thin reconstruction",
            },
            checkpoint,
            expected,
            actual,
        },
        other => other,
    }
}

fn sampled_search_replay_oracle_error(
    sequence: u64,
    config: &SearchReplayOracleSamplingConfig,
    error: EngineError,
) -> EngineError {
    match error {
        EngineError::ReplayOracleMismatch {
            checkpoint,
            expected,
            actual,
        } if config.samples(sequence, checkpoint) => EngineError::SearchReplayOracleMismatch {
            bisection: SearchReplayOracleBisectionRequest {
                sequence,
                checkpoint,
                reason: "sampled fat checkpoint differs from thin reconstruction",
            },
            checkpoint,
            expected,
            actual,
        },
        EngineError::ReplayOracleMismatch {
            checkpoint,
            expected,
            actual,
        } => EngineError::ReplayOracleMismatch {
            checkpoint,
            expected,
            actual,
        },
        other => other,
    }
}

fn validate_materialized_state(checkpoint: &Checkpoint) -> Result<(), EngineError> {
    let state =
        checkpoint
            .state
            .as_ref()
            .ok_or(EngineError::CheckpointMaterializedStateIncomplete {
                checkpoint: checkpoint.id,
                reason: "missing-state",
            })?;
    let expected_state_id = canonical::materialized_state_hash(
        &state.vm_snapshots,
        &state.device_overlays,
        &state.scheduler,
        &state.decision_rng,
        state.event_log,
    );
    if state.id != expected_state_id {
        return Err(EngineError::CheckpointMaterializedStateIncomplete {
            checkpoint: checkpoint.id,
            reason: "materialized-state-id-mismatch",
        });
    }

    for (node, blob) in &checkpoint.node_blobs {
        let snapshot = state.vm_snapshots.get(node).ok_or(
            EngineError::CheckpointMaterializedStateIncomplete {
                checkpoint: checkpoint.id,
                reason: "missing-vm-snapshot",
            },
        )?;
        if &snapshot.blob != blob {
            return Err(EngineError::CheckpointMaterializedStateIncomplete {
                checkpoint: checkpoint.id,
                reason: "vm-snapshot-blob-mismatch",
            });
        }
        let expected_icount = checkpoint
            .node_icounts
            .get(node)
            .copied()
            .unwrap_or_default();
        if snapshot.icount != expected_icount {
            return Err(EngineError::CheckpointMaterializedStateIncomplete {
                checkpoint: checkpoint.id,
                reason: "vm-snapshot-icount-mismatch",
            });
        }
    }

    for node in checkpoint.node_icounts.keys() {
        if !state.vm_snapshots.contains_key(node) {
            return Err(EngineError::CheckpointMaterializedStateIncomplete {
                checkpoint: checkpoint.id,
                reason: "missing-icount-vm-snapshot",
            });
        }
    }
    for node in state.vm_snapshots.keys() {
        if !checkpoint.node_blobs.contains_key(node) {
            return Err(EngineError::CheckpointMaterializedStateIncomplete {
                checkpoint: checkpoint.id,
                reason: "extra-vm-snapshot",
            });
        }
    }

    Ok(())
}

fn checkpoint_kind_label(kind: CheckpointKind) -> &'static str {
    match kind {
        CheckpointKind::Fat => "fat",
        CheckpointKind::Thin => "thin",
    }
}

fn materialized_state_for_kind(
    kind: CheckpointKind,
    node_icounts: &BTreeMap<NodeId, Icount>,
    node_blobs: &BTreeMap<NodeId, NodeBlobRef>,
) -> Option<MaterializedState> {
    match kind {
        CheckpointKind::Fat => Some(MaterializedState::from_checkpoint_parts(
            node_icounts,
            node_blobs,
        )),
        CheckpointKind::Thin => None,
    }
}

fn materialized_vm_snapshots(
    node_icounts: &BTreeMap<NodeId, Icount>,
    node_blobs: &BTreeMap<NodeId, NodeBlobRef>,
) -> BTreeMap<NodeId, VmSnapshotRef> {
    node_blobs
        .iter()
        .map(|(node, blob)| {
            let icount = node_icounts.get(node).copied().unwrap_or_default();
            (node.clone(), VmSnapshotRef::new(blob.clone(), icount))
        })
        .collect()
}

fn replayed_node_blobs(
    ancestor_blobs: &BTreeMap<NodeId, NodeBlobRef>,
    start: &Configuration,
    suffix: &Schedule,
    target: &Configuration,
) -> BTreeMap<NodeId, NodeBlobRef> {
    ancestor_blobs
        .iter()
        .map(|(node, blob)| {
            let parent = blob.content_hash();
            let delta = ContentHash::from_canonical_material(
                "crucible.model.replayed-node-blob.delta.v1",
                &format!(
                    "node={}\nstart={}\ntarget={}\nsuffix={}",
                    node.name,
                    content_hash_hex(start.id()),
                    content_hash_hex(target.id()),
                    content_hash_hex(suffix.content_hash())
                ),
            );
            let resolved = ContentHash::from_canonical_material(
                "crucible.model.replayed-node-blob.resolved.v1",
                &format!(
                    "node={}\nparent={}\ndelta={}",
                    node.name,
                    content_hash_hex(parent),
                    content_hash_hex(delta)
                ),
            );
            (
                node.clone(),
                NodeBlobRef::cow_delta(parent, delta, resolved),
            )
        })
        .collect()
}

fn replayed_node_icounts(
    ancestor_icounts: &BTreeMap<NodeId, Icount>,
    suffix: &Schedule,
) -> BTreeMap<NodeId, Icount> {
    let delta = suffix.len() as u64;
    ancestor_icounts
        .iter()
        .map(|(node, icount)| {
            (
                node.clone(),
                Icount {
                    retired: icount.retired.saturating_add(delta),
                },
            )
        })
        .collect()
}

fn decision_touched_nodes(decision: &Decision) -> Option<BTreeSet<NodeId>> {
    match decision {
        Decision::Preemption(preemption) => Some(BTreeSet::from([preemption.node.clone()])),
        Decision::AppRandom(random) => Some(BTreeSet::from([random.node.clone()])),
        Decision::DeliveryOrder(_)
        | Decision::FaultFires(_)
        | Decision::RngDraw(_)
        | Decision::Override(_) => None,
    }
}

fn decisions_are_independent(
    left: &Decision,
    right: &Decision,
    policy: &PartialOrderReductionPolicy,
) -> bool {
    if !policy.proves_independent(left, right) {
        return false;
    }
    let (Some(left_nodes), Some(right_nodes)) =
        (decision_touched_nodes(left), decision_touched_nodes(right))
    else {
        return false;
    };
    if !left_nodes.is_disjoint(&right_nodes) {
        return false;
    }
    decisions_have_commuting_resources(left, right)
}

fn decisions_have_commuting_resources(left: &Decision, right: &Decision) -> bool {
    match (left, right) {
        (Decision::Preemption(_), Decision::Preemption(_))
        | (Decision::Preemption(_), Decision::AppRandom(_))
        | (Decision::AppRandom(_), Decision::Preemption(_)) => true,
        (Decision::AppRandom(left), Decision::AppRandom(right)) => left.stream != right.stream,
        _ => false,
    }
}

fn decision_reduction_order_key(decision: &Decision) -> ContentHash {
    Schedule::empty().appended(decision.clone()).content_hash()
}

fn partial_order_cover(
    graph: &TemporalGraph,
    frontier: &Configuration,
    decision: Decision,
    configuration: Configuration,
    policy: &FrontierReductionPolicy,
) -> Option<FrontierCoveredChild> {
    let last = frontier.schedule.decisions().last()?;
    if !decision.is_independent_from(last, &policy.partial_order) {
        return None;
    }
    if decision.reduction_order_key() >= last.reduction_order_key() {
        return None;
    }

    let prefix = frontier
        .schedule
        .prefix(frontier.schedule.len().saturating_sub(1))
        .ok()?;
    let representative = Configuration {
        def: frontier.def.clone(),
        schedule: prefix.appended(decision.clone()).appended(last.clone()),
    };
    if !graph.contains_configuration(&representative) {
        return None;
    }
    let reduction_key = partial_order_reduction_key(&representative, &configuration);
    Some(FrontierCoveredChild {
        decision,
        configuration,
        representative: representative.id(),
        reason: FrontierReductionReason::PartialOrder,
        reduction_key: reduction_key.fingerprint,
    })
}

fn partial_order_reduction_key(
    representative: &Configuration,
    covered: &Configuration,
) -> PartialOrderReductionKey {
    PartialOrderReductionKey {
        fingerprint: ContentHash::from_canonical_material(
            "crucible.model.partial-order-reduction.v1",
            &format!(
                "representative={}\ncovered={}",
                content_hash_hex(representative.id()),
                content_hash_hex(covered.id())
            ),
        ),
    }
}

fn checkpoint_symmetry_reduction_key(
    checkpoint: &Checkpoint,
    classes: &SymmetryReductionClasses,
) -> Option<SymmetryReductionKey> {
    if checkpoint.coverage_fingerprint == ContentHash::default() || classes.is_empty() {
        return None;
    }
    let state = checkpoint.state.as_ref()?;
    let labels = canonical_symmetry_node_labels(checkpoint, state, classes)?;

    let mut lines = vec![
        format!("scenario_ref={}", content_hash_hex(checkpoint.scenario_ref)),
        format!(
            "coverage_fingerprint={}",
            content_hash_hex(checkpoint.coverage_fingerprint)
        ),
        format!("virtual_time_ticks={}", checkpoint.virtual_time.ticks),
    ];
    push_symmetry_checkpoint_lines(checkpoint, &labels, &mut lines)?;
    push_symmetry_materialized_state_lines(state, &labels, &mut lines)?;
    Some(SymmetryReductionKey {
        fingerprint: ContentHash::from_canonical_material(
            "crucible.model.symmetry-reduction.v1",
            &lines.join("\n"),
        ),
    })
}

fn canonical_symmetry_node_labels(
    checkpoint: &Checkpoint,
    state: &MaterializedState,
    classes: &SymmetryReductionClasses,
) -> Option<BTreeMap<NodeId, String>> {
    let mut labels = BTreeMap::new();
    let mut class_members: BTreeMap<&SymmetryClassId, Vec<(String, NodeId)>> = BTreeMap::new();
    for node in symmetry_nodes(checkpoint, state) {
        if let Some(class) = classes.classes.get(&node) {
            class_members.entry(class).or_default().push((
                symmetry_node_local_signature(checkpoint, state, &node),
                node,
            ));
        } else {
            labels.insert(
                node.clone(),
                format!("node:{}:{}", node.name.len(), node.name),
            );
        }
    }

    for (class, mut members) in class_members {
        members.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        for pair in members.windows(2) {
            if pair[0].0 == pair[1].0 {
                return None;
            }
        }
        for (index, (_, node)) in members.into_iter().enumerate() {
            labels.insert(
                node,
                format!("class:{}:{}:{index}", class.name.len(), class.name),
            );
        }
    }

    Some(labels)
}

fn symmetry_nodes(checkpoint: &Checkpoint, state: &MaterializedState) -> BTreeSet<NodeId> {
    let mut nodes = BTreeSet::new();
    nodes.extend(checkpoint.node_blobs.keys().cloned());
    nodes.extend(checkpoint.node_icounts.keys().cloned());
    nodes.extend(state.vm_snapshots.keys().cloned());
    nodes.extend(state.scheduler.horizons.keys().cloned());
    nodes.extend(state.scheduler.pending_frames.keys().cloned());
    for frames in state.scheduler.pending_frames.values() {
        nodes.extend(frames.iter().map(|frame| frame.source.clone()));
    }
    nodes.extend(
        state
            .scheduler
            .timers
            .timers
            .values()
            .map(|timer| timer.owner.clone()),
    );
    nodes
}

fn symmetry_node_local_signature(
    checkpoint: &Checkpoint,
    state: &MaterializedState,
    node: &NodeId,
) -> String {
    let mut lines = Vec::new();
    match checkpoint.node_icounts.get(node) {
        Some(icount) => lines.push(format!("checkpoint.icount={}", icount.retired)),
        None => lines.push(String::from("checkpoint.icount=none")),
    }
    match checkpoint.node_blobs.get(node) {
        Some(blob) => push_node_blob_ref_lines("checkpoint.blob", blob, &mut lines),
        None => lines.push(String::from("checkpoint.blob=none")),
    }
    match state.vm_snapshots.get(node) {
        Some(snapshot) => {
            push_node_blob_ref_lines("state.vm.blob", &snapshot.blob, &mut lines);
            lines.push(format!("state.vm.icount={}", snapshot.icount.retired));
        }
        None => lines.push(String::from("state.vm=none")),
    }
    lines.join("\n")
}

fn push_symmetry_checkpoint_lines(
    checkpoint: &Checkpoint,
    labels: &BTreeMap<NodeId, String>,
    lines: &mut Vec<String>,
) -> Option<()> {
    let mut icount_lines = Vec::new();
    for (node, icount) in &checkpoint.node_icounts {
        icount_lines.push(format!(
            "checkpoint.icount.node={}\ncheckpoint.icount.retired={}",
            labels.get(node)?,
            icount.retired
        ));
    }
    icount_lines.sort();
    lines.push(format!("checkpoint.icounts={}", icount_lines.len()));
    lines.extend(icount_lines);

    let mut blob_lines = Vec::new();
    for (node, blob) in &checkpoint.node_blobs {
        let mut entry = vec![format!("checkpoint.blob.node={}", labels.get(node)?)];
        push_node_blob_ref_lines("checkpoint.blob", blob, &mut entry);
        blob_lines.push(entry.join("\n"));
    }
    blob_lines.sort();
    lines.push(format!("checkpoint.blobs={}", blob_lines.len()));
    lines.extend(blob_lines);
    Some(())
}

fn push_symmetry_materialized_state_lines(
    state: &MaterializedState,
    labels: &BTreeMap<NodeId, String>,
    lines: &mut Vec<String>,
) -> Option<()> {
    let mut vm_lines = Vec::new();
    for (node, snapshot) in &state.vm_snapshots {
        let mut entry = vec![format!("state.vm.node={}", labels.get(node)?)];
        push_node_blob_ref_lines("state.vm.blob", &snapshot.blob, &mut entry);
        entry.push(format!("state.vm.icount={}", snapshot.icount.retired));
        vm_lines.push(entry.join("\n"));
    }
    vm_lines.sort();
    lines.push(format!("state.vm_snapshots={}", vm_lines.len()));
    lines.extend(vm_lines);

    let mut overlay_lines = Vec::new();
    for (device, overlay) in &state.device_overlays {
        let mut entry = vec![
            format!("state.overlay.device_len={}", device.name.len()),
            format!("state.overlay.device={}", device.name),
            format!("state.overlay.parent={}", content_hash_hex(overlay.parent)),
            format!("state.overlay.delta={}", content_hash_hex(overlay.delta)),
            format!(
                "state.overlay.resolved={}",
                content_hash_hex(overlay.resolved)
            ),
        ];
        push_symmetry_device_rng_lines("state.overlay.rng", &overlay.rng, &mut entry);
        overlay_lines.push(entry.join("\n"));
    }
    overlay_lines.sort();
    lines.push(format!("state.device_overlays={}", overlay_lines.len()));
    lines.extend(overlay_lines);

    push_symmetry_scheduler_lines(&state.scheduler, labels, lines)?;
    push_symmetry_decision_rng_lines("state.decision_rng", &state.decision_rng, lines);
    push_symmetry_event_log_lines(state.event_log, lines);
    Some(())
}

fn push_symmetry_scheduler_lines(
    scheduler: &SchedulerState,
    labels: &BTreeMap<NodeId, String>,
    lines: &mut Vec<String>,
) -> Option<()> {
    let mut horizon_lines = Vec::new();
    for (node, horizon) in &scheduler.horizons {
        horizon_lines.push(format!(
            "scheduler.horizon.node={}\nscheduler.horizon.ticks={}",
            labels.get(node)?,
            horizon.ticks
        ));
    }
    horizon_lines.sort();
    lines.push(format!("scheduler.horizons={}", horizon_lines.len()));
    lines.extend(horizon_lines);

    let mut pending_lines = Vec::new();
    for (node, frames) in &scheduler.pending_frames {
        let mut entry = vec![
            format!("scheduler.pending.node={}", labels.get(node)?),
            format!("scheduler.pending.frames={}", frames.len()),
        ];
        for frame in frames {
            entry.push(format!(
                "scheduler.pending.source={}",
                labels.get(&frame.source)?
            ));
            entry.push(format!("scheduler.pending.sequence={}", frame.sequence));
            entry.push(format!(
                "scheduler.pending.delivery_icount={}",
                frame.delivery_icount.retired
            ));
            entry.push(format!(
                "scheduler.pending.payload={}",
                content_hash_hex(frame.payload)
            ));
        }
        pending_lines.push(entry.join("\n"));
    }
    pending_lines.sort();
    lines.push(format!("scheduler.pending={}", pending_lines.len()));
    lines.extend(pending_lines);

    let mut timer_lines = Vec::new();
    for (timer, state) in &scheduler.timers.timers {
        timer_lines.push(format!(
            "scheduler.timer.name_len={}\nscheduler.timer.name={}\nscheduler.timer.owner={}\nscheduler.timer.armed_at={}\nscheduler.timer.fire_at={}\nscheduler.timer.fire_icount={}",
            timer.name.len(),
            timer.name,
            labels.get(&state.owner)?,
            state.armed_at.ticks,
            state.fire_at.ticks,
            state.fire_icount.retired
        ));
    }
    timer_lines.sort();
    lines.push(format!("scheduler.timers={}", timer_lines.len()));
    lines.extend(timer_lines);

    let mut fault_lines = Vec::new();
    for (fault, state) in &scheduler.active_faults {
        fault_lines.push(format!(
            "scheduler.fault.name_len={}\nscheduler.fault.name={}\nscheduler.fault.active_since={}\nscheduler.fault.heal_at={}",
            fault.name.len(),
            fault.name,
            state.active_since.ticks,
            state
                .heal_at
                .map(|time| time.ticks.to_string())
                .unwrap_or_else(|| String::from("none"))
        ));
    }
    fault_lines.sort();
    lines.push(format!("scheduler.active_faults={}", fault_lines.len()));
    lines.extend(fault_lines);
    Some(())
}

fn push_symmetry_device_rng_lines(prefix: &str, state: &DeviceRngState, lines: &mut Vec<String>) {
    lines.push(format!("{prefix}.streams={}", state.streams.len()));
    for (stream, position) in &state.streams {
        push_rng_stream_lines(prefix, stream, lines);
        lines.push(format!("{prefix}.draws={}", position.draws));
    }
}

fn push_symmetry_decision_rng_lines(
    prefix: &str,
    state: &DecisionRngState,
    lines: &mut Vec<String>,
) {
    lines.push(format!("{prefix}.positions={}", state.positions.len()));
    for (stream, position) in &state.positions {
        push_rng_stream_lines(prefix, stream, lines);
        lines.push(format!("{prefix}.draws={}", position.draws));
    }
}

fn push_rng_stream_lines(prefix: &str, stream: &RngStreamId, lines: &mut Vec<String>) {
    lines.push(format!(
        "{prefix}.stream_domain_len={}",
        stream.domain.len()
    ));
    lines.push(format!("{prefix}.stream_domain={}", stream.domain));
    lines.push(format!("{prefix}.stream_len={}", stream.name.len()));
    lines.push(format!("{prefix}.stream={}", stream.name));
}

fn push_symmetry_event_log_lines(event_log: EventLogOffset, lines: &mut Vec<String>) {
    lines.push(format!(
        "event_log.prefix={}",
        content_hash_hex(event_log.prefix)
    ));
    lines.push(format!(
        "event_log.appended_segment={}",
        event_log
            .appended_segment
            .map(content_hash_hex)
            .unwrap_or_else(|| String::from("none"))
    ));
    lines.push(format!("event_log.bytes={}", event_log.bytes));
    lines.push(format!("event_log.events={}", event_log.events));
}

fn checkpoint_edge(
    configuration: &Configuration,
    parent: Option<&Configuration>,
) -> Result<(Option<ContentHash>, Schedule), EngineError> {
    match (configuration.is_genesis(), parent) {
        (true, None) => Ok((None, Schedule::empty())),
        (true, Some(_)) => Err(EngineError::CheckpointTopologyMismatch {
            checkpoint: configuration.id(),
            reason: "genesis-has-parent",
        }),
        (false, None) => Err(EngineError::CheckpointTopologyMismatch {
            checkpoint: configuration.id(),
            reason: "descendant-missing-parent",
        }),
        (false, Some(parent)) => {
            if parent.def.id != configuration.def.id {
                return Err(EngineError::CheckpointTopologyMismatch {
                    checkpoint: configuration.id(),
                    reason: "parent-scenario-mismatch",
                });
            }
            let prefix = configuration
                .schedule
                .prefix(parent.schedule.len())
                .map_err(EngineError::SchedulePrefix)?;
            if prefix != parent.schedule {
                return Err(EngineError::CheckpointTopologyMismatch {
                    checkpoint: configuration.id(),
                    reason: "parent-not-schedule-prefix",
                });
            }
            let delta = configuration
                .schedule
                .suffix_from(parent.schedule.len())
                .map_err(EngineError::SchedulePrefix)?;
            if delta.is_empty() {
                return Err(EngineError::CheckpointTopologyMismatch {
                    checkpoint: configuration.id(),
                    reason: "empty-descendant-delta",
                });
            }
            Ok((Some(parent.id()), delta))
        }
    }
}

fn immediate_parent_configuration(
    configuration: &Configuration,
) -> Result<Option<Configuration>, EngineError> {
    if configuration.is_genesis() {
        Ok(None)
    } else {
        let schedule = configuration
            .schedule
            .prefix(configuration.schedule.len().saturating_sub(1))
            .map_err(EngineError::SchedulePrefix)?;
        Ok(Some(Configuration {
            def: configuration.def.clone(),
            schedule,
        }))
    }
}

fn validate_world_nodes(nodes: &[WorldNode]) -> Result<(), EngineError> {
    let mut seen = BTreeSet::new();
    for node in nodes {
        if !seen.insert(node.id.clone()) {
            return Err(EngineError::DuplicateWorldNodeId {
                node: node.id.clone(),
            });
        }
        if matches!(node.ready_point, ReadyPoint::AgentSignal) && !node.white_box.is_enabled() {
            return Err(EngineError::WhiteBoxReadyPointWithoutOptIn {
                node: node.id.clone(),
            });
        }
    }

    Ok(())
}

fn validate_world_links(nodes: &[WorldNode], links: &[LinkDef]) -> Result<(), EngineError> {
    let node_ids = nodes.iter().map(|node| &node.id).collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    for link in links {
        let (left, right) = link.endpoints();
        if left == right {
            return Err(EngineError::WorldLinkSelfLoop { node: left.clone() });
        }
        if !node_ids.contains(left) {
            return Err(EngineError::WorldLinkUnknownNode {
                link: link.clone(),
                node: left.clone(),
            });
        }
        if !node_ids.contains(right) {
            return Err(EngineError::WorldLinkUnknownNode {
                link: link.clone(),
                node: right.clone(),
            });
        }
        validate_link_transport(link)?;
        if !seen.insert((left.clone(), right.clone())) {
            return Err(EngineError::DuplicateWorldLink { link: link.clone() });
        }
    }

    Ok(())
}

fn validate_plan_entries_for_world(
    world: &World,
    entries: &[PlanEntry],
) -> Result<(), EngineError> {
    let node_ids = world
        .nodes
        .iter()
        .map(|node| &node.id)
        .collect::<BTreeSet<_>>();
    let link_ids = world
        .links
        .iter()
        .map(|link| {
            let (left, right) = link.endpoints();
            (left.clone(), right.clone())
        })
        .collect::<BTreeSet<_>>();
    let mut activated_tags = BTreeMap::<FaultTag, Vec<VirtualTime>>::new();
    for entry in entries {
        if let PlanEntry::Activate { at, tag, .. } = entry {
            activated_tags.entry(tag.clone()).or_default().push(*at);
        }
    }

    for entry in entries {
        match entry {
            PlanEntry::Activate { at, fault, .. } => {
                validate_membership_fault_for_world(*at, fault, &node_ids, &link_ids)?;
            }
            PlanEntry::Heal { tag, .. } => {
                validate_plan_heal(tag, entry, &activated_tags)?;
            }
        }
    }

    Ok(())
}

fn validate_membership_fault_for_world(
    at: VirtualTime,
    fault: &MembershipFault,
    node_ids: &BTreeSet<&NodeId>,
    link_ids: &BTreeSet<(NodeId, NodeId)>,
) -> Result<(), EngineError> {
    match fault {
        MembershipFault::Crash { node, .. } | MembershipFault::Isolate { node } => {
            validate_plan_node(node, node_ids)
        }
        MembershipFault::NotYetJoined { node } => {
            validate_plan_node(node, node_ids)?;
            if at != VirtualTime::default() {
                return Err(EngineError::PlanNotYetJoinedAfterStart {
                    node: node.clone(),
                    at,
                });
            }
            Ok(())
        }
        MembershipFault::Partition {
            endpoint_a,
            endpoint_b,
            ..
        } => {
            validate_plan_node(endpoint_a, node_ids)?;
            validate_plan_node(endpoint_b, node_ids)?;
            let link = canonical_link_endpoint_pair(endpoint_a, endpoint_b);
            if !link_ids.contains(&link) {
                return Err(EngineError::PlanFaultUnknownLink {
                    endpoint_a: endpoint_a.clone(),
                    endpoint_b: endpoint_b.clone(),
                });
            }
            Ok(())
        }
    }
}

fn validate_plan_heal(
    tag: &FaultTag,
    entry: &PlanEntry,
    activated_tags: &BTreeMap<FaultTag, Vec<VirtualTime>>,
) -> Result<(), EngineError> {
    let PlanEntry::Heal { at: heal_at, .. } = entry else {
        return Ok(());
    };
    let Some(activation_times) = activated_tags.get(tag) else {
        return Err(EngineError::PlanHealUnknownTag { tag: tag.clone() });
    };
    if activation_times
        .iter()
        .copied()
        .any(|activate_at| activate_at < *heal_at)
    {
        return Ok(());
    }

    if let Some(activate_at) = activation_times.iter().copied().min() {
        return Err(EngineError::PlanHealBeforeActivate {
            tag: tag.clone(),
            activate_at,
            heal_at: *heal_at,
        });
    }
    Err(EngineError::PlanHealUnknownTag { tag: tag.clone() })
}

fn validate_plan_node(node: &NodeId, node_ids: &BTreeSet<&NodeId>) -> Result<(), EngineError> {
    if node_ids.contains(node) {
        Ok(())
    } else {
        Err(EngineError::PlanFaultUnknownNode { node: node.clone() })
    }
}

fn validate_properties_for_world(
    world: &World,
    assertions: &[AssertionDef],
) -> Result<(), EngineError> {
    let node_ids = world.nodes.iter().map(|node| &node.id).collect();
    let mut assertion_ids = BTreeSet::new();

    for assertion in assertions {
        if !assertion_ids.insert(&assertion.id) {
            return Err(EngineError::PropertyDuplicateAssertionId {
                id: assertion.id.clone(),
            });
        }
        validate_property_for_world(&assertion.property, &node_ids)?;
    }

    Ok(())
}

fn validate_property_for_world(
    property: &Property,
    node_ids: &BTreeSet<&NodeId>,
) -> Result<(), EngineError> {
    match property {
        Property::Always { predicate }
        | Property::Sometimes { predicate }
        | Property::AfterQuiescence { predicate }
        | Property::Reachable { predicate, .. } => {
            validate_predicate_for_world(predicate, node_ids)
        }
        Property::Eventually {
            trigger, property, ..
        } => {
            validate_predicate_for_world(trigger, node_ids)?;
            validate_predicate_for_world(property, node_ids)
        }
    }
}

fn validate_predicate_for_world(
    predicate: &Predicate,
    node_ids: &BTreeSet<&NodeId>,
) -> Result<(), EngineError> {
    match predicate {
        Predicate::Named { nodes, .. } => {
            for node in nodes {
                validate_property_node(node, node_ids)?;
            }
            Ok(())
        }
        Predicate::GuestMarker { .. } => Ok(()),
        Predicate::AllOf { predicates } => {
            validate_compound_predicate("all-of", predicates, node_ids)
        }
        Predicate::AnyOf { predicates } => {
            validate_compound_predicate("any-of", predicates, node_ids)
        }
        Predicate::Once { predicate } | Predicate::Not { predicate } => {
            validate_predicate_for_world(predicate, node_ids)
        }
    }
}

fn validate_compound_predicate(
    kind: &'static str,
    predicates: &[Predicate],
    node_ids: &BTreeSet<&NodeId>,
) -> Result<(), EngineError> {
    if predicates.is_empty() {
        return Err(EngineError::PropertyPredicateEmptyCompound { kind });
    }

    for predicate in predicates {
        validate_predicate_for_world(predicate, node_ids)?;
    }

    Ok(())
}

fn validate_property_node(node: &NodeId, node_ids: &BTreeSet<&NodeId>) -> Result<(), EngineError> {
    if node_ids.contains(node) {
        Ok(())
    } else {
        Err(EngineError::PropertyPredicateUnknownNode { node: node.clone() })
    }
}

fn canonical_link_endpoint_pair(left: &NodeId, right: &NodeId) -> (NodeId, NodeId) {
    if left <= right {
        (left.clone(), right.clone())
    } else {
        (right.clone(), left.clone())
    }
}

fn canonical_plan_entries(entries: &[PlanEntry]) -> Vec<PlanEntry> {
    let mut entries = entries.iter().map(canonical_plan_entry).collect::<Vec<_>>();
    entries.sort_by(plan_entry_cmp);
    entries
}

fn canonical_plan_entry(entry: &PlanEntry) -> PlanEntry {
    match entry {
        PlanEntry::Activate { at, tag, fault } => PlanEntry::Activate {
            at: *at,
            tag: tag.clone(),
            fault: canonical_membership_fault(fault),
        },
        PlanEntry::Heal { at, tag } => PlanEntry::Heal {
            at: *at,
            tag: tag.clone(),
        },
    }
}

fn canonical_membership_fault(fault: &MembershipFault) -> MembershipFault {
    match fault {
        MembershipFault::Crash { node, restart } => MembershipFault::Crash {
            node: node.clone(),
            restart: *restart,
        },
        MembershipFault::Partition {
            endpoint_a,
            endpoint_b,
            direction,
        } => {
            if endpoint_a <= endpoint_b {
                MembershipFault::Partition {
                    endpoint_a: endpoint_a.clone(),
                    endpoint_b: endpoint_b.clone(),
                    direction: *direction,
                }
            } else {
                MembershipFault::Partition {
                    endpoint_a: endpoint_b.clone(),
                    endpoint_b: endpoint_a.clone(),
                    direction: inverted_partition_direction(*direction),
                }
            }
        }
        MembershipFault::Isolate { node } => MembershipFault::Isolate { node: node.clone() },
        MembershipFault::NotYetJoined { node } => {
            MembershipFault::NotYetJoined { node: node.clone() }
        }
    }
}

fn inverted_partition_direction(direction: PartitionDirection) -> PartitionDirection {
    match direction {
        PartitionDirection::Bidirectional => PartitionDirection::Bidirectional,
        PartitionDirection::EndpointAToEndpointB => PartitionDirection::EndpointBToEndpointA,
        PartitionDirection::EndpointBToEndpointA => PartitionDirection::EndpointAToEndpointB,
    }
}

fn plan_entry_cmp(left: &PlanEntry, right: &PlanEntry) -> std::cmp::Ordering {
    plan_entry_time(left)
        .cmp(&plan_entry_time(right))
        .then_with(|| plan_entry_kind_order(left).cmp(&plan_entry_kind_order(right)))
        .then_with(|| plan_entry_material(left).cmp(&plan_entry_material(right)))
}

fn plan_entry_time(entry: &PlanEntry) -> VirtualTime {
    match entry {
        PlanEntry::Activate { at, .. } | PlanEntry::Heal { at, .. } => *at,
    }
}

fn plan_entry_kind_order(entry: &PlanEntry) -> u8 {
    match entry {
        PlanEntry::Activate { .. } => 0,
        PlanEntry::Heal { .. } => 1,
    }
}

fn canonical_assertions(assertions: &[AssertionDef]) -> Vec<AssertionDef> {
    let mut assertions = assertions
        .iter()
        .map(canonical_assertion)
        .collect::<Vec<_>>();
    assertions.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| assertion_material(left).cmp(&assertion_material(right)))
    });
    assertions
}

fn canonical_assertion(assertion: &AssertionDef) -> AssertionDef {
    AssertionDef {
        id: assertion.id.clone(),
        message: assertion.message.clone(),
        property: canonical_property(&assertion.property),
    }
}

fn canonical_property(property: &Property) -> Property {
    match property {
        Property::Always { predicate } => Property::Always {
            predicate: canonical_predicate(predicate),
        },
        Property::Sometimes { predicate } => Property::Sometimes {
            predicate: canonical_predicate(predicate),
        },
        Property::Eventually {
            trigger,
            property,
            deadline,
        } => Property::Eventually {
            trigger: canonical_predicate(trigger),
            property: canonical_predicate(property),
            deadline: *deadline,
        },
        Property::AfterQuiescence { predicate } => Property::AfterQuiescence {
            predicate: canonical_predicate(predicate),
        },
        Property::Reachable {
            predicate,
            expectation,
        } => Property::Reachable {
            predicate: canonical_predicate(predicate),
            expectation: *expectation,
        },
    }
}

fn canonical_predicate(predicate: &Predicate) -> Predicate {
    match predicate {
        Predicate::Named { name, nodes } => Predicate::Named {
            name: name.clone(),
            nodes: nodes.clone(),
        },
        Predicate::GuestMarker { marker } => Predicate::GuestMarker {
            marker: marker.clone(),
        },
        Predicate::AllOf { predicates } => Predicate::AllOf {
            predicates: canonical_predicate_set(predicates),
        },
        Predicate::AnyOf { predicates } => Predicate::AnyOf {
            predicates: canonical_predicate_set(predicates),
        },
        Predicate::Once { predicate } => Predicate::Once {
            predicate: Box::new(canonical_predicate(predicate)),
        },
        Predicate::Not { predicate } => Predicate::Not {
            predicate: Box::new(canonical_predicate(predicate)),
        },
    }
}

fn canonical_predicate_set(predicates: &[Predicate]) -> Vec<Predicate> {
    let mut predicates = predicates
        .iter()
        .map(canonical_predicate)
        .collect::<Vec<_>>();
    predicates.sort_by_key(predicate_material);
    predicates
}

fn validate_link_transport(link: &LinkDef) -> Result<(), EngineError> {
    let latency = link.latency();
    let jitter = link.jitter();
    if latency < MIN_LINK_LATENCY {
        return Err(EngineError::WorldLinkLatencyBelowFloor {
            link: link.clone(),
            latency,
            minimum: MIN_LINK_LATENCY,
        });
    }
    if latency
        .nanos
        .checked_sub(jitter.nanos)
        .is_none_or(|effective| effective < MIN_LINK_LATENCY.nanos)
    {
        return Err(EngineError::WorldLinkJitterBelowLatencyFloor {
            link: link.clone(),
            latency,
            jitter,
            minimum: MIN_LINK_LATENCY,
        });
    }

    Ok(())
}

const SCENARIO_FORM_BINARY_MAGIC: &[u8] = b"crucible.scenario-def-form.v1\0";
const REPRODUCTION_ARTIFACT_BINARY_MAGIC: &[u8] = b"crucible.reproduction-artifact.v1\0";
const SCHEDULE_BINARY_MAGIC: &[u8] = b"crucible.schedule.v1\0";
const WORLD_BINARY_MAGIC: &[u8] = b"crucible.world.v1\0";
const PLAN_BINARY_MAGIC: &[u8] = b"crucible.plan.v1\0";
const PROPERTIES_BINARY_MAGIC: &[u8] = b"crucible.properties.v1\0";
const SEED_BINARY_MAGIC: &[u8] = b"crucible.seed.v1\0";
const MAX_SCENARIO_BINARY_COLLECTION_ITEMS: usize = 1_000_000;
const MAX_SCENARIO_BINARY_STRING_BYTES: usize = 16 * 1024 * 1024;
const MAX_SCENARIO_BINARY_BLOB_BYTES: usize = 256 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioDefToml {
    scenario: ScenarioHeaderToml,
    world: WorldToml,
    plan: PlanToml,
    properties: PropertiesToml,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioHeaderToml {
    id: String,
    seed: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorldToml {
    id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    node: Vec<WorldNodeToml>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    link: Vec<LinkToml>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorldNodeToml {
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kernel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root_image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    initrd: Option<String>,
    ready_point: ReadyPointToml,
    white_box: WhiteBoxToml,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ReadyPointToml {
    FixedIcount { retired: u64 },
    NetworkIdle { window_nanos: u64 },
    ConsoleMarker { marker: String },
    AgentSignal,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
enum WhiteBoxToml {
    Disabled,
    Enabled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkToml {
    endpoint_a: String,
    endpoint_b: String,
    latency_nanos: u64,
    jitter_nanos: u64,
    loss_millionths: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    bandwidth_bps: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanToml {
    id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    entry: Vec<PlanEntryToml>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PlanEntryToml {
    Activate {
        at_ticks: u64,
        tag: String,
        fault: MembershipFaultToml,
    },
    Heal {
        at_ticks: u64,
        tag: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum MembershipFaultToml {
    Crash {
        node: String,
        restart: RestartToml,
    },
    Partition {
        endpoint_a: String,
        endpoint_b: String,
        direction: PartitionDirectionToml,
    },
    Isolate {
        node: String,
    },
    NotYetJoined {
        node: String,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
enum RestartToml {
    FromReadyPoint,
    FromLastCheckpoint,
    StayDown,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
enum PartitionDirectionToml {
    Bidirectional,
    EndpointAToEndpointB,
    EndpointBToEndpointA,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PropertiesToml {
    id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    assertion: Vec<AssertionToml>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssertionToml {
    id: String,
    message: String,
    property: PropertyToml,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PropertyToml {
    Always {
        predicate: PredicateToml,
    },
    Sometimes {
        predicate: PredicateToml,
    },
    Eventually {
        trigger: PredicateToml,
        property: PredicateToml,
        deadline_ticks: u64,
    },
    AfterQuiescence {
        predicate: PredicateToml,
    },
    Reachable {
        predicate: PredicateToml,
        expectation: ReachabilityExpectationToml,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PredicateToml {
    Named {
        name: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        nodes: Vec<String>,
    },
    GuestMarker {
        marker: String,
    },
    AllOf {
        predicates: Vec<PredicateToml>,
    },
    AnyOf {
        predicates: Vec<PredicateToml>,
    },
    Once {
        predicate: Box<PredicateToml>,
    },
    Not {
        predicate: Box<PredicateToml>,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ReachabilityExpectationToml {
    Reachable {
        on_unreached: ReachableDispositionToml,
    },
    Unreachable,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
enum ReachableDispositionToml {
    Warn,
    Fail,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SeedToml {
    bytes: String,
}

fn scenario_form_to_toml(form: &ScenarioDefForm) -> ScenarioDefToml {
    ScenarioDefToml {
        scenario: ScenarioHeaderToml {
            id: format_content_hash_ref(form.id()),
            seed: format_seed_ref(form.seed),
        },
        world: world_to_toml(&form.world),
        plan: plan_to_toml(&form.plan),
        properties: properties_to_toml(&form.properties),
    }
}

fn scenario_form_from_toml(toml: ScenarioDefToml) -> Result<ScenarioDefForm, EngineError> {
    let world = world_from_toml(toml.world)?;
    let plan = plan_from_toml(&world, toml.plan)?;
    let properties = properties_from_toml(&world, toml.properties)?;
    let seed = parse_seed_ref(&toml.scenario.seed)?;
    let form = ScenarioDefForm::from_components(&world, &plan, &properties, seed)?;
    let expected = parse_content_hash_ref(&toml.scenario.id)?;
    validate_serialized_id("scenario", expected, form.id())?;
    Ok(form)
}

fn world_to_toml(world: &World) -> WorldToml {
    WorldToml {
        id: format_content_hash_ref(world.id()),
        node: world.nodes().iter().map(world_node_to_toml).collect(),
        link: world.links().iter().map(link_to_toml).collect(),
    }
}

fn world_from_toml(toml: WorldToml) -> Result<World, EngineError> {
    let id = parse_content_hash_ref(&toml.id)?;
    let nodes = toml
        .node
        .into_iter()
        .map(world_node_from_toml)
        .collect::<Result<Vec<_>, _>>()?;
    let links = toml
        .link
        .into_iter()
        .map(link_from_toml)
        .collect::<Result<Vec<_>, _>>()?;
    let world = World::from_recorded_parts(id, nodes, links)?;
    validate_world_serialized_identity(&world)?;
    Ok(world)
}

fn world_node_to_toml(node: &WorldNode) -> WorldNodeToml {
    WorldNodeToml {
        id: node.id.name.clone(),
        kernel: node.kernel.map(ContentAddressedBlobRef::to_uri),
        root_image: node.root_image.map(ContentAddressedBlobRef::to_uri),
        initrd: node.initrd.map(ContentAddressedBlobRef::to_uri),
        ready_point: ready_point_to_toml(&node.ready_point),
        white_box: white_box_to_toml(node.white_box),
    }
}

fn world_node_from_toml(toml: WorldNodeToml) -> Result<WorldNode, EngineError> {
    let kernel = parse_optional_blob_ref("kernel", toml.kernel)?;
    let root_image = parse_optional_blob_ref("root_image", toml.root_image)?;
    let initrd = parse_optional_blob_ref("initrd", toml.initrd)?;
    Ok(WorldNode {
        id: NodeId { name: toml.id },
        ready_point: ready_point_from_toml(toml.ready_point),
        white_box: white_box_from_toml(toml.white_box),
        kernel,
        root_image,
        initrd,
    })
}

fn ready_point_to_toml(ready_point: &ReadyPoint) -> ReadyPointToml {
    match ready_point {
        ReadyPoint::FixedIcount { icount } => ReadyPointToml::FixedIcount {
            retired: icount.retired,
        },
        ReadyPoint::NetworkIdle { window } => ReadyPointToml::NetworkIdle {
            window_nanos: window.nanos,
        },
        ReadyPoint::ConsoleMarker { marker } => ReadyPointToml::ConsoleMarker {
            marker: marker.clone(),
        },
        ReadyPoint::AgentSignal => ReadyPointToml::AgentSignal,
    }
}

fn ready_point_from_toml(toml: ReadyPointToml) -> ReadyPoint {
    match toml {
        ReadyPointToml::FixedIcount { retired } => ReadyPoint::FixedIcount {
            icount: Icount { retired },
        },
        ReadyPointToml::NetworkIdle { window_nanos } => ReadyPoint::NetworkIdle {
            window: SimDuration {
                nanos: window_nanos,
            },
        },
        ReadyPointToml::ConsoleMarker { marker } => ReadyPoint::ConsoleMarker { marker },
        ReadyPointToml::AgentSignal => ReadyPoint::AgentSignal,
    }
}

fn white_box_to_toml(policy: WhiteBoxPolicy) -> WhiteBoxToml {
    match policy {
        WhiteBoxPolicy::Disabled => WhiteBoxToml::Disabled,
        WhiteBoxPolicy::Enabled => WhiteBoxToml::Enabled,
    }
}

fn white_box_from_toml(toml: WhiteBoxToml) -> WhiteBoxPolicy {
    match toml {
        WhiteBoxToml::Disabled => WhiteBoxPolicy::Disabled,
        WhiteBoxToml::Enabled => WhiteBoxPolicy::Enabled,
    }
}

fn link_to_toml(link: &LinkDef) -> LinkToml {
    let (endpoint_a, endpoint_b) = link.endpoints();
    LinkToml {
        endpoint_a: endpoint_a.name.clone(),
        endpoint_b: endpoint_b.name.clone(),
        latency_nanos: link.latency().nanos,
        jitter_nanos: link.jitter().nanos,
        loss_millionths: link.loss().millionths(),
        bandwidth_bps: link.bandwidth_bps(),
    }
}

fn link_from_toml(toml: LinkToml) -> Result<LinkDef, EngineError> {
    LinkDef::with_transport(
        NodeId {
            name: toml.endpoint_a,
        },
        NodeId {
            name: toml.endpoint_b,
        },
        SimDuration {
            nanos: toml.latency_nanos,
        },
        SimDuration {
            nanos: toml.jitter_nanos,
        },
        LinkLossProbability::from_millionths(toml.loss_millionths)?,
        toml.bandwidth_bps,
    )
}

fn plan_to_toml(plan: &Plan) -> PlanToml {
    PlanToml {
        id: format_content_hash_ref(plan.content_hash()),
        entry: plan.entries().iter().map(plan_entry_to_toml).collect(),
    }
}

fn plan_from_toml(world: &World, toml: PlanToml) -> Result<Plan, EngineError> {
    let id = parse_content_hash_ref(&toml.id)?;
    let entries = toml
        .entry
        .into_iter()
        .map(plan_entry_from_toml)
        .collect::<Vec<_>>();
    let plan = Plan::from_entries_for_world(world, entries)?;
    validate_serialized_id("plan", id, plan.content_hash())?;
    Ok(plan)
}

fn plan_entry_to_toml(entry: &PlanEntry) -> PlanEntryToml {
    match entry {
        PlanEntry::Activate { at, tag, fault } => PlanEntryToml::Activate {
            at_ticks: at.ticks,
            tag: tag.name.clone(),
            fault: membership_fault_to_toml(fault),
        },
        PlanEntry::Heal { at, tag } => PlanEntryToml::Heal {
            at_ticks: at.ticks,
            tag: tag.name.clone(),
        },
    }
}

fn plan_entry_from_toml(toml: PlanEntryToml) -> PlanEntry {
    match toml {
        PlanEntryToml::Activate {
            at_ticks,
            tag,
            fault,
        } => PlanEntry::Activate {
            at: VirtualTime { ticks: at_ticks },
            tag: FaultTag { name: tag },
            fault: membership_fault_from_toml(fault),
        },
        PlanEntryToml::Heal { at_ticks, tag } => PlanEntry::Heal {
            at: VirtualTime { ticks: at_ticks },
            tag: FaultTag { name: tag },
        },
    }
}

fn membership_fault_to_toml(fault: &MembershipFault) -> MembershipFaultToml {
    match fault {
        MembershipFault::Crash { node, restart } => MembershipFaultToml::Crash {
            node: node.name.clone(),
            restart: restart_to_toml(*restart),
        },
        MembershipFault::Partition {
            endpoint_a,
            endpoint_b,
            direction,
        } => MembershipFaultToml::Partition {
            endpoint_a: endpoint_a.name.clone(),
            endpoint_b: endpoint_b.name.clone(),
            direction: partition_direction_to_toml(*direction),
        },
        MembershipFault::Isolate { node } => MembershipFaultToml::Isolate {
            node: node.name.clone(),
        },
        MembershipFault::NotYetJoined { node } => MembershipFaultToml::NotYetJoined {
            node: node.name.clone(),
        },
    }
}

fn membership_fault_from_toml(toml: MembershipFaultToml) -> MembershipFault {
    match toml {
        MembershipFaultToml::Crash { node, restart } => MembershipFault::Crash {
            node: NodeId { name: node },
            restart: restart_from_toml(restart),
        },
        MembershipFaultToml::Partition {
            endpoint_a,
            endpoint_b,
            direction,
        } => MembershipFault::Partition {
            endpoint_a: NodeId { name: endpoint_a },
            endpoint_b: NodeId { name: endpoint_b },
            direction: partition_direction_from_toml(direction),
        },
        MembershipFaultToml::Isolate { node } => MembershipFault::Isolate {
            node: NodeId { name: node },
        },
        MembershipFaultToml::NotYetJoined { node } => MembershipFault::NotYetJoined {
            node: NodeId { name: node },
        },
    }
}

fn restart_to_toml(policy: RestartPolicy) -> RestartToml {
    match policy {
        RestartPolicy::FromReadyPoint => RestartToml::FromReadyPoint,
        RestartPolicy::FromLastCheckpoint => RestartToml::FromLastCheckpoint,
        RestartPolicy::StayDown => RestartToml::StayDown,
    }
}

fn restart_from_toml(toml: RestartToml) -> RestartPolicy {
    match toml {
        RestartToml::FromReadyPoint => RestartPolicy::FromReadyPoint,
        RestartToml::FromLastCheckpoint => RestartPolicy::FromLastCheckpoint,
        RestartToml::StayDown => RestartPolicy::StayDown,
    }
}

fn partition_direction_to_toml(direction: PartitionDirection) -> PartitionDirectionToml {
    match direction {
        PartitionDirection::Bidirectional => PartitionDirectionToml::Bidirectional,
        PartitionDirection::EndpointAToEndpointB => PartitionDirectionToml::EndpointAToEndpointB,
        PartitionDirection::EndpointBToEndpointA => PartitionDirectionToml::EndpointBToEndpointA,
    }
}

fn partition_direction_from_toml(toml: PartitionDirectionToml) -> PartitionDirection {
    match toml {
        PartitionDirectionToml::Bidirectional => PartitionDirection::Bidirectional,
        PartitionDirectionToml::EndpointAToEndpointB => PartitionDirection::EndpointAToEndpointB,
        PartitionDirectionToml::EndpointBToEndpointA => PartitionDirection::EndpointBToEndpointA,
    }
}

fn properties_to_toml(properties: &Properties) -> PropertiesToml {
    PropertiesToml {
        id: format_content_hash_ref(properties.content_hash()),
        assertion: properties
            .assertions()
            .iter()
            .map(assertion_to_toml)
            .collect(),
    }
}

fn properties_from_toml(world: &World, toml: PropertiesToml) -> Result<Properties, EngineError> {
    let id = parse_content_hash_ref(&toml.id)?;
    let assertions = toml
        .assertion
        .into_iter()
        .map(assertion_from_toml)
        .collect::<Vec<_>>();
    let properties = Properties::from_assertions_for_world(world, assertions)?;
    validate_serialized_id("properties", id, properties.content_hash())?;
    Ok(properties)
}

fn assertion_to_toml(assertion: &AssertionDef) -> AssertionToml {
    AssertionToml {
        id: assertion.id.name.clone(),
        message: assertion.message.clone(),
        property: property_to_toml(&assertion.property),
    }
}

fn assertion_from_toml(toml: AssertionToml) -> AssertionDef {
    AssertionDef {
        id: AssertionId { name: toml.id },
        message: toml.message,
        property: property_from_toml(toml.property),
    }
}

fn property_to_toml(property: &Property) -> PropertyToml {
    match property {
        Property::Always { predicate } => PropertyToml::Always {
            predicate: predicate_to_toml(predicate),
        },
        Property::Sometimes { predicate } => PropertyToml::Sometimes {
            predicate: predicate_to_toml(predicate),
        },
        Property::Eventually {
            trigger,
            property,
            deadline,
        } => PropertyToml::Eventually {
            trigger: predicate_to_toml(trigger),
            property: predicate_to_toml(property),
            deadline_ticks: deadline.ticks,
        },
        Property::AfterQuiescence { predicate } => PropertyToml::AfterQuiescence {
            predicate: predicate_to_toml(predicate),
        },
        Property::Reachable {
            predicate,
            expectation,
        } => PropertyToml::Reachable {
            predicate: predicate_to_toml(predicate),
            expectation: reachability_expectation_to_toml(*expectation),
        },
    }
}

fn property_from_toml(toml: PropertyToml) -> Property {
    match toml {
        PropertyToml::Always { predicate } => Property::Always {
            predicate: predicate_from_toml(predicate),
        },
        PropertyToml::Sometimes { predicate } => Property::Sometimes {
            predicate: predicate_from_toml(predicate),
        },
        PropertyToml::Eventually {
            trigger,
            property,
            deadline_ticks,
        } => Property::Eventually {
            trigger: predicate_from_toml(trigger),
            property: predicate_from_toml(property),
            deadline: VirtualTime {
                ticks: deadline_ticks,
            },
        },
        PropertyToml::AfterQuiescence { predicate } => Property::AfterQuiescence {
            predicate: predicate_from_toml(predicate),
        },
        PropertyToml::Reachable {
            predicate,
            expectation,
        } => Property::Reachable {
            predicate: predicate_from_toml(predicate),
            expectation: reachability_expectation_from_toml(expectation),
        },
    }
}

fn predicate_to_toml(predicate: &Predicate) -> PredicateToml {
    match predicate {
        Predicate::Named { name, nodes } => PredicateToml::Named {
            name: name.clone(),
            nodes: nodes.iter().map(|node| node.name.clone()).collect(),
        },
        Predicate::GuestMarker { marker } => PredicateToml::GuestMarker {
            marker: marker.name.clone(),
        },
        Predicate::AllOf { predicates } => PredicateToml::AllOf {
            predicates: predicates.iter().map(predicate_to_toml).collect(),
        },
        Predicate::AnyOf { predicates } => PredicateToml::AnyOf {
            predicates: predicates.iter().map(predicate_to_toml).collect(),
        },
        Predicate::Once { predicate } => PredicateToml::Once {
            predicate: Box::new(predicate_to_toml(predicate)),
        },
        Predicate::Not { predicate } => PredicateToml::Not {
            predicate: Box::new(predicate_to_toml(predicate)),
        },
    }
}

fn predicate_from_toml(toml: PredicateToml) -> Predicate {
    match toml {
        PredicateToml::Named { name, nodes } => Predicate::Named {
            name,
            nodes: nodes.into_iter().map(|name| NodeId { name }).collect(),
        },
        PredicateToml::GuestMarker { marker } => Predicate::GuestMarker {
            marker: MarkerId { name: marker },
        },
        PredicateToml::AllOf { predicates } => Predicate::AllOf {
            predicates: predicates.into_iter().map(predicate_from_toml).collect(),
        },
        PredicateToml::AnyOf { predicates } => Predicate::AnyOf {
            predicates: predicates.into_iter().map(predicate_from_toml).collect(),
        },
        PredicateToml::Once { predicate } => Predicate::Once {
            predicate: Box::new(predicate_from_toml(*predicate)),
        },
        PredicateToml::Not { predicate } => Predicate::Not {
            predicate: Box::new(predicate_from_toml(*predicate)),
        },
    }
}

fn reachability_expectation_to_toml(
    expectation: ReachabilityExpectation,
) -> ReachabilityExpectationToml {
    match expectation {
        ReachabilityExpectation::Reachable { on_unreached } => {
            ReachabilityExpectationToml::Reachable {
                on_unreached: reachable_disposition_to_toml(on_unreached),
            }
        }
        ReachabilityExpectation::Unreachable => ReachabilityExpectationToml::Unreachable,
    }
}

fn reachability_expectation_from_toml(
    toml: ReachabilityExpectationToml,
) -> ReachabilityExpectation {
    match toml {
        ReachabilityExpectationToml::Reachable { on_unreached } => {
            ReachabilityExpectation::Reachable {
                on_unreached: reachable_disposition_from_toml(on_unreached),
            }
        }
        ReachabilityExpectationToml::Unreachable => ReachabilityExpectation::Unreachable,
    }
}

fn reachable_disposition_to_toml(disposition: ReachableDisposition) -> ReachableDispositionToml {
    match disposition {
        ReachableDisposition::Warn => ReachableDispositionToml::Warn,
        ReachableDisposition::Fail => ReachableDispositionToml::Fail,
    }
}

fn reachable_disposition_from_toml(toml: ReachableDispositionToml) -> ReachableDisposition {
    match toml {
        ReachableDispositionToml::Warn => ReachableDisposition::Warn,
        ReachableDispositionToml::Fail => ReachableDisposition::Fail,
    }
}

fn seed_to_toml(seed: Seed) -> SeedToml {
    SeedToml {
        bytes: format_seed_ref(seed),
    }
}

fn seed_from_toml(toml: &SeedToml) -> Result<Seed, EngineError> {
    parse_seed_ref(&toml.bytes)
}

struct ScenarioBinaryWriter {
    bytes: Vec<u8>,
}

impl ScenarioBinaryWriter {
    fn new(magic: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(magic.len().saturating_add(256));
        bytes.extend_from_slice(magic);
        Self { bytes }
    }

    fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn write_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_count(&mut self, count: usize) {
        self.write_u64(count as u64);
    }

    fn write_string(&mut self, value: &str) {
        self.write_count(value.len());
        self.bytes.extend_from_slice(value.as_bytes());
    }

    fn write_binary_blob(&mut self, value: &[u8]) {
        self.write_count(value.len());
        self.bytes.extend_from_slice(value);
    }

    fn write_hash(&mut self, hash: ContentHash) {
        self.bytes.extend_from_slice(&hash.bytes);
    }

    fn write_optional_blob_ref(&mut self, reference: Option<ContentAddressedBlobRef>) {
        match reference {
            Some(reference) => {
                self.write_u8(1);
                self.write_hash(reference.hash());
            }
            None => self.write_u8(0),
        }
    }

    fn write_seed(&mut self, seed: Seed) {
        self.bytes.extend_from_slice(&seed.bytes());
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct ScenarioBinaryReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ScenarioBinaryReader<'a> {
    fn new(bytes: &'a [u8], magic: &[u8]) -> Result<Self, EngineError> {
        if !bytes.starts_with(magic) {
            return Err(scenario_serialization_error("binary magic mismatch"));
        }
        Ok(Self {
            bytes,
            offset: magic.len(),
        })
    }

    fn finish(&self) -> Result<(), EngineError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(scenario_serialization_error("trailing binary bytes"))
        }
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], EngineError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| scenario_serialization_error("binary offset overflow"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| scenario_serialization_error("truncated binary input"))?;
        self.offset = end;
        Ok(bytes)
    }

    fn read_u8(&mut self) -> Result<u8, EngineError> {
        let bytes = self.read_exact(1)?;
        Ok(bytes[0])
    }

    fn read_u32(&mut self) -> Result<u32, EngineError> {
        let bytes = self.read_exact(4)?;
        let mut fixed = [0; 4];
        fixed.copy_from_slice(bytes);
        Ok(u32::from_le_bytes(fixed))
    }

    fn read_u64(&mut self) -> Result<u64, EngineError> {
        let bytes = self.read_exact(8)?;
        let mut fixed = [0; 8];
        fixed.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(fixed))
    }

    fn read_count(&mut self) -> Result<usize, EngineError> {
        usize::try_from(self.read_u64()?)
            .map_err(|_| scenario_serialization_error("binary count does not fit usize"))
    }

    fn read_collection_count(&mut self, label: &'static str) -> Result<usize, EngineError> {
        let count = self.read_count()?;
        if count > MAX_SCENARIO_BINARY_COLLECTION_ITEMS {
            Err(scenario_serialization_error(format!(
                "{label} count exceeds serialized collection limit"
            )))
        } else {
            Ok(count)
        }
    }

    fn read_string(&mut self) -> Result<String, EngineError> {
        let len = self.read_count()?;
        if len > MAX_SCENARIO_BINARY_STRING_BYTES {
            return Err(scenario_serialization_error(
                "binary string exceeds serialized string limit",
            ));
        }
        let bytes = self.read_exact(len)?.to_vec();
        String::from_utf8(bytes)
            .map_err(|source| scenario_serialization_error(format!("invalid UTF-8: {source}")))
    }

    fn read_binary_blob(&mut self, label: &'static str) -> Result<&'a [u8], EngineError> {
        let len = self.read_count()?;
        if len > MAX_SCENARIO_BINARY_BLOB_BYTES {
            return Err(scenario_serialization_error(format!(
                "{label} exceeds serialized blob limit"
            )));
        }
        self.read_exact(len)
    }

    fn read_hash(&mut self) -> Result<ContentHash, EngineError> {
        let bytes = self.read_exact(32)?;
        let mut fixed = [0; 32];
        fixed.copy_from_slice(bytes);
        Ok(ContentHash { bytes: fixed })
    }

    fn read_optional_blob_ref(&mut self) -> Result<Option<ContentAddressedBlobRef>, EngineError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(ContentAddressedBlobRef::from_hash(self.read_hash()?))),
            _ => Err(scenario_serialization_error(
                "invalid optional blob-ref tag",
            )),
        }
    }

    fn read_seed(&mut self) -> Result<Seed, EngineError> {
        let bytes = self.read_exact(32)?;
        let mut fixed = [0; 32];
        fixed.copy_from_slice(bytes);
        Ok(Seed::from_bytes(fixed))
    }
}

fn write_scenario_form_binary(form: &ScenarioDefForm, writer: &mut ScenarioBinaryWriter) {
    writer.write_hash(form.id());
    write_world_binary(&form.world, writer);
    write_plan_binary(&form.plan, writer);
    write_properties_binary(&form.properties, writer);
    writer.write_seed(form.seed);
}

fn read_scenario_form_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<ScenarioDefForm, EngineError> {
    let expected = reader.read_hash()?;
    let world = read_world_binary(reader)?;
    let plan = read_plan_binary(&world, reader)?;
    let properties = read_properties_binary(&world, reader)?;
    let seed = reader.read_seed()?;
    let form = ScenarioDefForm::from_components(&world, &plan, &properties, seed)?;
    validate_serialized_id("scenario", expected, form.id())?;
    Ok(form)
}

fn write_schedule_binary(schedule: &Schedule, writer: &mut ScenarioBinaryWriter) {
    writer.write_hash(schedule.content_hash());
    writer.write_count(schedule.decisions().len());
    for decision in schedule.decisions() {
        write_decision_binary(decision, writer);
    }
}

fn read_schedule_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<Schedule, EngineError> {
    let expected = reader.read_hash()?;
    let count = reader.read_collection_count("schedule.decision")?;
    let mut decisions = Vec::with_capacity(count);
    for _ in 0..count {
        decisions.push(read_decision_binary(reader)?);
    }
    let schedule = Schedule { decisions };
    validate_serialized_id("schedule", expected, schedule.content_hash())?;
    Ok(schedule)
}

fn write_decision_binary(decision: &Decision, writer: &mut ScenarioBinaryWriter) {
    match decision {
        Decision::DeliveryOrder(order) => {
            writer.write_u8(0);
            writer.write_u64(order.at.ticks);
            writer.write_count(order.order.len());
            for event in &order.order {
                writer.write_u64(event.sequence);
            }
        }
        Decision::FaultFires(fault) => {
            writer.write_u8(1);
            writer.write_u64(fault.at.ticks);
            writer.write_string(&fault.fault.name);
            write_binary_bool(writer, fault.fired);
        }
        Decision::RngDraw(draw) => {
            writer.write_u8(2);
            write_rng_stream_binary(&draw.stream, writer);
            writer.write_u64(draw.value);
        }
        Decision::Override(override_decision) => {
            writer.write_u8(3);
            writer.write_string(&override_decision.point.key);
            writer.write_string(&override_decision.choice.name);
        }
        Decision::Preemption(preemption) => {
            writer.write_u8(4);
            writer.write_string(&preemption.node.name);
            writer.write_u64(preemption.at.retired);
            write_preemption_kind_binary(&preemption.kind, writer);
        }
        Decision::AppRandom(random) => {
            writer.write_u8(5);
            writer.write_string(&random.node.name);
            write_rng_stream_binary(&random.stream, writer);
            writer.write_u64(random.request_id);
            writer.write_u8(random.width);
            writer.write_u64(random.value);
        }
    }
}

fn read_decision_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<Decision, EngineError> {
    match reader.read_u8()? {
        0 => {
            let at = VirtualTime {
                ticks: reader.read_u64()?,
            };
            let count = reader.read_collection_count("decision.delivery-order.event")?;
            let mut order = Vec::with_capacity(count);
            for _ in 0..count {
                order.push(EventKey {
                    sequence: reader.read_u64()?,
                });
            }
            Ok(Decision::DeliveryOrder(DeliveryOrderDecision { at, order }))
        }
        1 => Ok(Decision::FaultFires(FaultDecision {
            at: VirtualTime {
                ticks: reader.read_u64()?,
            },
            fault: FaultId {
                name: reader.read_string()?,
            },
            fired: read_binary_bool(reader, "fault decision fired")?,
        })),
        2 => Ok(Decision::RngDraw(RngDecision {
            stream: read_rng_stream_binary(reader)?,
            value: reader.read_u64()?,
        })),
        3 => Ok(Decision::Override(OverrideDecision {
            point: SchedulingPoint {
                key: reader.read_string()?,
            },
            choice: ChoiceTag {
                name: reader.read_string()?,
            },
        })),
        4 => Ok(Decision::Preemption(PreemptionDecision {
            node: NodeId {
                name: reader.read_string()?,
            },
            at: Icount {
                retired: reader.read_u64()?,
            },
            kind: read_preemption_kind_binary(reader)?,
        })),
        5 => Ok(Decision::AppRandom(AppRandomDecision {
            node: NodeId {
                name: reader.read_string()?,
            },
            stream: read_rng_stream_binary(reader)?,
            request_id: reader.read_u64()?,
            width: reader.read_u8()?,
            value: reader.read_u64()?,
        })),
        _ => Err(scenario_serialization_error("invalid decision tag")),
    }
}

fn write_rng_stream_binary(stream: &RngStreamId, writer: &mut ScenarioBinaryWriter) {
    writer.write_string(&stream.domain);
    writer.write_string(&stream.name);
}

fn read_rng_stream_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<RngStreamId, EngineError> {
    Ok(RngStreamId::new(
        reader.read_string()?,
        reader.read_string()?,
    ))
}

fn write_preemption_kind_binary(kind: &PreemptionKind, writer: &mut ScenarioBinaryWriter) {
    match kind {
        PreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => {
            writer.write_u8(0);
            writer.write_u32(from_vcpu.index);
            writer.write_u32(to_vcpu.index);
        }
        PreemptionKind::InterruptAt { target_vcpu, irq } => {
            writer.write_u8(1);
            writer.write_u32(target_vcpu.index);
            writer.write_u32(irq.vector);
        }
    }
}

fn read_preemption_kind_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<PreemptionKind, EngineError> {
    match reader.read_u8()? {
        0 => Ok(PreemptionKind::VcpuSwitch {
            from_vcpu: VcpuId {
                index: reader.read_u32()?,
            },
            to_vcpu: VcpuId {
                index: reader.read_u32()?,
            },
        }),
        1 => Ok(PreemptionKind::InterruptAt {
            target_vcpu: VcpuId {
                index: reader.read_u32()?,
            },
            irq: IrqVector {
                vector: reader.read_u32()?,
            },
        }),
        _ => Err(scenario_serialization_error("invalid preemption-kind tag")),
    }
}

fn write_binary_bool(writer: &mut ScenarioBinaryWriter, value: bool) {
    writer.write_u8(u8::from(value));
}

fn read_binary_bool(
    reader: &mut ScenarioBinaryReader<'_>,
    label: &'static str,
) -> Result<bool, EngineError> {
    match reader.read_u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(scenario_serialization_error(format!(
            "invalid binary bool for {label}"
        ))),
    }
}

fn write_world_binary(world: &World, writer: &mut ScenarioBinaryWriter) {
    writer.write_hash(world.id());
    writer.write_count(world.nodes().len());
    for node in world.nodes() {
        write_world_node_binary(node, writer);
    }
    writer.write_count(world.links().len());
    for link in world.links() {
        write_link_binary(link, writer);
    }
}

fn read_world_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<World, EngineError> {
    let id = reader.read_hash()?;
    let node_count = reader.read_collection_count("world.node")?;
    let mut nodes = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        nodes.push(read_world_node_binary(reader)?);
    }
    let link_count = reader.read_collection_count("world.link")?;
    let mut links = Vec::with_capacity(link_count);
    for _ in 0..link_count {
        links.push(read_link_binary(reader)?);
    }
    let world = World::from_recorded_parts(id, nodes, links)?;
    validate_world_serialized_identity(&world)?;
    Ok(world)
}

fn write_world_node_binary(node: &WorldNode, writer: &mut ScenarioBinaryWriter) {
    writer.write_string(&node.id.name);
    writer.write_optional_blob_ref(node.kernel);
    writer.write_optional_blob_ref(node.root_image);
    writer.write_optional_blob_ref(node.initrd);
    write_ready_point_binary(&node.ready_point, writer);
    writer.write_u8(match node.white_box {
        WhiteBoxPolicy::Disabled => 0,
        WhiteBoxPolicy::Enabled => 1,
    });
}

fn read_world_node_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<WorldNode, EngineError> {
    let id = NodeId {
        name: reader.read_string()?,
    };
    let kernel = reader.read_optional_blob_ref()?;
    let root_image = reader.read_optional_blob_ref()?;
    let initrd = reader.read_optional_blob_ref()?;
    let ready_point = read_ready_point_binary(reader)?;
    let white_box = match reader.read_u8()? {
        0 => WhiteBoxPolicy::Disabled,
        1 => WhiteBoxPolicy::Enabled,
        _ => return Err(scenario_serialization_error("invalid white-box policy tag")),
    };
    Ok(WorldNode {
        id,
        ready_point,
        white_box,
        kernel,
        root_image,
        initrd,
    })
}

fn write_ready_point_binary(ready_point: &ReadyPoint, writer: &mut ScenarioBinaryWriter) {
    match ready_point {
        ReadyPoint::FixedIcount { icount } => {
            writer.write_u8(0);
            writer.write_u64(icount.retired);
        }
        ReadyPoint::NetworkIdle { window } => {
            writer.write_u8(1);
            writer.write_u64(window.nanos);
        }
        ReadyPoint::ConsoleMarker { marker } => {
            writer.write_u8(2);
            writer.write_string(marker);
        }
        ReadyPoint::AgentSignal => {
            writer.write_u8(3);
        }
    }
}

fn read_ready_point_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<ReadyPoint, EngineError> {
    match reader.read_u8()? {
        0 => Ok(ReadyPoint::FixedIcount {
            icount: Icount {
                retired: reader.read_u64()?,
            },
        }),
        1 => Ok(ReadyPoint::NetworkIdle {
            window: SimDuration {
                nanos: reader.read_u64()?,
            },
        }),
        2 => Ok(ReadyPoint::ConsoleMarker {
            marker: reader.read_string()?,
        }),
        3 => Ok(ReadyPoint::AgentSignal),
        _ => Err(scenario_serialization_error("invalid ready-point tag")),
    }
}

fn write_link_binary(link: &LinkDef, writer: &mut ScenarioBinaryWriter) {
    let (endpoint_a, endpoint_b) = link.endpoints();
    writer.write_string(&endpoint_a.name);
    writer.write_string(&endpoint_b.name);
    writer.write_u64(link.latency().nanos);
    writer.write_u64(link.jitter().nanos);
    writer.write_u32(link.loss().millionths());
    match link.bandwidth_bps() {
        Some(bandwidth) => {
            writer.write_u8(1);
            writer.write_u64(bandwidth);
        }
        None => writer.write_u8(0),
    }
}

fn read_link_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<LinkDef, EngineError> {
    let endpoint_a = NodeId {
        name: reader.read_string()?,
    };
    let endpoint_b = NodeId {
        name: reader.read_string()?,
    };
    let latency = SimDuration {
        nanos: reader.read_u64()?,
    };
    let jitter = SimDuration {
        nanos: reader.read_u64()?,
    };
    let loss = LinkLossProbability::from_millionths(reader.read_u32()?)?;
    let bandwidth_bps = match reader.read_u8()? {
        0 => None,
        1 => Some(reader.read_u64()?),
        _ => return Err(scenario_serialization_error("invalid bandwidth tag")),
    };
    LinkDef::with_transport(endpoint_a, endpoint_b, latency, jitter, loss, bandwidth_bps)
}

fn write_plan_binary(plan: &Plan, writer: &mut ScenarioBinaryWriter) {
    writer.write_hash(plan.content_hash());
    writer.write_count(plan.entries().len());
    for entry in plan.entries() {
        write_plan_entry_binary(entry, writer);
    }
}

fn read_plan_binary(
    world: &World,
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<Plan, EngineError> {
    let id = reader.read_hash()?;
    let count = reader.read_collection_count("plan.entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        entries.push(read_plan_entry_binary(reader)?);
    }
    let plan = Plan::from_entries_for_world(world, entries)?;
    validate_serialized_id("plan", id, plan.content_hash())?;
    Ok(plan)
}

fn write_plan_entry_binary(entry: &PlanEntry, writer: &mut ScenarioBinaryWriter) {
    match entry {
        PlanEntry::Activate { at, tag, fault } => {
            writer.write_u8(0);
            writer.write_u64(at.ticks);
            writer.write_string(&tag.name);
            write_membership_fault_binary(fault, writer);
        }
        PlanEntry::Heal { at, tag } => {
            writer.write_u8(1);
            writer.write_u64(at.ticks);
            writer.write_string(&tag.name);
        }
    }
}

fn read_plan_entry_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<PlanEntry, EngineError> {
    match reader.read_u8()? {
        0 => Ok(PlanEntry::Activate {
            at: VirtualTime {
                ticks: reader.read_u64()?,
            },
            tag: FaultTag {
                name: reader.read_string()?,
            },
            fault: read_membership_fault_binary(reader)?,
        }),
        1 => Ok(PlanEntry::Heal {
            at: VirtualTime {
                ticks: reader.read_u64()?,
            },
            tag: FaultTag {
                name: reader.read_string()?,
            },
        }),
        _ => Err(scenario_serialization_error("invalid plan-entry tag")),
    }
}

fn write_membership_fault_binary(fault: &MembershipFault, writer: &mut ScenarioBinaryWriter) {
    match fault {
        MembershipFault::Crash { node, restart } => {
            writer.write_u8(0);
            writer.write_string(&node.name);
            writer.write_u8(match restart {
                RestartPolicy::FromReadyPoint => 0,
                RestartPolicy::FromLastCheckpoint => 1,
                RestartPolicy::StayDown => 2,
            });
        }
        MembershipFault::Partition {
            endpoint_a,
            endpoint_b,
            direction,
        } => {
            writer.write_u8(1);
            writer.write_string(&endpoint_a.name);
            writer.write_string(&endpoint_b.name);
            writer.write_u8(match direction {
                PartitionDirection::Bidirectional => 0,
                PartitionDirection::EndpointAToEndpointB => 1,
                PartitionDirection::EndpointBToEndpointA => 2,
            });
        }
        MembershipFault::Isolate { node } => {
            writer.write_u8(2);
            writer.write_string(&node.name);
        }
        MembershipFault::NotYetJoined { node } => {
            writer.write_u8(3);
            writer.write_string(&node.name);
        }
    }
}

fn read_membership_fault_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<MembershipFault, EngineError> {
    match reader.read_u8()? {
        0 => {
            let node = NodeId {
                name: reader.read_string()?,
            };
            let restart = match reader.read_u8()? {
                0 => RestartPolicy::FromReadyPoint,
                1 => RestartPolicy::FromLastCheckpoint,
                2 => RestartPolicy::StayDown,
                _ => return Err(scenario_serialization_error("invalid restart-policy tag")),
            };
            Ok(MembershipFault::Crash { node, restart })
        }
        1 => {
            let endpoint_a = NodeId {
                name: reader.read_string()?,
            };
            let endpoint_b = NodeId {
                name: reader.read_string()?,
            };
            let direction = match reader.read_u8()? {
                0 => PartitionDirection::Bidirectional,
                1 => PartitionDirection::EndpointAToEndpointB,
                2 => PartitionDirection::EndpointBToEndpointA,
                _ => {
                    return Err(scenario_serialization_error(
                        "invalid partition-direction tag",
                    ));
                }
            };
            Ok(MembershipFault::Partition {
                endpoint_a,
                endpoint_b,
                direction,
            })
        }
        2 => Ok(MembershipFault::Isolate {
            node: NodeId {
                name: reader.read_string()?,
            },
        }),
        3 => Ok(MembershipFault::NotYetJoined {
            node: NodeId {
                name: reader.read_string()?,
            },
        }),
        _ => Err(scenario_serialization_error("invalid membership-fault tag")),
    }
}

fn write_properties_binary(properties: &Properties, writer: &mut ScenarioBinaryWriter) {
    writer.write_hash(properties.content_hash());
    writer.write_count(properties.assertions().len());
    for assertion in properties.assertions() {
        write_assertion_binary(assertion, writer);
    }
}

fn read_properties_binary(
    world: &World,
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<Properties, EngineError> {
    let id = reader.read_hash()?;
    let count = reader.read_collection_count("properties.assertion")?;
    let mut assertions = Vec::with_capacity(count);
    for _ in 0..count {
        assertions.push(read_assertion_binary(reader)?);
    }
    let properties = Properties::from_assertions_for_world(world, assertions)?;
    validate_serialized_id("properties", id, properties.content_hash())?;
    Ok(properties)
}

fn write_assertion_binary(assertion: &AssertionDef, writer: &mut ScenarioBinaryWriter) {
    writer.write_string(&assertion.id.name);
    writer.write_string(&assertion.message);
    write_property_binary(&assertion.property, writer);
}

fn read_assertion_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<AssertionDef, EngineError> {
    Ok(AssertionDef {
        id: AssertionId {
            name: reader.read_string()?,
        },
        message: reader.read_string()?,
        property: read_property_binary(reader)?,
    })
}

fn write_property_binary(property: &Property, writer: &mut ScenarioBinaryWriter) {
    match property {
        Property::Always { predicate } => {
            writer.write_u8(0);
            write_predicate_binary(predicate, writer);
        }
        Property::Sometimes { predicate } => {
            writer.write_u8(1);
            write_predicate_binary(predicate, writer);
        }
        Property::Eventually {
            trigger,
            property,
            deadline,
        } => {
            writer.write_u8(2);
            write_predicate_binary(trigger, writer);
            write_predicate_binary(property, writer);
            writer.write_u64(deadline.ticks);
        }
        Property::AfterQuiescence { predicate } => {
            writer.write_u8(3);
            write_predicate_binary(predicate, writer);
        }
        Property::Reachable {
            predicate,
            expectation,
        } => {
            writer.write_u8(4);
            write_predicate_binary(predicate, writer);
            write_reachability_expectation_binary(*expectation, writer);
        }
    }
}

fn read_property_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<Property, EngineError> {
    match reader.read_u8()? {
        0 => Ok(Property::Always {
            predicate: read_predicate_binary(reader)?,
        }),
        1 => Ok(Property::Sometimes {
            predicate: read_predicate_binary(reader)?,
        }),
        2 => Ok(Property::Eventually {
            trigger: read_predicate_binary(reader)?,
            property: read_predicate_binary(reader)?,
            deadline: VirtualTime {
                ticks: reader.read_u64()?,
            },
        }),
        3 => Ok(Property::AfterQuiescence {
            predicate: read_predicate_binary(reader)?,
        }),
        4 => Ok(Property::Reachable {
            predicate: read_predicate_binary(reader)?,
            expectation: read_reachability_expectation_binary(reader)?,
        }),
        _ => Err(scenario_serialization_error("invalid property tag")),
    }
}

fn write_predicate_binary(predicate: &Predicate, writer: &mut ScenarioBinaryWriter) {
    match predicate {
        Predicate::Named { name, nodes } => {
            writer.write_u8(0);
            writer.write_string(name);
            writer.write_count(nodes.len());
            for node in nodes {
                writer.write_string(&node.name);
            }
        }
        Predicate::GuestMarker { marker } => {
            writer.write_u8(1);
            writer.write_string(&marker.name);
        }
        Predicate::AllOf { predicates } => {
            writer.write_u8(2);
            writer.write_count(predicates.len());
            for predicate in predicates {
                write_predicate_binary(predicate, writer);
            }
        }
        Predicate::AnyOf { predicates } => {
            writer.write_u8(3);
            writer.write_count(predicates.len());
            for predicate in predicates {
                write_predicate_binary(predicate, writer);
            }
        }
        Predicate::Once { predicate } => {
            writer.write_u8(4);
            write_predicate_binary(predicate, writer);
        }
        Predicate::Not { predicate } => {
            writer.write_u8(5);
            write_predicate_binary(predicate, writer);
        }
    }
}

fn read_predicate_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<Predicate, EngineError> {
    match reader.read_u8()? {
        0 => {
            let name = reader.read_string()?;
            let count = reader.read_collection_count("predicate.node")?;
            let mut nodes = Vec::with_capacity(count);
            for _ in 0..count {
                nodes.push(NodeId {
                    name: reader.read_string()?,
                });
            }
            Ok(Predicate::Named { name, nodes })
        }
        1 => Ok(Predicate::GuestMarker {
            marker: MarkerId {
                name: reader.read_string()?,
            },
        }),
        2 => {
            let count = reader.read_collection_count("predicate.all_of")?;
            let mut predicates = Vec::with_capacity(count);
            for _ in 0..count {
                predicates.push(read_predicate_binary(reader)?);
            }
            Ok(Predicate::AllOf { predicates })
        }
        3 => {
            let count = reader.read_collection_count("predicate.any_of")?;
            let mut predicates = Vec::with_capacity(count);
            for _ in 0..count {
                predicates.push(read_predicate_binary(reader)?);
            }
            Ok(Predicate::AnyOf { predicates })
        }
        4 => Ok(Predicate::Once {
            predicate: Box::new(read_predicate_binary(reader)?),
        }),
        5 => Ok(Predicate::Not {
            predicate: Box::new(read_predicate_binary(reader)?),
        }),
        _ => Err(scenario_serialization_error("invalid predicate tag")),
    }
}

fn write_reachability_expectation_binary(
    expectation: ReachabilityExpectation,
    writer: &mut ScenarioBinaryWriter,
) {
    match expectation {
        ReachabilityExpectation::Reachable { on_unreached } => {
            writer.write_u8(0);
            writer.write_u8(match on_unreached {
                ReachableDisposition::Warn => 0,
                ReachableDisposition::Fail => 1,
            });
        }
        ReachabilityExpectation::Unreachable => writer.write_u8(1),
    }
}

fn read_reachability_expectation_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<ReachabilityExpectation, EngineError> {
    match reader.read_u8()? {
        0 => {
            let on_unreached = match reader.read_u8()? {
                0 => ReachableDisposition::Warn,
                1 => ReachableDisposition::Fail,
                _ => {
                    return Err(scenario_serialization_error(
                        "invalid reachable-disposition tag",
                    ));
                }
            };
            Ok(ReachabilityExpectation::Reachable { on_unreached })
        }
        1 => Ok(ReachabilityExpectation::Unreachable),
        _ => Err(scenario_serialization_error(
            "invalid reachability-expectation tag",
        )),
    }
}

fn validate_world_serialized_identity(world: &World) -> Result<(), EngineError> {
    validate_serialized_id("world", world.id(), serialized_world_identity(world))
}

fn validate_serialized_id(
    component: &'static str,
    expected: ContentHash,
    actual: ContentHash,
) -> Result<(), EngineError> {
    if expected == actual {
        Ok(())
    } else {
        Err(EngineError::ScenarioSerializedIdMismatch {
            component,
            expected,
            actual,
        })
    }
}

fn validate_no_host_path_image_refs_in_toml(value: &str) -> Result<(), EngineError> {
    let value = toml::from_str::<toml::Value>(value).map_err(|source| {
        scenario_serialization_error(format!("parse TOML before image-ref validation: {source}"))
    })?;
    validate_toml_image_refs_value(&value)
}

fn validate_plan_entries_in_toml(value: &str) -> Result<(), EngineError> {
    let value = toml::from_str::<toml::Value>(value).map_err(|source| {
        scenario_serialization_error(format!("parse TOML before plan validation: {source}"))
    })?;
    let Some(plan) = toml_plan_table(&value) else {
        return Ok(());
    };
    let Some(entries) = plan.get("entry") else {
        return Ok(());
    };
    let Some(entries) = entries.as_array() else {
        return Err(scenario_serialization_error(
            "serialized plan entry list must be an array",
        ));
    };

    for (index, entry) in entries.iter().enumerate() {
        validate_plan_entry_toml_value(index, entry)?;
    }

    Ok(())
}

fn toml_plan_table(value: &toml::Value) -> Option<&toml::map::Map<String, toml::Value>> {
    let table = value.as_table()?;
    match table.get("plan") {
        Some(plan) => plan.as_table(),
        None => Some(table),
    }
}

fn validate_plan_entry_toml_value(index: usize, entry: &toml::Value) -> Result<(), EngineError> {
    let Some(entry) = entry.as_table() else {
        return Err(scenario_serialization_error(
            "serialized plan entry must be a table",
        ));
    };
    if let Some(at_ticks) = entry
        .get("at_ticks")
        .and_then(toml::Value::as_integer)
        .filter(|at_ticks| *at_ticks < 0)
    {
        return Err(EngineError::PlanNegativeTime {
            entry: index,
            at_ticks,
        });
    }
    if entry.get("kind").and_then(toml::Value::as_str) != Some("activate") {
        return Ok(());
    }
    let Some(fault) = entry.get("fault") else {
        return Ok(());
    };
    validate_membership_fault_toml_value(index, fault)
}

fn validate_membership_fault_toml_value(
    index: usize,
    fault: &toml::Value,
) -> Result<(), EngineError> {
    let Some(fault) = fault.as_table() else {
        return Err(scenario_serialization_error(
            "serialized membership fault must be a table",
        ));
    };
    let Some(kind) = fault.get("kind").and_then(toml::Value::as_str) else {
        return Ok(());
    };
    let allowed = match kind {
        "crash" => &["kind", "node", "restart"][..],
        "partition" => &["kind", "endpoint_a", "endpoint_b", "direction"][..],
        "isolate" | "not_yet_joined" => &["kind", "node"][..],
        _ => return Ok(()),
    };
    for field in fault.keys() {
        if !allowed.contains(&field.as_str()) {
            return Err(EngineError::PlanFaultUnsupportedParam {
                entry: index,
                field: field.clone(),
            });
        }
    }
    if kind == "partition" {
        validate_partition_direction_toml_value(index, fault)?;
    }
    Ok(())
}

fn validate_partition_direction_toml_value(
    index: usize,
    fault: &toml::map::Map<String, toml::Value>,
) -> Result<(), EngineError> {
    let Some(direction) = fault.get("direction").and_then(toml::Value::as_str) else {
        return Ok(());
    };
    if matches!(
        direction,
        "bidirectional" | "endpoint_a_to_endpoint_b" | "endpoint_b_to_endpoint_a"
    ) {
        Ok(())
    } else {
        Err(EngineError::PlanFaultUnknownDirection {
            entry: index,
            direction: direction.to_owned(),
        })
    }
}

fn validate_toml_image_refs_value(value: &toml::Value) -> Result<(), EngineError> {
    match value {
        toml::Value::Table(table) => {
            for (key, value) in table {
                if let Some(field) = image_ref_field(key) {
                    let Some(reference) = value.as_str() else {
                        return Err(scenario_serialization_error(format!(
                            "{field} image reference must be a string"
                        )));
                    };
                    let _ = ContentAddressedBlobRef::parse(field, reference)?;
                }
                validate_toml_image_refs_value(value)?;
            }
        }
        toml::Value::Array(values) => {
            for value in values {
                validate_toml_image_refs_value(value)?;
            }
        }
        toml::Value::String(_)
        | toml::Value::Integer(_)
        | toml::Value::Float(_)
        | toml::Value::Boolean(_)
        | toml::Value::Datetime(_) => {}
    }
    Ok(())
}

fn image_ref_field(key: &str) -> Option<&'static str> {
    for field in ["kernel", "root_image", "initrd"] {
        if key == field {
            return Some(field);
        }
    }
    None
}

fn parse_content_addressed_blob_ref(
    field: &'static str,
    value: &str,
) -> Result<ContentAddressedBlobRef, EngineError> {
    let Some(hex) = value.strip_prefix("blake3:") else {
        return Err(EngineError::ScenarioImageReferenceNotContentAddressed {
            field,
            value: value.to_owned(),
        });
    };
    let hash = parse_content_hash_hex(hex).map_err(|_| {
        EngineError::ScenarioImageReferenceNotContentAddressed {
            field,
            value: value.to_owned(),
        }
    })?;
    Ok(ContentAddressedBlobRef::from_hash(hash))
}

fn parse_optional_blob_ref(
    field: &'static str,
    value: Option<String>,
) -> Result<Option<ContentAddressedBlobRef>, EngineError> {
    value
        .as_deref()
        .map(|reference| ContentAddressedBlobRef::parse(field, reference))
        .transpose()
}

fn parse_content_hash_ref(value: &str) -> Result<ContentHash, EngineError> {
    let Some(hex) = value.strip_prefix("blake3:") else {
        return Err(scenario_serialization_error(
            "content hash reference must start with blake3:",
        ));
    };
    parse_content_hash_hex(hex)
}

fn parse_content_hash_hex(hex: &str) -> Result<ContentHash, EngineError> {
    let bytes = parse_fixed_hex_32(hex, "content hash")?;
    Ok(ContentHash { bytes })
}

fn parse_seed_ref(value: &str) -> Result<Seed, EngineError> {
    let Some(hex) = value.strip_prefix("0x") else {
        return Err(scenario_serialization_error(
            "seed must start with 0x and contain 64 lowercase hex characters",
        ));
    };
    Ok(Seed::from_bytes(parse_fixed_hex_32(hex, "seed")?))
}

fn parse_fixed_hex_32(hex: &str, label: &'static str) -> Result<[u8; 32], EngineError> {
    if hex.len() != 64 {
        return Err(scenario_serialization_error(format!(
            "{label} must contain 64 lowercase hex characters"
        )));
    }
    let mut bytes = [0; 32];
    let raw = hex.as_bytes();
    for index in 0..32 {
        let high = hex_value(raw[index * 2]).ok_or_else(|| {
            scenario_serialization_error(format!("{label} contains non-lowercase-hex character"))
        })?;
        let low = hex_value(raw[index * 2 + 1]).ok_or_else(|| {
            scenario_serialization_error(format!("{label} contains non-lowercase-hex character"))
        })?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn format_content_hash_ref(hash: ContentHash) -> String {
    format!("blake3:{}", content_hash_hex(hash))
}

fn format_seed_ref(seed: Seed) -> String {
    format!("0x{}", seed.to_hex())
}

fn scenario_serialization_error(reason: impl Into<String>) -> EngineError {
    EngineError::ScenarioSerialization {
        reason: reason.into(),
    }
}

fn canonical_world_nodes(nodes: &[WorldNode]) -> Vec<WorldNode> {
    let mut nodes = nodes.to_vec();
    nodes.sort_by(|left, right| left.id.cmp(&right.id));
    nodes
}

fn canonical_world_links(links: &[LinkDef]) -> Vec<LinkDef> {
    let mut links = links.to_vec();
    links.sort_by(|left, right| {
        let (left_a, left_b) = left.endpoints();
        let (right_a, right_b) = right.endpoints();
        left_a
            .cmp(right_a)
            .then_with(|| left_b.cmp(right_b))
            .then_with(|| left.latency().cmp(&right.latency()))
            .then_with(|| left.jitter().cmp(&right.jitter()))
            .then_with(|| left.loss().cmp(&right.loss()))
            .then_with(|| left.bandwidth_bps().cmp(&right.bandwidth_bps()))
    });
    links
}

fn world_participants(world: &World) -> Vec<NodeId> {
    canonical_world_nodes(&world.nodes)
        .into_iter()
        .map(|node| node.id)
        .collect()
}

fn world_rng_streams(world: &World) -> Vec<RngStreamId> {
    let mut streams = Vec::with_capacity(world.nodes.len().saturating_add(world.links.len()));
    for node in canonical_world_nodes(&world.nodes) {
        streams.push(RngStreamId::for_node(node.id.name));
    }
    for link in canonical_world_links(&world.links) {
        streams.push(RngStreamId::for_link(world_link_stream_name(&link)));
    }
    streams.sort();
    streams.dedup();
    streams
}

fn world_lookahead_edges(world: &World) -> Vec<WorldLookaheadEdge> {
    let mut edges = Vec::with_capacity(world.links.len().saturating_mul(2));
    for link in canonical_world_links(&world.links) {
        let (left, right) = link.endpoints();
        edges.push(WorldLookaheadEdge {
            from: left.clone(),
            to: right.clone(),
            minimum_latency: link_minimum_latency(&link),
        });
        edges.push(WorldLookaheadEdge {
            from: right.clone(),
            to: left.clone(),
            minimum_latency: link_minimum_latency(&link),
        });
    }
    edges.sort();
    edges
}

fn world_bake_nodes(world: &World) -> Vec<NodeId> {
    world_participants(world)
}

fn world_link_stream_name(link: &LinkDef) -> String {
    let (left, right) = link.endpoints();
    format!(
        "link_endpoint_a_len={}\nlink_endpoint_a={}\nlink_endpoint_b_len={}\nlink_endpoint_b={}",
        left.name.len(),
        left.name,
        right.name.len(),
        right.name
    )
}

fn link_minimum_latency(link: &LinkDef) -> SimDuration {
    SimDuration {
        nanos: link.latency().nanos.saturating_sub(link.jitter().nanos),
    }
}

fn derive_family_seed(meta_seed: Seed, index: u64) -> Seed {
    let hash = ContentHash::from_canonical_material(
        "crucible.model.scenario-family.seed.v1",
        &format!("{}\nseed_index={index}", seed_material(meta_seed)),
    );
    Seed::from_bytes(hash.bytes)
}

fn family_node_id(index: u32) -> NodeId {
    NodeId {
        name: format!("node-{index}"),
    }
}

fn family_links(params: FamilyParams) -> Result<Vec<LinkDef>, EngineError> {
    let mut pairs = BTreeSet::new();
    match params.topology_shape {
        TopologyShape::Ring => {
            if params.topology_size > 1 {
                for left in 0..params.topology_size {
                    add_family_link_pair(&mut pairs, left, (left + 1) % params.topology_size);
                }
            }
        }
        TopologyShape::Star => {
            for node in 1..params.topology_size {
                add_family_link_pair(&mut pairs, 0, node);
            }
        }
        TopologyShape::Mesh => {
            for left in 0..params.topology_size {
                for right in (left + 1)..params.topology_size {
                    add_family_link_pair(&mut pairs, left, right);
                }
            }
        }
        TopologyShape::Random => {
            for left in 0..params.topology_size.saturating_sub(1) {
                add_family_link_pair(&mut pairs, left, left + 1);
            }

            let mut stream = params.seed.decision_rng().fork_in_domain(
                "crucible.model.scenario-family.random-topology.v1",
                &format!(
                    "topology_shape=random\ntopology_size={}",
                    params.topology_size
                ),
            );
            for left in 0..params.topology_size {
                for right in (left + 1)..params.topology_size {
                    if pairs.contains(&(left, right)) {
                        continue;
                    }
                    if stream.next_u64() & 1 == 1 {
                        add_family_link_pair(&mut pairs, left, right);
                    }
                }
            }
        }
    }

    pairs
        .into_iter()
        .map(|(left, right)| LinkDef::new(family_node_id(left), family_node_id(right)))
        .collect()
}

fn add_family_link_pair(pairs: &mut BTreeSet<(u32, u32)>, left: u32, right: u32) {
    if left == right {
        return;
    }
    let pair = if left < right {
        (left, right)
    } else {
        (right, left)
    };
    pairs.insert(pair);
}

fn family_fault_candidates(world: &World) -> Vec<FamilyFaultCandidate> {
    let mut candidates =
        Vec::with_capacity(world.links().len().saturating_add(world.nodes().len()));
    for link in world.links() {
        let (endpoint_a, endpoint_b) = link.endpoints();
        candidates.push(FamilyFaultCandidate::Partition {
            endpoint_a: endpoint_a.clone(),
            endpoint_b: endpoint_b.clone(),
        });
    }
    for node in world.nodes() {
        candidates.push(FamilyFaultCandidate::Crash(node.id.clone()));
    }
    candidates
}

fn baked_node_blobs(world: &World) -> BTreeMap<NodeId, NodeBlobRef> {
    let world_identity = canonical_world_identity(world);
    canonical_world_nodes(&world.nodes)
        .into_iter()
        .map(|node| {
            let blob = ContentHash::from_canonical_material(
                "crucible.model.node-baked-blob.v1",
                &format!(
                    "world_id={}\n{}",
                    content_hash_hex(world_identity),
                    world_node_material(&node)
                ),
            );
            (node.id, NodeBlobRef::baked(blob))
        })
        .collect()
}

fn baked_node_icounts(world: &World) -> BTreeMap<NodeId, Icount> {
    canonical_world_nodes(&world.nodes)
        .into_iter()
        .map(|node| {
            let icount = match node.ready_point {
                ReadyPoint::FixedIcount { icount } => icount,
                ReadyPoint::NetworkIdle { .. }
                | ReadyPoint::ConsoleMarker { .. }
                | ReadyPoint::AgentSignal => Icount::default(),
            };
            (node.id, icount)
        })
        .collect()
}

fn canonical_world_identity(world: &World) -> ContentHash {
    let nodes = canonical_world_nodes(&world.nodes);
    let links = canonical_world_links(&world.links);
    if nodes.is_empty() && links.is_empty() {
        return world.id;
    }

    ContentHash::from_canonical_material("crucible.model.world.v1", &world_material(&nodes, &links))
}

fn serialized_world_identity(world: &World) -> ContentHash {
    ContentHash::from_canonical_material(
        "crucible.model.world.v1",
        &world_material(
            &canonical_world_nodes(&world.nodes),
            &canonical_world_links(&world.links),
        ),
    )
}

fn scenario_world_plan_properties_seed_material(
    world: &World,
    plan: &Plan,
    properties: &Properties,
    seed: Seed,
) -> String {
    format!(
        "world_ref={}\nplan_ref={}\nproperties_ref={}\n{}",
        content_hash_hex(canonical_world_identity(world)),
        content_hash_hex(plan.content_hash()),
        content_hash_hex(properties.content_hash()),
        seed_material(seed)
    )
}

fn world_material(nodes: &[WorldNode], links: &[LinkDef]) -> String {
    format!(
        "{}\n{}",
        world_nodes_material(nodes),
        world_links_material(links)
    )
}

fn world_nodes_material(nodes: &[WorldNode]) -> String {
    let mut lines = Vec::with_capacity(nodes.len().saturating_mul(5) + 1);
    lines.push(format!("nodes={}", nodes.len()));
    for node in nodes {
        lines.push(world_node_material(node));
    }
    lines.join("\n")
}

fn world_links_material(links: &[LinkDef]) -> String {
    let mut lines = Vec::with_capacity(links.len().saturating_mul(8) + 1);
    lines.push(format!("links={}", links.len()));
    for link in links {
        lines.push(world_link_material(link));
    }
    lines.join("\n")
}

fn world_node_material(node: &WorldNode) -> String {
    format!(
        "node_id_len={}\nnode_id={}\nkernel_ref={}\nroot_image_ref={}\ninitrd_ref={}\n{}\nwhite_box={}",
        node.id.name.len(),
        node.id.name,
        optional_blob_ref_material(node.kernel),
        optional_blob_ref_material(node.root_image),
        optional_blob_ref_material(node.initrd),
        ready_point_material(&node.ready_point),
        white_box_material(node.white_box)
    )
}

fn world_link_material(link: &LinkDef) -> String {
    let (left, right) = link.endpoints();
    format!(
        "link_endpoint_a_len={}\nlink_endpoint_a={}\nlink_endpoint_b_len={}\nlink_endpoint_b={}\nlink_latency_ns={}\nlink_jitter_ns={}\nlink_loss_millionths={}\nlink_bandwidth_bps={}",
        left.name.len(),
        left.name,
        right.name.len(),
        right.name,
        link.latency().nanos,
        link.jitter().nanos,
        link.loss().millionths(),
        link.bandwidth_bps()
            .map_or_else(|| String::from("none"), |bandwidth| bandwidth.to_string())
    )
}

fn plan_material(entries: &[PlanEntry]) -> String {
    let mut lines = Vec::with_capacity(entries.len().saturating_mul(12) + 1);
    lines.push(format!("entries={}", entries.len()));
    for entry in entries {
        lines.push(plan_entry_material(entry));
    }
    lines.join("\n")
}

fn plan_entry_material(entry: &PlanEntry) -> String {
    match entry {
        PlanEntry::Activate { at, tag, fault } => {
            format!(
                "plan_entry=activate\nplan_at_ticks={}\n{}\n{}",
                at.ticks,
                fault_tag_material(tag),
                membership_fault_material(fault)
            )
        }
        PlanEntry::Heal { at, tag } => {
            format!(
                "plan_entry=heal\nplan_at_ticks={}\n{}",
                at.ticks,
                fault_tag_material(tag)
            )
        }
    }
}

fn membership_fault_material(fault: &MembershipFault) -> String {
    match fault {
        MembershipFault::Crash { node, restart } => {
            format!(
                "fault=crash\n{}\nrestart={}",
                node_ref_material("node", node),
                restart_policy_label(*restart)
            )
        }
        MembershipFault::Partition {
            endpoint_a,
            endpoint_b,
            direction,
        } => {
            format!(
                "fault=partition\n{}\n{}\ndirection={}",
                node_ref_material("endpoint_a", endpoint_a),
                node_ref_material("endpoint_b", endpoint_b),
                partition_direction_label(*direction)
            )
        }
        MembershipFault::Isolate { node } => {
            format!("fault=isolate\n{}", node_ref_material("node", node))
        }
        MembershipFault::NotYetJoined { node } => {
            format!("fault=not-yet-joined\n{}", node_ref_material("node", node))
        }
    }
}

fn fault_tag_material(tag: &FaultTag) -> String {
    format!("tag_len={}\ntag={}", tag.name.len(), tag.name)
}

fn properties_material(assertions: &[AssertionDef]) -> String {
    let mut lines = Vec::with_capacity(assertions.len().saturating_mul(16) + 1);
    lines.push(format!("assertions={}", assertions.len()));
    for assertion in assertions {
        lines.push(assertion_material(assertion));
    }
    lines.join("\n")
}

fn assertion_material(assertion: &AssertionDef) -> String {
    format!(
        "{}\nmessage_len={}\nmessage={}\n{}",
        assertion_id_material(&assertion.id),
        assertion.message.len(),
        assertion.message,
        property_material(&assertion.property)
    )
}

fn property_material(property: &Property) -> String {
    match property {
        Property::Always { predicate } => {
            format!("property=always\n{}", predicate_material(predicate))
        }
        Property::Sometimes { predicate } => {
            format!("property=sometimes\n{}", predicate_material(predicate))
        }
        Property::Eventually {
            trigger,
            property,
            deadline,
        } => {
            format!(
                "property=eventually\ndeadline_ticks={}\ntrigger:\n{}\nproperty_predicate:\n{}",
                deadline.ticks,
                predicate_material(trigger),
                predicate_material(property)
            )
        }
        Property::AfterQuiescence { predicate } => {
            format!(
                "property=after-quiescence\n{}",
                predicate_material(predicate)
            )
        }
        Property::Reachable {
            predicate,
            expectation,
        } => {
            let expectation_material = match expectation {
                ReachabilityExpectation::Reachable { on_unreached } => {
                    format!(
                        "expectation=reachable\non_unreached={}",
                        reachable_disposition_label(*on_unreached)
                    )
                }
                ReachabilityExpectation::Unreachable => String::from("expectation=unreachable"),
            };
            format!(
                "property=reachable\n{}\n{}",
                expectation_material,
                predicate_material(predicate)
            )
        }
    }
}

fn predicate_material(predicate: &Predicate) -> String {
    match predicate {
        Predicate::Named { name, nodes } => {
            format!(
                "predicate=named\npredicate_name_len={}\npredicate_name={}\n{}",
                name.len(),
                name,
                predicate_nodes_material(nodes)
            )
        }
        Predicate::GuestMarker { marker } => {
            format!("predicate=guest-marker\n{}", marker_id_material(marker))
        }
        Predicate::AllOf { predicates } => {
            format!("predicate=all-of\n{}", predicate_list_material(predicates))
        }
        Predicate::AnyOf { predicates } => {
            format!("predicate=any-of\n{}", predicate_list_material(predicates))
        }
        Predicate::Once { predicate } => {
            format!("predicate=once\n{}", predicate_material(predicate))
        }
        Predicate::Not { predicate } => {
            format!("predicate=not\n{}", predicate_material(predicate))
        }
    }
}

fn predicate_nodes_material(nodes: &[NodeId]) -> String {
    let mut lines = Vec::with_capacity(nodes.len().saturating_mul(2) + 1);
    lines.push(format!("predicate_nodes={}", nodes.len()));
    for node in nodes {
        lines.push(node_ref_material("predicate_node", node));
    }
    lines.join("\n")
}

fn predicate_list_material(predicates: &[Predicate]) -> String {
    let mut lines = Vec::with_capacity(predicates.len().saturating_mul(8) + 1);
    lines.push(format!("predicates={}", predicates.len()));
    for predicate in predicates {
        lines.push(predicate_material(predicate));
    }
    lines.join("\n")
}

fn assertion_id_material(id: &AssertionId) -> String {
    format!(
        "assertion_id_len={}\nassertion_id={}",
        id.name.len(),
        id.name
    )
}

fn marker_id_material(id: &MarkerId) -> String {
    format!("marker_id_len={}\nmarker_id={}", id.name.len(), id.name)
}

fn seed_material(seed: Seed) -> String {
    format!("seed_bytes={}", seed.to_hex())
}

fn optional_blob_ref_material(reference: Option<ContentAddressedBlobRef>) -> String {
    reference.map_or_else(|| String::from("none"), ContentAddressedBlobRef::to_uri)
}

fn node_ref_material(prefix: &str, node: &NodeId) -> String {
    format!("{prefix}_len={}\n{prefix}={}", node.name.len(), node.name)
}

fn restart_policy_label(policy: RestartPolicy) -> &'static str {
    match policy {
        RestartPolicy::FromReadyPoint => "from-ready-point",
        RestartPolicy::FromLastCheckpoint => "from-last-checkpoint",
        RestartPolicy::StayDown => "stay-down",
    }
}

fn partition_direction_label(direction: PartitionDirection) -> &'static str {
    match direction {
        PartitionDirection::Bidirectional => "bidirectional",
        PartitionDirection::EndpointAToEndpointB => "endpoint-a-to-endpoint-b",
        PartitionDirection::EndpointBToEndpointA => "endpoint-b-to-endpoint-a",
    }
}

fn reachable_disposition_label(disposition: ReachableDisposition) -> &'static str {
    match disposition {
        ReachableDisposition::Warn => "warn",
        ReachableDisposition::Fail => "fail",
    }
}

fn ready_point_material(ready_point: &ReadyPoint) -> String {
    match ready_point {
        ReadyPoint::FixedIcount { icount } => {
            format!("ready_point=fixed-icount\nready_icount={}", icount.retired)
        }
        ReadyPoint::NetworkIdle { window } => {
            format!("ready_point=network-idle\nidle_window_ns={}", window.nanos)
        }
        ReadyPoint::ConsoleMarker { marker } => format!(
            "ready_point=console-marker\nmarker_len={}\nmarker={marker}",
            marker.len()
        ),
        ReadyPoint::AgentSignal => String::from("ready_point=agent-signal"),
    }
}

fn white_box_material(policy: WhiteBoxPolicy) -> &'static str {
    match policy {
        WhiteBoxPolicy::Disabled => "disabled",
        WhiteBoxPolicy::Enabled => "enabled",
    }
}

fn persist_checkpoint_cow_deltas<S>(
    store: &S,
    checkpoint: &Checkpoint,
    cow_deltas: &mut BTreeMap<CowDeltaRef, ContentHash>,
    schedule_deltas: &mut Vec<ContentHash>,
) -> Result<(), TemporalGraphStoreError>
where
    S: DagStore + ?Sized,
{
    for cow_ref in checkpoint.cow_delta_refs() {
        if cow_deltas.contains_key(&cow_ref) {
            continue;
        }
        let delta_key =
            match cow_ref.kind {
                CowDeltaKind::ScheduleDelta => {
                    let key = store
                        .put(&schedule_delta_store_bytes(&checkpoint.schedule_delta))
                        .map_err(|source| TemporalGraphStoreError::Store {
                            operation: "put-schedule-delta",
                            source,
                        })?;
                    schedule_deltas.push(key);
                    key
                }
                CowDeltaKind::VmMemory
                | CowDeltaKind::DeviceOverlay
                | CowDeltaKind::EventLogSegment => store
                    .put(&cow_delta_store_bytes(cow_ref))
                    .map_err(|source| TemporalGraphStoreError::Store {
                        operation: "put-cow-delta",
                        source,
                    })?,
            };
        cow_deltas.insert(cow_ref, delta_key);
    }
    Ok(())
}

fn insert_checkpoint_store_keys(checkpoint: &Checkpoint, keys: &mut BTreeSet<ContentHash>) {
    keys.insert(ContentHash::from_bytes(&checkpoint_store_bytes(checkpoint)));
    if !checkpoint.schedule_delta.is_empty() {
        keys.insert(ContentHash::from_bytes(&schedule_delta_store_bytes(
            &checkpoint.schedule_delta,
        )));
    }
    for cow_ref in checkpoint.cow_delta_refs() {
        if cow_ref.kind != CowDeltaKind::ScheduleDelta {
            keys.insert(ContentHash::from_bytes(&cow_delta_store_bytes(cow_ref)));
        }
    }
}

fn delete_collectible_store_keys<S>(
    store: &S,
    report: &mut TemporalGraphGcReport,
) -> Result<(), TemporalGraphStoreError>
where
    S: DagStore + ?Sized,
{
    for key in &report.collectible_store_keys {
        let deleted = store
            .delete(key)
            .map_err(|source| TemporalGraphStoreError::Store {
                operation: "delete-gc-object",
                source,
            })?;
        if deleted {
            report.deleted_store_keys.insert(*key);
        } else {
            report.missing_store_keys.insert(*key);
        }
    }
    Ok(())
}

fn scenario_def_store_bytes(def: &ScenarioDef) -> Vec<u8> {
    format!(
        "crucible.dag-store.scenario-def.v1\nscenario_ref={}\n{}\n",
        content_hash_hex(def.id),
        seed_material(def.seed)
    )
    .into_bytes()
}

fn reproduction_artifact_canonical_bytes(
    scenario: &ScenarioDefForm,
    schedule: &Schedule,
) -> Vec<u8> {
    let mut writer = ScenarioBinaryWriter::new(REPRODUCTION_ARTIFACT_BINARY_MAGIC);
    writer.write_binary_blob(&scenario.to_compact_binary());
    writer.write_binary_blob(&schedule.to_compact_binary());
    writer.finish()
}

fn checkpoint_store_bytes(checkpoint: &Checkpoint) -> Vec<u8> {
    let mut lines = vec![
        String::from("crucible.dag-store.checkpoint-node.v1"),
        format!("id={}", content_hash_hex(checkpoint.id)),
        format!(
            "configuration={}",
            content_hash_hex(checkpoint.configuration)
        ),
        format!("scenario_ref={}", content_hash_hex(checkpoint.scenario_ref)),
        format!(
            "parent={}",
            checkpoint
                .parent
                .map(content_hash_hex)
                .unwrap_or_else(|| String::from("none"))
        ),
        format!(
            "schedule_delta={}",
            content_hash_hex(checkpoint.schedule_delta.content_hash())
        ),
        format!("kind={}", checkpoint_kind_label(checkpoint.kind)),
        format!("virtual_time_ticks={}", checkpoint.virtual_time.ticks),
        format!(
            "coverage_fingerprint={}",
            content_hash_hex(checkpoint.coverage_fingerprint)
        ),
    ];

    lines.push(format!("node_icounts={}", checkpoint.node_icounts.len()));
    for (node, icount) in &checkpoint.node_icounts {
        lines.push(format!("node_icount.node={}", node.name));
        lines.push(format!("node_icount.retired={}", icount.retired));
    }

    match &checkpoint.state {
        Some(state) => {
            lines.push(format!("state={}", content_hash_hex(state.id)));
            lines.push(format!("state_cow_refs={}", state.cow_delta_refs().len()));
            for cow_ref in state.cow_delta_refs() {
                push_cow_delta_ref_lines("state_cow_ref", cow_ref, &mut lines);
            }
        }
        None => lines.push(String::from("state=none")),
    }

    lines.push(format!("node_blobs={}", checkpoint.node_blobs.len()));
    for (node, blob) in &checkpoint.node_blobs {
        lines.push(format!("node_blob.node={}", node.name));
        push_node_blob_ref_lines("node_blob", blob, &mut lines);
    }

    lines.push(format!(
        "metadata_labels={}",
        checkpoint.metadata.labels.len()
    ));
    for (key, value) in &checkpoint.metadata.labels {
        lines.push(format!("metadata.key_len={}", key.len()));
        lines.push(format!("metadata.key={key}"));
        lines.push(format!("metadata.value_len={}", value.len()));
        lines.push(format!("metadata.value={value}"));
    }

    lines.join("\n").into_bytes()
}

fn schedule_delta_store_bytes(schedule: &Schedule) -> Vec<u8> {
    let mut lines = vec![
        String::from("crucible.dag-store.schedule-delta.v1"),
        format!("id={}", content_hash_hex(schedule.content_hash())),
        format!("decisions={}", schedule.decisions().len()),
    ];
    for (index, decision) in schedule.decisions().iter().enumerate() {
        push_decision_lines(index, decision, &mut lines);
    }
    lines.join("\n").into_bytes()
}

fn cow_delta_store_bytes(cow_ref: CowDeltaRef) -> Vec<u8> {
    let mut lines = vec![String::from("crucible.dag-store.cow-delta-ref.v1")];
    push_cow_delta_ref_lines("cow_delta", cow_ref, &mut lines);
    lines.join("\n").into_bytes()
}

fn push_cow_delta_ref_lines(prefix: &str, cow_ref: CowDeltaRef, lines: &mut Vec<String>) {
    lines.push(format!(
        "{prefix}.kind={}",
        cow_delta_kind_label(cow_ref.kind)
    ));
    lines.push(format!(
        "{prefix}.content={}",
        content_hash_hex(cow_ref.content)
    ));
}

fn push_node_blob_ref_lines(prefix: &str, blob: &NodeBlobRef, lines: &mut Vec<String>) {
    match blob {
        NodeBlobRef::Baked(blob) => {
            lines.push(format!("{prefix}.kind=baked"));
            lines.push(format!("{prefix}.blob={}", content_hash_hex(*blob)));
        }
        NodeBlobRef::CowDelta {
            parent,
            delta,
            resolved,
        } => {
            lines.push(format!("{prefix}.kind=cow-delta"));
            lines.push(format!("{prefix}.parent={}", content_hash_hex(*parent)));
            lines.push(format!("{prefix}.delta={}", content_hash_hex(*delta)));
            lines.push(format!("{prefix}.resolved={}", content_hash_hex(*resolved)));
        }
    }
}

fn push_decision_lines(index: usize, decision: &Decision, lines: &mut Vec<String>) {
    let prefix = format!("decision.{index}");
    match decision {
        Decision::DeliveryOrder(order) => {
            lines.push(format!("{prefix}.kind=delivery-order"));
            lines.push(format!("{prefix}.at_ticks={}", order.at.ticks));
            lines.push(format!("{prefix}.events={}", order.order.len()));
            for event in &order.order {
                lines.push(format!("{prefix}.event.sequence={}", event.sequence));
            }
        }
        Decision::FaultFires(fault) => {
            lines.push(format!("{prefix}.kind=fault-fires"));
            lines.push(format!("{prefix}.at_ticks={}", fault.at.ticks));
            lines.push(format!("{prefix}.fault_len={}", fault.fault.name.len()));
            lines.push(format!("{prefix}.fault={}", fault.fault.name));
            lines.push(format!("{prefix}.fired={}", fault.fired));
        }
        Decision::RngDraw(draw) => {
            lines.push(format!("{prefix}.kind=rng-draw"));
            push_rng_stream_lines(&prefix, &draw.stream, lines);
            lines.push(format!("{prefix}.value={}", draw.value));
        }
        Decision::Override(override_decision) => {
            lines.push(format!("{prefix}.kind=override"));
            lines.push(format!(
                "{prefix}.point_len={}",
                override_decision.point.key.len()
            ));
            lines.push(format!("{prefix}.point={}", override_decision.point.key));
            lines.push(format!(
                "{prefix}.choice_len={}",
                override_decision.choice.name.len()
            ));
            lines.push(format!("{prefix}.choice={}", override_decision.choice.name));
        }
        Decision::Preemption(preemption) => {
            lines.push(format!("{prefix}.kind=preemption"));
            lines.push(format!("{prefix}.node_len={}", preemption.node.name.len()));
            lines.push(format!("{prefix}.node={}", preemption.node.name));
            lines.push(format!("{prefix}.at_retired={}", preemption.at.retired));
            match &preemption.kind {
                PreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => {
                    lines.push(format!("{prefix}.preemption_kind=vcpu-switch"));
                    lines.push(format!("{prefix}.from_vcpu={}", from_vcpu.index));
                    lines.push(format!("{prefix}.to_vcpu={}", to_vcpu.index));
                }
                PreemptionKind::InterruptAt { target_vcpu, irq } => {
                    lines.push(format!("{prefix}.preemption_kind=interrupt-at"));
                    lines.push(format!("{prefix}.target_vcpu={}", target_vcpu.index));
                    lines.push(format!("{prefix}.irq={}", irq.vector));
                }
            }
        }
        Decision::AppRandom(random) => {
            lines.push(format!("{prefix}.kind=app-random"));
            lines.push(format!("{prefix}.node_len={}", random.node.name.len()));
            lines.push(format!("{prefix}.node={}", random.node.name));
            push_rng_stream_lines(&prefix, &random.stream, lines);
            lines.push(format!("{prefix}.request_id={}", random.request_id));
            lines.push(format!("{prefix}.width={}", random.width));
            lines.push(format!("{prefix}.value={}", random.value));
        }
    }
}

fn cow_delta_kind_label(kind: CowDeltaKind) -> &'static str {
    match kind {
        CowDeltaKind::VmMemory => "vm-memory",
        CowDeltaKind::DeviceOverlay => "device-overlay",
        CowDeltaKind::ScheduleDelta => "schedule-delta",
        CowDeltaKind::EventLogSegment => "event-log-segment",
    }
}

fn local_store_temp_path(path: &Path, key: &ContentHash) -> PathBuf {
    let index = LOCAL_DAG_STORE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let file_name = format!("{}.tmp.{}.{}", key.to_hex(), std::process::id(), index);
    path.with_file_name(file_name)
}

fn search_replay_oracle_sampling_score(
    seed_tag: &str,
    sequence: u64,
    checkpoint: ContentHash,
) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    hash = fold_fnv_bytes(hash, REPLAY_ORACLE_SEARCH_SAMPLING_DOMAIN);
    hash = fold_fnv_bytes(hash, seed_tag.as_bytes());
    hash = fold_fnv_bytes(hash, &sequence.to_le_bytes());
    fold_fnv_bytes(hash, checkpoint.to_hex().as_bytes())
}

fn fold_fnv_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn content_hash_hex(hash: ContentHash) -> String {
    bytes_hex(&hash.bytes)
}

fn bytes_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(HEX[usize::from(*byte >> 4)] as char);
        encoded.push(HEX[usize::from(*byte & 0x0f)] as char);
    }
    encoded
}
