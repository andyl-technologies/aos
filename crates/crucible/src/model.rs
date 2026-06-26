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

mod canonical;

static LOCAL_DAG_STORE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    pub id: ContentHash,
}

impl ScenarioDef {
    /// Builds a scenario definition from canonical material.
    ///
    /// This helper is the engine-side content-addressing entry point for
    /// backend-produced canonical material.
    #[must_use]
    pub fn from_canonical_material(domain: &str, material: &str) -> Self {
        Self {
            id: ContentHash::from_canonical_material(domain, material),
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
        }
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
        let nodes = canonical_world_nodes(&nodes);
        validate_world_nodes(&nodes)?;
        Ok(Self {
            id: ContentHash::from_canonical_material(
                "crucible.model.world.v1",
                &world_nodes_material(&nodes),
            ),
            nodes,
        })
    }

    /// Validates the world's ready-point policy configuration.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DuplicateWorldNodeId`] when a node id appears
    /// more than once, or [`EngineError::WhiteBoxReadyPointWithoutOptIn`] when
    /// a node selects [`ReadyPoint::AgentSignal`] without enabling
    /// [`WhiteBoxPolicy::Enabled`].
    pub fn validate_ready_point_policies(&self) -> Result<(), EngineError> {
        validate_world_nodes(&self.nodes)
    }

    /// Builds the canonical genesis scenario definition for this world.
    ///
    /// The full `ScenarioDef` schema will carry `World`, plan, properties, and
    /// seed components. Until that schema lands, this helper makes the model's
    /// world-to-genesis relationship explicit without weakening checkpoint
    /// validation.
    #[must_use]
    pub fn scenario_def(&self) -> ScenarioDef {
        ScenarioDef::from_canonical_material(
            "crucible.model.world-scenario.v1",
            &world_hash_material(self),
        )
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

/// A deterministic decision-stream identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RngStreamId {
    /// The canonical stream name.
    pub name: String,
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
    /// Canonicalized node ready-point configuration for this world.
    pub nodes: Vec<WorldNode>,
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
    /// An agent-signal ready point was configured without white-box opt-in.
    WhiteBoxReadyPointWithoutOptIn {
        /// The node whose ready-point configuration is invalid.
        node: NodeId,
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
            Self::WhiteBoxReadyPointWithoutOptIn { .. } => {
                f.write_str("agent-signal ready point requires white-box opt-in")
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

fn canonical_world_nodes(nodes: &[WorldNode]) -> Vec<WorldNode> {
    let mut nodes = nodes.to_vec();
    nodes.sort_by(|left, right| left.id.cmp(&right.id));
    nodes
}

fn baked_node_blobs(world: &World) -> BTreeMap<NodeId, NodeBlobRef> {
    canonical_world_nodes(&world.nodes)
        .into_iter()
        .map(|node| {
            let blob = ContentHash::from_canonical_material(
                "crucible.model.node-baked-blob.v1",
                &format!(
                    "world_id={}\n{}",
                    content_hash_hex(world.id),
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

fn world_hash_material(world: &World) -> String {
    let nodes = canonical_world_nodes(&world.nodes);
    format!(
        "world_id={}\n{}",
        content_hash_hex(world.id),
        world_nodes_material(&nodes)
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

fn world_node_material(node: &WorldNode) -> String {
    format!(
        "node_id_len={}\nnode_id={}\n{}\nwhite_box={}",
        node.id.name.len(),
        node.id.name,
        ready_point_material(&node.ready_point),
        white_box_material(node.white_box)
    )
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

fn scenario_def_store_bytes(def: &ScenarioDef) -> Vec<u8> {
    format!(
        "crucible.dag-store.scenario-def.v1\nscenario_ref={}\n",
        content_hash_hex(def.id)
    )
    .into_bytes()
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
            lines.push(format!("{prefix}.stream_len={}", draw.stream.name.len()));
            lines.push(format!("{prefix}.stream={}", draw.stream.name));
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
            lines.push(format!("{prefix}.stream_len={}", random.stream.name.len()));
            lines.push(format!("{prefix}.stream={}", random.stream.name));
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

fn content_hash_hex(hash: ContentHash) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(64);
    for byte in hash.bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}
