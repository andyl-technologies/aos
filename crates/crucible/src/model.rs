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
use std::num::NonZeroUsize;
use std::ops;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crucible_sim::{
    DECISION_RNG_LINK_STREAM_DOMAIN, DECISION_RNG_NAME_HASH_DOMAIN,
    DECISION_RNG_NODE_STREAM_DOMAIN, DecisionRng, DecisionStream,
};
use serde::de;
use serde::{Deserialize, Serialize};

use crate::backend::ExecutionFingerprint;
use crate::scheduler::{
    ControlOperation, ControlOperationKind, EventAttributeValue, EventDiagnosticPayload,
    EventLevel, EventLogCausalDivergencePoint, EventLogCausalProjection, EventLogCoverageFeedback,
    EventLogCoverageFeedbackConsumer, EventLogIcountStamp, EventSource, ScheduledEventPayload,
    SchedulerEventLogClass, SchedulerEventLogEntry, SchedulerEventLogPayload, SchedulerQuiescence,
    coverage_fingerprint_from_event_log, event_log_causal_projection,
    recorded_assertion_log_from_schedule_for_search,
};
use crate::trigger::{
    Action, AssertionQuantifierKind, BlackBoxHostOracle, Condition, ConditionEvaluationPass,
    ConditionLeaf, ConditionLeafOracle, Event, EventGraph, EventGraphError, FirePolicy,
    HostAssertionOracle, HostAssertionOutcome, HostAssertionOutcomeKind, HostAssertionViolation,
    LogLevel, ObservableEventPayload, OfflineAssertionChecker, RecordedAssertionLog,
    ResolvedCodePoint, ResolvedMemPlace, SearchScheduleNamedPredicateHostOracle,
    SearchScheduleNamedPredicateTruths,
};

mod canonical;
mod guest_assertion;

static LOCAL_DAG_STORE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The stable domain used for device-scoped decision streams ([IO-21]).
///
/// A device (block / 9p / network sub-node) draws its probabilistic faults from a
/// stream forked by name-hash in this fixed domain, so a device named `"disk"` and
/// a node named `"disk"` never collide and adding or renaming an unrelated device
/// never perturbs another device's draws ([DET-25]).
pub const DECISION_RNG_DEVICE_STREAM_DOMAIN: &str = "crucible.decision-rng.device-stream.v1";

/// Minimum one-way logical link latency in virtual nanoseconds.
pub const MIN_LINK_LATENCY: SimDuration = SimDuration { nanos: 1 };
const MAX_WORLD_ICOUNT_SHIFT: u8 = 62;
const MIN_WORLD_MEMORY_MIB: u32 = 1;
const MAX_LINK_LOSS_MILLIONTHS: u32 = 1_000_000;
const MAX_FAMILY_FAULT_DENSITY_MILLIONTHS: u32 = 1_000_000;
const MAX_FAULT_RATE_BASIS_POINTS: u32 = 10_000;
const MIN_FAULT_SLOWDOWN_FACTOR_BASIS_POINTS: u32 = 10_000;
const MAX_SCENARIO_FAMILY_SEEDS: u32 = 1_000_000;
const MAX_SCENARIO_FAMILY_TOPOLOGY_SIZE: u32 = 256;
const FAMILY_FAULT_STEP_TICKS: u64 = 20;
const FAMILY_FAULT_HEAL_DELAY_TICKS: u64 = 5;
const RANDOM_FAULT_CONFIG_RNG_DOMAIN: &str = "crucible.model.random-fault-config.v1";
const REPLAY_ORACLE_SEARCH_SAMPLING_DOMAIN: &[u8] = b"crucible.replay-oracle.search-sampling.v1";
const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x00000100000001b3;
const EVENT_GRAPH_PLAN_BINARY_SENTINEL: u64 = u64::MAX;
const FAULT_PLAN_BINARY_SENTINEL: u64 = u64::MAX - 1;
const SEARCH_PRIORITY_SCORE_DOMAIN: &[u8] = b"crucible.search.strategy.priority.v1";
const COVERAGE_GUIDED_FUZZ_SAMPLE_DOMAIN: &str = "crucible.coverage-guided-fuzz.sample.v1";
const COVERAGE_GUIDED_FUZZ_OVERRIDE_DOMAIN: &str = "crucible.coverage-guided-fuzz.override.v1";
const FAILURE_SIGNATURE_DOMAIN: &str = "crucible.failure-signature.v1";
const FAILURE_SIGNATURE_KEY_DOMAIN: &str = "crucible.failure-signature.key.v1";
const FAILURE_CAUSAL_SLICE_DOMAIN: &str = "crucible.failure-signature.causal-slice.v1";
const FAILURE_FINDINGS_LEDGER_DOMAIN: &str = "crucible.failure-triage.findings-ledger.v1";
const FAILURE_TRIAGE_RESULT_IDENTITY_DOMAIN: &str = "crucible.failure-triage.result-identity.v1";
const FAILURE_TRIAGE_SIGNATURE_SELF_CHECK_DOMAIN: &str =
    "crucible.failure-triage.signature-self-check.v1";
const FAILURE_CLUSTERING_RESULT_DOMAIN: &str = "crucible.failure-triage.clustering-result.v1";
const FAILURE_SIGNATURE_MINIMIZATION_RESULT_DOMAIN: &str =
    "crucible.failure-triage.signature-preserving-minimization.v1";
const FAILURE_CLUSTER_REPORT_DOMAIN: &str = "crucible.failure-triage.cluster-report.v1";
const FAILURE_CLUSTER_REPORT_SET_DOMAIN: &str = "crucible.failure-triage.cluster-report-set.v1";
const FAILURE_TRIAGE_RESULT_DOMAIN: &str = "crucible.failure-triage.result.v1";
const FAILURE_TRIAGE_RESULT_DIFF_DOMAIN: &str = "crucible.failure-triage.result-diff.v1";
const FAILURE_COVERAGE_CLASS_ALGORITHM: &str = "crucible.failure-signature.coverage-class.top16.v1";
const SIGNATURE_POLICY_SCHEMA_VERSION: u16 = 1;
const GUIDANCE_SCORE_ONE_MICRO: u64 = 1_000_000;
const ADAPTIVE_CONFIRMED_FAILURE_REWARD: u64 = 1_000_000_000_000;

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

/// Filesystem-backed [`DagStore`] using the RFC-0010 two-level layout.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LocalDagStore {
    root: PathBuf,
}

/// Local lookup record from a checkpoint id to its persisted closure artifact.
///
/// The record itself is stored as normal content-addressed bytes. The local
/// store keeps only a sidecar pointer from checkpoint id to this record so CLI
/// commands can resolve `blake3:<checkpoint>` without scanning the whole store.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LocalCheckpointClosureIndex {
    /// Checkpoint/configuration id accepted by resume and fork commands.
    pub checkpoint: ContentHash,
    /// Store key for the self-contained `(seed, scenario, schedule)` artifact.
    pub reproduction_artifact: ContentHash,
    /// Shared virtual-time frontier of the saved configuration.
    pub frontier: VirtualTime,
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

    /// Writes a checkpoint lookup record and returns its content-addressed key.
    ///
    /// # Errors
    ///
    /// Returns [`DagStoreError`] when the record cannot be stored or when the
    /// local sidecar pointer cannot be written.
    pub fn write_checkpoint_closure_index(
        &self,
        checkpoint: ContentHash,
        reproduction_artifact: ContentHash,
        frontier: VirtualTime,
    ) -> Result<ContentHash, DagStoreError> {
        let bytes = checkpoint_closure_index_bytes(checkpoint, reproduction_artifact, frontier);
        let index_key = self.put(&bytes)?;
        let path = self.checkpoint_closure_index_path(&checkpoint);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| DagStoreError::Io {
                operation: "create-dir",
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let temp_path = local_store_temp_path(&path, &index_key);
        fs::write(
            &temp_path,
            format!(
                "{}\n",
                ContentAddressedBlobRef::from_hash(index_key).to_uri()
            ),
        )
        .map_err(|source| DagStoreError::Io {
            operation: "write",
            path: temp_path.clone(),
            source,
        })?;
        if let Err(source) = fs::rename(&temp_path, &path) {
            let _ = fs::remove_file(&temp_path);
            return Err(DagStoreError::Io {
                operation: "rename",
                path,
                source,
            });
        }
        Ok(index_key)
    }

    /// Reads a checkpoint lookup record previously written by this store.
    ///
    /// # Errors
    ///
    /// Returns [`DagStoreError::NotFound`] when no lookup exists for
    /// `checkpoint`. Returns [`DagStoreError::CorruptIndex`] when the sidecar or
    /// content-addressed record is malformed or names a different checkpoint.
    pub fn read_checkpoint_closure_index(
        &self,
        checkpoint: ContentHash,
    ) -> Result<LocalCheckpointClosureIndex, DagStoreError> {
        let path = self.checkpoint_closure_index_path(&checkpoint);
        let sidecar = fs::read_to_string(&path).map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                DagStoreError::NotFound { key: checkpoint }
            } else {
                DagStoreError::Io {
                    operation: "read",
                    path: path.clone(),
                    source,
                }
            }
        })?;
        let index_key = parse_checkpoint_closure_index_sidecar(checkpoint, &sidecar)?;
        let bytes = self.get(&index_key)?;
        parse_checkpoint_closure_index_bytes(checkpoint, &bytes)
    }

    fn checkpoint_closure_index_path(&self, checkpoint: &ContentHash) -> PathBuf {
        let hex = checkpoint.to_hex();
        self.root
            .join("_indexes")
            .join("checkpoint-closures")
            .join(&hex[0..2])
            .join(hex)
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
            if let Ok(existing) = fs::read(&path)
                && ContentHash::from_bytes(&existing) == key
                && existing == bytes
            {
                let _ = fs::remove_file(&temp_path);
                return Ok(key);
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

mod binary_plan;
mod binary_state;
mod configuration;
mod debug;
mod engine;
mod exploration;
mod failure;
mod family;
mod fault_signal;
mod material;
mod materialized;
mod plan_properties;
mod reproduction;
mod runtime;
mod scenario;
mod store_artifacts;
mod temporal_graph;
mod time;
#[path = "model/toml.rs"]
mod toml_codec;
mod topology_faults;
mod validation;
mod workload;

use binary_plan::*;
use binary_state::*;
pub use configuration::*;
pub use debug::*;
pub use engine::*;
pub use exploration::*;
use failure::failure_assertion_quantifier_label;
pub use failure::*;
pub use family::*;
pub use fault_signal::*;
use material::*;
pub use materialized::*;
pub use plan_properties::*;
pub use reproduction::*;
pub use runtime::*;
pub use scenario::*;
use store_artifacts::*;
pub use temporal_graph::*;
use temporal_graph::{debug_configuration_prefix, maps_equal_except_key};
pub use time::*;
use toml_codec::*;
pub use topology_faults::*;
use validation::*;
pub use workload::*;

mod store_error;
#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
#[path = "model/tests.rs"]
mod tests;
