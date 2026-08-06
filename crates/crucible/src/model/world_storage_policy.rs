//! Closed, scenario-owned policy data consumed by storage and 9p effects.
//!
//! Storage effects use [`FaultObjectId`] values as stable references. This
//! module gives every such reference a typed, immutable meaning included in
//! the [`World`](super::World) identity. Production adapters therefore never
//! infer behavior from a string or consult host-local configuration.

use std::collections::BTreeSet;

use super::world_faults::{invalid, require};
use super::*;

/// Maximum storage-policy declarations in one World.
pub const HARD_STORAGE_POLICY_ARTIFACTS: usize = 65_536;
/// Maximum entries in one storage-policy declaration.
pub const HARD_STORAGE_POLICY_ENTRIES: usize = 65_536;
/// Maximum bytes carried by one inline storage artifact.
pub const HARD_STORAGE_POLICY_BYTES: usize = 16 * 1024 * 1024;

/// A protocol-neutral terminal storage result.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum StoragePolicyResult {
    /// The operation completed successfully.
    Success,
    /// The device is unavailable.
    Offline,
    /// A write targeted read-only storage.
    ReadOnly,
    /// The addressed range is invalid or beyond capacity.
    InvalidRange,
    /// The controller or queue is temporarily busy.
    Busy,
    /// The operation exceeded its modeled deadline.
    Timeout,
    /// The medium reported an uncorrectable error.
    MediumError,
    /// Data-integrity verification failed.
    IntegrityError,
    /// Device or controller I/O failed without a narrower class.
    IoError,
    /// Capacity or allocation was exhausted.
    NoSpace,
    /// A requested object or namespace entry does not exist.
    NotFound,
    /// A retained handle or object version is stale.
    Stale,
}

/// Guest protocol encoding for one terminal result.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub enum StoragePolicyTypedResult {
    /// A block-device completion status.
    Block {
        /// Protocol-neutral semantic result.
        result: StoragePolicyResult,
    },
    /// A Linux 9P2000.L `Rlerror` result.
    NineP {
        /// Positive Linux errno encoded in the reply.
        errno: i32,
    },
}

/// Queue discipline for integrated storage service.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePolicyQueueDiscipline {
    /// Oldest admitted request runs first; identity breaks equal-time ties.
    Fifo,
    /// Lowest configured class priority runs first.
    StrictPriority,
    /// Classes receive deterministic weighted round-robin service.
    WeightedRoundRobin,
}

/// One operation class used by a storage service queue.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePolicyServiceClass {
    /// Stable class identity.
    pub class: FaultObjectId,
    /// Operations assigned to the class.
    pub operations: OperationSet,
    /// Lower values run first under strict priority.
    pub priority: u16,
    /// Positive weighted-round-robin share.
    pub weight: PositiveU64,
}

/// Complete deterministic storage service policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePolicyService {
    /// Queue selection discipline.
    pub discipline: StoragePolicyQueueDiscipline,
    /// Canonically class-ID-ordered operation classes.
    pub classes: Vec<StoragePolicyServiceClass>,
    /// Whether rebuild work shares the foreground byte and IOPS budgets.
    pub rebuild_shares_service: bool,
}

/// Volatile-cache eviction order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePolicyCacheEviction {
    /// Evicts the lowest cache sequence first.
    Fifo,
    /// Evicts the least recently accessed entry in modeled access order.
    Lru,
    /// Evicts the lowest writeback sequence first.
    WritebackSequence,
}

/// Treatment of a dirty cache entry selected for eviction.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "kind",
    content = "parameters",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum StoragePolicyDirtyEviction {
    /// Schedules normal persistence before reclaiming the entry.
    Persist,
    /// Rejects the admitting operation with a typed result.
    Fail {
        /// Typed result artifact returned to the guest.
        result: FaultObjectId,
    },
}

/// Guest-transport treatment of a protocol-valid duplicate completion.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "kind",
    content = "parameters",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum StoragePolicyDuplicateCompletion {
    /// The guest transport ignores every completion after the first.
    Ignore,
    /// The guest transport reports a typed protocol error.
    ProtocolError {
        /// Typed result artifact describing the protocol error.
        result: FaultObjectId,
    },
    /// The guest transport resets the device after observing the duplicate.
    Reset {
        /// Complete controller reset transition policy.
        transition_policy: FaultObjectId,
    },
}

/// Treatment of a request that arrives while a controller transition is active.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePolicyTransitionUnadmitted {
    /// Rejects the request with the transition policy's typed failure result.
    Reject,
    /// Holds admission until the exact recovery boundary.
    WaitForRecovery,
}

/// Treatment of an admitted queued or executing operation during a transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePolicyTransitionPendingOperation {
    /// Completes the operation with the transition policy's typed failure result.
    Fail,
    /// Reissues the operation with its existing request identity.
    RetryPreserveId,
    /// Reissues the operation with a newly allocated post-transition identity.
    RetryNewId,
}

/// Treatment of a resolved operation during a controller transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePolicyTransitionResolvedOperation {
    /// Keeps the already-resolved result.
    Complete,
    /// Replaces the result with the transition policy's typed failure result.
    Fail,
    /// Reissues the operation with its existing request identity.
    RetryPreserveId,
    /// Reissues the operation with a newly allocated post-transition identity.
    RetryNewId,
}

/// Treatment of a completed but guest-undelivered operation during a transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePolicyTransitionUndeliveredOperation {
    /// Keeps and later delivers the already-computed result.
    Complete,
    /// Replaces the result with the transition policy's typed failure result.
    Fail,
    /// Reissues the operation with its existing request identity.
    RetryPreserveId,
    /// Reissues the operation with a newly allocated post-transition identity.
    RetryNewId,
    /// Discards the completion without exposing it to the guest.
    DropCompletion,
}

/// Treatment of volatile device state during a controller transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePolicyTransitionState {
    /// Retains the state byte-for-byte across the transition.
    Preserve,
    /// Loses the complete state at the transition boundary.
    Lose,
}

/// Post-transition allocation of guest transport request identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePolicyTransitionRequestIds {
    /// Continues the checked monotonic request-ID sequence.
    PreserveMonotonic,
    /// Increments the transport epoch and restarts its request-ID counter at zero.
    NewEpochFromZero,
}

/// Namespace and path discovery treatment during transition recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePolicyTransitionTopology {
    /// Retains the current namespace and path generation.
    Preserve,
    /// Re-enumerates the exact declared namespace and path sets at recovery.
    ReenumerateDeclared,
}

/// Complete live controller lifecycle transition.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePolicyControllerTransition {
    /// Lifecycle transition this policy resolves.
    pub transition: StorageControllerTransition,
    /// Typed non-success result used by every stage configured as `fail`.
    pub failure_result: FaultObjectId,
    /// Treatment of new requests arriving during the transition interval.
    pub unadmitted: StoragePolicyTransitionUnadmitted,
    /// Treatment of requests admitted but not executing.
    pub queued: StoragePolicyTransitionPendingOperation,
    /// Treatment of requests whose device mutation is in progress.
    pub executing: StoragePolicyTransitionPendingOperation,
    /// Treatment of requests whose result is resolved but not yet scheduled.
    pub resolved: StoragePolicyTransitionResolvedOperation,
    /// Treatment of scheduled completions not yet delivered to the guest.
    pub completed_undelivered: StoragePolicyTransitionUndeliveredOperation,
    /// Treatment of controller-accepted write-buffer entries.
    pub controller_buffer: StoragePolicyTransitionState,
    /// Treatment of volatile write-cache entries.
    pub volatile_cache: StoragePolicyTransitionState,
    /// Post-transition request-ID allocation and epoch behavior.
    pub request_ids: StoragePolicyTransitionRequestIds,
    /// Treatment of duplicate-suppression identities from the prior epoch.
    pub duplicate_history: StoragePolicyTransitionState,
    /// Namespace and path discovery treatment at recovery.
    pub topology: StoragePolicyTransitionTopology,
    /// Exact transition recovery duration in virtual nanoseconds.
    pub recovery_nanos: PositiveU64,
}

/// Complete volatile write-cache policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePolicyCache {
    /// Entry eviction order.
    pub eviction: StoragePolicyCacheEviction,
    /// Dirty-entry eviction behavior.
    pub dirty_eviction: StoragePolicyDirtyEviction,
    /// Whether entries are protected from ordinary power-loss selection.
    pub power_loss_protected: bool,
}

/// Closed transformation of the persistence dependency DAG.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePolicyPersistenceOrdering {
    /// Keeps all normal dependency edges.
    Preserve,
    /// Reverses only mutually-ready fragments within the named group.
    ReverseReady,
    /// Selects mutually-ready fragments by descending addressed range.
    DescendingRange,
    /// Selects mutually-ready fragments by a keyed permutation.
    KeyedPermutation,
}

/// Complete persistence-order transformation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePolicyPersistence {
    /// Transformation applied to mutually-ready fragments.
    pub ordering: StoragePolicyPersistenceOrdering,
    /// Additional persistence delay for every selected fragment.
    pub delay_nanos: u64,
    /// Whether flush/FUA dependency edges remain immutable.
    pub preserve_barriers: bool,
}

/// Flash-retention lookup behavior.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePolicyRetention {
    /// Minimum virtual age before decay is eligible.
    pub minimum_age_nanos: PositiveU64,
    /// Additional age per erase cycle before one keyed trial.
    pub wear_age_nanos: u64,
    /// Probability of changing an eligible bit per trial.
    pub bit_probability: ProbabilityMillionths,
    /// Maximum bits changed in one page per opportunity.
    pub maximum_changed_bits: BoundedCount,
}

/// Flash read-disturb behavior.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePolicyReadDisturb {
    /// Reads of an aggressor page required before disturbance.
    pub read_threshold: PositiveU64,
    /// Symmetric neighboring-page distance affected by the threshold.
    pub neighbor_pages: BoundedCount,
    /// Probability of changing an eligible neighbor bit.
    pub bit_probability: ProbabilityMillionths,
    /// Maximum bits changed per affected page.
    pub maximum_changed_bits: BoundedCount,
}

/// Flash program/erase failure behavior.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePolicyProgramErase {
    /// Program failure probability before rated endurance.
    pub program_probability: ProbabilityMillionths,
    /// Erase failure probability before rated endurance.
    pub erase_probability: ProbabilityMillionths,
    /// Failure probability at or beyond rated endurance.
    pub worn_probability: ProbabilityMillionths,
    /// Whether a failed program applies a canonical prefix.
    pub partial_program: bool,
    /// Whether a failed erase applies to a canonical sector subset.
    pub partial_erase: bool,
}

/// Deterministic array member-selection order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePolicyArraySelection {
    /// Uses the lowest healthy member ordinal.
    LowestHealthy,
    /// Uses a stable operation-key hash over healthy members.
    StableHash,
    /// Reads the least-loaded healthy member and writes every quorum member.
    LeastLoaded,
}

/// Array consistency behavior after a partial member update.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePolicyArrayConsistency {
    /// Rejects any update that cannot reach the declared write quorum.
    RequireQuorum,
    /// Commits a degraded update and records members requiring repair.
    DegradedCommit,
    /// Preserves old stripe versions until every selected member commits.
    AtomicStripe,
}

/// Complete bounded array rebuild policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePolicyRebuild {
    /// Positive rebuild chunk size.
    pub chunk_bytes: PositiveU64,
    /// Maximum concurrent rebuild chunks.
    pub queue_depth: BoundedCount,
    /// Positive rebuild byte rate before shared-service constraints.
    pub bytes_per_second: PositiveU64,
}

/// Deterministic path-selection rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePolicyPathSelection {
    /// Uses the first online path in canonical path-ID order.
    ActivePassive,
    /// Rotates requests over online paths in operation-sequence order.
    RoundRobin,
    /// Uses the online path with the fewest modeled outstanding requests.
    LeastOutstanding,
    /// Uses a stable operation-key hash over online paths.
    StableHash,
}

/// Complete bounded path failover and retry policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePolicyPath {
    /// Path selection rule.
    pub selection: StoragePolicyPathSelection,
    /// Maximum attempts including the initial attempt.
    pub maximum_attempts: BoundedCount,
    /// Positive modeled delay between attempts.
    pub retry_delay_nanos: PositiveU64,
    /// Positive modeled delay before an offline path is probed again.
    pub recovery_probe_interval_nanos: PositiveU64,
    /// Canonically ordered terminal results that trigger another attempt.
    pub retry_results: Vec<StoragePolicyResult>,
}

/// Closed remote-media wire protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePolicyRemoteTransport {
    /// NVMe over TCP.
    NvmeTcp,
    /// iSCSI over TCP.
    Iscsi,
    /// Network Block Device.
    Nbd,
}

/// Complete deterministic remote-media transport contract.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePolicyRemoteProtocol {
    /// Wire protocol family.
    pub transport: StoragePolicyRemoteTransport,
    /// Maximum modeled commands outstanding on one connection.
    pub maximum_outstanding: BoundedCount,
    /// Positive modeled command timeout.
    pub command_timeout_nanos: PositiveU64,
    /// Positive modeled reconnect delay.
    pub reconnect_delay_nanos: PositiveU64,
    /// Whether reconnect preserves completion ordering across connections.
    pub preserve_order_across_reconnect: bool,
}

/// One array member state record.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePolicyArrayMemberState {
    /// Member identity declared by the referenced World array.
    pub member: FaultObjectId,
    /// Whether the member accepts operations.
    pub online: bool,
}

/// One array access-path state record.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePolicyArrayPathState {
    /// Path identity declared by the referenced World array.
    pub path: FaultObjectId,
    /// Whether the path accepts operations.
    pub online: bool,
}

/// Immutable 9p object version used for stale or misdirected results.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePolicyNinePObject {
    /// Absolute canonical slash-separated path.
    pub path: String,
    /// Stable object version sequence.
    pub version: u64,
    /// Exact Linux mode bits returned with the object.
    pub mode: u32,
    /// Exact regular-file/symlink data, or empty bytes for a directory.
    pub data: Vec<u8>,
}

/// Visibility scope for committed 9p updates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePolicyNinePVisibilityScope {
    /// All sessions advance together.
    Global,
    /// Each session advances independently in request order.
    PerSession,
    /// The writing session advances immediately; others follow the delay/event.
    WriterImmediate,
}

/// Complete 9p committed-versus-visible policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePolicyNinePVisibility {
    /// Visibility scope.
    pub scope: StoragePolicyNinePVisibilityScope,
    /// Whether metadata and data share one frontier.
    pub atomic_metadata_and_data: bool,
    /// Whether lookup may retain a deleted object until visibility advances.
    pub retain_deleted_objects: bool,
}

/// Closed class of storage policy artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StoragePolicyArtifactClass {
    /// Guest protocol status or errno.
    TypedResult,
    /// Queue and integrated-service policy.
    Service,
    /// Multipath selection, retry, and recovery policy.
    Path,
    /// Remote-media wire and reconnect protocol.
    RemoteProtocol,
    /// Volatile-cache policy.
    Cache,
    /// Duplicate-completion guest protocol policy.
    DuplicateCompletion,
    /// Controller reset and request-epoch policy.
    ControllerTransition,
    /// Persistence dependency/order policy.
    Persistence,
    /// Flash-retention policy.
    Retention,
    /// Flash read-disturb policy.
    ReadDisturb,
    /// Flash program/erase policy.
    ProgramErase,
    /// Array member-selection policy.
    ArraySelection,
    /// Array member and path state.
    ArrayState,
    /// Array rebuild policy.
    Rebuild,
    /// Array consistency policy.
    ArrayConsistency,
    /// 9p visibility policy.
    NinePVisibility,
    /// Immutable 9p object version.
    NinePObject,
    /// Immutable byte content used by stale/versioned results.
    Bytes,
}

impl StoragePolicyArtifactClass {
    /// Returns the canonical schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TypedResult => "typed_result",
            Self::Service => "service",
            Self::Path => "path",
            Self::RemoteProtocol => "remote_protocol",
            Self::Cache => "cache",
            Self::DuplicateCompletion => "duplicate_completion",
            Self::ControllerTransition => "controller_transition",
            Self::Persistence => "persistence",
            Self::Retention => "retention",
            Self::ReadDisturb => "read_disturb",
            Self::ProgramErase => "program_erase",
            Self::ArraySelection => "array_selection",
            Self::ArrayState => "array_state",
            Self::Rebuild => "rebuild",
            Self::ArrayConsistency => "array_consistency",
            Self::NinePVisibility => "ninep_visibility",
            Self::NinePObject => "ninep_object",
            Self::Bytes => "bytes",
        }
    }
}

/// Typed storage policy data referenced by effects and World declarations.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "kind",
    content = "parameters",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum StoragePolicyArtifactKind {
    /// Guest-visible terminal result.
    TypedResult(StoragePolicyTypedResult),
    /// Queue and service behavior.
    Service(StoragePolicyService),
    /// Multipath selection, retry, and recovery behavior.
    Path(StoragePolicyPath),
    /// Remote-media wire and reconnect behavior.
    RemoteProtocol(StoragePolicyRemoteProtocol),
    /// Volatile write-cache behavior.
    Cache(StoragePolicyCache),
    /// Guest treatment of duplicate completions.
    DuplicateCompletion(StoragePolicyDuplicateCompletion),
    /// Complete controller reset transition.
    ControllerTransition(StoragePolicyControllerTransition),
    /// Persistence DAG behavior.
    Persistence(StoragePolicyPersistence),
    /// Flash retention behavior.
    Retention(StoragePolicyRetention),
    /// Flash read-disturb behavior.
    ReadDisturb(StoragePolicyReadDisturb),
    /// Flash program/erase behavior.
    ProgramErase(StoragePolicyProgramErase),
    /// Array read/write member selection.
    ArraySelection(StoragePolicyArraySelection),
    /// Array member and access-path states.
    ArrayState {
        /// Canonically member-ID-ordered state records.
        members: Vec<StoragePolicyArrayMemberState>,
        /// Canonically path-ID-ordered state records.
        paths: Vec<StoragePolicyArrayPathState>,
    },
    /// Array rebuild service.
    Rebuild(StoragePolicyRebuild),
    /// Array consistency behavior.
    ArrayConsistency(StoragePolicyArrayConsistency),
    /// 9p committed-versus-visible behavior.
    NinePVisibility(StoragePolicyNinePVisibility),
    /// Immutable 9p object version.
    NinePObject(StoragePolicyNinePObject),
    /// Immutable content-addressed bytes for retained values.
    Bytes {
        /// Exact bytes.
        bytes: Vec<u8>,
    },
}

impl StoragePolicyArtifactKind {
    /// Returns the closed class used for reference validation.
    #[must_use]
    pub const fn class(&self) -> StoragePolicyArtifactClass {
        match self {
            Self::TypedResult(_) => StoragePolicyArtifactClass::TypedResult,
            Self::Service(_) => StoragePolicyArtifactClass::Service,
            Self::Path(_) => StoragePolicyArtifactClass::Path,
            Self::RemoteProtocol(_) => StoragePolicyArtifactClass::RemoteProtocol,
            Self::Cache(_) => StoragePolicyArtifactClass::Cache,
            Self::DuplicateCompletion(_) => StoragePolicyArtifactClass::DuplicateCompletion,
            Self::ControllerTransition(_) => StoragePolicyArtifactClass::ControllerTransition,
            Self::Persistence(_) => StoragePolicyArtifactClass::Persistence,
            Self::Retention(_) => StoragePolicyArtifactClass::Retention,
            Self::ReadDisturb(_) => StoragePolicyArtifactClass::ReadDisturb,
            Self::ProgramErase(_) => StoragePolicyArtifactClass::ProgramErase,
            Self::ArraySelection(_) => StoragePolicyArtifactClass::ArraySelection,
            Self::ArrayState { .. } => StoragePolicyArtifactClass::ArrayState,
            Self::Rebuild(_) => StoragePolicyArtifactClass::Rebuild,
            Self::ArrayConsistency(_) => StoragePolicyArtifactClass::ArrayConsistency,
            Self::NinePVisibility(_) => StoragePolicyArtifactClass::NinePVisibility,
            Self::NinePObject(_) => StoragePolicyArtifactClass::NinePObject,
            Self::Bytes { .. } => StoragePolicyArtifactClass::Bytes,
        }
    }
}

/// One stable, scenario-owned storage policy declaration.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldStoragePolicyArtifact {
    /// Stable reference used by effects and other policies.
    pub id: FaultObjectId,
    /// Exact semantic version; version 1 is the only accepted version.
    pub semantic_version: u16,
    /// Typed policy data.
    pub artifact: StoragePolicyArtifactKind,
}

impl WorldStoragePolicyArtifact {
    /// Validates local invariants independent of cross-artifact references.
    ///
    /// # Errors
    ///
    /// Returns [`WorldFaultTopologyError`] for unsupported versions, empty or
    /// excessive tables, malformed protocol results, or inconsistent policy
    /// parameters.
    pub(super) fn validate(&self) -> Result<(), WorldFaultTopologyError> {
        require(
            self.semantic_version == 1,
            "storage policy semantic version",
        )?;
        match &self.artifact {
            StoragePolicyArtifactKind::TypedResult(StoragePolicyTypedResult::NineP { errno }) => {
                require(*errno > 0, "storage 9p errno")
            }
            StoragePolicyArtifactKind::Service(policy) => {
                require(
                    policy.classes.len() <= HARD_STORAGE_POLICY_ENTRIES,
                    "storage service class count",
                )?;
                require(
                    policy
                        .classes
                        .windows(2)
                        .all(|pair| pair[0].class < pair[1].class),
                    "storage service class canonical identity order",
                )?;
                let operations = policy
                    .classes
                    .iter()
                    .flat_map(|class| class.operations.as_slice())
                    .copied()
                    .collect::<Vec<_>>();
                require(
                    policy
                        .classes
                        .iter()
                        .all(|class| class.operations.adapter() == FaultAdapter::Storage)
                        && operations.iter().copied().collect::<BTreeSet<_>>().len()
                            == operations.len(),
                    "storage service operation assignment",
                )?;
                if policy.discipline != StoragePolicyQueueDiscipline::Fifo {
                    require(!policy.classes.is_empty(), "storage service classes")?;
                }
                Ok(())
            }
            StoragePolicyArtifactKind::Path(policy) => require(
                policy.maximum_attempts.get() <= 65_536
                    && !policy.retry_results.is_empty()
                    && policy.retry_results.len() <= HARD_STORAGE_POLICY_ENTRIES
                    && policy
                        .retry_results
                        .windows(2)
                        .all(|pair| pair[0] < pair[1])
                    && policy
                        .retry_results
                        .iter()
                        .all(|result| *result != StoragePolicyResult::Success),
                "storage path retry policy",
            ),
            StoragePolicyArtifactKind::RemoteProtocol(policy) => require(
                policy.maximum_outstanding.get() <= 4_194_304,
                "storage remote protocol outstanding-command bound",
            ),
            StoragePolicyArtifactKind::Retention(policy) => require(
                policy.maximum_changed_bits.get() <= 1_048_576,
                "storage retention changed-bit bound",
            ),
            StoragePolicyArtifactKind::ReadDisturb(policy) => require(
                policy.neighbor_pages.get() <= 65_536
                    && policy.maximum_changed_bits.get() <= 1_048_576,
                "storage read-disturb bound",
            ),
            StoragePolicyArtifactKind::Rebuild(policy) => require(
                policy.queue_depth.get() <= 1_048_576,
                "storage rebuild queue bound",
            ),
            StoragePolicyArtifactKind::ArrayState { members, paths } => {
                require(
                    !members.is_empty()
                        && !paths.is_empty()
                        && members.len() <= HARD_STORAGE_POLICY_ENTRIES
                        && paths.len() <= HARD_STORAGE_POLICY_ENTRIES,
                    "storage array member state count",
                )?;
                require(
                    members
                        .windows(2)
                        .all(|pair| pair[0].member < pair[1].member),
                    "storage array member state canonical identity order",
                )?;
                require(
                    paths.windows(2).all(|pair| pair[0].path < pair[1].path),
                    "storage array path state canonical identity order",
                )
            }
            StoragePolicyArtifactKind::NinePObject(object) => require(
                object.path.starts_with('/')
                    && !object.path.contains("//")
                    && !object
                        .path
                        .split('/')
                        .any(|component| component == "." || component == "..")
                    && object.data.len() <= HARD_STORAGE_POLICY_BYTES,
                "storage 9p object artifact",
            ),
            StoragePolicyArtifactKind::Bytes { bytes } => require(
                !bytes.is_empty() && bytes.len() <= HARD_STORAGE_POLICY_BYTES,
                "storage inline byte artifact",
            ),
            _ => Ok(()),
        }
    }
}

pub(super) fn validate_storage_policy_reference(
    topology: &WorldFaultTopology,
    id: &FaultObjectId,
    expected: StoragePolicyArtifactClass,
    field: &'static str,
) -> Result<(), WorldFaultTopologyError> {
    let artifact = topology
        .storage_policy_artifact(id)
        .ok_or_else(|| invalid(field))?;
    require(artifact.artifact.class() == expected, field)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> FaultObjectId {
        FaultObjectId::parse(value)
            .unwrap_or_else(|error| panic!("test storage policy ID should be valid: {error}"))
    }

    #[test]
    fn ninep_errno_and_object_paths_fail_closed() {
        let errno = WorldStoragePolicyArtifact {
            id: id("ninep-error"),
            semantic_version: 1,
            artifact: StoragePolicyArtifactKind::TypedResult(StoragePolicyTypedResult::NineP {
                errno: 0,
            }),
        };
        assert!(errno.validate().is_err());

        let object = WorldStoragePolicyArtifact {
            id: id("stale-object"),
            semantic_version: 1,
            artifact: StoragePolicyArtifactKind::NinePObject(StoragePolicyNinePObject {
                path: String::from("/safe/../escape"),
                version: 1,
                mode: 0o100_644,
                data: Vec::new(),
            }),
        };
        assert!(object.validate().is_err());
    }

    #[test]
    fn service_classes_and_array_members_require_strict_canonical_order() {
        let operations = OperationSet::new(vec![FaultOperation::StorageRead])
            .unwrap_or_else(|error| panic!("test storage operation set should be valid: {error}"));
        let class = StoragePolicyServiceClass {
            class: id("foreground"),
            operations,
            priority: 0,
            weight: PositiveU64::new("weight", 1)
                .unwrap_or_else(|error| panic!("test weight should be valid: {error}")),
        };
        let service = WorldStoragePolicyArtifact {
            id: id("service"),
            semantic_version: 1,
            artifact: StoragePolicyArtifactKind::Service(StoragePolicyService {
                discipline: StoragePolicyQueueDiscipline::StrictPriority,
                classes: vec![class.clone(), class],
                rebuild_shares_service: true,
            }),
        };
        assert!(service.validate().is_err());

        let reversed_service = WorldStoragePolicyArtifact {
            id: id("reversed-service"),
            semantic_version: 1,
            artifact: StoragePolicyArtifactKind::Service(StoragePolicyService {
                discipline: StoragePolicyQueueDiscipline::StrictPriority,
                classes: vec![
                    StoragePolicyServiceClass {
                        class: id("foreground-z"),
                        operations: OperationSet::new(vec![FaultOperation::StorageRead])
                            .unwrap_or_else(|error| panic!("operation set: {error}")),
                        priority: 0,
                        weight: PositiveU64::new("weight", 1)
                            .unwrap_or_else(|error| panic!("weight: {error}")),
                    },
                    StoragePolicyServiceClass {
                        class: id("foreground-a"),
                        operations: OperationSet::new(vec![FaultOperation::StorageWrite])
                            .unwrap_or_else(|error| panic!("operation set: {error}")),
                        priority: 1,
                        weight: PositiveU64::new("weight", 1)
                            .unwrap_or_else(|error| panic!("weight: {error}")),
                    },
                ],
                rebuild_shares_service: true,
            }),
        };
        assert!(reversed_service.validate().is_err());

        let member = StoragePolicyArrayMemberState {
            member: id("member-a"),
            online: true,
        };
        let path = StoragePolicyArrayPathState {
            path: id("path-a"),
            online: true,
        };
        let array = WorldStoragePolicyArtifact {
            id: id("array-state"),
            semantic_version: 1,
            artifact: StoragePolicyArtifactKind::ArrayState {
                members: vec![member.clone(), member],
                paths: vec![path.clone()],
            },
        };
        assert!(array.validate().is_err());

        let reversed_array = WorldStoragePolicyArtifact {
            id: id("reversed-array-state"),
            semantic_version: 1,
            artifact: StoragePolicyArtifactKind::ArrayState {
                members: vec![
                    StoragePolicyArrayMemberState {
                        member: id("member-z"),
                        online: true,
                    },
                    StoragePolicyArrayMemberState {
                        member: id("member-a"),
                        online: true,
                    },
                ],
                paths: vec![path],
            },
        };
        assert!(reversed_array.validate().is_err());
    }

    #[test]
    fn unknown_storage_policy_fields_are_rejected() {
        let json = r#"{
            "id":"result",
            "semantic_version":1,
            "artifact":{"kind":"typed_result","parameters":{"protocol":"block","result":"success","ignored":true}}
        }"#;
        assert!(serde_json::from_str::<WorldStoragePolicyArtifact>(json).is_err());

        let outer = r#"{
            "id":"bytes",
            "semantic_version":1,
            "artifact":{"kind":"bytes","parameters":{"bytes":[1]},"ignored":true}
        }"#;
        assert!(serde_json::from_str::<WorldStoragePolicyArtifact>(outer).is_err());

        let dirty_eviction = r#"{
            "id":"cache",
            "semantic_version":1,
            "artifact":{"kind":"cache","parameters":{
                "eviction":"fifo",
                "dirty_eviction":{"kind":"persist","ignored":true},
                "power_loss_protected":false
            }}
        }"#;
        assert!(serde_json::from_str::<WorldStoragePolicyArtifact>(dirty_eviction).is_err());

        let duplicate = r#"{
            "id":"duplicate",
            "semantic_version":1,
            "artifact":{"kind":"duplicate_completion","parameters":{
                "kind":"ignore","ignored":true
            }}
        }"#;
        assert!(serde_json::from_str::<WorldStoragePolicyArtifact>(duplicate).is_err());
    }

    #[test]
    fn path_retry_results_are_nonempty_canonical_failures() {
        let path = |retry_results| WorldStoragePolicyArtifact {
            id: id("path-policy"),
            semantic_version: 1,
            artifact: StoragePolicyArtifactKind::Path(StoragePolicyPath {
                selection: StoragePolicyPathSelection::ActivePassive,
                maximum_attempts: BoundedCount::new(CountLimit::LargeStateEntries, 3)
                    .unwrap_or_else(|error| panic!("attempt count: {error}")),
                retry_delay_nanos: PositiveU64::new("retry delay", 1)
                    .unwrap_or_else(|error| panic!("retry delay: {error}")),
                recovery_probe_interval_nanos: PositiveU64::new("probe interval", 1)
                    .unwrap_or_else(|error| panic!("probe interval: {error}")),
                retry_results,
            }),
        };
        assert!(
            path(vec![
                StoragePolicyResult::Busy,
                StoragePolicyResult::Timeout
            ])
            .validate()
            .is_ok()
        );
        assert!(path(Vec::new()).validate().is_err());
        assert!(
            path(vec![
                StoragePolicyResult::Timeout,
                StoragePolicyResult::Busy
            ])
            .validate()
            .is_err()
        );
        assert!(path(vec![StoragePolicyResult::Success]).validate().is_err());
    }
}
