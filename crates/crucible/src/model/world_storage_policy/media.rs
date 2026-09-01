//! Storage media, array, path, transport, and 9p policy types.

use super::*;

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
    /// Whether this version is a namespace tombstone rather than an object.
    pub deleted: bool,
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
    /// Additional data lag when metadata and data do not advance atomically.
    pub data_visibility_lag_nanos: Option<PositiveU64>,
    /// Whether lookup may retain a deleted object until visibility advances.
    pub retain_deleted_objects: bool,
}
