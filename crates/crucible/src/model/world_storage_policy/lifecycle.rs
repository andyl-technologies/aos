//! Storage cache and controller-transition policy types.

use super::*;

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
