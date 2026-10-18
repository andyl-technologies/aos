//! Factual queue observations used before scheduler input admission.
//!
//! These values carry observation data. An operational backend retains the
//! actual stopped-source or accepted-run receipt and authenticates it before
//! and after reading its queue owners; these records grant no native authority.

use std::num::NonZeroU64;

use crate::{ContentHash, NodeCounter, NodeId, SchedulerNodeId};

/// Identifies the implemented owner of a backend's complete I/O inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendIoInventoryAuthority {
    /// The explicitly modeled backend uses the scheduler's retained device queues.
    SchedulerOwnedModel,
    /// Physical queues require a fresh, complete native Source observation.
    PhysicalSource,
}

/// Complete current real-device queue observation for one stopped VM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendIoInventory {
    /// Logical VM whose independently authenticated queue owners were read.
    pub node: NodeId,
    /// Actual node-local logical tick from the same retained physical source.
    pub observed: NodeCounter,
    /// Source-owned observation revision, never a scheduler ordinal or request ID.
    pub generation: NonZeroU64,
    /// Independently observed native timer and input bounds from the same source.
    ///
    /// Queue coverage cannot establish native absence. The operational backend
    /// joins a current complete native report under its retained source owner.
    pub native_caps: BackendIoNativeCaps,
    /// Every configured physical queue, including explicitly observed empty queues.
    pub queues: Vec<BackendIoQueueSnapshot>,
}

/// Factual native event bounds observed under one retained physical source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendIoNativeCaps {
    /// Actual native virtual timer observation, independently of queued replies.
    pub timer: BackendIoNativeCap,
    /// Actual native input observation, independently of configured queue coverage.
    pub input: BackendIoNativeCap,
}

/// Distinguishes unavailable cap knowledge from actual observed absence.
///
/// An armed zero is a real deadline. These facts constrain the actor's original
/// semantic authorization; they neither authorize execution nor describe a
/// consumed event or successful semantic completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BackendIoNativeCap {
    /// Indicates that current complete native observation is unavailable.
    Unknown,
    /// Records absence established by the actual complete native observer.
    ObservedAbsent,
    /// Records an actual armed deadline in backend node-local logical ticks.
    Armed(crate::NodeCounter),
}

/// One World-bound queue observed without draining or recomputing responses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendIoQueueSnapshot {
    /// Exact World declaration retained by the real queue owner.
    pub world: ContentHash,
    /// Logical device that owns the computed replies.
    pub device: SchedulerNodeId,
    /// Canonical producer number derived from the same World layout.
    pub source_node: u32,
    /// Actual queue-owner revision retained across checkpoint and fork.
    pub revision: NonZeroU64,
    /// Independent retained block request-pipeline revision.
    ///
    /// Block queues require the actual `BlockFaultState` revision. Nine-p
    /// queues use their single queue owner and must carry `None` here.
    pub pipeline_revision: Option<NonZeroU64>,
    /// Actual retained request-pipeline deadline, without a computed delivery key.
    ///
    /// This bounds physical progress only. It never represents a completion or
    /// permits the actor to consume a request during observation.
    pub next_pipeline_boundary: Option<NodeCounter>,
    /// Complete ordered computed queue with its original physical keys and bytes.
    pub completions: Vec<BackendIoComputedReply>,
}

/// One computed physical queue reply before actor time projection.
///
/// The runtime retains only its original node-local key and actual bytes. The
/// actor derives the consumer, scheduler event and shared time from its current
/// immutable World and node mapping; the runtime cannot guess that mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendIoComputedReply {
    /// Original physical queue identity, including node-local delivery tick.
    pub source_delivery: crucible_device::FrameDeliveryKey,
    /// Actual computed bytes retained by this exact queue entry.
    pub payload: Vec<u8>,
}
