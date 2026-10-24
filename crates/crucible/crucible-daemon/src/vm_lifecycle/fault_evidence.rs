//! Read-only evidence snapshots for production network, block, and node faults.

use super::*;

/// Read-only evidence for one active production network outage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionNetworkOutageEvidence {
    /// Concrete World target whose route stages reject frames.
    pub target: crucible_engine::model::ResolvedFaultTarget,
    /// Exclusive virtual-time end of the outage.
    pub unavailable_until_nanos: u64,
}

/// Read-only evidence for one live production network queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionNetworkQueueEvidence {
    /// Concrete World queue target owning the reservations.
    pub target: crucible_engine::model::ResolvedFaultTarget,
    /// Number of frames currently reserved in the queue.
    pub reservations: usize,
    /// Canonical digest of the complete queue continuation.
    pub continuation_digest: ContentHash,
    /// Latest scheduled completion tick among current reservations.
    pub last_finish_ticks: Option<u64>,
}

/// Read-only evidence for one authoritative production block continuation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionBlockFaultEvidence {
    /// Immutable World identity of the attached block device.
    pub device: ContentHash,
    /// Number of currently live volatile-cache fragments.
    pub volatile_entries: usize,
    /// Canonical digest of the complete volatile-cache entry set.
    pub volatile_entries_digest: ContentHash,
    /// Exclusive durable write frontier.
    pub actual_durable_frontier: u64,
    /// Number of leading guest-visible bytes covered by `visible_prefix_digest`.
    pub visible_prefix_bytes: u32,
    /// Canonical digest of the bounded guest-visible prefix.
    pub visible_prefix_digest: ContentHash,
}

/// Read-only evidence for one production QEMU node continuation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionNodeFaultEvidence {
    /// World node identity.
    pub node: NodeId,
    /// Monotone process generation, incremented by terminal replacement.
    pub generation: u64,
    /// Stable service-state spelling used in evidence artifacts.
    pub service_state: &'static str,
    /// Scheduler-owned activity at the evidence boundary.
    pub scheduler_activity: SchedulerNodeActivity,
    /// Whether the production backend retains a QEMU process for this node.
    pub backend_owned: bool,
    /// Exact relationship between backend, current manifest, and staged owner.
    pub process_ownership: &'static str,
}

/// Exact observable state of all production fault adapters at one boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionFaultEvidenceSnapshot {
    /// Scheduler frontier at which the snapshot was collected.
    pub frontier: VirtualTime,
    /// Committed replay trace, including pass work items.
    pub resolved_effect_trace: Option<ResolvedEffectTrace>,
    /// Committed locked-effect replay trace, including pass work items.
    pub locked_effect_trace: Option<ResolvedEffectTrace>,
    /// Signal events emitted in authoritative evaluation order.
    pub emitted_events: Vec<crucible_engine::model::ReferencedSignalEvent>,
    /// Last Applied native memory-service occurrence at the committed boundary.
    ///
    /// This fixed-size diagnostic follows node/event traversal order and does
    /// not represent all accesses or survive restore. Full occurrence coverage
    /// remains authenticated by the canonical event log.
    pub memory_service_occurrence: Option<crucible_qemu_host::QemuMemoryServiceOccurrence>,
    /// Network outages active at `frontier`.
    pub network_outages: Vec<ProductionNetworkOutageEvidence>,
    /// Live network queues with at least one reservation.
    pub network_queues: Vec<ProductionNetworkQueueEvidence>,
    /// Authoritative live block continuations in device-identity order.
    pub block_devices: Vec<ProductionBlockFaultEvidence>,
    /// Live-QEMU service state in World node order.
    pub nodes: Vec<ProductionNodeFaultEvidence>,
}
