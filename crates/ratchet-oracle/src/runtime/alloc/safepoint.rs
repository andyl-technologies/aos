//! GC-stress policy, allocation safepoint, and memory-budget-decision types,
//! split from [`super`].

use super::*;

/// GC-stress polling policy evaluated at allocation safepoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcStressPolicy {
    mode: GcStressPolicyMode,
}

impl Default for GcStressPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

impl GcStressPolicy {
    /// Creates a policy that never requests a GC-stress collector poll.
    pub const fn disabled() -> Self {
        Self {
            mode: GcStressPolicyMode::Disabled,
        }
    }

    /// Creates a policy that requests a GC-stress collector poll at every
    /// allocation safepoint.
    pub const fn every_safepoint() -> Self {
        Self {
            mode: GcStressPolicyMode::EverySafepoint,
        }
    }

    /// Creates a policy that requests a GC-stress collector poll every `period`
    /// allocation safepoints.
    ///
    /// The cadence is evaluated against the allocator's lifetime safepoint
    /// sequence, not the policy-installation epoch.
    ///
    /// # Errors
    ///
    /// Returns [`GcStressPolicyError::ZeroPeriod`] when `period` is zero.
    pub const fn every_n_safepoints(period: u64) -> Result<Self, GcStressPolicyError> {
        if period == 0 {
            return Err(GcStressPolicyError::ZeroPeriod);
        }
        Ok(Self {
            mode: GcStressPolicyMode::EveryNSafepoints { period },
        })
    }

    /// Returns whether this policy never requests a GC-stress collector poll.
    pub const fn is_disabled(self) -> bool {
        matches!(self.mode, GcStressPolicyMode::Disabled)
    }

    const fn poll_reason_for(self, sequence: u64) -> Option<AllocationGcPollReason> {
        match self.mode {
            GcStressPolicyMode::Disabled => None,
            _ if sequence == u64::MAX => Some(AllocationGcPollReason::GcStressSequenceSaturated),
            GcStressPolicyMode::EverySafepoint => {
                Some(AllocationGcPollReason::GcStressEverySafepoint)
            }
            GcStressPolicyMode::EveryNSafepoints { period } => {
                if sequence % period == 0 {
                    Some(AllocationGcPollReason::GcStressEveryNSafepoints { period })
                } else {
                    None
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GcStressPolicyMode {
    Disabled,
    EverySafepoint,
    EveryNSafepoints { period: u64 },
}

/// A GC-stress policy configuration failure.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum GcStressPolicyError {
    /// Periodic GC-stress polling needs a non-zero period.
    #[error("GC-stress safepoint period cannot be zero")]
    ZeroPeriod,
}

/// The reason an allocation safepoint requested a collector poll.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocationGcPollReason {
    /// GC-stress mode requested a collector poll at every safepoint.
    GcStressEverySafepoint,
    /// GC-stress mode requested a collector poll at a periodic safepoint.
    GcStressEveryNSafepoints {
        /// The configured safepoint period.
        period: u64,
    },
    /// GC-stress mode requested a collector poll because the safepoint sequence
    /// saturated.
    GcStressSequenceSaturated,
}

/// A collector poll requested by an allocation safepoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocationCollectorPoll {
    sequence: u64,
    tier: RuntimeAllocatorTier,
    request: RuntimeAllocationRequest,
    reason: AllocationGcPollReason,
    stats_after: ArenaStats,
}

impl AllocationCollectorPoll {
    pub(in crate::runtime::alloc) const fn new(
        safepoint: AllocationSafepoint,
        reason: AllocationGcPollReason,
    ) -> Self {
        Self {
            sequence: safepoint.sequence,
            tier: safepoint.tier,
            request: safepoint.request,
            reason,
            stats_after: safepoint.stats_after,
        }
    }

    /// Returns the allocation safepoint sequence that requested the poll.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the allocation tier that requested the poll.
    pub const fn tier(self) -> RuntimeAllocatorTier {
        self.tier
    }

    /// Returns the allocation entry point that requested the poll.
    pub const fn entrypoint(self) -> RuntimeAllocationEntryPoint {
        self.request.entrypoint()
    }

    /// Returns the typed allocation request that produced the poll.
    pub const fn request(self) -> RuntimeAllocationRequest {
        self.request
    }

    /// Returns why the collector poll was requested.
    pub const fn reason(self) -> AllocationGcPollReason {
        self.reason
    }

    /// Returns allocator accounting after the safepoint allocation completed.
    pub const fn stats_after(self) -> ArenaStats {
        self.stats_after
    }
}

/// A high-water memory-budget decision made at an allocation safepoint.
///
/// The current runtime does not have a live RSS sampler, so allocation
/// safepoints use post-allocation mapped arena bytes as the resident-memory
/// proxy and accept caller-supplied cheap-reclaim capacity for dead arena pages
/// and cold hash-consed values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocationMemoryBudgetDecision {
    sequence: u64,
    tier: RuntimeAllocatorTier,
    request: RuntimeAllocationRequest,
    budget: HeapMemoryBudget,
    sample: HeapMemorySample,
    stats_after: ArenaStats,
    response: HeapMemoryBudgetResponse,
}

impl AllocationMemoryBudgetDecision {
    pub(in crate::runtime::alloc) const fn new(
        safepoint: AllocationSafepoint,
        budget: HeapMemoryBudget,
        sample: HeapMemorySample,
    ) -> Self {
        Self {
            sequence: safepoint.sequence,
            tier: safepoint.tier,
            request: safepoint.request,
            budget,
            sample,
            stats_after: safepoint.stats_after,
            response: budget.classify(sample),
        }
    }

    /// Returns the allocation safepoint sequence that produced this decision.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the allocation tier sampled by this decision.
    pub const fn tier(self) -> RuntimeAllocatorTier {
        self.tier
    }

    /// Returns the allocation entry point sampled by this decision.
    pub const fn entrypoint(self) -> RuntimeAllocationEntryPoint {
        self.request.entrypoint()
    }

    /// Returns the typed allocation request sampled by this decision.
    pub const fn request(self) -> RuntimeAllocationRequest {
        self.request
    }

    /// Returns the budget used to classify memory pressure.
    pub const fn budget(self) -> HeapMemoryBudget {
        self.budget
    }

    /// Returns the memory sample classified by the budget policy.
    pub const fn sample(self) -> HeapMemorySample {
        self.sample
    }

    /// Returns allocator accounting captured after the safepoint allocation.
    pub const fn stats_after(self) -> ArenaStats {
        self.stats_after
    }

    /// Returns the high-water budget response selected for this safepoint.
    pub const fn response(self) -> HeapMemoryBudgetResponse {
        self.response
    }

    /// Returns whether the response asks runtime code to do more than continue.
    pub const fn requires_runtime_action(self) -> bool {
        match self.response {
            HeapMemoryBudgetResponse::ContinueTierA { .. } => false,
            HeapMemoryBudgetResponse::SpillCold { .. }
            | HeapMemoryBudgetResponse::InstallTierB { .. } => true,
        }
    }

    /// Returns whether the response asks the runtime to install Tier B.
    pub const fn requests_tier_b(self) -> bool {
        matches!(self.response, HeapMemoryBudgetResponse::InstallTierB { .. })
    }
}

/// Metadata captured at one allocation safepoint.
///
/// The current tree-walk runtime records safepoints and GC-stress poll intent
/// only. It does not yet invoke a collector, build a root set, or run GC stress
/// collection from this event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocationSafepoint {
    sequence: u64,
    tier: RuntimeAllocatorTier,
    request: RuntimeAllocationRequest,
    kind: HeapObjectKind,
    requested_size: usize,
    reserved_size: usize,
    stats_after: ArenaStats,
    gc_poll_reason: Option<AllocationGcPollReason>,
}

impl AllocationSafepoint {
    pub(in crate::runtime::alloc) const fn new(
        sequence: u64,
        tier: RuntimeAllocatorTier,
        request: RuntimeAllocationRequest,
        allocation: ArenaAllocation,
        stats_after: ArenaStats,
        gc_poll_reason: Option<AllocationGcPollReason>,
    ) -> Self {
        Self {
            sequence,
            tier,
            request,
            kind: allocation.kind,
            requested_size: allocation.requested_size,
            reserved_size: allocation.reserved_size,
            stats_after,
            gc_poll_reason,
        }
    }

    /// Returns the monotonic safepoint sequence number for this allocator.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the allocation tier that produced this safepoint.
    pub const fn tier(self) -> RuntimeAllocatorTier {
        self.tier
    }

    /// Returns the centralized allocation entry point.
    pub const fn entrypoint(self) -> RuntimeAllocationEntryPoint {
        self.request.entrypoint()
    }

    /// Returns the typed allocation request that produced this safepoint.
    pub const fn request(self) -> RuntimeAllocationRequest {
        self.request
    }

    /// Returns the logical heap-object kind requested by the caller.
    pub const fn kind(self) -> HeapObjectKind {
        self.kind
    }

    /// Returns the caller-requested allocation size in bytes.
    pub const fn requested_size(self) -> usize {
        self.requested_size
    }

    /// Returns the word-rounded bump distance in bytes.
    pub const fn reserved_size(self) -> usize {
        self.reserved_size
    }

    /// Returns the full arena accounting snapshot after this allocation.
    pub const fn stats_after(self) -> ArenaStats {
        self.stats_after
    }

    /// Returns why this safepoint requested a collector poll.
    pub const fn gc_poll_reason(self) -> Option<AllocationGcPollReason> {
        self.gc_poll_reason
    }

    /// Returns the typed collector poll requested by this safepoint.
    pub const fn collector_poll(self) -> Option<AllocationCollectorPoll> {
        match self.gc_poll_reason {
            Some(reason) => Some(AllocationCollectorPoll::new(self, reason)),
            None => None,
        }
    }

    /// Builds the high-water budget sample for this safepoint.
    ///
    /// The active runtime does not have live RSS sampling yet, so the sample uses
    /// post-allocation mapped arena bytes as its resident-memory proxy. The
    /// caller supplies cheap-reclaim estimates for dead arena pages and cold
    /// hash-consed values.
    pub const fn memory_budget_sample(
        self,
        dead_arena_bytes: usize,
        cold_hash_consed_bytes: usize,
    ) -> HeapMemorySample {
        HeapMemorySample::new(
            self.heap_mapped_bytes_after(),
            dead_arena_bytes,
            cold_hash_consed_bytes,
        )
    }

    /// Classifies this safepoint against a high-water memory budget.
    pub const fn classify_memory_budget(
        self,
        budget: HeapMemoryBudget,
        dead_arena_bytes: usize,
        cold_hash_consed_bytes: usize,
    ) -> AllocationMemoryBudgetDecision {
        let sample = self.memory_budget_sample(dead_arena_bytes, cold_hash_consed_bytes);
        AllocationMemoryBudgetDecision::new(self, budget, sample)
    }

    /// Returns heap chunks owned after this allocation completed.
    pub const fn heap_chunks_after(self) -> usize {
        self.stats_after.chunks
    }

    /// Returns heap bytes reserved after this allocation completed.
    pub const fn heap_reserved_bytes_after(self) -> usize {
        self.stats_after.reserved_bytes
    }

    /// Returns page-rounded mapped bytes after this allocation completed.
    pub const fn heap_mapped_bytes_after(self) -> usize {
        self.stats_after.mapped_bytes
    }

    /// Returns heap bytes consumed after this allocation completed.
    pub const fn heap_used_bytes_after(self) -> usize {
        self.stats_after.used_bytes
    }
}

/// Allocation-safepoint accounting for one allocator domain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllocationSafepointState {
    pub(in crate::runtime::alloc) count: u64,
    pub(in crate::runtime::alloc) last: Option<AllocationSafepoint>,
}

impl AllocationSafepointState {
    /// Returns how many allocation safepoints have been recorded.
    pub const fn count(self) -> u64 {
        self.count
    }

    /// Returns the most recent allocation safepoint.
    pub const fn last(self) -> Option<AllocationSafepoint> {
        self.last
    }

    /// Returns the collector poll requested by the most recent safepoint.
    pub const fn last_safepoint_collector_poll(self) -> Option<AllocationCollectorPoll> {
        match self.last {
            Some(safepoint) => safepoint.collector_poll(),
            None => None,
        }
    }

    /// Classifies the most recent safepoint against a high-water memory budget.
    pub const fn last_memory_budget_decision(
        self,
        budget: HeapMemoryBudget,
        dead_arena_bytes: usize,
        cold_hash_consed_bytes: usize,
    ) -> Option<AllocationMemoryBudgetDecision> {
        match self.last {
            Some(safepoint) => Some(safepoint.classify_memory_budget(
                budget,
                dead_arena_bytes,
                cold_hash_consed_bytes,
            )),
            None => None,
        }
    }

    pub(in crate::runtime::alloc) fn record(
        &mut self,
        tier: RuntimeAllocatorTier,
        request: RuntimeAllocationRequest,
        allocation: ArenaAllocation,
        stats_after: ArenaStats,
        gc_stress_policy: GcStressPolicy,
    ) {
        let sequence = self.count.saturating_add(1);
        self.count = sequence;
        let gc_poll_reason = gc_stress_policy.poll_reason_for(sequence);
        self.last = Some(AllocationSafepoint::new(
            sequence,
            tier,
            request,
            allocation,
            stats_after,
            gc_poll_reason,
        ));
    }
}
