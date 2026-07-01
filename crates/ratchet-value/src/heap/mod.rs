//! Heap allocation strategies for evaluator runtime objects.
//!
//! Tier A uses a one-shot bump arena: allocate monotonically, never free
//! individual objects, and `munmap` all anonymous chunks when the arena drops.
//! Later phases add precise GC and daemon-mode collectors behind the same
//! allocation entry-point shape.

pub mod advice;
pub mod arena;
pub mod budget;
pub mod concurrent_gc;
pub mod gc;
pub mod region;

pub use advice::{
    MemoryAdviceKind, MemoryAdviceOutcome, MemoryAdviceRange, advise_cold, advise_dead,
    advise_evict, advise_free, advise_huge, advise_range,
};
pub use arena::{
    ArenaAllocation, ArenaError, ArenaStats, BumpArena, HeapObjectKind, ThreadLocalBumpArena,
};
pub use budget::{
    DEFAULT_BUDGET_HEADROOM_DENOMINATOR, HeapMemoryBudget, HeapMemoryBudgetError,
    HeapMemoryBudgetResponse, HeapMemorySample,
};
pub use concurrent_gc::{
    BarrierAddress, ConcurrentGcError, ConcurrentGcTier, GcColor, LoadBarrierAction,
    LoadBarrierSlowReason, ThunkMutation, ThunkMutationBarrier, classify_load_barrier,
    classify_thunk_mutation_barrier,
};
pub use gc::{
    GcHeapAddress, GenerationalGcError, GenerationalGcTier, HeapGeneration, MinorGcCommitBuffers,
    MinorGcCommitPlan, MinorGcDestinationAllocation, MinorGcDestinationAllocationPlan,
    MinorGcDestinationBases, MinorGcDestinationPlacement, MinorGcDestinationPlacementPlan,
    MinorGcForwardingPointer, MinorGcForwardingPointerPlan, MinorGcForwardingSlot,
    MinorGcObjectByteCopyBuffer, MinorGcObjectCopy, MinorGcObjectCopyPlan, MinorGcPlan,
    MinorGcPromotionPolicy, MinorGcReferenceRewrite, MinorGcReferenceRewritePlan,
    MinorGcRelocation, MinorGcRelocationDestination, MinorGcRelocationDestinationPlan,
    MinorGcRelocationPlan, MinorGcRememberedSetRefresh, MinorGcRememberedSetRefreshAction,
    MinorGcRememberedSetRefreshPlan, MinorGcSurvivor, MinorGcSurvivorAction, NurseryObjectAge,
    NurseryObjectFields, NurseryObjectLayout, RememberedEdge, RememberedSet, RememberedSetEpoch,
    RememberedSetSnapshot, RememberedSetUpdate, ResolvedValueGeneration, ThunkResolveWrite,
    ThunkResolveWriteBarrier, classify_thunk_resolve_write_barrier,
    record_thunk_resolve_write_barrier,
};
pub use region::{
    AllocationRegionFacts, RegionEffect, RegionLifetime, RegionPlacement, RegionPlacementReason,
    RegionPlan, RegionRuntimeTier, RegionSharing,
};
