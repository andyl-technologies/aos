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
pub mod flat;
pub mod gauges;
pub mod gc;
pub mod region;
pub mod reservation;
pub mod reservation_registry;
pub mod resident;
pub mod safety;
#[cfg(feature = "candidate_c_value")]
pub mod snapshot;

pub use advice::{
    AllocatorReleaseOutcome, MemoryAdviceKind, MemoryAdviceOutcome, MemoryAdviceRange, advise_cold,
    advise_cold_heap_object_allocation, advise_dead, advise_evict,
    advise_evict_heap_object_allocation, advise_free, advise_huge, advise_range,
    release_free_allocator_memory,
};
pub use arena::{
    ArenaAllocation, ArenaError, ArenaMemoryAdviceReport, ArenaRegionMark, ArenaRegionPopReport,
    ArenaStats, BumpArena, HeapObjectKind, ThreadLocalBumpArena,
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
pub use flat::{
    FlatAllocation, FlatObjectError, FlatObjectKind, FlatObjectRef, FlatObjectStore,
    FlatStoredObject,
};
pub use gauges::ArenaProcessGauges;
pub use gc::{
    DEFAULT_GC_CARD_SIZE_BYTES, GcCardTable, GcCardTableClearReport, GcCardTableSnapshot,
    GcCardTableUpdate, GcDirtyCard, GcHeapAddress, GenerationalGcError, GenerationalGcTier,
    HeapGeneration, MinorGcCommitBuffers, MinorGcCommitPlan, MinorGcCommitReport,
    MinorGcDestinationAllocation, MinorGcDestinationAllocationPlan, MinorGcDestinationBases,
    MinorGcDestinationPlacement, MinorGcDestinationPlacementPlan, MinorGcForwardingPointer,
    MinorGcForwardingPointerPlan, MinorGcForwardingSlot, MinorGcObjectByteCopyBuffer,
    MinorGcObjectCopy, MinorGcObjectCopyPlan, MinorGcOldFieldRescan, MinorGcOldFieldRescanPlan,
    MinorGcOldObjectFields, MinorGcOwnedCommitBuffers, MinorGcOwnedDestinationStorage,
    MinorGcOwnedDestinationStorageCopyReport, MinorGcPlan, MinorGcPromotionPolicy,
    MinorGcReferenceRewrite, MinorGcReferenceRewritePlan, MinorGcRelocation,
    MinorGcRelocationDestination, MinorGcRelocationDestinationPlan, MinorGcRelocationPlan,
    MinorGcRememberedSetRefresh, MinorGcRememberedSetRefreshAction,
    MinorGcRememberedSetRefreshPlan, MinorGcSourceObjectBytes, MinorGcSurvivor,
    MinorGcSurvivorAction, NurseryObjectAge, NurseryObjectFields, NurseryObjectLayout,
    RememberedEdge, RememberedSet, RememberedSetEpoch, RememberedSetSnapshot, RememberedSetUpdate,
    ResolvedValueGeneration, ThunkResolveWrite, ThunkResolveWriteBarrier,
    classify_thunk_resolve_write_barrier, record_thunk_resolve_write_barrier,
    record_thunk_resolve_write_barrier_with_card_table,
};
pub use region::{
    AllocationRegionFacts, RegionEffect, RegionLifetime, RegionPlacement, RegionPlacementReason,
    RegionPlan, RegionRuntimeTier, RegionSharing,
};
pub use reservation::{
    ArenaDomainId, ArenaIndex, CANDIDATE_C_ADDRESS_SPACE_BYTES, CANDIDATE_C_ARENA_DOMAIN_MAX,
    ReservedArena, ReservedArenaAllocation, ReservedArenaError, ReservedArenaHighMark,
    ReservedArenaMark, ReservedArenaStats,
};
pub use reservation_registry::{
    ReservationRegistryError, register_reservation_base, reservation_base,
    reservation_containing_address, unregister_reservation_base,
};
pub use resident::{
    PeakResidentMemoryScope, ProcessResidentMemoryError, ProcessResidentMemorySample,
    ProcessResidentMemorySource, peak_resident_memory_bytes, process_resident_memory_sample,
    process_resident_memory_sample_from_linux_statm,
};
#[cfg(feature = "candidate_c_value")]
pub use snapshot::{HeapImage, SnapshotError, capture_reservation, restore_reservation};
