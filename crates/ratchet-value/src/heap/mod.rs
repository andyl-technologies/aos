//! Heap allocation strategies for evaluator runtime objects.
//!
//! Phase 1 starts with the Tier-A one-shot bump arena: allocate monotonically,
//! never free individual objects, and drop all chunks with the arena. Later
//! phases add precise GC and daemon-mode collectors behind the same allocation
//! entry-point shape.

pub mod arena;
pub mod concurrent_gc;
pub mod region;

pub use arena::{ArenaAllocation, ArenaError, ArenaStats, BumpArena, HeapObjectKind};
pub use concurrent_gc::{
    BarrierAddress, ConcurrentGcError, ConcurrentGcTier, GcColor, LoadBarrierAction,
    LoadBarrierSlowReason, ThunkMutation, ThunkMutationBarrier, classify_load_barrier,
    classify_thunk_mutation_barrier,
};
pub use region::{
    AllocationRegionFacts, RegionEffect, RegionLifetime, RegionPlacement, RegionPlacementReason,
    RegionPlan, RegionRuntimeTier, RegionSharing,
};
