//! Heap allocation strategies for evaluator runtime objects.
//!
//! Phase 1 starts with the Tier-A one-shot bump arena: allocate monotonically,
//! never free individual objects, and drop all chunks with the arena. Later
//! phases add precise GC and daemon-mode collectors behind the same allocation
//! entry-point shape.

pub mod arena;
pub mod region;

pub use arena::{ArenaAllocation, ArenaError, ArenaStats, BumpArena, HeapObjectKind};
pub use region::{
    AllocationRegionFacts, RegionEffect, RegionLifetime, RegionPlacement, RegionPlacementReason,
    RegionPlan, RegionRuntimeTier, RegionSharing,
};
