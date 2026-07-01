//! Runtime allocation strategy dispatch for evaluator heap objects.
//!
//! The tree-walk oracle allocates through this layer instead of naming a heap
//! backend directly. Today the installed worker strategy is the Tier-A one-shot
//! bump arena, with a separate permanent-shared bump arena for hash-consed
//! values. Later Phase-3 work can install the precise generational collector
//! behind the same worker `aos_alloc_*` entry-point surface.

use crate::heap::arena::{ArenaAllocation, ArenaError, ArenaStats, BumpArena, HeapObjectKind};

/// The installed runtime allocation strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAllocatorTier {
    /// One-shot CLI evaluation backed by a never-free bump arena.
    TierAOneShot,
    /// Hash-consed shared values backed by a non-collected permanent arena.
    PermanentShared,
}

/// A centralized allocation entry point that forms an allocation safepoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAllocationEntryPoint {
    /// The `aos_alloc_thunk` helper.
    AosAllocThunk,
    /// The `aos_alloc_lambda` helper.
    AosAllocLambda,
    /// The `aos_alloc_attrs` helper.
    AosAllocAttrs,
    /// The `aos_alloc_cons` helper.
    AosAllocCons,
    /// The `aos_alloc_list` helper.
    AosAllocList,
    /// The `aos_alloc_string` helper.
    AosAllocString,
    /// The `aos_alloc_raw` helper.
    AosAllocRaw,
}

/// Metadata captured at one allocation safepoint.
///
/// The current tree-walk runtime records safepoints only. It does not yet poll a
/// collector, build a root set, or run GC stress mode from this event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocationSafepoint {
    sequence: u64,
    tier: RuntimeAllocatorTier,
    entrypoint: RuntimeAllocationEntryPoint,
    kind: HeapObjectKind,
    requested_size: usize,
    reserved_size: usize,
    stats_after: ArenaStats,
}

impl AllocationSafepoint {
    const fn new(
        sequence: u64,
        tier: RuntimeAllocatorTier,
        entrypoint: RuntimeAllocationEntryPoint,
        allocation: ArenaAllocation,
        stats_after: ArenaStats,
    ) -> Self {
        Self {
            sequence,
            tier,
            entrypoint,
            kind: allocation.kind,
            requested_size: allocation.requested_size,
            reserved_size: allocation.reserved_size,
            stats_after,
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
        self.entrypoint
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
    count: u64,
    last: Option<AllocationSafepoint>,
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

    fn record(
        &mut self,
        tier: RuntimeAllocatorTier,
        entrypoint: RuntimeAllocationEntryPoint,
        allocation: ArenaAllocation,
        stats_after: ArenaStats,
    ) {
        let sequence = self.count.saturating_add(1);
        self.count = sequence;
        self.last = Some(AllocationSafepoint::new(
            sequence,
            tier,
            entrypoint,
            allocation,
            stats_after,
        ));
    }
}

/// Routes heap allocations through the active runtime allocation strategy.
#[derive(Debug)]
pub struct RuntimeAllocator {
    backend: RuntimeAllocatorBackend,
    safepoints: AllocationSafepointState,
}

impl Default for RuntimeAllocator {
    fn default() -> Self {
        Self::tier_a_one_shot()
    }
}

impl RuntimeAllocator {
    /// Creates a runtime allocator backed by the Tier-A one-shot arena.
    pub fn tier_a_one_shot() -> Self {
        Self {
            backend: RuntimeAllocatorBackend::TierAOneShot(BumpArena::new()),
            safepoints: AllocationSafepointState::default(),
        }
    }

    /// Creates a Tier-A runtime allocator with an explicit first chunk size.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError::InvalidChunkSize`] when `chunk_bytes` is zero, or
    /// [`ArenaError::SizeOverflow`] if rounding the chunk size overflows.
    pub fn tier_a_with_initial_chunk_bytes(chunk_bytes: usize) -> Result<Self, ArenaError> {
        Ok(Self {
            backend: RuntimeAllocatorBackend::TierAOneShot(BumpArena::with_initial_chunk_bytes(
                chunk_bytes,
            )?),
            safepoints: AllocationSafepointState::default(),
        })
    }

    /// Returns the installed allocation tier.
    pub fn tier(&self) -> RuntimeAllocatorTier {
        match &self.backend {
            RuntimeAllocatorBackend::TierAOneShot(_) => RuntimeAllocatorTier::TierAOneShot,
        }
    }

    /// Returns current allocation accounting for the installed strategy.
    pub fn stats(&self) -> ArenaStats {
        match &self.backend {
            RuntimeAllocatorBackend::TierAOneShot(arena) => arena.stats(),
        }
    }

    /// Returns allocation-safepoint accounting for this allocator domain.
    pub const fn allocation_safepoints(&self) -> AllocationSafepointState {
        self.safepoints
    }

    /// Allocates a thunk-sized heap object through `aos_alloc_thunk`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    pub fn aos_alloc_thunk(&mut self) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena_mut().aos_alloc_thunk()?;
        self.record_allocation_safepoint(RuntimeAllocationEntryPoint::AosAllocThunk, allocation);
        Ok(allocation)
    }

    /// Allocates a lambda-sized heap object through `aos_alloc_lambda`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    pub fn aos_alloc_lambda(&mut self) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena_mut().aos_alloc_lambda()?;
        self.record_allocation_safepoint(RuntimeAllocationEntryPoint::AosAllocLambda, allocation);
        Ok(allocation)
    }

    /// Allocates an attribute-set heap object through `aos_alloc_attrs`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    pub fn aos_alloc_attrs(
        &mut self,
        shape: u32,
        slots: u32,
    ) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena_mut().aos_alloc_attrs(shape, slots)?;
        self.record_allocation_safepoint(RuntimeAllocationEntryPoint::AosAllocAttrs, allocation);
        Ok(allocation)
    }

    /// Allocates a cons-cell heap object through `aos_alloc_cons`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    pub fn aos_alloc_cons(&mut self) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena_mut().aos_alloc_cons()?;
        self.record_allocation_safepoint(RuntimeAllocationEntryPoint::AosAllocCons, allocation);
        Ok(allocation)
    }

    /// Allocates a contiguous list heap object through `aos_alloc_list`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    pub fn aos_alloc_list(&mut self, len: usize) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena_mut().aos_alloc_list(len)?;
        self.record_allocation_safepoint(RuntimeAllocationEntryPoint::AosAllocList, allocation);
        Ok(allocation)
    }

    /// Allocates a string heap object through `aos_alloc_string`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    pub fn aos_alloc_string(&mut self, len: usize) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena_mut().aos_alloc_string(len)?;
        self.record_allocation_safepoint(RuntimeAllocationEntryPoint::AosAllocString, allocation);
        Ok(allocation)
    }

    /// Allocates raw heap storage through `aos_alloc_raw`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    pub fn aos_alloc_raw(
        &mut self,
        size: usize,
        align: usize,
        type_tag: u32,
    ) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena_mut().aos_alloc_raw(size, align, type_tag)?;
        self.record_allocation_safepoint(RuntimeAllocationEntryPoint::AosAllocRaw, allocation);
        Ok(allocation)
    }

    fn arena_mut(&mut self) -> &mut BumpArena {
        match &mut self.backend {
            RuntimeAllocatorBackend::TierAOneShot(arena) => arena,
        }
    }

    fn record_allocation_safepoint(
        &mut self,
        entrypoint: RuntimeAllocationEntryPoint,
        allocation: ArenaAllocation,
    ) {
        self.safepoints
            .record(self.tier(), entrypoint, allocation, self.stats());
    }
}

#[derive(Debug)]
enum RuntimeAllocatorBackend {
    TierAOneShot(BumpArena),
}

/// Allocates reusable hash-consed values in permanent shared storage.
#[derive(Debug)]
pub(crate) struct PermanentSharedAllocator {
    arena: BumpArena,
    safepoints: AllocationSafepointState,
}

impl Default for PermanentSharedAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl PermanentSharedAllocator {
    /// Creates a permanent-shared allocator.
    pub(crate) fn new() -> Self {
        Self {
            arena: BumpArena::new(),
            safepoints: AllocationSafepointState::default(),
        }
    }

    /// Creates a permanent-shared allocator with an explicit first chunk size.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError::InvalidChunkSize`] when `chunk_bytes` is zero, or
    /// [`ArenaError::SizeOverflow`] if rounding the chunk size overflows.
    pub(crate) fn with_initial_chunk_bytes(chunk_bytes: usize) -> Result<Self, ArenaError> {
        Ok(Self {
            arena: BumpArena::with_initial_chunk_bytes(chunk_bytes)?,
            safepoints: AllocationSafepointState::default(),
        })
    }

    /// Returns the allocator tier for permanent shared storage.
    pub(crate) const fn tier(&self) -> RuntimeAllocatorTier {
        RuntimeAllocatorTier::PermanentShared
    }

    /// Returns current permanent shared allocation accounting.
    pub(crate) fn stats(&self) -> ArenaStats {
        self.arena.stats()
    }

    /// Returns allocation-safepoint accounting for permanent shared storage.
    pub(crate) const fn allocation_safepoints(&self) -> AllocationSafepointState {
        self.safepoints
    }

    /// Allocates a permanent-shared attribute-set heap object.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if permanent storage cannot reserve the object.
    pub(crate) fn aos_alloc_attrs(
        &mut self,
        shape: u32,
        slots: u32,
    ) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena.aos_alloc_attrs(shape, slots)?;
        self.record_allocation_safepoint(RuntimeAllocationEntryPoint::AosAllocAttrs, allocation);
        Ok(allocation)
    }

    /// Allocates a permanent-shared contiguous list heap object.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if permanent storage cannot reserve the object.
    pub(crate) fn aos_alloc_list(&mut self, len: usize) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena.aos_alloc_list(len)?;
        self.record_allocation_safepoint(RuntimeAllocationEntryPoint::AosAllocList, allocation);
        Ok(allocation)
    }

    /// Allocates a permanent-shared string or path heap object.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if permanent storage cannot reserve the object.
    pub(crate) fn aos_alloc_string(&mut self, len: usize) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena.aos_alloc_string(len)?;
        self.record_allocation_safepoint(RuntimeAllocationEntryPoint::AosAllocString, allocation);
        Ok(allocation)
    }

    fn record_allocation_safepoint(
        &mut self,
        entrypoint: RuntimeAllocationEntryPoint,
        allocation: ArenaAllocation,
    ) {
        self.safepoints
            .record(self.tier(), entrypoint, allocation, self.stats());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::compile::{RuntimeHelperRole, runtime_helper_symbols};
    use crate::heap::arena::HeapObjectKind;

    use super::*;

    fn assert_last_safepoint(
        state: AllocationSafepointState,
        sequence: u64,
        tier: RuntimeAllocatorTier,
        entrypoint: RuntimeAllocationEntryPoint,
        allocation: ArenaAllocation,
        stats: ArenaStats,
    ) {
        assert_eq!(state.count(), sequence);
        let event = state.last().expect("safepoint records");
        assert_eq!(event.sequence(), sequence);
        assert_eq!(event.tier(), tier);
        assert_eq!(event.entrypoint(), entrypoint);
        assert_eq!(event.kind(), allocation.kind);
        assert_eq!(event.requested_size(), allocation.requested_size);
        assert_eq!(event.reserved_size(), allocation.reserved_size);
        assert_eq!(event.stats_after(), stats);
        assert_eq!(event.heap_chunks_after(), stats.chunks);
        assert_eq!(event.heap_used_bytes_after(), stats.used_bytes);
        assert_eq!(event.heap_reserved_bytes_after(), stats.reserved_bytes);
        assert_eq!(event.heap_mapped_bytes_after(), stats.mapped_bytes);
    }

    #[test]
    fn tier_a_allocator_routes_every_entrypoint() {
        let mut allocator =
            RuntimeAllocator::tier_a_with_initial_chunk_bytes(512).expect("allocator creates");

        assert_eq!(allocator.tier(), RuntimeAllocatorTier::TierAOneShot);
        assert_eq!(
            allocator.allocation_safepoints(),
            AllocationSafepointState::default()
        );
        let allocation = allocator.aos_alloc_thunk().expect("thunk allocates");
        assert_eq!(allocation.kind, HeapObjectKind::Thunk);
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            1,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocThunk,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator.aos_alloc_lambda().expect("lambda allocates");
        assert_eq!(allocation.kind, HeapObjectKind::Lambda);
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            2,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocLambda,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator.aos_alloc_attrs(7, 2).expect("attrs allocates");
        assert_eq!(
            allocation.kind,
            HeapObjectKind::Attrs { shape: 7, slots: 2 }
        );
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            3,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocAttrs,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator.aos_alloc_cons().expect("cons allocates");
        assert_eq!(allocation.kind, HeapObjectKind::Cons);
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            4,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocCons,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator.aos_alloc_list(3).expect("list allocates");
        assert_eq!(allocation.kind, HeapObjectKind::List { len: 3 });
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            5,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocList,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator.aos_alloc_string(5).expect("string allocates");
        assert_eq!(allocation.kind, HeapObjectKind::String { len: 5 });
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            6,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocString,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator
            .aos_alloc_raw(8, 8, 0x7261_7770)
            .expect("raw allocates");
        assert_eq!(
            allocation.kind,
            HeapObjectKind::Raw {
                type_tag: 0x7261_7770,
            }
        );
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            7,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocRaw,
            allocation,
            allocator.stats(),
        );

        let stats = allocator.stats();
        assert_eq!(stats.chunks, 1);
        assert!(stats.used_bytes > 0);
    }

    #[test]
    fn permanent_shared_allocator_routes_only_reusable_value_shapes() {
        let mut allocator =
            PermanentSharedAllocator::with_initial_chunk_bytes(256).expect("allocator creates");

        assert_eq!(allocator.tier(), RuntimeAllocatorTier::PermanentShared);
        assert_eq!(allocator.stats(), ArenaStats::default());
        assert_eq!(
            allocator.allocation_safepoints(),
            AllocationSafepointState::default()
        );
        let allocation = allocator.aos_alloc_attrs(7, 2).expect("attrs allocates");
        assert_eq!(
            allocation.kind,
            HeapObjectKind::Attrs { shape: 7, slots: 2 }
        );
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            1,
            RuntimeAllocatorTier::PermanentShared,
            RuntimeAllocationEntryPoint::AosAllocAttrs,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator.aos_alloc_list(3).expect("list allocates");
        assert_eq!(allocation.kind, HeapObjectKind::List { len: 3 });
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            2,
            RuntimeAllocatorTier::PermanentShared,
            RuntimeAllocationEntryPoint::AosAllocList,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator.aos_alloc_string(5).expect("string allocates");
        assert_eq!(allocation.kind, HeapObjectKind::String { len: 5 });
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            3,
            RuntimeAllocatorTier::PermanentShared,
            RuntimeAllocationEntryPoint::AosAllocString,
            allocation,
            allocator.stats(),
        );

        let stats = allocator.stats();
        assert_eq!(stats.chunks, 1);
        assert!(stats.used_bytes > 0);
    }

    #[test]
    fn runtime_abi_declares_allocator_entrypoint_names() {
        let allocation_symbols = runtime_helper_symbols()
            .iter()
            .copied()
            .filter(|symbol| symbol.role() == RuntimeHelperRole::Allocation)
            .map(|symbol| symbol.name())
            .collect::<BTreeSet<_>>();

        assert_eq!(
            allocation_symbols,
            BTreeSet::from([
                "aos_alloc_attrs",
                "aos_alloc_cons",
                "aos_alloc_lambda",
                "aos_alloc_list",
                "aos_alloc_raw",
                "aos_alloc_string",
                "aos_alloc_thunk",
            ])
        );
    }

    #[test]
    fn invalid_tier_a_chunk_size_is_rejected() {
        let error = RuntimeAllocator::tier_a_with_initial_chunk_bytes(0)
            .expect_err("zero-sized chunks are invalid");

        assert_eq!(error, ArenaError::InvalidChunkSize { chunk_bytes: 0 });
    }
}
