//! Runtime allocation strategy dispatch for evaluator heap objects.
//!
//! The tree-walk oracle allocates through this layer instead of naming a heap
//! backend directly. Today the installed worker strategy is the Tier-A one-shot
//! bump arena, with a separate permanent-shared bump arena for hash-consed
//! values. Later Phase-3 work can install the precise generational collector
//! behind the same worker `aos_alloc_*` entry-point surface.

use crate::heap::arena::{ArenaAllocation, ArenaError, ArenaStats, BumpArena};

/// The installed runtime allocation strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAllocatorTier {
    /// One-shot CLI evaluation backed by a never-free bump arena.
    TierAOneShot,
    /// Hash-consed shared values backed by a non-collected permanent arena.
    PermanentShared,
}

/// Routes heap allocations through the active runtime allocation strategy.
#[derive(Debug)]
pub struct RuntimeAllocator {
    backend: RuntimeAllocatorBackend,
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

    /// Allocates a thunk-sized heap object through `aos_alloc_thunk`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    pub fn aos_alloc_thunk(&mut self) -> Result<ArenaAllocation, ArenaError> {
        self.arena_mut().aos_alloc_thunk()
    }

    /// Allocates a lambda-sized heap object through `aos_alloc_lambda`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    pub fn aos_alloc_lambda(&mut self) -> Result<ArenaAllocation, ArenaError> {
        self.arena_mut().aos_alloc_lambda()
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
        self.arena_mut().aos_alloc_attrs(shape, slots)
    }

    /// Allocates a cons-cell heap object through `aos_alloc_cons`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    pub fn aos_alloc_cons(&mut self) -> Result<ArenaAllocation, ArenaError> {
        self.arena_mut().aos_alloc_cons()
    }

    /// Allocates a contiguous list heap object through `aos_alloc_list`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    pub fn aos_alloc_list(&mut self, len: usize) -> Result<ArenaAllocation, ArenaError> {
        self.arena_mut().aos_alloc_list(len)
    }

    /// Allocates a string heap object through `aos_alloc_string`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    pub fn aos_alloc_string(&mut self, len: usize) -> Result<ArenaAllocation, ArenaError> {
        self.arena_mut().aos_alloc_string(len)
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
        self.arena_mut().aos_alloc_raw(size, align, type_tag)
    }

    fn arena_mut(&mut self) -> &mut BumpArena {
        match &mut self.backend {
            RuntimeAllocatorBackend::TierAOneShot(arena) => arena,
        }
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
        self.arena.aos_alloc_attrs(shape, slots)
    }

    /// Allocates a permanent-shared contiguous list heap object.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if permanent storage cannot reserve the object.
    pub(crate) fn aos_alloc_list(&mut self, len: usize) -> Result<ArenaAllocation, ArenaError> {
        self.arena.aos_alloc_list(len)
    }

    /// Allocates a permanent-shared string or path heap object.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if permanent storage cannot reserve the object.
    pub(crate) fn aos_alloc_string(&mut self, len: usize) -> Result<ArenaAllocation, ArenaError> {
        self.arena.aos_alloc_string(len)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::compile::{RuntimeHelperRole, runtime_helper_symbols};
    use crate::heap::arena::HeapObjectKind;

    use super::*;

    #[test]
    fn tier_a_allocator_routes_every_entrypoint() {
        let mut allocator =
            RuntimeAllocator::tier_a_with_initial_chunk_bytes(512).expect("allocator creates");

        assert_eq!(allocator.tier(), RuntimeAllocatorTier::TierAOneShot);
        assert_eq!(
            allocator.aos_alloc_thunk().expect("thunk allocates").kind,
            HeapObjectKind::Thunk
        );
        assert_eq!(
            allocator.aos_alloc_lambda().expect("lambda allocates").kind,
            HeapObjectKind::Lambda
        );
        assert_eq!(
            allocator
                .aos_alloc_attrs(7, 2)
                .expect("attrs allocates")
                .kind,
            HeapObjectKind::Attrs { shape: 7, slots: 2 }
        );
        assert_eq!(
            allocator.aos_alloc_cons().expect("cons allocates").kind,
            HeapObjectKind::Cons
        );
        assert_eq!(
            allocator.aos_alloc_list(3).expect("list allocates").kind,
            HeapObjectKind::List { len: 3 }
        );
        assert_eq!(
            allocator
                .aos_alloc_string(5)
                .expect("string allocates")
                .kind,
            HeapObjectKind::String { len: 5 }
        );
        assert_eq!(
            allocator
                .aos_alloc_raw(8, 8, 0x7261_7770)
                .expect("raw allocates")
                .kind,
            HeapObjectKind::Raw {
                type_tag: 0x7261_7770,
            }
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
            allocator
                .aos_alloc_attrs(7, 2)
                .expect("attrs allocates")
                .kind,
            HeapObjectKind::Attrs { shape: 7, slots: 2 }
        );
        assert_eq!(
            allocator.aos_alloc_list(3).expect("list allocates").kind,
            HeapObjectKind::List { len: 3 }
        );
        assert_eq!(
            allocator
                .aos_alloc_string(5)
                .expect("string allocates")
                .kind,
            HeapObjectKind::String { len: 5 }
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
