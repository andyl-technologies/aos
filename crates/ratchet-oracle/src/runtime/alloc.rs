//! Runtime allocation strategy dispatch for evaluator heap objects.
//!
//! The tree-walk oracle allocates through this layer instead of naming a heap
//! backend directly. Today the default worker strategy is the Tier-A one-shot
//! bump arena, an opt-in Tier-A backend can route through the current thread's
//! arena, and a separate permanent-shared bump arena stores hash-consed values.
//! Later Phase-3 work can install the precise generational collector behind the
//! same worker `aos_alloc_*` entry-point surface. A
//! [`RuntimeAllocationRequest`] provides the current safe Rust call boundary
//! that native wrappers can eventually lower into the same dispatch table.

use std::{
    collections::HashMap,
    mem,
    sync::{
        LazyLock, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread::{self, ThreadId},
};

use crate::heap::arena::{
    ArenaAllocation, ArenaError, ArenaMemoryAdviceReport, ArenaRegionMark, ArenaRegionPopReport,
    ArenaStats, BumpArena, HeapObjectKind, ThreadLocalBumpArena,
};
use crate::heap::{HeapMemoryBudget, HeapMemoryBudgetResponse, HeapMemorySample, MemoryAdviceKind};

static NEXT_THREAD_LOCAL_RUNTIME_ALLOCATOR_TOKEN: AtomicU64 = AtomicU64::new(1);
static THREAD_LOCAL_RUNTIME_ALLOCATOR_OWNERS: LazyLock<Mutex<HashMap<ThreadId, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn with_thread_local_runtime_allocator_owners<R>(
    f: impl FnOnce(&mut HashMap<ThreadId, u64>) -> R,
) -> R {
    let owners = THREAD_LOCAL_RUNTIME_ALLOCATOR_OWNERS.lock();
    let mut owners = match owners {
        Ok(owners) => owners,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(&mut owners)
}

fn reserve_thread_local_runtime_allocator(owner: ThreadId) -> u64 {
    let token = match NEXT_THREAD_LOCAL_RUNTIME_ALLOCATOR_TOKEN.fetch_update(
        Ordering::Relaxed,
        Ordering::Relaxed,
        |token| token.checked_add(1),
    ) {
        Ok(token) => token,
        Err(_) => panic!("thread-local runtime allocator token space exhausted"),
    };
    with_thread_local_runtime_allocator_owners(|owners| {
        assert!(
            !owners.contains_key(&owner),
            "thread already has an active thread-local runtime allocator"
        );
        owners.insert(owner, token);
    });
    token
}

fn release_thread_local_runtime_allocator(owner: ThreadId, token: u64) {
    with_thread_local_runtime_allocator_owners(|owners| {
        if owners.get(&owner).copied() == Some(token) {
            owners.remove(&owner);
        }
    });
}

fn assert_thread_local_runtime_allocator_owner(owner: ThreadId, token: u64) {
    assert_eq!(
        thread::current().id(),
        owner,
        "thread-local runtime allocator used from a different thread"
    );
    with_thread_local_runtime_allocator_owners(|owners| {
        assert_eq!(
            owners.get(&owner).copied(),
            Some(token),
            "thread-local runtime allocator is no longer active for this thread"
        );
    });
}

mod descriptors;
mod request_types;
mod safepoint;
pub use descriptors::*;
pub use request_types::*;
pub use safepoint::*;
/// Routes heap allocations through the active runtime allocation strategy.
#[derive(Debug)]
pub struct RuntimeAllocator {
    backend: RuntimeAllocatorBackend,
    safepoints: AllocationSafepointState,
    gc_stress_policy: GcStressPolicy,
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
            gc_stress_policy: GcStressPolicy::disabled(),
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
            gc_stress_policy: GcStressPolicy::disabled(),
        })
    }

    /// Creates a Tier-A runtime allocator backed by the current thread's arena.
    ///
    /// The allocator preserves the same `TierAOneShot` safepoint tier and
    /// `aos_alloc_*` dispatch table as [`Self::tier_a_one_shot`], but allocation
    /// storage comes from [`ThreadLocalBumpArena`] instead of an owned
    /// [`BumpArena`]. Exactly one thread-local runtime allocator may be active
    /// on a worker thread at a time, and using that allocator from another
    /// thread fails closed. This is the per-worker arena precursor; it is
    /// opt-in and does not change the tree-walk evaluator's default owned
    /// arena.
    ///
    /// # Panics
    ///
    /// Panics if the current thread already has an active thread-local runtime
    /// allocator, or if the internal owner-token counter is exhausted.
    pub fn tier_a_thread_local() -> Self {
        let owner = thread::current().id();
        let token = reserve_thread_local_runtime_allocator(owner);
        Self {
            backend: RuntimeAllocatorBackend::TierAThreadLocal { owner, token },
            safepoints: AllocationSafepointState::default(),
            gc_stress_policy: GcStressPolicy::disabled(),
        }
    }

    /// Creates a Tier-A thread-local allocator after clearing the worker arena.
    ///
    /// This constructor preserves the same dispatch and ownership checks as
    /// [`Self::tier_a_thread_local`], but it first replaces the current
    /// thread's [`ThreadLocalBumpArena`] with an empty arena. Owned evaluator
    /// runs use this path so a previous opt-in run cannot leak worker allocation
    /// accounting into the next one.
    ///
    /// # Panics
    ///
    /// Panics if the current thread already has an active thread-local runtime
    /// allocator, if the internal owner-token counter is exhausted, or if the
    /// current thread's arena is already mutably borrowed.
    pub fn tier_a_thread_local_empty() -> Self {
        let owner = thread::current().id();
        let token = reserve_thread_local_runtime_allocator(owner);
        if let Err(payload) = std::panic::catch_unwind(ThreadLocalBumpArena::reset_current) {
            release_thread_local_runtime_allocator(owner, token);
            std::panic::resume_unwind(payload);
        }
        Self {
            backend: RuntimeAllocatorBackend::TierAThreadLocal { owner, token },
            safepoints: AllocationSafepointState::default(),
            gc_stress_policy: GcStressPolicy::disabled(),
        }
    }

    /// Returns this allocator with a GC-stress polling policy installed.
    pub fn with_gc_stress_policy(mut self, policy: GcStressPolicy) -> Self {
        self.gc_stress_policy = policy;
        self
    }

    /// Installs a GC-stress polling policy for later allocation safepoints.
    ///
    /// Periodic policies use this allocator's lifetime safepoint sequence, so
    /// installing a policy does not reset the cadence.
    pub fn set_gc_stress_policy(&mut self, policy: GcStressPolicy) {
        self.gc_stress_policy = policy;
    }

    /// Returns the installed GC-stress polling policy.
    pub const fn gc_stress_policy(&self) -> GcStressPolicy {
        self.gc_stress_policy
    }

    /// Returns the installed allocation tier.
    pub fn tier(&self) -> RuntimeAllocatorTier {
        match &self.backend {
            RuntimeAllocatorBackend::TierAOneShot(_) => RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocatorBackend::TierAThreadLocal { .. } => RuntimeAllocatorTier::TierAOneShot,
        }
    }

    /// Returns whether this allocator stores worker allocations in thread-local Tier-A storage.
    pub fn uses_thread_local_tier_a(&self) -> bool {
        matches!(
            self.backend,
            RuntimeAllocatorBackend::TierAThreadLocal { .. }
        )
    }

    /// Returns the safe allocation dispatch table for the installed backend.
    fn allocation_vtable(&self) -> &'static RuntimeAllocationVTable {
        let vtable = match &self.backend {
            RuntimeAllocatorBackend::TierAOneShot(_)
            | RuntimeAllocatorBackend::TierAThreadLocal { .. } => {
                &TIER_A_ONE_SHOT_ALLOCATION_VTABLE
            }
        };
        debug_assert_eq!(vtable.tier(), self.tier());
        debug_assert_eq!(vtable.entrypoints(), runtime_allocation_entrypoints());
        debug_assert_eq!(vtable.abi_signatures(), runtime_allocation_abi_signatures());
        vtable
    }

    /// Returns current allocation accounting for the installed strategy.
    ///
    /// # Panics
    ///
    /// Panics when this allocator uses [`Self::tier_a_thread_local`] from a
    /// different thread, when its thread-local owner token is inactive, or when
    /// the current thread's arena is already mutably borrowed.
    pub fn stats(&self) -> ArenaStats {
        match &self.backend {
            RuntimeAllocatorBackend::TierAOneShot(arena) => arena.stats(),
            RuntimeAllocatorBackend::TierAThreadLocal { owner, token } => {
                assert_thread_local_runtime_allocator_owner(*owner, *token);
                ThreadLocalBumpArena::with_current(|arena| arena.stats())
            }
        }
    }

    /// Advises unused bytes at the end of chunks owned by this allocator.
    ///
    /// # Panics
    ///
    /// Panics when this allocator uses [`Self::tier_a_thread_local`] from a
    /// different thread, when its thread-local owner token is inactive, or when
    /// the current thread's arena is already mutably borrowed.
    pub fn advise_unused_tail(&self, kind: MemoryAdviceKind) -> ArenaMemoryAdviceReport {
        match &self.backend {
            RuntimeAllocatorBackend::TierAOneShot(arena) => arena.advise_unused_tail(kind),
            RuntimeAllocatorBackend::TierAThreadLocal { owner, token } => {
                assert_thread_local_runtime_allocator_owner(*owner, *token);
                ThreadLocalBumpArena::with_current(|arena| arena.advise_unused_tail(kind))
            }
        }
    }

    /// Returns unused-tail bytes this allocator can lower to page advice.
    ///
    /// # Panics
    ///
    /// Panics when this allocator uses [`Self::tier_a_thread_local`] from a
    /// different thread, when its thread-local owner token is inactive, or when
    /// the current thread's arena is already mutably borrowed.
    pub fn supported_unused_tail_advice_bytes(&self) -> usize {
        match &self.backend {
            RuntimeAllocatorBackend::TierAOneShot(arena) => {
                arena.supported_unused_tail_advice_bytes()
            }
            RuntimeAllocatorBackend::TierAThreadLocal { owner, token } => {
                assert_thread_local_runtime_allocator_owner(*owner, *token);
                ThreadLocalBumpArena::with_current(|arena| {
                    arena.supported_unused_tail_advice_bytes()
                })
            }
        }
    }

    /// Captures the current worker allocator position for lexical reclamation.
    pub(crate) fn region_mark(&self) -> RuntimeAllocatorRegionMark {
        match &self.backend {
            RuntimeAllocatorBackend::TierAOneShot(arena) => {
                RuntimeAllocatorRegionMark::new(arena.region_mark(), self.safepoints)
            }
            RuntimeAllocatorBackend::TierAThreadLocal { owner, token } => {
                assert_thread_local_runtime_allocator_owner(*owner, *token);
                ThreadLocalBumpArena::with_current(|arena| {
                    RuntimeAllocatorRegionMark::new(arena.region_mark(), self.safepoints)
                })
            }
        }
    }

    /// Restores the worker allocator to a previously captured region marker.
    ///
    /// The caller must first validate and invalidate any typed heap records for
    /// allocations above the marker. Successful pops also roll allocation
    /// safepoint accounting back to the marker so later collector polls cannot
    /// describe reclaimed allocations.
    pub(crate) fn pop_caller_validated_region(
        &mut self,
        mark: RuntimeAllocatorRegionMark,
        _reclaimed_records: usize,
    ) -> Result<ArenaRegionPopReport, ArenaError> {
        let report = self.with_tier_a_arena_mut(|arena| {
            arena.pop_caller_validated_region_to_mark(mark.arena())
        })?;
        self.safepoints = mark.safepoints();
        Ok(report)
    }

    /// Returns allocation-safepoint accounting for this allocator domain.
    pub const fn allocation_safepoints(&self) -> AllocationSafepointState {
        self.safepoints
    }

    /// Drops the installed worker arena and replaces it with an empty arena.
    ///
    /// For owned Tier-A allocators, the method replaces the owned
    /// [`BumpArena`]. For thread-local allocators, it resets the current
    /// thread's [`ThreadLocalBumpArena`]. The returned accounting describes the
    /// dropped arena. The installed GC-stress policy is preserved for the next
    /// worker lifetime, while allocation-safepoint accounting is reset with the
    /// new empty arena. Any allocation handles returned before the reset must be
    /// considered dead by the caller;
    /// [`EvalHeap::reset_worker_allocator_if_idle`](crate::eval::heap::EvalHeap::reset_worker_allocator_if_idle)
    /// is the typed side-table admission boundary for evaluator-owned values.
    ///
    /// # Panics
    ///
    /// Panics when this allocator uses [`Self::tier_a_thread_local`] from a
    /// different thread, when its thread-local owner token is inactive, or when
    /// the current thread's arena is already mutably borrowed.
    pub(crate) fn reset_to_empty(&mut self) -> ArenaStats {
        let stats = match &mut self.backend {
            RuntimeAllocatorBackend::TierAOneShot(arena) => {
                let previous = mem::take(arena);
                previous.stats()
            }
            RuntimeAllocatorBackend::TierAThreadLocal { owner, token } => {
                assert_thread_local_runtime_allocator_owner(*owner, *token);
                ThreadLocalBumpArena::reset_current()
            }
        };
        self.safepoints = AllocationSafepointState::default();
        stats
    }

    /// Allocates heap storage through the active runtime allocation request path.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    ///
    /// # Panics
    ///
    /// Panics when this allocator uses [`Self::tier_a_thread_local`] from a
    /// different thread, when its thread-local owner token is inactive, or when
    /// the current thread's arena is already mutably borrowed.
    pub fn allocate(
        &mut self,
        request: RuntimeAllocationRequest,
    ) -> Result<ArenaAllocation, ArenaError> {
        self.allocation_vtable().allocate(self, request)
    }

    /// Records a worker allocation safepoint for a flat thunk object.
    ///
    /// RFC-0007 doc 30 FV-3: flat worker closures are allocated by the
    /// evaluator heap's flat closure store, which owns its own arena. The
    /// worker domain's safepoint sequence and GC-stress polling cadence must
    /// keep observing those allocations exactly as they observed the
    /// record-backed thunk allocations, so the heap replays each flat
    /// allocation here under the same `aos_alloc_thunk` request shape.
    pub(crate) fn record_flat_thunk_allocation_safepoint(&mut self, allocation: ArenaAllocation) {
        self.record_allocation_safepoint(RuntimeAllocationRequest::Thunk, allocation);
    }

    /// Records a worker allocation safepoint for a flat lambda object.
    ///
    /// The lambda analog of
    /// [`RuntimeAllocator::record_flat_thunk_allocation_safepoint`], replayed
    /// under the `aos_alloc_lambda` request shape.
    pub(crate) fn record_flat_lambda_allocation_safepoint(&mut self, allocation: ArenaAllocation) {
        self.record_allocation_safepoint(RuntimeAllocationRequest::Lambda, allocation);
    }

    /// Records a worker allocation safepoint for a flat primop object.
    ///
    /// The builtin-record analog of
    /// [`RuntimeAllocator::record_flat_thunk_allocation_safepoint`], replayed
    /// under the raw request shape record-backed primop handles used.
    pub(crate) fn record_flat_primop_allocation_safepoint(
        &mut self,
        size: usize,
        align: usize,
        type_tag: u32,
        allocation: ArenaAllocation,
    ) {
        self.record_allocation_safepoint(
            RuntimeAllocationRequest::Raw {
                size,
                align,
                type_tag,
            },
            allocation,
        );
    }

    /// Allocates a thunk-sized heap object through `aos_alloc_thunk`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::allocate`].
    pub fn aos_alloc_thunk(&mut self) -> Result<ArenaAllocation, ArenaError> {
        self.allocate(RuntimeAllocationRequest::Thunk)
    }

    /// Allocates a lambda-sized heap object through `aos_alloc_lambda`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::allocate`].
    pub fn aos_alloc_lambda(&mut self) -> Result<ArenaAllocation, ArenaError> {
        self.allocate(RuntimeAllocationRequest::Lambda)
    }

    /// Allocates an attribute-set heap object through `aos_alloc_attrs`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::allocate`].
    pub fn aos_alloc_attrs(
        &mut self,
        shape: u32,
        slots: u32,
    ) -> Result<ArenaAllocation, ArenaError> {
        self.allocate(RuntimeAllocationRequest::Attrs { shape, slots })
    }

    /// Allocates a cons-cell heap object through `aos_alloc_cons`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::allocate`].
    pub fn aos_alloc_cons(&mut self) -> Result<ArenaAllocation, ArenaError> {
        self.allocate(RuntimeAllocationRequest::Cons)
    }

    /// Allocates a contiguous list heap object through `aos_alloc_list`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::allocate`].
    pub fn aos_alloc_list(&mut self, len: usize) -> Result<ArenaAllocation, ArenaError> {
        self.allocate(RuntimeAllocationRequest::List { len })
    }

    /// Allocates a string heap object through `aos_alloc_string`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::allocate`].
    pub fn aos_alloc_string(&mut self, len: usize) -> Result<ArenaAllocation, ArenaError> {
        self.allocate(RuntimeAllocationRequest::String { len })
    }

    /// Allocates raw heap storage through `aos_alloc_raw`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::allocate`].
    pub fn aos_alloc_raw(
        &mut self,
        size: usize,
        align: usize,
        type_tag: u32,
    ) -> Result<ArenaAllocation, ArenaError> {
        self.allocate(RuntimeAllocationRequest::Raw {
            size,
            align,
            type_tag,
        })
    }

    fn with_tier_a_arena_mut<R>(&mut self, f: impl FnOnce(&mut BumpArena) -> R) -> R {
        match &mut self.backend {
            RuntimeAllocatorBackend::TierAOneShot(arena) => f(arena),
            RuntimeAllocatorBackend::TierAThreadLocal { owner, token } => {
                assert_thread_local_runtime_allocator_owner(*owner, *token);
                ThreadLocalBumpArena::with_current(f)
            }
        }
    }

    fn record_allocation_safepoint(
        &mut self,
        request: RuntimeAllocationRequest,
        allocation: ArenaAllocation,
    ) {
        let tier = self.tier();
        let stats = self.stats();
        let gc_stress_policy = self.gc_stress_policy;
        self.safepoints
            .record(tier, request, allocation, stats, gc_stress_policy);
    }
}

impl Drop for RuntimeAllocator {
    fn drop(&mut self) {
        if let RuntimeAllocatorBackend::TierAThreadLocal { owner, token } = &self.backend {
            release_thread_local_runtime_allocator(*owner, *token);
        }
    }
}

fn tier_a_alloc_thunk(allocator: &mut RuntimeAllocator) -> Result<ArenaAllocation, ArenaError> {
    let allocation = allocator.with_tier_a_arena_mut(BumpArena::aos_alloc_thunk)?;
    allocator.record_allocation_safepoint(RuntimeAllocationRequest::Thunk, allocation);
    Ok(allocation)
}

fn tier_a_alloc_lambda(allocator: &mut RuntimeAllocator) -> Result<ArenaAllocation, ArenaError> {
    let allocation = allocator.with_tier_a_arena_mut(BumpArena::aos_alloc_lambda)?;
    allocator.record_allocation_safepoint(RuntimeAllocationRequest::Lambda, allocation);
    Ok(allocation)
}

fn tier_a_alloc_attrs(
    allocator: &mut RuntimeAllocator,
    shape: u32,
    slots: u32,
) -> Result<ArenaAllocation, ArenaError> {
    let allocation =
        allocator.with_tier_a_arena_mut(|arena| arena.aos_alloc_attrs(shape, slots))?;
    allocator
        .record_allocation_safepoint(RuntimeAllocationRequest::Attrs { shape, slots }, allocation);
    Ok(allocation)
}

fn tier_a_alloc_cons(allocator: &mut RuntimeAllocator) -> Result<ArenaAllocation, ArenaError> {
    let allocation = allocator.with_tier_a_arena_mut(BumpArena::aos_alloc_cons)?;
    allocator.record_allocation_safepoint(RuntimeAllocationRequest::Cons, allocation);
    Ok(allocation)
}

fn tier_a_alloc_list(
    allocator: &mut RuntimeAllocator,
    len: usize,
) -> Result<ArenaAllocation, ArenaError> {
    let allocation = allocator.with_tier_a_arena_mut(|arena| arena.aos_alloc_list(len))?;
    allocator.record_allocation_safepoint(RuntimeAllocationRequest::List { len }, allocation);
    Ok(allocation)
}

fn tier_a_alloc_string(
    allocator: &mut RuntimeAllocator,
    len: usize,
) -> Result<ArenaAllocation, ArenaError> {
    let allocation = allocator.with_tier_a_arena_mut(|arena| arena.aos_alloc_string(len))?;
    allocator.record_allocation_safepoint(RuntimeAllocationRequest::String { len }, allocation);
    Ok(allocation)
}

fn tier_a_alloc_raw(
    allocator: &mut RuntimeAllocator,
    size: usize,
    align: usize,
    type_tag: u32,
) -> Result<ArenaAllocation, ArenaError> {
    let allocation =
        allocator.with_tier_a_arena_mut(|arena| arena.aos_alloc_raw(size, align, type_tag))?;
    allocator.record_allocation_safepoint(
        RuntimeAllocationRequest::Raw {
            size,
            align,
            type_tag,
        },
        allocation,
    );
    Ok(allocation)
}

fn native_aos_alloc_thunk(allocator: &mut RuntimeAllocator) -> Result<ArenaAllocation, ArenaError> {
    allocator.aos_alloc_thunk()
}

fn native_aos_alloc_lambda(
    allocator: &mut RuntimeAllocator,
) -> Result<ArenaAllocation, ArenaError> {
    allocator.aos_alloc_lambda()
}

fn native_aos_alloc_attrs(
    allocator: &mut RuntimeAllocator,
    shape: u32,
    slots: u32,
) -> Result<ArenaAllocation, ArenaError> {
    allocator.aos_alloc_attrs(shape, slots)
}

fn native_aos_alloc_cons(allocator: &mut RuntimeAllocator) -> Result<ArenaAllocation, ArenaError> {
    allocator.aos_alloc_cons()
}

fn native_aos_alloc_list(
    allocator: &mut RuntimeAllocator,
    len: usize,
) -> Result<ArenaAllocation, ArenaError> {
    allocator.aos_alloc_list(len)
}

fn native_aos_alloc_string(
    allocator: &mut RuntimeAllocator,
    len: usize,
) -> Result<ArenaAllocation, ArenaError> {
    allocator.aos_alloc_string(len)
}

fn native_aos_alloc_raw(
    allocator: &mut RuntimeAllocator,
    size: usize,
    align: usize,
    type_tag: u32,
) -> Result<ArenaAllocation, ArenaError> {
    allocator.aos_alloc_raw(size, align, type_tag)
}

#[derive(Debug)]
enum RuntimeAllocatorBackend {
    TierAOneShot(BumpArena),
    TierAThreadLocal { owner: ThreadId, token: u64 },
}

/// Allocates reusable hash-consed values in permanent shared storage.
#[derive(Debug)]
pub(crate) struct PermanentSharedAllocator {
    arena: BumpArena,
    safepoints: AllocationSafepointState,
    gc_stress_policy: GcStressPolicy,
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
            gc_stress_policy: GcStressPolicy::disabled(),
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
            gc_stress_policy: GcStressPolicy::disabled(),
        })
    }

    /// Installs a GC-stress polling policy for later allocation safepoints.
    ///
    /// Periodic policies use this allocator's lifetime safepoint sequence, so
    /// installing a policy does not reset the cadence.
    pub(crate) fn set_gc_stress_policy(&mut self, policy: GcStressPolicy) {
        self.gc_stress_policy = policy;
    }

    /// Returns the installed GC-stress polling policy.
    pub(crate) const fn gc_stress_policy(&self) -> GcStressPolicy {
        self.gc_stress_policy
    }

    /// Returns the allocator tier for permanent shared storage.
    pub(crate) const fn tier(&self) -> RuntimeAllocatorTier {
        RuntimeAllocatorTier::PermanentShared
    }

    /// Returns current permanent shared allocation accounting.
    pub(crate) fn stats(&self) -> ArenaStats {
        self.arena.stats()
    }

    /// Advises unused bytes at the end of permanent shared arena chunks.
    pub(crate) fn advise_unused_tail(&self, kind: MemoryAdviceKind) -> ArenaMemoryAdviceReport {
        self.arena.advise_unused_tail(kind)
    }

    /// Returns unused-tail bytes this allocator can lower to page advice.
    pub(crate) fn supported_unused_tail_advice_bytes(&self) -> usize {
        self.arena.supported_unused_tail_advice_bytes()
    }

    /// Returns allocation-safepoint accounting for permanent shared storage.
    pub(crate) const fn allocation_safepoints(&self) -> AllocationSafepointState {
        self.safepoints
    }

    /// Test-only permanent allocation through the retired reusable route.
    ///
    /// FV-1/FV-2 moved every production string/list/attrs allocation into the
    /// evaluator heap's flat stores and FV-3 retired the permanent-shared
    /// typed-allocation vtable outright; this helper keeps the permanent
    /// domain's arena accounting, unused-tail advice, and GC-stress poll
    /// machinery testable by reserving arena storage and replaying the same
    /// safepoint shape the retired `aos_alloc_string` route recorded.
    #[cfg(test)]
    pub(crate) fn test_alloc_string(&mut self, len: usize) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena.aos_alloc_string(len)?;
        self.record_allocation_safepoint(RuntimeAllocationRequest::String { len }, allocation);
        Ok(allocation)
    }

    /// Records a permanent allocation safepoint for a flat string/path object.
    ///
    /// RFC-0007 doc 30 FV-1: flat strings and paths are allocated by the
    /// evaluator heap's flat object store, which owns its own arena. The
    /// permanent domain's safepoint sequence and GC-stress polling cadence
    /// must keep observing those allocations exactly as they observed the
    /// record-backed string allocations, so the heap replays each flat
    /// allocation here under the same `aos_alloc_string` request shape.
    pub(crate) fn record_flat_allocation_safepoint(
        &mut self,
        len: usize,
        allocation: ArenaAllocation,
    ) {
        self.record_allocation_safepoint(RuntimeAllocationRequest::String { len }, allocation);
    }

    /// Records a permanent allocation safepoint for a flat list object.
    ///
    /// The list analog of
    /// [`PermanentSharedAllocator::record_flat_allocation_safepoint`]: flat
    /// lists are allocated by the evaluator heap's flat list store, and the
    /// permanent domain's safepoint sequence and GC-stress polling cadence
    /// must observe them exactly as they observed record-backed list
    /// allocations, under the same `aos_alloc_list` request shape.
    pub(crate) fn record_flat_list_allocation_safepoint(
        &mut self,
        len: usize,
        allocation: ArenaAllocation,
    ) {
        self.record_allocation_safepoint(RuntimeAllocationRequest::List { len }, allocation);
    }

    /// Records a permanent allocation safepoint for a flat attrset object.
    ///
    /// The attrs analog of
    /// [`PermanentSharedAllocator::record_flat_allocation_safepoint`]
    /// (doc 30 FV-2): flat attrsets are allocated by the evaluator heap's
    /// flat attrs store, and the permanent domain's safepoint sequence and
    /// GC-stress polling cadence must observe them exactly as they observed
    /// record-backed attrset allocations, under the same `aos_alloc_attrs`
    /// request shape.
    pub(crate) fn record_flat_attrs_allocation_safepoint(
        &mut self,
        shape: u32,
        slots: u32,
        allocation: ArenaAllocation,
    ) {
        self.record_allocation_safepoint(
            RuntimeAllocationRequest::Attrs { shape, slots },
            allocation,
        );
    }

    fn record_allocation_safepoint(
        &mut self,
        request: RuntimeAllocationRequest,
        allocation: ArenaAllocation,
    ) {
        let tier = self.tier();
        let stats = self.stats();
        let gc_stress_policy = self.gc_stress_policy;
        self.safepoints
            .record(tier, request, allocation, stats, gc_stress_policy);
    }
}

#[cfg(test)]
mod tests;
