//! Stable serial thunk heads and reclaimable suspended-work slots.
//!
//! This is the default-off RFC-0007 typed-head proving ground. A runtime
//! [`Value`] addresses a permanent flat head containing only the authoritative
//! [`ThunkCell`] and a generational work handle. Deferred [`EvalThunk`] work
//! lives in a compact indexed pool. Slots are reused only after successful
//! force publication, and every reuse advances the generation so a delayed
//! handle cannot observe unrelated work after an ABA cycle.
//!
//! The first experiment admits only serial one-argument Apply-shaped thunks:
//! ordinary `Apply` and the layout-identical `GenListElemAtAddOne` marker. It
//! keeps the full work record in the pool deliberately: the census measured
//! the peak simultaneously-live work rather than total allocations, and
//! recycling fixed-size slots tests that bound without first redesigning every
//! work variant.

#[cfg(not(feature = "candidate_c_value"))]
use std::cell::Cell;
#[cfg(feature = "candidate_c_value")]
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
#[cfg(not(feature = "candidate_c_value"))]
use crate::eval::thunk::{ForceClaim, ForceGuard, ThunkCell};
use crate::eval::thunk::{ForceError, ThunkState};
#[cfg(feature = "candidate_c_value")]
use crate::value::compressed::CompressedValueWord;

/// Invalid Candidate-C kind byte marking a suspended-work coordinate.
const WORK_HANDLE_KIND_MARKER: u64 = 0xff << 32;
/// Distinct invalid Candidate-C kind byte for shape-sized Node work.
const NODE_WORK_HANDLE_KIND_MARKER: u64 = 0xfd << 32;
/// Secondary marker in payload bits not occupied by the slot coordinate.
const WORK_HANDLE_PAYLOAD_MARKER: u64 = 0xa5 << 24;
/// Mask selecting both work-coordinate markers.
const WORK_HANDLE_MARKER_MASK: u64 = (0xff << 32) | (0xff << 24);
/// Complete marker shared by every generated work coordinate.
const WORK_HANDLE_MARKER: u64 = WORK_HANDLE_KIND_MARKER | WORK_HANDLE_PAYLOAD_MARKER;
/// Complete marker for a generated Node-work coordinate.
const NODE_WORK_HANDLE_MARKER: u64 = NODE_WORK_HANDLE_KIND_MARKER | WORK_HANDLE_PAYLOAD_MARKER;
/// Mask for each 24-bit generated work-handle field.
const WORK_HANDLE_FIELD_MASK: u64 = (1 << 24) - 1;
/// Invalid Candidate-C word installed while one evaluator owns the force.
const TYPED_BLACKHOLE: u64 = (0xfe << 32) | (0x5a << 24);

/// Stable payload addressed by a typed thunk [`Value`].
#[cfg(feature = "candidate_c_value")]
#[derive(Debug)]
pub(in crate::eval::heap) struct StableThunkHead {
    /// Suspended work coordinate, blackhole sentinel, or forced value word.
    word: AtomicU64,
}

/// Baseline fallback used by the default carrier's typed-head tests.
#[cfg(not(feature = "candidate_c_value"))]
#[derive(Debug)]
pub(in crate::eval::heap) struct StableThunkHead {
    cell: ThunkCell,
    work: Cell<u64>,
}

impl StableThunkHead {
    /// Creates a suspended head pointing at `work`.
    fn new(work: TypedThunkWorkHandle) -> Self {
        #[cfg(feature = "candidate_c_value")]
        {
            Self {
                word: AtomicU64::new(work.raw()),
            }
        }
        #[cfg(not(feature = "candidate_c_value"))]
        {
            Self {
                cell: ThunkCell::new(),
                work: Cell::new(work.raw()),
            }
        }
    }

    /// Returns the current work handle, if the work has not been released.
    fn work(&self) -> Option<TypedThunkWorkHandle> {
        #[cfg(feature = "candidate_c_value")]
        {
            TypedThunkWorkHandle::from_raw(self.word.load(Ordering::Acquire))
        }
        #[cfg(not(feature = "candidate_c_value"))]
        {
            TypedThunkWorkHandle::from_raw(self.work.get())
        }
    }

    /// Claims suspended work or returns the already-published result.
    fn begin_force(&self) -> Result<TypedThunkForceClaim<'_>, ForceError> {
        #[cfg(not(feature = "candidate_c_value"))]
        {
            return Ok(match self.cell.begin_force()? {
                ForceClaim::Claimed(guard) => {
                    let handle = self.work().ok_or(ForceError::InvalidStateWord { raw: 0 })?;
                    TypedThunkForceClaim::Claimed(TypedThunkForceGuard {
                        handle,
                        inner: TypedThunkForceGuardInner::Baseline(guard),
                    })
                }
                ForceClaim::AlreadyForced(value) => TypedThunkForceClaim::AlreadyForced(value),
            });
        }
        #[cfg(feature = "candidate_c_value")]
        loop {
            let word = self.word.load(Ordering::Acquire);
            if let Some(handle) = TypedThunkWorkHandle::from_raw(word) {
                if self
                    .word
                    .compare_exchange(word, TYPED_BLACKHOLE, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return Ok(TypedThunkForceClaim::Claimed(TypedThunkForceGuard {
                        handle,
                        inner: TypedThunkForceGuardInner::Candidate(
                            CandidateTypedThunkForceGuard {
                                head: self,
                                suspended: word,
                                active: true,
                            },
                        ),
                    }));
                }
                continue;
            }
            if word == TYPED_BLACKHOLE {
                return Err(ForceError::InfiniteRecursion);
            }
            let value = CompressedValueWord::from_raw(word)
                .map(Value::from_word)
                .map_err(|_| ForceError::InvalidStateWord { raw: word })?;
            return Ok(TypedThunkForceClaim::AlreadyForced(value));
        }
    }

    /// Returns whether this head is currently owned by a force guard.
    fn is_blackholed(&self) -> bool {
        #[cfg(feature = "candidate_c_value")]
        {
            self.word.load(Ordering::Acquire) == TYPED_BLACKHOLE
        }
        #[cfg(not(feature = "candidate_c_value"))]
        {
            self.cell.state() == Ok(ThunkState::Blackhole)
        }
    }

    /// Returns the authoritative force state when the word is valid.
    pub(in crate::eval::heap) fn state(&self) -> Option<ThunkState> {
        #[cfg(feature = "candidate_c_value")]
        {
            let word = self.word.load(Ordering::Acquire);
            if word == TYPED_BLACKHOLE {
                return Some(ThunkState::Blackhole);
            }
            if TypedThunkWorkHandle::from_raw(word).is_some() {
                return Some(ThunkState::Suspended);
            }
            CompressedValueWord::from_raw(word)
                .is_ok()
                .then_some(ThunkState::Forced)
        }
        #[cfg(not(feature = "candidate_c_value"))]
        {
            self.cell.state().ok()
        }
    }

    /// Returns the published value when the head is forced.
    pub(in crate::eval::heap) fn published_value(&self) -> Result<Option<Value>, ForceError> {
        #[cfg(feature = "candidate_c_value")]
        {
            let word = self.word.load(Ordering::Acquire);
            if word == TYPED_BLACKHOLE || TypedThunkWorkHandle::from_raw(word).is_some() {
                return Ok(None);
            }
            return CompressedValueWord::from_raw(word)
                .map(Value::from_word)
                .map(Some)
                .map_err(|_| ForceError::InvalidStateWord { raw: word });
        }
        #[cfg(not(feature = "candidate_c_value"))]
        {
            self.cell.cached_value()
        }
    }

    /// Returns whether this head contains a published Candidate-C value.
    fn is_forced(&self) -> bool {
        #[cfg(feature = "candidate_c_value")]
        {
            let word = self.word.load(Ordering::Acquire);
            word != TYPED_BLACKHOLE
                && TypedThunkWorkHandle::from_raw(word).is_none()
                && CompressedValueWord::from_raw(word).is_ok()
        }
        #[cfg(not(feature = "candidate_c_value"))]
        {
            self.cell.state() == Ok(ThunkState::Forced)
        }
    }

    /// Clears baseline sidecar metadata after successful publication.
    fn finish_work_release(&self, expected: TypedThunkWorkHandle) -> bool {
        #[cfg(feature = "candidate_c_value")]
        {
            let _ = expected;
            true
        }
        #[cfg(not(feature = "candidate_c_value"))]
        {
            if self.work.get() != expected.raw() {
                return false;
            }
            self.work.set(0);
            true
        }
    }

    /// Creates a private evacuation head with an already-published value.
    #[cfg(feature = "evacuation_plan_probe")]
    fn evacuation_forced(value: Value) -> Self {
        #[cfg(feature = "candidate_c_value")]
        {
            Self {
                word: AtomicU64::new(value.word().raw()),
            }
        }
        #[cfg(not(feature = "candidate_c_value"))]
        {
            Self {
                cell: ThunkCell::forced(value),
                work: Cell::new(0),
            }
        }
    }

    /// Replaces a forced result while the destination head is unpublished.
    #[cfg(feature = "evacuation_plan_probe")]
    fn replace_evacuation_forced(&self, value: Value) -> Result<(), EvalHeapError> {
        if self.state() != Some(ThunkState::Forced) {
            return Err(EvalHeapError::ShedRejected {
                address: 0,
                reason: "evacuation forced typed head changed state",
            });
        }
        #[cfg(feature = "candidate_c_value")]
        self.word.store(value.word().raw(), Ordering::Release);
        #[cfg(not(feature = "candidate_c_value"))]
        self.cell
            .replace_forced_for_relocation(value)
            .map_err(EvalHeapError::Thunk)?;
        Ok(())
    }
}

/// Result of attempting to force a one-word stable typed head.
pub(in crate::eval) enum TypedThunkForceClaim<'a> {
    /// The caller owns the work coordinate until publication or guard drop.
    Claimed(TypedThunkForceGuard<'a>),
    /// The head already contains its terminal value.
    AlreadyForced(Value),
}

/// Live claim that restores the exact work coordinate on evaluator unwind.
pub(in crate::eval) struct TypedThunkForceGuard<'a> {
    handle: TypedThunkWorkHandle,
    inner: TypedThunkForceGuardInner<'a>,
}

enum TypedThunkForceGuardInner<'a> {
    #[cfg(feature = "candidate_c_value")]
    Candidate(CandidateTypedThunkForceGuard<'a>),
    #[cfg(not(feature = "candidate_c_value"))]
    Baseline(ForceGuard<'a>),
}

#[cfg(feature = "candidate_c_value")]
struct CandidateTypedThunkForceGuard<'a> {
    head: &'a StableThunkHead,
    suspended: u64,
    active: bool,
}

impl TypedThunkForceGuard<'_> {
    /// Returns the generated work coordinate claimed with this head.
    pub(in crate::eval) const fn handle(&self) -> TypedThunkWorkHandle {
        self.handle
    }

    /// Publishes a forced Candidate-C value into the one-word head.
    pub(in crate::eval) fn finish(self, value: Value) -> Result<Value, ForceError> {
        match self.inner {
            #[cfg(feature = "candidate_c_value")]
            TypedThunkForceGuardInner::Candidate(mut guard) => {
                guard
                    .head
                    .word
                    .compare_exchange(
                        TYPED_BLACKHOLE,
                        value.word().raw(),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .map_err(|actual| ForceError::UnexpectedState {
                        expected: ThunkState::Blackhole,
                        actual: typed_state(actual),
                    })?;
                guard.active = false;
                Ok(value)
            }
            #[cfg(not(feature = "candidate_c_value"))]
            TypedThunkForceGuardInner::Baseline(guard) => guard.finish(value),
        }
    }
}

#[cfg(feature = "candidate_c_value")]
impl Drop for CandidateTypedThunkForceGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.head.word.compare_exchange(
                TYPED_BLACKHOLE,
                self.suspended,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }
}

#[cfg(feature = "candidate_c_value")]
fn typed_state(word: u64) -> ThunkState {
    if word == TYPED_BLACKHOLE {
        ThunkState::Blackhole
    } else if TypedThunkWorkHandle::from_raw(word).is_some() {
        ThunkState::Suspended
    } else {
        ThunkState::Forced
    }
}

/// ABA-safe coordinate into [`TypedThunkWorkPool`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::eval) struct TypedThunkWorkHandle(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Work-pool family encoded into a stable head's generated coordinate.
pub(in crate::eval::heap) enum TypedThunkWorkKind {
    /// Full synthetic work variants.
    General,
    /// Shape-sized ordinary Node work.
    Node,
}

impl TypedThunkWorkHandle {
    /// Packs a non-zero 24-bit generation and zero-based 24-bit slot index.
    fn new(kind: TypedThunkWorkKind, generation: u32, slot: u32) -> Option<Self> {
        if generation == 0
            || u64::from(generation) > WORK_HANDLE_FIELD_MASK
            || u64::from(slot) >= WORK_HANDLE_FIELD_MASK
        {
            return None;
        }
        let marker = match kind {
            TypedThunkWorkKind::General => WORK_HANDLE_MARKER,
            TypedThunkWorkKind::Node => NODE_WORK_HANDLE_MARKER,
        };
        Some(Self(
            marker | (u64::from(generation) << 40) | u64::from(slot.wrapping_add(1)),
        ))
    }

    /// Decodes a marker-tagged generated work coordinate.
    fn from_raw(raw: u64) -> Option<Self> {
        let marker = raw & WORK_HANDLE_MARKER_MASK;
        if marker != WORK_HANDLE_MARKER && marker != NODE_WORK_HANDLE_MARKER {
            return None;
        }
        let generation = ((raw >> 40) & WORK_HANDLE_FIELD_MASK) as u32;
        let encoded_slot = (raw & WORK_HANDLE_FIELD_MASK) as u32;
        (generation != 0 && encoded_slot != 0).then_some(Self(raw))
    }

    /// Returns the packed representation stored in a head.
    const fn raw(self) -> u64 {
        self.0
    }

    /// Returns the slot index.
    const fn slot(self) -> u32 {
        ((self.0 & WORK_HANDLE_FIELD_MASK) as u32).wrapping_sub(1)
    }

    /// Returns the allocation generation.
    const fn generation(self) -> u32 {
        ((self.0 >> 40) & WORK_HANDLE_FIELD_MASK) as u32
    }

    const fn kind(self) -> TypedThunkWorkKind {
        if self.0 & WORK_HANDLE_MARKER_MASK == NODE_WORK_HANDLE_MARKER {
            TypedThunkWorkKind::Node
        } else {
            TypedThunkWorkKind::General
        }
    }
}

/// One reusable suspended-work slot.
#[derive(Debug)]
struct TypedThunkWorkSlot<T> {
    generation: u32,
    work: Option<T>,
    next_free: Option<u32>,
    is_free: bool,
}

/// Indexed serial work arena with generational ABA protection.
#[derive(Debug)]
pub(in crate::eval::heap) struct TypedThunkWorkPool<T> {
    slots: Vec<TypedThunkWorkSlot<T>>,
    free_head: Option<u32>,
    live: usize,
    peak_live: usize,
}

/// Binds one pool payload type to its disjoint handle marker.
pub(in crate::eval::heap) trait TypedThunkPoolWork {
    /// Marker family accepted and generated by this payload's pool.
    const KIND: TypedThunkWorkKind;
}

impl TypedThunkPoolWork for EvalThunk {
    const KIND: TypedThunkWorkKind = TypedThunkWorkKind::General;
}

impl TypedThunkPoolWork for TypedNodeThunkWork {
    const KIND: TypedThunkWorkKind = TypedThunkWorkKind::Node;
}

impl<T> Default for TypedThunkWorkPool<T> {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            free_head: None,
            live: 0,
            peak_live: 0,
        }
    }
}

impl<T: TypedThunkPoolWork> TypedThunkWorkPool<T> {
    /// Allocates a work slot and returns its new generation coordinate.
    ///
    /// A slot at the largest encodable generation is permanently poisoned
    /// on release
    /// rather than wrapping to a generation that an ancient handle could
    /// carry.
    fn alloc(&mut self, work: T) -> Result<TypedThunkWorkHandle, T> {
        while let Some(slot_index) = self.free_head {
            let handle = {
                let Some(slot) = self.slots.get_mut(slot_index as usize) else {
                    return Err(work);
                };
                if !slot.is_free {
                    return Err(work);
                }
                self.free_head = slot.next_free.take();
                let Some(generation) = slot.generation.checked_add(1) else {
                    continue;
                };
                let Some(handle) = TypedThunkWorkHandle::new(T::KIND, generation, slot_index)
                else {
                    continue;
                };
                slot.generation = generation;
                slot.is_free = false;
                slot.work = Some(work);
                handle
            };
            self.note_alloc();
            return Ok(handle);
        }

        let Ok(slot_index) = u32::try_from(self.slots.len()) else {
            return Err(work);
        };
        if u64::from(slot_index) >= WORK_HANDLE_FIELD_MASK {
            return Err(work);
        }
        self.slots.push(TypedThunkWorkSlot {
            generation: 1,
            work: Some(work),
            next_free: None,
            is_free: false,
        });
        self.note_alloc();
        match TypedThunkWorkHandle::new(T::KIND, 1, slot_index) {
            Some(handle) => Ok(handle),
            None => match self.slots.pop().and_then(|slot| slot.work) {
                Some(work) => Err(work),
                None => unreachable!("fresh work slot lost its payload"),
            },
        }
    }

    /// Resolves `handle` only when both its slot and generation are current.
    fn get(&self, handle: TypedThunkWorkHandle) -> Option<&T> {
        if handle.kind() != T::KIND {
            return None;
        }
        let slot = self.slots.get(handle.slot() as usize)?;
        (!slot.is_free && slot.generation == handle.generation())
            .then(|| slot.work.as_ref())
            .flatten()
    }

    /// Replaces live work while its destination head remains unpublished.
    #[cfg(feature = "evacuation_plan_probe")]
    fn replace_evacuation_work(&mut self, handle: TypedThunkWorkHandle, work: T) -> Result<(), T> {
        if handle.kind() != T::KIND {
            return Err(work);
        }
        let Some(slot) = self.slots.get_mut(handle.slot() as usize) else {
            return Err(work);
        };
        if slot.is_free || slot.generation != handle.generation() || slot.work.is_none() {
            return Err(work);
        }
        slot.work = Some(work);
        Ok(())
    }

    /// Moves current work out while keeping its generated slot reserved.
    fn take_work(&mut self, handle: TypedThunkWorkHandle) -> Option<T> {
        if handle.kind() != T::KIND {
            return None;
        }
        let slot = self.slots.get_mut(handle.slot() as usize)?;
        (!slot.is_free && slot.generation == handle.generation())
            .then(|| slot.work.take())
            .flatten()
    }

    /// Restores work to the same generated slot after an aborted force.
    fn restore_work(&mut self, handle: TypedThunkWorkHandle, work: T) -> Result<(), T> {
        if handle.kind() != T::KIND {
            return Err(work);
        }
        let Some(slot) = self.slots.get_mut(handle.slot() as usize) else {
            return Err(work);
        };
        if slot.is_free || slot.generation != handle.generation() || slot.work.is_some() {
            return Err(work);
        }
        slot.work = Some(work);
        Ok(())
    }

    /// Releases a generated slot whose work is owned by the successful force.
    fn release_taken(&mut self, handle: TypedThunkWorkHandle) -> bool {
        if handle.kind() != T::KIND {
            return false;
        }
        let Some(slot) = self.slots.get_mut(handle.slot() as usize) else {
            return false;
        };
        if slot.is_free || slot.generation != handle.generation() || slot.work.is_some() {
            return false;
        }
        slot.is_free = true;
        if u64::from(slot.generation) < WORK_HANDLE_FIELD_MASK {
            slot.next_free = self.free_head;
            self.free_head = Some(handle.slot());
        }
        self.live = self.live.saturating_sub(1);
        true
    }

    /// Returns whether the generated slot is reserved with its work moved out.
    fn is_taken(&self, handle: TypedThunkWorkHandle) -> bool {
        if handle.kind() != T::KIND {
            return false;
        }
        self.slots.get(handle.slot() as usize).is_some_and(|slot| {
            !slot.is_free && slot.generation == handle.generation() && slot.work.is_none()
        })
    }

    /// Releases the exact current generation and makes its slot reusable.
    fn release(&mut self, handle: TypedThunkWorkHandle) -> Option<T> {
        if handle.kind() != T::KIND {
            return None;
        }
        let slot = self.slots.get_mut(handle.slot() as usize)?;
        if slot.is_free || slot.generation != handle.generation() {
            return None;
        }
        let work = slot.work.take()?;
        slot.is_free = true;
        if u64::from(slot.generation) < WORK_HANDLE_FIELD_MASK {
            slot.next_free = self.free_head;
            self.free_head = Some(handle.slot());
        }
        self.live = self.live.saturating_sub(1);
        Some(work)
    }

    fn note_alloc(&mut self) {
        self.live = self.live.saturating_add(1);
        self.peak_live = self.peak_live.max(self.live);
    }
}

/// Detached typed-head force metadata safe across evaluator re-entry.
#[derive(Debug)]
pub(in crate::eval) struct TypedThunkForceParts {
    /// Validated stable head in the permanent headerless lane.
    head: std::ptr::NonNull<StableThunkHead>,
}

impl TypedThunkForceParts {
    /// Claims this stable head or returns its already-published value.
    ///
    /// # Errors
    ///
    /// Returns [`ForceError`] for blackhole recursion or an invalid state word.
    ///
    /// # Safety
    ///
    /// The originating [`EvalHeap`] must remain alive until the returned claim
    /// and any force guard derived from it have been dropped.
    #[allow(unsafe_code)]
    pub(in crate::eval) unsafe fn begin_force(
        &self,
    ) -> Result<TypedThunkForceClaim<'_>, ForceError> {
        // SAFETY: construction resolved this address in the permanent
        // headerless lane, whose blocks are never rewound or relocated.
        unsafe { self.head.as_ref() }.begin_force()
    }
}

impl EvalHeap {
    /// Forces one typed head into its blackhole sentinel for collector tests.
    #[cfg(all(test, feature = "candidate_c_value"))]
    pub(in crate::eval::heap) fn test_blackhole_typed_thunk(
        &mut self,
        value: Value,
    ) -> Result<(), EvalHeapError> {
        let ptr = self.thunk_ptr(value)?;
        let head = self
            .typed_thunk_heads
            .resolve(ptr)
            .map_err(|_| EvalHeapError::unknown(ValueTag::Thunk, ptr))?;
        let Some(_work) = head.work() else {
            return Err(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "collector test requires a suspended typed thunk",
            });
        };
        head.word.store(TYPED_BLACKHOLE, Ordering::Release);
        Ok(())
    }

    /// Allocates an unpublished suspended typed head for evacuation.
    #[cfg(feature = "evacuation_plan_probe")]
    pub(in crate::eval::heap) fn alloc_evacuation_suspended_typed_thunk(
        &mut self,
        work: EvalThunk,
    ) -> Result<(Value, TypedThunkWorkHandle), EvalHeapError> {
        let handle =
            self.typed_thunk_work
                .alloc(work)
                .map_err(|_| EvalHeapError::ShedRejected {
                    address: 0,
                    reason: "evacuation typed-work allocation failed",
                })?;
        let allocation = self
            .typed_thunk_heads
            .alloc(StableThunkHead::new(handle))
            .map_err(flat_alloc_error)?;
        let value = self.value_for_flat_allocation(ValueTag::Thunk, allocation.ptr)?;
        Ok((value, handle))
    }

    /// Allocates an unpublished forced typed head for evacuation.
    #[cfg(feature = "evacuation_plan_probe")]
    pub(in crate::eval::heap) fn alloc_evacuation_forced_typed_thunk(
        &mut self,
        value: Value,
    ) -> Result<Value, EvalHeapError> {
        let allocation = self
            .typed_thunk_heads
            .alloc(StableThunkHead::evacuation_forced(value))
            .map_err(flat_alloc_error)?;
        self.value_for_flat_allocation(ValueTag::Thunk, allocation.ptr)
    }

    /// Replaces unpublished destination work after forwarding is complete.
    #[cfg(feature = "evacuation_plan_probe")]
    pub(in crate::eval::heap) fn replace_evacuation_typed_work(
        &mut self,
        handle: TypedThunkWorkHandle,
        work: EvalThunk,
    ) -> Result<(), EvalHeapError> {
        self.typed_thunk_work
            .replace_evacuation_work(handle, work)
            .map_err(|_| EvalHeapError::ShedRejected {
                address: 0,
                reason: "evacuation typed-work handle became stale",
            })
    }

    /// Replaces an unpublished destination head's forced result.
    #[cfg(feature = "evacuation_plan_probe")]
    pub(in crate::eval::heap) fn replace_evacuation_typed_result(
        &self,
        ptr: std::ptr::NonNull<HeapObject>,
        value: Value,
    ) -> Result<(), EvalHeapError> {
        self.typed_thunk_heads
            .resolve(ptr)
            .map_err(|_| EvalHeapError::unknown(ValueTag::Thunk, ptr))?
            .replace_evacuation_forced(value)
    }

    /// Enables the default-off broad serial typed-head experiment.
    ///
    /// The method retains its historical Apply-specific name for configuration
    /// compatibility; the current predicate admits every plain serial thunk
    /// without a capture tail.
    pub(in crate::eval) fn enable_typed_apply_thunk_heads(&mut self) {
        self.typed_apply_thunk_heads_enabled = true;
    }

    /// Attempts typed-head allocation and returns the untouched thunk on fallback.
    pub(in crate::eval::heap) fn try_typed_alloc_thunk(
        &mut self,
        thunk: EvalThunk,
    ) -> Result<Result<Value, EvalThunk>, EvalHeapError> {
        if !self.typed_apply_thunk_heads_enabled
            || self.shared.is_some()
            || self.worker_closure_placement != WorkerClosurePlacement::Flat
            || !self.worker_region_mark_stack.is_empty()
            || !thunk.is_plain_serial_typed_shape()
        {
            return Ok(Err(thunk));
        }

        let handle = match thunk.into_typed_node_work() {
            Ok(work) => match self.typed_node_thunk_work.alloc(work) {
                Ok(handle) => handle,
                Err(work) => return Ok(Err(work.into_eval_thunk())),
            },
            Err(thunk) => match self.typed_thunk_work.alloc(thunk) {
                Ok(handle) => handle,
                Err(thunk) => return Ok(Err(thunk)),
            },
        };
        let allocation = match self.typed_thunk_heads.alloc(StableThunkHead::new(handle)) {
            Ok(allocation) => allocation,
            Err(error) => {
                self.drop_typed_thunk_work(handle);
                return Err(flat_alloc_error(error));
            }
        };
        self.allocator
            .record_flat_thunk_allocation_safepoint(allocation.allocation);
        let value = self.value_for_flat_allocation(ValueTag::Thunk, allocation.ptr)?;
        self.alloc_counters.note_value_allocated();
        #[cfg(feature = "peak_ordinal_probe")]
        self.note_peak_ordinal_publication(ValueTag::Thunk);
        self.poll_memory_budget_after_allocation();
        Ok(Ok(value))
    }

    /// Returns detached force parts when `ptr` names a typed thunk head.
    ///
    /// The returned token retains only the already-validated permanent head.
    pub(in crate::eval) fn typed_thunk_force_parts(
        &self,
        ptr: std::ptr::NonNull<HeapObject>,
    ) -> Result<Option<TypedThunkForceParts>, EvalHeapError> {
        let object = match self.typed_thunk_heads.resolve(ptr) {
            Ok(object) => object,
            Err(_) => return Ok(None),
        };
        Ok(Some(TypedThunkForceParts {
            head: std::ptr::NonNull::from(object),
        }))
    }

    /// Returns whether `ptr` names a stable typed thunk head.
    pub(in crate::eval) fn is_typed_thunk_head(&self, ptr: std::ptr::NonNull<HeapObject>) -> bool {
        self.typed_thunk_heads.resolve(ptr).is_ok()
    }

    /// Returns authoritative state when `value` names a typed thunk head.
    pub(in crate::eval) fn typed_thunk_state_if_any(&self, value: Value) -> Option<ThunkState> {
        let ptr = self.thunk_ptr(value).ok()?;
        self.typed_thunk_heads.resolve(ptr).ok()?.state()
    }

    /// Returns the authoritative publication state for a typed thunk head.
    ///
    /// The outer option distinguishes ordinary thunks from typed heads. The
    /// inner option is empty while a typed head is suspended or blackholed.
    pub(in crate::eval) fn typed_thunk_published_value_if_any(
        &self,
        value: Value,
    ) -> Option<Option<Value>> {
        let ptr = self.thunk_ptr(value).ok()?;
        self.typed_thunk_heads
            .resolve(ptr)
            .ok()?
            .published_value()
            .ok()
    }

    /// Borrows live typed suspended work for metadata-only heap readers.
    ///
    /// The returned record's inline cell is not authoritative; callers that
    /// inspect force state must use the stable-head force/cell APIs instead.
    pub(in crate::eval::heap) fn typed_thunk_work_ref(
        &self,
        ptr: std::ptr::NonNull<HeapObject>,
    ) -> Result<Option<&EvalThunk>, EvalHeapError> {
        let object = match self.typed_thunk_heads.resolve(ptr) {
            Ok(object) => object,
            Err(_) => return Ok(None),
        };
        let handle = object.work().ok_or(EvalHeapError::ReleasedThunkWork {
            address: ptr.as_ptr() as usize,
        })?;
        let work = match handle.kind() {
            TypedThunkWorkKind::General => self.typed_thunk_work.get(handle),
            TypedThunkWorkKind::Node => self
                .typed_node_thunk_work
                .get(handle)
                .map(TypedNodeThunkWork::as_eval_thunk),
        };
        work.map(Some)
            .ok_or_else(|| EvalHeapError::unknown(ValueTag::Thunk, ptr))
    }

    /// Moves typed suspended work into the force owner without freeing its slot.
    pub(in crate::eval) fn take_typed_thunk_work(
        &mut self,
        ptr: std::ptr::NonNull<HeapObject>,
        handle: TypedThunkWorkHandle,
    ) -> Result<EvalThunk, EvalHeapError> {
        let head = self
            .typed_thunk_heads
            .resolve(ptr)
            .map_err(|_| EvalHeapError::unknown(ValueTag::Thunk, ptr))?;
        if !head.is_blackholed() {
            return Err(EvalHeapError::unknown(ValueTag::Thunk, ptr));
        }
        match handle.kind() {
            TypedThunkWorkKind::General => self.typed_thunk_work.take_work(handle),
            TypedThunkWorkKind::Node => self
                .typed_node_thunk_work
                .take_work(handle)
                .map(TypedNodeThunkWork::into_eval_thunk),
        }
        .ok_or_else(|| EvalHeapError::unknown(ValueTag::Thunk, ptr))
    }

    /// Restores work to a still-reserved typed slot after an aborted force.
    pub(in crate::eval) fn restore_typed_thunk_work(
        &mut self,
        ptr: std::ptr::NonNull<HeapObject>,
        handle: TypedThunkWorkHandle,
        work: EvalThunk,
    ) -> Result<(), EvalHeapError> {
        let head = self
            .typed_thunk_heads
            .resolve(ptr)
            .map_err(|_| EvalHeapError::unknown(ValueTag::Thunk, ptr))?;
        if !head.is_blackholed() && head.work() != Some(handle) {
            return Err(EvalHeapError::unknown(ValueTag::Thunk, ptr));
        }
        let restored = match handle.kind() {
            TypedThunkWorkKind::General => self.typed_thunk_work.restore_work(handle, work),
            TypedThunkWorkKind::Node => match work.into_typed_node_work() {
                Ok(work) => self
                    .typed_node_thunk_work
                    .restore_work(handle, work)
                    .map_err(TypedNodeThunkWork::into_eval_thunk),
                Err(work) => Err(work),
            },
        };
        restored.map_err(|_| EvalHeapError::unknown(ValueTag::Thunk, ptr))
    }

    /// Reclaims a claimed typed work slot after its head published a result.
    pub(in crate::eval) fn release_taken_typed_thunk_work(
        &mut self,
        ptr: std::ptr::NonNull<HeapObject>,
        handle: TypedThunkWorkHandle,
    ) -> Result<(), EvalHeapError> {
        let head = self
            .typed_thunk_heads
            .resolve(ptr)
            .map_err(|_| EvalHeapError::unknown(ValueTag::Thunk, ptr))?;
        let is_taken = match handle.kind() {
            TypedThunkWorkKind::General => self.typed_thunk_work.is_taken(handle),
            TypedThunkWorkKind::Node => self.typed_node_thunk_work.is_taken(handle),
        };
        if !head.is_forced() || !is_taken {
            return Err(EvalHeapError::unknown(ValueTag::Thunk, ptr));
        }
        if !head.finish_work_release(handle) {
            return Err(EvalHeapError::unknown(ValueTag::Thunk, ptr));
        }
        let released = match handle.kind() {
            TypedThunkWorkKind::General => self.typed_thunk_work.release_taken(handle),
            TypedThunkWorkKind::Node => self.typed_node_thunk_work.release_taken(handle),
        };
        if !released {
            return Err(EvalHeapError::unknown(ValueTag::Thunk, ptr));
        }
        Ok(())
    }

    /// Returns `(heads, live work, peak live work, slots, slot capacity)`.
    pub(in crate::eval) fn typed_thunk_head_counts(&self) -> (usize, usize, usize, usize, usize) {
        (
            self.typed_thunk_heads.len(),
            self.typed_thunk_work
                .live
                .saturating_add(self.typed_node_thunk_work.live),
            self.typed_thunk_work
                .peak_live
                .saturating_add(self.typed_node_thunk_work.peak_live),
            self.typed_thunk_work
                .slots
                .len()
                .saturating_add(self.typed_node_thunk_work.slots.len()),
            self.typed_thunk_work
                .slots
                .capacity()
                .saturating_add(self.typed_node_thunk_work.slots.capacity()),
        )
    }

    /// Returns `(Node live, Node slots, general live, general slots)` in tests.
    #[cfg(test)]
    pub(in crate::eval) fn typed_thunk_work_shape_counts(&self) -> (usize, usize, usize, usize) {
        (
            self.typed_node_thunk_work.live,
            self.typed_node_thunk_work.slots.len(),
            self.typed_thunk_work.live,
            self.typed_thunk_work.slots.len(),
        )
    }

    fn drop_typed_thunk_work(&mut self, handle: TypedThunkWorkHandle) {
        match handle.kind() {
            TypedThunkWorkKind::General => {
                let _ = self.typed_thunk_work.release(handle);
            }
            TypedThunkWorkKind::Node => {
                let _ = self.typed_node_thunk_work.release(handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::IrId;

    fn work(id: u32) -> EvalThunk {
        EvalThunk::new(IrId::new(id))
    }

    #[test]
    fn work_handle_zero_is_reserved_for_released_heads() {
        assert_eq!(TypedThunkWorkHandle::from_raw(0), None);
        assert_eq!(
            TypedThunkWorkHandle::new(TypedThunkWorkKind::General, 0, 0),
            None
        );
        assert_eq!(
            TypedThunkWorkHandle::new(
                TypedThunkWorkKind::General,
                WORK_HANDLE_FIELD_MASK as u32,
                0,
            )
            .map(TypedThunkWorkHandle::generation),
            Some(WORK_HANDLE_FIELD_MASK as u32)
        );
        assert_eq!(
            TypedThunkWorkHandle::new(
                TypedThunkWorkKind::General,
                1,
                WORK_HANDLE_FIELD_MASK as u32 - 1,
            )
            .map(TypedThunkWorkHandle::slot),
            Some(WORK_HANDLE_FIELD_MASK as u32 - 1)
        );
        assert_eq!(
            TypedThunkWorkHandle::new(
                TypedThunkWorkKind::General,
                WORK_HANDLE_FIELD_MASK as u32 + 1,
                0,
            ),
            None
        );
        assert_eq!(
            TypedThunkWorkHandle::new(
                TypedThunkWorkKind::General,
                1,
                WORK_HANDLE_FIELD_MASK as u32,
            ),
            None
        );
        assert_eq!(
            TypedThunkWorkHandle::new(TypedThunkWorkKind::General, 1, u32::MAX),
            None
        );
    }

    #[test]
    fn stable_head_payload_is_one_machine_word_in_candidate_c() {
        #[cfg(feature = "candidate_c_value")]
        {
            use crate::heap::{ArenaDomainId, ArenaIndex};

            assert_eq!(std::mem::size_of::<StableThunkHead>(), 8);
            let handle = TypedThunkWorkHandle::new(TypedThunkWorkKind::General, 1, 0)
                .expect("handle is representable");
            let node_handle = TypedThunkWorkHandle::new(TypedThunkWorkKind::Node, 1, 0)
                .expect("Node handle is representable");
            assert!(CompressedValueWord::from_raw(handle.raw()).is_err());
            assert!(CompressedValueWord::from_raw(node_handle.raw()).is_err());
            assert!(CompressedValueWord::from_raw(TYPED_BLACKHOLE).is_err());

            let collision_probe = CompressedValueWord::heap(
                ArenaDomainId::from_raw(0x7f_fd00).expect("boundary domain is valid"),
                ValueTag::Thunk,
                ArenaIndex::new(1),
            )
            .expect("thunk word is valid")
            .with_forced_bit()
            .expect("forced thunk word is valid");
            assert!(TypedThunkWorkHandle::from_raw(collision_probe.raw()).is_none());
        }
    }

    #[test]
    fn node_work_is_shape_sized_and_compatibility_expansion_round_trips() {
        assert!(
            std::mem::size_of::<TypedNodeThunkWork>() < std::mem::size_of::<EvalThunk>(),
            "the Node pool must reserve less per slot than the full work enum"
        );
        let node = EvalThunk::new(IrId::new(41));
        let compact = node
            .into_typed_node_work()
            .expect("ordinary serial Node work compacts");
        assert_eq!(compact.as_eval_thunk().body(), Some(IrId::new(41)));
        assert!(compact.as_eval_thunk().env().is_some_and(EvalEnv::is_empty));
        let restored = compact.into_eval_thunk();
        assert_eq!(restored.body(), Some(IrId::new(41)));
        assert_eq!(restored.cell().state(), Ok(ThunkState::Suspended));
    }

    #[test]
    fn node_and_general_pool_handles_are_disjoint() {
        let mut general = TypedThunkWorkPool::default();
        let mut nodes = TypedThunkWorkPool::default();
        let general_handle = general.alloc(work(1)).expect("general work allocates");
        let node_handle = nodes
            .alloc(work(2).into_typed_node_work().expect("Node work compacts"))
            .expect("Node work allocates");

        assert_eq!(general_handle.slot(), node_handle.slot());
        assert_eq!(general_handle.generation(), node_handle.generation());
        assert_ne!(general_handle.raw(), node_handle.raw());
        assert_eq!(general_handle.kind(), TypedThunkWorkKind::General);
        assert_eq!(node_handle.kind(), TypedThunkWorkKind::Node);
        assert!(general.get(node_handle).is_none());
        assert!(nodes.get(general_handle).is_none());
    }

    #[test]
    fn released_slot_reuse_rejects_stale_generation() {
        let mut pool = TypedThunkWorkPool::default();
        let first = pool.alloc(work(1)).expect("first slot allocates");
        assert_eq!(
            pool.get(first).and_then(EvalThunk::body),
            Some(IrId::new(1))
        );
        let released = pool.release(first).expect("current handle releases");
        assert_eq!(released.body(), Some(IrId::new(1)));

        let second = pool.alloc(work(2)).expect("released slot is reused");
        assert_eq!(first.slot(), second.slot());
        assert_ne!(first.generation(), second.generation());
        assert!(pool.get(first).is_none());
        assert_eq!(
            pool.get(second).and_then(EvalThunk::body),
            Some(IrId::new(2))
        );
        assert!(pool.release(first).is_none());
    }

    #[test]
    fn taken_slot_cannot_be_released_twice() {
        let mut pool = TypedThunkWorkPool::default();
        let first = pool.alloc(work(1)).expect("first slot allocates");
        let _taken = pool.take_work(first).expect("work moves out");
        assert!(pool.release_taken(first));
        assert!(!pool.release_taken(first));

        let second = pool.alloc(work(2)).expect("released slot reuses once");
        let third = pool.alloc(work(3)).expect("another live slot allocates");
        assert_ne!(second.slot(), third.slot());
        assert_eq!(
            pool.get(second).and_then(EvalThunk::body),
            Some(IrId::new(2))
        );
        assert_eq!(
            pool.get(third).and_then(EvalThunk::body),
            Some(IrId::new(3))
        );
        assert_eq!(pool.live, 2);
    }

    #[test]
    fn maximum_generation_slot_is_permanently_poisoned() {
        let mut pool = TypedThunkWorkPool::default();
        let initial = pool.alloc(work(1)).expect("first slot allocates");
        let slot = initial.slot();
        pool.slots[slot as usize].generation = WORK_HANDLE_FIELD_MASK as u32 - 1;
        let penultimate = TypedThunkWorkHandle::new(
            TypedThunkWorkKind::General,
            WORK_HANDLE_FIELD_MASK as u32 - 1,
            slot,
        )
        .expect("penultimate generation is representable");
        let _ = pool
            .release(penultimate)
            .expect("penultimate work releases");

        let maximum = pool.alloc(work(2)).expect("maximum generation allocates");
        assert_eq!(maximum.slot(), slot);
        assert_eq!(maximum.generation(), WORK_HANDLE_FIELD_MASK as u32);
        let _ = pool.release(maximum).expect("maximum work releases");

        let replacement = pool.alloc(work(3)).expect("fresh slot allocates");
        assert_ne!(replacement.slot(), slot);
        assert!(pool.get(initial).is_none());
        assert!(pool.get(penultimate).is_none());
        assert!(pool.get(maximum).is_none());
        assert!(pool.take_work(maximum).is_none());
        assert!(pool.release(maximum).is_none());
        assert!(pool.restore_work(maximum, work(4)).is_err());
    }

    #[test]
    fn taken_work_survives_pool_growth_and_restores() {
        let mut pool = TypedThunkWorkPool::default();
        let first = pool.alloc(work(1)).expect("first slot allocates");
        let taken = pool.take_work(first).expect("work moves out");
        for id in 2..4096 {
            pool.alloc(work(id)).expect("pool grows");
        }
        assert_eq!(taken.body(), Some(IrId::new(1)));
        assert!(pool.get(first).is_none());
        pool.restore_work(first, taken)
            .expect("current generated slot restores");
        assert_eq!(
            pool.get(first).and_then(EvalThunk::body),
            Some(IrId::new(1))
        );
    }

    #[test]
    fn head_guard_restores_work_and_then_publishes() {
        let mut pool = TypedThunkWorkPool::default();
        let first = pool.alloc(work(1)).expect("first slot allocates");
        let head = StableThunkHead::new(first);
        assert_eq!(head.work(), Some(first));
        let TypedThunkForceClaim::Claimed(guard) =
            head.begin_force().expect("suspended head claims")
        else {
            panic!("suspended head must claim");
        };
        assert_eq!(guard.handle(), first);
        drop(guard);
        assert_eq!(head.work(), Some(first));

        let TypedThunkForceClaim::Claimed(guard) =
            head.begin_force().expect("restored head reclaims")
        else {
            panic!("restored head must claim");
        };
        let value = Value::bool(true);
        let expected_word = value.word().raw();
        let published = guard.finish(value).expect("guard publishes");
        assert_eq!(published.word().raw(), expected_word);
        assert!(head.is_forced());
        match head.begin_force().expect("forced head replays") {
            TypedThunkForceClaim::AlreadyForced(cached) => {
                assert_eq!(cached.word().raw(), expected_word);
            }
            TypedThunkForceClaim::Claimed(_) => panic!("forced head must not claim"),
        }
    }
}
