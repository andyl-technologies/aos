//! Flat worker-domain closures for the serial evaluator heap.
//!
//! RFC-0007 doc 30 stage FV-3: thunks, lambdas, and partially applied
//! builtins — the mutable, claim-carrying, region-popped worker kinds — move
//! out of the record side table into one flat closure store. One allocation
//! holds the flat header plus the direct payload at the value's address, so
//! resolution is a membership check plus one header load with no address-hash
//! probe and no record `Vec` load.
//!
//! # Arena-owned payloads and side-owned force state
//!
//! FV-6 stores each `EvalThunk`, `EvalLambda`, and `EvalPrimOp` directly in
//! its flat arena object. Owned resolver snapshots clone the immutable payload
//! metadata while a thunk's serial force cell and optional parallel cell use
//! independently reference-counted side ownership: those cells must remain
//! live across evaluator re-entry, whereas the payload and its captured
//! environments are reclaimed when the sweep installs the retired tombstone.
//!
//! # Placement and the Tier-B B2 relocation proving ground
//!
//! The collector-poll / minor-GC machinery (destination reservation, object
//! byte copies, forwarding headers, generation writes) is Tier-B B2
//! scaffolding that relocates *young record-table objects* — and after FV-2
//! the young population is exactly these worker kinds. That machinery is
//! driven only by an installed [`GcStressPolicy`]; production never installs
//! one. Worker-closure placement is therefore mode-selected
//! ([`WorkerClosurePlacement`]): heaps default to flat closures, and
//! [`EvalHeap::set_gc_stress_policy`] switches new worker allocations to the
//! record-table layout so the B2 proving ground keeps relocating real
//! records. Resolution, region pops, and the B1 sweep handle both
//! populations (each empty in the other mode), so the placement switch is a
//! per-allocation choice, never a correctness seam.
//!
//! # Reclamation (both record-table doors, re-expressed)
//!
//! - **Region pops**: the flat closure store participates in worker
//!   lexical-region pops through [`FlatObjectStore::pop_region`] — payloads
//!   drop, headers are wiped so stale addresses fail loudly, and the store's
//!   arena rewinds (addresses may be reused afterwards, the record-table pop
//!   contract). Pops remain mutually exclusive with sweep retirement.
//! - **B1 sweep**: retirement swaps the payload for
//!   [`FlatClosurePayload::Retired`] in place through the exclusive
//!   `resolve_mut` door. The entry, header, and address remain; the address
//!   is never reissued; any later resolution fails as
//!   [`EvalHeapError::UnknownPointer`] — the same loud-failure class the
//!   record table produced via its index removal.
//!
//! [`GcStressPolicy`]: crate::runtime::alloc::GcStressPolicy
//! [`FlatObjectStore::pop_region`]: crate::heap::flat::FlatObjectStore::pop_region
//! [`EvalThunkKind::Released`]: super::super::EvalThunkKind::Released

use super::*;
use std::sync::Arc;

/// Where a heap places newly allocated worker-domain closures (doc 30 FV-3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WorkerClosurePlacement {
    /// Flat closure objects in the heap's flat closure store (production).
    #[default]
    Flat,
    /// Record-table records (the pre-FV-3 layout), kept for the Tier-B B2
    /// relocation proving ground: minor-GC plans reserve, copy, and forward
    /// record-table objects, so heaps running under a GC-stress policy
    /// allocate worker kinds as records.
    Record,
}

/// The arena-owned payload stored in one flat worker-closure object.
///
/// The variant always matches the flat header's kind word as allocated;
/// retirement keeps the header intact and swaps only the payload, so a
/// retired address stays recognizable (and fails loudly) without reissuing
/// header state.
#[derive(Debug)]
pub(crate) enum FlatClosurePayload {
    /// A suspended (or forced, or shed) thunk handle owned inline.
    Thunk(EvalThunk),
    /// A thunk handle promoted into a shared `Arc` on its first force clone.
    ///
    /// The force path mints this lazily (doc 15 §5.5 cheap-thunk-clone I1): the
    /// inline [`EvalThunk`] is moved into an `Arc` on the first
    /// [`EvalHeap::share_thunk`] so subsequent forces pay one `Arc::clone`
    /// instead of copying the whole record and re-incrementing its ~5 inner
    /// `Arc`s. The variant carries the same thunk the [`Thunk`](Self::Thunk)
    /// variant would; every reader dereferences it identically through
    /// [`FlatClosurePayload::as_thunk`].
    SharedThunk(Arc<EvalThunk>),
    /// A lambda closure handle.
    Lambda(EvalLambda),
    /// A builtin or partially applied builtin handle.
    Primop(EvalPrimOp),
    /// The object was reclaimed by the Tier-B sweep; the direct payload was
    /// dropped and the address is never reissued. `ValueTag` preserves the
    /// retired object's original type for diagnostics.
    Retired(ValueTag),
}

impl FlatClosurePayload {
    /// Returns the runtime tag this payload resolves under.
    pub(in crate::eval::heap) const fn tag(&self) -> ValueTag {
        match self {
            Self::Thunk(_) | Self::SharedThunk(_) => ValueTag::Thunk,
            Self::Lambda(_) => ValueTag::Lambda,
            Self::Primop(_) => ValueTag::Primop,
            Self::Retired(tag) => *tag,
        }
    }

    /// Returns `true` when the payload was reclaimed by the Tier-B sweep.
    pub(in crate::eval::heap) const fn is_retired(&self) -> bool {
        matches!(self, Self::Retired(_))
    }

    /// Borrows the inline or lazily shared thunk, if this payload holds one.
    ///
    /// Both [`Thunk`](Self::Thunk) and [`SharedThunk`](Self::SharedThunk)
    /// resolve to the same `&EvalThunk`; every non-mint reader (get, clone,
    /// root scan, sweep, shed) goes through here so the lazy `Arc` promotion is
    /// invisible to them.
    pub(in crate::eval::heap) fn as_thunk(&self) -> Option<&EvalThunk> {
        match self {
            Self::Thunk(thunk) => Some(thunk),
            Self::SharedThunk(thunk) => Some(thunk.as_ref()),
            Self::Lambda(_) | Self::Primop(_) | Self::Retired(_) => None,
        }
    }

    /// Mutably borrows the inline thunk, if this payload holds one that is not
    /// yet promoted to a shared `Arc`.
    ///
    /// Returns `None` for a [`SharedThunk`](Self::SharedThunk): once a thunk has
    /// been shared behind an `Arc<EvalThunk>` its record is immutable through
    /// this handle. Only the still-inline [`Thunk`](Self::Thunk) variant grants
    /// mutable access (used by the test-only serial-cell promotion helper).
    #[cfg(test)]
    pub(in crate::eval::heap) fn as_thunk_mut(&mut self) -> Option<&mut EvalThunk> {
        match self {
            Self::Thunk(thunk) => Some(thunk),
            Self::SharedThunk(_) | Self::Lambda(_) | Self::Primop(_) | Self::Retired(_) => None,
        }
    }
}

/// Outcome of publishing a deferred flat capture into a pending closure.
///
/// Distinguishes the two legitimate non-error endings of the FV-5
/// post-assembly publication protocol from the inapplicable cases so the
/// caller's invariant check keeps its teeth: a pending unique closure must
/// either accept the flat environment or have been forced first — any other
/// outcome means the publication was lost to a plumbing bug.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::eval) enum FlatCapturePublication {
    /// The flat environment and capture tail were installed.
    Published,
    /// The closure was forced before its enclosing binding form reached the
    /// publication boundary, so its cached result made the conversion moot.
    ///
    /// The I1 force path (`force_value` -> `share_thunk`) promotes every
    /// forced thunk to an `Arc`-shared payload, which is how this state is
    /// observed. Skipping the publication is correct: the retained chain
    /// environment produced the cached value, and the reserved tail bytes
    /// simply stay unreachable (a missed representation optimization, not a
    /// wrongness class).
    ForcedBeforePublication,
    /// The closure kind or reserved metadata disagreed with the buffer; no
    /// bytes were written.
    Inapplicable,
}

/// Creates the production closure store or its chunked platform fallback.
pub(crate) fn serial_flat_closure_store(
    arena: &SharedFlatStoreArena,
) -> FlatObjectStore<FlatClosurePayload> {
    FlatObjectStore::with_rewindable_shared_arena(
        arena.clone(),
        FlatKindSet::of(&[
            FlatObjectKind::Thunk,
            FlatObjectKind::Lambda,
            FlatObjectKind::Primop,
        ]),
    )
    .unwrap_or_else(FlatObjectStore::new)
}

impl EvalHeap {
    /// Returns the placement newly allocated worker closures receive.
    pub fn worker_closure_placement(&self) -> WorkerClosurePlacement {
        self.worker_closure_placement
    }

    /// Returns whether serial flat closures can be rewritten before publish.
    pub(in crate::eval) fn supports_post_assembly_flat_capture(&self) -> bool {
        self.shared.is_none() && self.worker_closure_placement == WorkerClosurePlacement::Flat
    }

    /// Returns values stored in a serial flat closure's registry-backed tail.
    #[cfg(test)]
    pub(in crate::eval) fn flat_closure_capture_values(
        &self,
        value: Value,
    ) -> Result<Option<&[Value]>, EvalHeapError> {
        if self.shared.is_some() {
            return Ok(None);
        }
        let (ptr, kind) = match value.tag() {
            ValueTag::Thunk => (
                value.as_thunk_ptr().map_err(EvalHeapError::Value)?,
                FlatObjectKind::Thunk,
            ),
            ValueTag::Lambda => (
                value.as_lambda_ptr().map_err(EvalHeapError::Value)?,
                FlatObjectKind::Lambda,
            ),
            _ => return Ok(None),
        };
        let (object, values) = self
            .flat_closures
            .resolve_with_value_tail(ptr, kind)
            .map_err(|error| self.closure_resolution_error(value.tag(), ptr, error))?;
        if object.payload().is_retired() {
            return Err(EvalHeapError::unknown(value.tag(), ptr));
        }
        Ok(values)
    }

    /// Returns closure capture values through a prevalidated tail handle.
    #[inline]
    pub(in crate::eval) fn flat_closure_capture_values_at(
        &self,
        value: Value,
        handle: FlatValueTailHandle,
    ) -> Result<Option<&[Value]>, EvalHeapError> {
        let ptr = value.as_heap_ptr().map_err(EvalHeapError::Value)?;
        let (object, values) = self
            .flat_closures
            .resolve_value_tail_handle(ptr, handle)
            .map_err(|error| self.closure_resolution_error(value.tag(), ptr, error))?;
        if object.payload().is_retired() {
            return Err(EvalHeapError::unknown(value.tag(), ptr));
        }
        Ok(Some(values))
    }

    /// Copies one closure capture through its prevalidated tail handle.
    #[inline]
    pub(in crate::eval) fn flat_closure_capture_value_at(
        &self,
        value: Value,
        handle: FlatValueTailHandle,
        index: usize,
    ) -> Result<Option<Value>, EvalHeapError> {
        let ptr = value.as_heap_ptr().map_err(EvalHeapError::Value)?;
        let captured = self
            .flat_closures
            .value_tail_get_handle(ptr, handle, index)
            .map_err(|error| self.closure_resolution_error(value.tag(), ptr, error))?;
        Ok(captured)
    }

    /// Installs a flat lexical environment in one unique serial closure.
    ///
    /// Returns `false` when the addressed payload cannot accept the environment.
    pub(in crate::eval) fn replace_unique_flat_closure_env(
        &mut self,
        value: Value,
        env: EvalEnv,
    ) -> Result<bool, EvalHeapError> {
        let (ptr, kind) = match value.tag() {
            ValueTag::Thunk => (
                value.as_thunk_ptr().map_err(EvalHeapError::Value)?,
                FlatObjectKind::Thunk,
            ),
            ValueTag::Lambda => (
                value.as_lambda_ptr().map_err(EvalHeapError::Value)?,
                FlatObjectKind::Lambda,
            ),
            tag => {
                return Err(EvalHeapError::record_type_mismatch(
                    ValueTag::Thunk,
                    tag,
                    value.as_heap_ptr().map_err(EvalHeapError::Value)?,
                ));
            }
        };
        let payload = match self.flat_closures.resolve_mut(ptr, kind) {
            Ok(payload) => payload,
            Err(error) => {
                return Err(self.closure_resolution_error(value.tag(), ptr, error));
            }
        };
        match payload {
            FlatClosurePayload::Thunk(thunk) => Ok(thunk.replace_node_env(env)),
            FlatClosurePayload::Lambda(lambda) => {
                lambda.replace_env(env);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Publishes final recursive-binding values into a reserved capture tail.
    ///
    /// Returns [`FlatCapturePublication::Inapplicable`] if the closure kind or
    /// its reserved metadata disagrees with `buffer` (no bytes are written),
    /// and [`FlatCapturePublication::ForcedBeforePublication`] when the
    /// pending closure was legitimately forced before its enclosing binding
    /// form reached the publication boundary — the I1 force path promotes a
    /// forced thunk to an `Arc`-shared handle, and a forced thunk's captured
    /// environment is semantically inert (its result is cached; the flat
    /// conversion is only a representation optimization), so skipping the
    /// publication is correct. That interleaving is real in module-system
    /// shapes: a nested allocation escapes into the enclosing assembly's
    /// order-sensitive evaluation (a dynamic attr name forcing an option
    /// record's field, for example) and is forced before the boundary.
    pub(in crate::eval) fn publish_unique_flat_closure_capture(
        &mut self,
        value: Value,
        handle: FlatValueTailHandle,
        buffer: EvalFlatCaptureBuffer,
    ) -> Result<FlatCapturePublication, EvalHeapError> {
        if !buffer.is_ready() {
            return Ok(FlatCapturePublication::Inapplicable);
        }
        let (ptr, kind) = match value.tag() {
            ValueTag::Thunk => (
                value.as_thunk_ptr().map_err(EvalHeapError::Value)?,
                FlatObjectKind::Thunk,
            ),
            ValueTag::Lambda => (
                value.as_lambda_ptr().map_err(EvalHeapError::Value)?,
                FlatObjectKind::Lambda,
            ),
            _ => return Ok(FlatCapturePublication::Inapplicable),
        };
        if handle.len() != buffer.values().len() {
            return Ok(FlatCapturePublication::Inapplicable);
        }
        let env = EvalEnv::inline_flat(
            buffer.allocation_site(),
            buffer.frame_count(),
            value,
            handle,
        )?;
        let (payload, tail) = match self
            .flat_closures
            .resolve_mut_with_value_tail_handle(ptr, handle, kind)
        {
            Ok(resolved) => resolved,
            Err(error) => {
                return Err(self.closure_resolution_error(value.tag(), ptr, error));
            }
        };
        match payload {
            FlatClosurePayload::Thunk(thunk) => {
                if !matches!(thunk.kind(), EvalThunkKind::Node { .. }) {
                    return Ok(FlatCapturePublication::Inapplicable);
                }
                tail.copy_from_slice(buffer.values());
                if thunk.replace_node_env(env) {
                    Ok(FlatCapturePublication::Published)
                } else {
                    Ok(FlatCapturePublication::Inapplicable)
                }
            }
            FlatClosurePayload::Lambda(lambda) => {
                tail.copy_from_slice(buffer.values());
                lambda.replace_env(env);
                Ok(FlatCapturePublication::Published)
            }
            // The pending thunk was forced before the publication boundary:
            // the I1 force path shares the handle, its result is already
            // cached, and its retained chain environment stays semantically
            // correct — the flat conversion window has simply passed.
            FlatClosurePayload::SharedThunk(_) => {
                Ok(FlatCapturePublication::ForcedBeforePublication)
            }
            FlatClosurePayload::Primop(_) | FlatClosurePayload::Retired(_) => {
                Ok(FlatCapturePublication::Inapplicable)
            }
        }
    }

    /// Switches new worker-closure allocations to the record-table layout.
    ///
    /// This is the Tier-B B2 relocation proving ground's admission door; see
    /// [`WorkerClosurePlacement::Record`]. Existing flat closures (if any)
    /// stay flat and keep resolving — placement is a per-allocation choice.
    pub fn use_record_worker_closures_for_gc_scaffolding(&mut self) {
        self.worker_closure_placement = WorkerClosurePlacement::Record;
    }

    /// Serial flat thunk allocation (no heap record, no address-map insert).
    pub(in crate::eval::heap) fn flat_alloc_thunk(
        &mut self,
        thunk: EvalThunk,
        capture: Option<EvalFlatCaptureBuffer>,
    ) -> Result<(Value, Option<FlatValueTailHandle>), EvalHeapError> {
        let epoch = self.next_access_epoch();
        let capture_metadata = capture.as_ref().map(|capture| {
            (
                capture.allocation_site(),
                capture.frame_count(),
                capture.values().len(),
                capture.is_ready(),
            )
        });
        let (allocation, tail) = match capture {
            Some(capture) => {
                let tail_allocation = self
                    .flat_closures
                    .alloc_with_value_tail(
                        FlatObjectKind::Thunk,
                        0,
                        epoch,
                        capture.values(),
                        FlatClosurePayload::Thunk(thunk),
                    )
                    .map_err(flat_alloc_error)?;
                let handle = tail_allocation.handle.ok_or_else(|| {
                    flat_alloc_error(FlatObjectError::UnknownAddress {
                        address: tail_allocation.allocation.ptr.as_ptr() as usize,
                    })
                })?;
                (tail_allocation.allocation, Some(handle))
            }
            None => (
                self.flat_closures
                    .alloc(
                        FlatObjectKind::Thunk,
                        0,
                        epoch,
                        FlatClosurePayload::Thunk(thunk),
                    )
                    .map_err(flat_alloc_error)?,
                None,
            ),
        };
        self.allocator
            .record_flat_thunk_allocation_safepoint(allocation.allocation);
        let value = self.value_for_flat_allocation(ValueTag::Thunk, allocation.ptr)?;
        if let (Some((allocation_site, frame_count, _, true)), Some(handle)) =
            (capture_metadata, tail)
        {
            let env = EvalEnv::inline_flat(allocation_site, frame_count, value, handle)?;
            let replaced = self.replace_unique_flat_closure_env(value, env)?;
            debug_assert!(replaced, "fresh flat thunk payload must be unique");
        }
        self.alloc_counters.note_value_allocated();
        self.poll_memory_budget_after_allocation();
        Ok((value, tail))
    }

    /// Serial flat lambda allocation (no heap record, no address-map insert).
    pub(in crate::eval::heap) fn flat_alloc_lambda(
        &mut self,
        lambda: EvalLambda,
        capture: Option<EvalFlatCaptureBuffer>,
    ) -> Result<(Value, Option<FlatValueTailHandle>), EvalHeapError> {
        let epoch = self.next_access_epoch();
        let capture_metadata = capture.as_ref().map(|capture| {
            (
                capture.allocation_site(),
                capture.frame_count(),
                capture.values().len(),
                capture.is_ready(),
            )
        });
        let (allocation, tail) = match capture {
            Some(capture) => {
                let tail_allocation = self
                    .flat_closures
                    .alloc_with_value_tail(
                        FlatObjectKind::Lambda,
                        0,
                        epoch,
                        capture.values(),
                        FlatClosurePayload::Lambda(lambda),
                    )
                    .map_err(flat_alloc_error)?;
                let handle = tail_allocation.handle.ok_or_else(|| {
                    flat_alloc_error(FlatObjectError::UnknownAddress {
                        address: tail_allocation.allocation.ptr.as_ptr() as usize,
                    })
                })?;
                (tail_allocation.allocation, Some(handle))
            }
            None => (
                self.flat_closures
                    .alloc(
                        FlatObjectKind::Lambda,
                        0,
                        epoch,
                        FlatClosurePayload::Lambda(lambda),
                    )
                    .map_err(flat_alloc_error)?,
                None,
            ),
        };
        self.allocator
            .record_flat_lambda_allocation_safepoint(allocation.allocation);
        let value = self.value_for_flat_allocation(ValueTag::Lambda, allocation.ptr)?;
        if let (Some((allocation_site, frame_count, _, true)), Some(handle)) =
            (capture_metadata, tail)
        {
            let env = EvalEnv::inline_flat(allocation_site, frame_count, value, handle)?;
            let replaced = self.replace_unique_flat_closure_env(value, env)?;
            debug_assert!(replaced, "fresh flat lambda payload must be unique");
        }
        self.alloc_counters.note_value_allocated();
        self.poll_memory_budget_after_allocation();
        Ok((value, tail))
    }

    /// Serial flat primop allocation (no heap record, no address-map insert).
    pub(in crate::eval::heap) fn flat_alloc_primop(
        &mut self,
        primop: EvalPrimOp,
    ) -> Result<Value, EvalHeapError> {
        let epoch = self.next_access_epoch();
        let allocation = self
            .flat_closures
            .alloc(
                FlatObjectKind::Primop,
                0,
                epoch,
                FlatClosurePayload::Primop(primop),
            )
            .map_err(flat_alloc_error)?;
        self.allocator.record_flat_primop_allocation_safepoint(
            PRIMOP_HANDLE_BYTES,
            PRIMOP_HANDLE_ALIGN,
            PRIMOP_TYPE_TAG,
            allocation.allocation,
        );
        let value = self.value_for_flat_allocation(ValueTag::Primop, allocation.ptr)?;
        self.alloc_counters.note_value_allocated();
        self.poll_memory_budget_after_allocation();
        Ok(value)
    }

    /// Probes the flat closure store for an object of `kind`.
    ///
    /// One membership check plus one header load on the hit path. Returns
    /// `Ok(Some(payload))` for a live flat closure of the requested kind
    /// (with the flat-resolution counter and access epoch stamped), and
    /// `Ok(None)` when the address is not a flat closure at all — the caller
    /// then falls back to the record-table layout (the Tier-B B2 proving
    /// ground's placement) with its full error fidelity.
    ///
    /// # Errors
    ///
    /// A retired payload fails as [`EvalHeapError::UnknownPointer`] (the
    /// record table's index-miss shape); a flat closure of another kind
    /// fails as a record-type mismatch, unless that object is itself retired
    /// (then unknown), matching record resolution's fidelity.
    #[inline]
    pub(in crate::eval::heap) fn flat_closure_probe(
        &self,
        tag: ValueTag,
        kind: FlatObjectKind,
        ptr: NonNull<HeapObject>,
    ) -> Result<Option<&FlatClosurePayload>, EvalHeapError> {
        match self.flat_closures.resolve(ptr, kind) {
            Ok(object) => match object.payload() {
                payload @ (FlatClosurePayload::Thunk(_)
                | FlatClosurePayload::SharedThunk(_)
                | FlatClosurePayload::Lambda(_)
                | FlatClosurePayload::Primop(_)) => {
                    self.deref_counters.note_flat_resolution(tag);
                    if self.epoch_tracking_enabled {
                        object.touch(self.next_access_epoch());
                    }
                    Ok(Some(payload))
                }
                FlatClosurePayload::Retired(_) => Err(EvalHeapError::unknown(tag, ptr)),
            },
            Err(FlatObjectError::KindMismatch { actual, .. }) => {
                match self.flat_closures.resolve(ptr, actual) {
                    Ok(object) if object.payload().is_retired() => {
                        Err(EvalHeapError::unknown(tag, ptr))
                    }
                    _ => Err(EvalHeapError::record_type_mismatch(
                        tag,
                        value_tag_for_flat_kind(actual),
                        ptr,
                    )),
                }
            }
            Err(_) => Ok(None),
        }
    }

    /// Resolves a flat closure without stamping its access epoch (scan
    /// paths), tolerating any closure kind at the address.
    pub(in crate::eval::heap) fn flat_closure_payload_any(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Option<&FlatClosurePayload> {
        let kind = self.flat_closures.kind_of(ptr)?;
        let object = self.flat_closures.resolve(ptr, kind).ok()?;
        Some(object.payload())
    }

    /// Returns the value tag of the live flat closure at `ptr`, if any.
    ///
    /// Retired addresses report `None`: a retired object's address must keep
    /// failing as an unknown pointer, exactly like a retired record's removed
    /// index entry.
    pub(in crate::eval::heap) fn flat_closure_tag(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Option<ValueTag> {
        let payload = self.flat_closure_payload_any(ptr)?;
        if payload.is_retired() {
            return None;
        }
        Some(payload.tag())
    }

    /// Swaps a live flat thunk's payload in place (capture shedding).
    ///
    /// The flat analog of the record table's `HeapObjectValue` swap at shed
    /// time: the header (address identity, kind) is untouched and only the
    /// thunk payload is replaced, so owned metadata snapshots keep their view
    /// while later resolutions observe the released thunk. Shared force-state
    /// cells remain live through those snapshots. An inline capture tail stays
    /// attached because conservative descendants may inherit it through their
    /// flat-base owner edge.
    ///
    /// A [`SharedThunk`](FlatClosurePayload::SharedThunk) slot (minted by the
    /// force path) is accepted the same way: the whole payload is replaced with
    /// the new inline thunk, dropping this slot's `Arc` reference. Any in-flight
    /// force still holds its own `Arc` clone of the pre-shed thunk, so the
    /// captured graph is released only once that last reference drops — one
    /// stack frame later — which is observationally identical to the inline
    /// swap.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` is not a live flat
    /// thunk of this heap (retired payloads included).
    pub(in crate::eval::heap) fn flat_swap_thunk_payload(
        &mut self,
        ptr: NonNull<HeapObject>,
        thunk: EvalThunk,
    ) -> Result<(), EvalHeapError> {
        match self.flat_closures.resolve_mut(ptr, FlatObjectKind::Thunk) {
            Ok(payload @ (FlatClosurePayload::Thunk(_) | FlatClosurePayload::SharedThunk(_))) => {
                *payload = FlatClosurePayload::Thunk(thunk);
                Ok(())
            }
            Ok(_) => Err(EvalHeapError::unknown(ValueTag::Thunk, ptr)),
            Err(error) => Err(self.closure_resolution_error(ValueTag::Thunk, ptr, error)),
        }
    }

    /// Returns a lazily minted shared handle to the flat thunk at `ptr`.
    ///
    /// On the first call the inline [`EvalThunk`] is moved into an `Arc` and the
    /// slot is swapped to [`FlatClosurePayload::SharedThunk`] in place — the
    /// header, address, and any inline capture tail are preserved exactly as the
    /// retirement swap preserves them ([`flat_retire_closure`] is the
    /// precedent). Later calls return a cheap `Arc::clone` of the cached handle.
    ///
    /// Returns `Ok(None)` for anything that is not a live flat thunk at `ptr`
    /// (a different flat kind, a retired slot, a record-table or shared-backend
    /// thunk, or an unknown address); the caller then falls back to the owned
    /// [`EvalHeap::clone_thunk`] path, which reproduces the authoritative error
    /// or record/shared resolution.
    ///
    /// [`flat_retire_closure`]: Self::flat_retire_closure
    pub(in crate::eval::heap) fn flat_share_thunk(
        &mut self,
        ptr: NonNull<HeapObject>,
    ) -> Result<Option<Arc<EvalThunk>>, EvalHeapError> {
        match self.flat_closures.resolve_mut(ptr, FlatObjectKind::Thunk) {
            Ok(FlatClosurePayload::SharedThunk(shared)) => Ok(Some(Arc::clone(shared))),
            Ok(payload @ FlatClosurePayload::Thunk(_)) => {
                // Move the inline thunk out to wrap it in an `Arc`. The `Retired`
                // tombstone is only a transient placeholder here: it is
                // overwritten with `SharedThunk` before this `&mut` borrow ends,
                // so no reader ever observes a retired slot at this address.
                let FlatClosurePayload::Thunk(inner) =
                    std::mem::replace(payload, FlatClosurePayload::Retired(ValueTag::Thunk))
                else {
                    unreachable!("payload matched Thunk in the arm guard above")
                };
                let shared = Arc::new(inner);
                *payload = FlatClosurePayload::SharedThunk(Arc::clone(&shared));
                Ok(Some(shared))
            }
            // Not a live flat thunk here: defer error/record/shared fidelity to
            // the owned clone path (mirrors `clone_thunk`'s fallbacks exactly).
            Ok(_) | Err(_) => Ok(None),
        }
    }

    /// Retires the flat closure at `ptr` in place (the B1 sweep door).
    ///
    /// Drops the direct payload (releasing its side-owned graph), swaps in the
    /// [`FlatClosurePayload::Retired`] tombstone, clears the address's
    /// cutoff-cache hashes, and counts the retirement for the region-pop
    /// interlock. Returns the retired object's original tag, or `None` if
    /// the object was already retired.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` is not a flat
    /// closure of this heap.
    pub(in crate::eval::heap) fn flat_retire_closure(
        &mut self,
        ptr: NonNull<HeapObject>,
    ) -> Result<Option<ValueTag>, EvalHeapError> {
        let Some(kind) = self.flat_closures.kind_of(ptr) else {
            return Err(EvalHeapError::unknown(ValueTag::Thunk, ptr));
        };
        let payload = match self.flat_closures.resolve_mut(ptr, kind) {
            Ok(payload) => payload,
            Err(error) => {
                let tag = value_tag_for_flat_kind(kind);
                return Err(self.closure_resolution_error(tag, ptr, error));
            }
        };
        if payload.is_retired() {
            return Ok(None);
        }
        let tag = payload.tag();
        *payload = FlatClosurePayload::Retired(tag);
        let _ = self.flat_closures.retire_value_tail(ptr);
        self.flat_cold_hashes.clear(ptr.as_ptr() as usize);
        self.flat_closures_retired = self.flat_closures_retired.saturating_add(1);
        Ok(Some(tag))
    }

    /// Maps a flat-closure resolution failure to the heap error vocabulary.
    ///
    /// Kind mismatches inside the closure store first check whether the
    /// actual object is retired — a retired address is *unknown* (today's
    /// index-miss contract), not a type mismatch. Unknown addresses fall
    /// through the shared flat/record error path so cross-domain mismatches
    /// keep their fidelity.
    pub(in crate::eval::heap) fn closure_resolution_error(
        &self,
        tag: ValueTag,
        ptr: NonNull<HeapObject>,
        error: FlatObjectError,
    ) -> EvalHeapError {
        match error {
            FlatObjectError::KindMismatch { actual, .. } => {
                match self.flat_closures.resolve(ptr, actual) {
                    Ok(object) if object.payload().is_retired() => EvalHeapError::unknown(tag, ptr),
                    _ => EvalHeapError::record_type_mismatch(
                        tag,
                        value_tag_for_flat_kind(actual),
                        ptr,
                    ),
                }
            }
            error => self.flat_resolution_error(tag, ptr, error),
        }
    }

    /// Counts live (non-retired) flat worker closures.
    pub(in crate::eval::heap) fn live_flat_closures(&self) -> usize {
        self.flat_closures
            .iter()
            .filter(|entry| !entry.object().payload().is_retired())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::{EvalThunk, FlatClosurePayload};

    #[test]
    fn closure_payload_owns_the_largest_migrated_payload_inline() {
        assert!(
            std::mem::size_of::<FlatClosurePayload>() >= std::mem::size_of::<EvalThunk>(),
            "the flat closure payload must contain the migrated thunk by value",
        );
    }
}
