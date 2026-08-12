//! Serial evaluator integration for active packed Apply-shaped thunks.
//!
//! This default-off experiment owns one logical Candidate-C domain. Values in
//! that domain carry direct head-lane coordinates and must be resolved here
//! before generic pointer reconstruction.

use super::packed_thunk_lane::{
    ActivePackedThunkLane, PackedApplyWork, PackedNodeRef, PackedSpan, PackedThunkClaim,
    PackedThunkLaneBytes, PackedThunkLaneCapacities, PackedThunkRef, PackedThunkState,
    PackedThunkWorkHandle, PackedValueWord,
};
use super::*;
use crate::eval::ThunkState;
use crate::eval::tree_walk::ActivePackedThunkCapacities;

/// Copyable Apply-shaped work detached from any lane borrow.
#[derive(Clone, Copy, Debug)]
pub(in crate::eval) struct ActivePackedApplyWork {
    /// Whether this is the exact GenListElemAtAddOne marker.
    pub(in crate::eval) gen_list_elem_at_add_one: bool,
    /// Function expression.
    pub(in crate::eval) function: EvalNodeRef,
    /// Function diagnostic span.
    pub(in crate::eval) function_span: Span,
    /// Lazy function value.
    pub(in crate::eval) function_value: Value,
    /// Argument expression.
    pub(in crate::eval) argument: EvalNodeRef,
    /// Lazy argument value.
    pub(in crate::eval) argument_value: Value,
}

/// Result of resolving and claiming an active packed thunk.
#[derive(Clone, Copy, Debug)]
pub(in crate::eval) enum ActivePackedThunkForce {
    /// The value is not owned by the active packed lane.
    NotPacked,
    /// The head already contains its terminal result.
    AlreadyForced(Value),
    /// The caller owns the head until publication or abort.
    Claimed {
        /// Direct stable head coordinate.
        reference: PackedThunkRef,
        /// Exact work coordinate installed in the blackhole.
        handle: PackedThunkWorkHandle,
        /// Copy of the Apply-shaped work needed during evaluator re-entry.
        work: ActivePackedApplyWork,
    },
}

/// Active packed-lane byte and event accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ActivePackedThunkAccounting {
    /// Successfully allocated packed Apply heads.
    pub apply_allocated: u64,
    /// Successfully allocated packed GenList marker heads.
    pub gen_list_elem_at_add_one_allocated: u64,
    /// Exact initialized lane bytes, including tombstones.
    pub initialized_bytes: usize,
    /// Fixed admitted payload bytes.
    pub capacity_bytes: usize,
    /// Demand-paged virtual reservation bytes.
    pub virtual_reserved_bytes: usize,
}

/// Lazily constructed fixed-capacity owner.
#[derive(Debug, Default)]
pub(super) struct ActivePackedThunkStore {
    configured: Option<ActivePackedThunkCapacities>,
    lane: Option<ActivePackedThunkLane>,
    apply_allocated: u64,
    gen_list_elem_at_add_one_allocated: u64,
}

impl ActivePackedThunkStore {
    fn error(error: impl std::fmt::Display) -> EvalHeapError {
        EvalHeapError::ActivePackedThunk {
            message: error.to_string(),
        }
    }

    fn ensure_lane(&mut self) -> Result<&mut ActivePackedThunkLane, EvalHeapError> {
        if self.lane.is_none() {
            let configured = self.configured.ok_or_else(|| {
                Self::error("active packed thunk store was used before configuration")
            })?;
            let total = configured
                .apply
                .checked_add(configured.gen_list_elem_at_add_one)
                .ok_or_else(|| Self::error("active packed thunk capacity sum overflowed"))?;
            if configured.heads < total {
                return Err(Self::error(
                    "active packed thunk head capacity is smaller than admitted work",
                ));
            }
            let owner = crate::heap::ArenaDomainId::allocate_logical().map_err(Self::error)?;
            let admitted = PackedThunkLaneCapacities {
                heads: configured.heads,
                apply: configured.apply,
                gen_list_elem_at_add_one: configured.gen_list_elem_at_add_one,
                ..PackedThunkLaneCapacities::default()
            };
            self.lane = Some(
                ActivePackedThunkLane::try_with_capacities(owner, admitted).map_err(Self::error)?,
            );
        }
        self.lane
            .as_mut()
            .ok_or_else(|| Self::error("active packed thunk lane initialization disappeared"))
    }

    pub(super) fn configure(&mut self, capacities: ActivePackedThunkCapacities) {
        self.configured = Some(capacities);
    }

    pub(super) const fn is_configured(&self) -> bool {
        self.configured.is_some()
    }

    fn reference(&self, value: Value) -> Option<PackedThunkRef> {
        let lane = self.lane.as_ref()?;
        (value.tag() == ValueTag::Thunk && value.word().arena_domain() == Some(lane.owner_domain()))
            .then(|| value.word().arena_index())
            .flatten()
            .map(crate::heap::ArenaIndex::raw)
            .map(PackedThunkRef::from_index)
    }

    pub(super) fn try_allocate(
        &mut self,
        thunk: &EvalThunk,
    ) -> Result<Option<Value>, EvalHeapError> {
        if self.configured.is_none() {
            return Ok(None);
        }
        let (is_gen_list, work) = match thunk.kind() {
            EvalThunkKind::Apply {
                function,
                function_span,
                function_value,
                argument,
                argument_value,
            } => (
                false,
                pack_apply(
                    *function,
                    *function_span,
                    *function_value,
                    *argument,
                    *argument_value,
                ),
            ),
            EvalThunkKind::GenListElemAtAddOne {
                function,
                function_span,
                function_value,
                argument,
                argument_value,
            } => (
                true,
                pack_apply(
                    *function,
                    *function_span,
                    *function_value,
                    *argument,
                    *argument_value,
                ),
            ),
            _ => return Ok(None),
        };
        let next_count = if is_gen_list {
            self.gen_list_elem_at_add_one_allocated
                .checked_add(1)
                .ok_or_else(|| Self::error("packed GenList allocation counter overflowed"))?
        } else {
            self.apply_allocated
                .checked_add(1)
                .ok_or_else(|| Self::error("packed Apply allocation counter overflowed"))?
        };
        let lane = self.ensure_lane()?;
        let reference = if is_gen_list {
            lane.allocate_gen_list_elem_at_add_one(work)
        } else {
            lane.allocate_apply(work)
        }
        .map_err(Self::error)?;
        let value = Value::from_domain_index(
            ValueTag::Thunk,
            lane.owner_domain(),
            crate::heap::ArenaIndex::new(reference.index()),
        )?;
        if is_gen_list {
            self.gen_list_elem_at_add_one_allocated = next_count;
        } else {
            self.apply_allocated = next_count;
        }
        Ok(Some(value))
    }

    pub(super) fn begin_force(
        &self,
        value: Value,
    ) -> Result<ActivePackedThunkForce, EvalHeapError> {
        let Some(reference) = self.reference(value) else {
            return Ok(ActivePackedThunkForce::NotPacked);
        };
        let lane = self
            .lane
            .as_ref()
            .ok_or_else(|| Self::error("recognized packed domain has no lane"))?;
        match lane.claim(reference).map_err(Self::error)? {
            PackedThunkClaim::AlreadyForced(value) => Ok(ActivePackedThunkForce::AlreadyForced(
                Value::from_word(value.compressed()),
            )),
            PackedThunkClaim::Claimed(handle) => {
                let (gen_list_elem_at_add_one, packed) = match lane
                    .state(reference)
                    .map_err(Self::error)?
                {
                    PackedThunkState::Blackhole(actual) if actual == handle => match handle.raw()
                        >> 29
                    {
                        1 => (false, *lane.apply_work(handle).map_err(Self::error)?),
                        2 => (
                            true,
                            *lane
                                .gen_list_elem_at_add_one_work(handle)
                                .map_err(Self::error)?,
                        ),
                        _ => return Err(Self::error("active packed head has a non-Apply shape")),
                    },
                    _ => {
                        return Err(Self::error(
                            "active packed claim changed before work resolve",
                        ));
                    }
                };
                Ok(ActivePackedThunkForce::Claimed {
                    reference,
                    handle,
                    work: unpack_apply(packed, gen_list_elem_at_add_one),
                })
            }
        }
    }

    pub(super) fn abort(
        &self,
        reference: PackedThunkRef,
        handle: PackedThunkWorkHandle,
    ) -> Result<(), EvalHeapError> {
        self.lane
            .as_ref()
            .ok_or_else(|| Self::error("active packed abort has no lane"))?
            .abort(reference, handle)
            .map_err(Self::error)
    }

    pub(super) fn publish(
        &mut self,
        reference: PackedThunkRef,
        handle: PackedThunkWorkHandle,
        value: Value,
    ) -> Result<(), EvalHeapError> {
        self.lane
            .as_mut()
            .ok_or_else(|| Self::error("active packed publication has no lane"))?
            .publish(reference, handle, PackedValueWord::new(value.word()))
            .map_err(Self::error)
    }

    pub(super) fn state(&self, value: Value) -> Option<ThunkState> {
        let reference = self.reference(value)?;
        match self.lane.as_ref()?.state(reference).ok()? {
            PackedThunkState::Suspended(_) => Some(ThunkState::Suspended),
            PackedThunkState::Blackhole(_) => Some(ThunkState::Blackhole),
            PackedThunkState::Forced(_) => Some(ThunkState::Forced),
        }
    }

    pub(super) fn accounting(&self) -> ActivePackedThunkAccounting {
        let (initialized, capacity, virtual_reserved_bytes) = self.lane.as_ref().map_or(
            (
                PackedThunkLaneBytes::default(),
                PackedThunkLaneBytes::default(),
                0,
            ),
            |lane| {
                (
                    lane.initialized_bytes(),
                    lane.capacity_bytes(),
                    lane.virtual_reserved_bytes(),
                )
            },
        );
        ActivePackedThunkAccounting {
            apply_allocated: self.apply_allocated,
            gen_list_elem_at_add_one_allocated: self.gen_list_elem_at_add_one_allocated,
            initialized_bytes: initialized.total(),
            capacity_bytes: capacity.total(),
            virtual_reserved_bytes,
        }
    }
}

fn pack_apply(
    function: EvalNodeRef,
    function_span: Span,
    function_value: Value,
    argument: EvalNodeRef,
    argument_value: Value,
) -> PackedApplyWork {
    PackedApplyWork::new(
        PackedNodeRef::new(function.module().as_u32(), function.id().as_u32()),
        PackedSpan::new(function_span.start, function_span.end),
        PackedValueWord::new(function_value.word()),
        PackedNodeRef::new(argument.module().as_u32(), argument.id().as_u32()),
        PackedValueWord::new(argument_value.word()),
    )
}

fn unpack_apply(work: PackedApplyWork, gen_list_elem_at_add_one: bool) -> ActivePackedApplyWork {
    ActivePackedApplyWork {
        gen_list_elem_at_add_one,
        function: EvalNodeRef::new(
            EvalModuleId::new(work.function().module()),
            IrId::new(work.function().node()),
        ),
        function_span: Span::new(work.function_span().start(), work.function_span().end()),
        function_value: Value::from_word(work.function_value().compressed()),
        argument: EvalNodeRef::new(
            EvalModuleId::new(work.argument().module()),
            IrId::new(work.argument().node()),
        ),
        argument_value: Value::from_word(work.argument_value().compressed()),
    }
}

impl EvalHeap {
    /// Configures the fixed-capacity active packed-thunk experiment.
    pub(in crate::eval) fn enable_active_packed_thunks(
        &mut self,
        capacities: ActivePackedThunkCapacities,
    ) {
        self.active_packed_thunks.configure(capacities);
    }

    pub(in crate::eval::heap) fn try_active_packed_alloc_thunk(
        &mut self,
        thunk: &EvalThunk,
    ) -> Result<Option<Value>, EvalHeapError> {
        self.active_packed_thunks.try_allocate(thunk)
    }

    /// Returns whether `value` is a direct coordinate in the active lane.
    #[inline]
    pub(in crate::eval) fn is_active_packed_thunk(&self, value: Value) -> bool {
        self.active_packed_thunks.reference(value).is_some()
    }

    /// Returns active packed-thunk accounting.
    pub fn active_packed_thunk_accounting(&self) -> ActivePackedThunkAccounting {
        self.active_packed_thunks.accounting()
    }

    pub(in crate::eval) fn active_packed_thunk_state(&self, value: Value) -> Option<ThunkState> {
        self.active_packed_thunks.state(value)
    }

    pub(in crate::eval) fn begin_active_packed_thunk_force(
        &self,
        value: Value,
    ) -> Result<ActivePackedThunkForce, EvalHeapError> {
        self.active_packed_thunks.begin_force(value)
    }

    pub(in crate::eval) fn abort_active_packed_thunk_force(
        &self,
        reference: PackedThunkRef,
        handle: PackedThunkWorkHandle,
    ) -> Result<(), EvalHeapError> {
        self.active_packed_thunks.abort(reference, handle)
    }

    pub(in crate::eval) fn publish_active_packed_thunk_force(
        &mut self,
        reference: PackedThunkRef,
        handle: PackedThunkWorkHandle,
        value: Value,
    ) -> Result<(), EvalHeapError> {
        self.active_packed_thunks.publish(reference, handle, value)
    }
}
