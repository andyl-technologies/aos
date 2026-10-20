//! Retains the genuine pre-Ownership Root input flight and its native C turn.
//!
//! Only the closed Entry constructor lends the actual accepted Start originals.
//! The completed borrower joins stored positive C disposition with the client's
//! strict reply/EOF/native conjunction. No raw reply or returned Result issues it.

use super::*;
use crate::normal_root::RootStartAssignmentInputsClientOriginalV2;

#[derive(Clone, Copy)]
pub(super) enum InputsFirstV2 {
    Next,
    Body,
    ControllerAfter,
    RootAfter,
    Resident,
    Reentry,
}

pub(super) struct StartAssignmentInputsOriginalV2 {
    pub(super) client: RootStartAssignmentInputsClientOriginalV2,
    pub(super) base: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    pub(super) next: Option<Result<(), ResourceReservationErrorV1>>,
    pub(super) body: Option<Result<(), ResourceReservationErrorV1>>,
    pub(super) controller_after: Option<Result<(), ResourceReservationErrorV1>>,
    pub(super) root_after: Option<Result<(), crate::normal_root::RootHostLaunchClientClosedV1>>,
    pub(super) resident: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    pub(super) native_selected: bool,
    pub(super) root_selected: bool,
    pub(super) first: Option<InputsFirstV2>,
}

impl StartAssignmentInputsOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            client: RootStartAssignmentInputsClientOriginalV2::new(),
            base: None,
            next: None,
            body: None,
            controller_after: None,
            root_after: None,
            resident: None,
            native_selected: false,
            root_selected: false,
            first: None,
        }
    }

    pub(super) fn completed_v2(&self) -> bool {
        self.first.is_none()
            && matches!(self.resident, Some(Ok(_)))
            && self.client.borrow_completed_inputs_v2().is_ok()
    }

    pub(super) fn fixed_demand_v2() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    pub(super) fn failure<'held>(&'held self, native: Option<&'held (dyn Error + 'static)>)
        -> Option<&'held (dyn Error + 'static)>
    {
        if self.native_selected {
            return native.or(Some(&CLOSED));
        }
        if self.root_selected {
            return self.client.failure().or(Some(&CLOSED));
        }
        match self.first? {
            InputsFirstV2::Next => cause(&self.base).or_else(|| cause(&self.next)),
            InputsFirstV2::Body => cause(&self.body),
            InputsFirstV2::ControllerAfter => cause(&self.controller_after),
            InputsFirstV2::RootAfter => self.client.failure().or_else(|| cause(&self.root_after)),
            InputsFirstV2::Resident => cause(&self.resident),
            InputsFirstV2::Reentry => Some(&CLOSED),
        }
    }
}

fn cause<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause as _)
}

const CLOSED: ResourceReservationErrorV1 = ResourceReservationErrorV1::Conflict;
