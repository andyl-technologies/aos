//! Keeps the original concrete receiving permit and service-before slots.
//!
//! Finite private Root owners derive their actual cumulative demand and retain
//! the same financial original before filling these fields. This module accepts
//! no public vector, receipt, phase selector, callback or completion adopter.

use std::error::Error;
use aos_sandbox_broker::receiving::{RootJournalFinancialOriginalV1, RootObservationErrorV1,
    RootSelectedStartupBorrowV1, RootUpperMutationGuardV1};
use aos_sandbox_model::ResourceVector;
use crate::native::PolicyNativeJournalErrorV1 as NativeError;
use super::initial_open::RootInitialOpenErrorV1 as E;

pub(super) struct RootInitialStageOriginalV1 {
    pub(super) financial: Option<RootJournalFinancialOriginalV1>,
    pub(super) permit: Option<Result<ResourceVector, NativeError>>,
    pub(super) before: Option<Result<(), RootObservationErrorV1>>,
    pub(super) entered: bool,
}

impl RootInitialStageOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            financial: None,
            permit: None,
            before: None,
            entered: false,
        }
    }

    pub(super) fn require_complete_v1(&self) -> Result<ResourceVector, E> {
        let demand = *positive(&self.permit)?;
        positive(&self.before)?;
        Ok(demand)
    }

    pub(super) fn finish_v1(
        &mut self,
        initial: &mut aos_sandbox_broker::receiving::RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if !matches!(self.permit, Some(Ok(_))) {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.before = Some(startup.recheck_under_upper_exclusion_v1(exclusion));
        if matches!(self.before, Some(Ok(()))) {
            Ok(())
        } else {
            initial.latch_root_refusal_v1();
            Err(RootObservationErrorV1::Service)
        }
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.permit).or_else(|| cause(&self.before))
    }
}

fn positive<T, F>(slot: &Option<Result<T, F>>) -> Result<&T, E> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::Boundary)
}

fn cause<T, F: Error + 'static>(slot: &Option<Result<T, F>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}
