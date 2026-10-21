//! Retains the real initial Open Stage and its first service observation.
//!
//! The same Current owner supplies its actual completed cumulative prefix,
//! captured full Authority extent, retained semantic supplement and financial
//! original. The same owned peer lends real Initial only during this Stage.

use std::error::Error;

use aos_sandbox_broker::receiving::{
    RootJournalFinancialOriginalV1, RootObservationErrorV1, RootSelectedStartupBorrowV1,
    RootUpperMutationGuardV1,
};
use aos_sandbox_model::ResourceVector;

use crate::native::PolicyNativeJournalErrorV1;
use crate::native::startup::RootCurrentWritersPredecessorV1;

use super::preopen_geometry::ProtectedJournalPreopenReplayExtentV1;
use super::writers::RootCurrentWritersOriginalV1;

type E = PolicyNativeJournalErrorV1;

// These are borrowed comparison inputs from the same genuinely complete Current
// owner. Only its private method constructs this view; no scalar input is adopted
// as a completed prefix, financial original or native extent.
pub(super) struct RootInitialOpenReceivingDataV1<'held> {
    pub(super) financial: &'held RootJournalFinancialOriginalV1,
    pub(super) base: ResourceVector,
    pub(super) held: &'held ProtectedJournalPreopenReplayExtentV1,
    pub(super) supplement: ResourceVector,
}

pub(super) struct RootInitialOpenProvisionOriginalV1 {
    financial: Option<RootJournalFinancialOriginalV1>,
    permit: Option<Result<ResourceVector, E>>,
    before: Option<Result<(), RootObservationErrorV1>>,
    entered: bool,
}

impl RootInitialOpenProvisionOriginalV1 {
    pub(super) fn new() -> Self {
        Self { financial: None, permit: None, before: None, entered: false }
    }

    pub(super) fn begin_once_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let (initial, financial) = predecessor.split_initial_v1();
        if self.entered || self.permit.is_some() || initial.failure().is_some() {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        // This is the old once-only Open provision frontier, before quote/debit.
        self.entered = true;
        self.financial = Some(financial.clone());
        self.permit = Some(self.stage_inner_v1(writers, financial, startup, exclusion));
        if !matches!(self.permit, Some(Ok(_))) {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }

        // This is the FIRST service observation. Initial identity later keeps
        // its independent SECOND recheck before the first Instant/kernel pair.
        self.before = Some(startup.recheck_under_upper_exclusion_v1(exclusion));
        if matches!(self.before, Some(Ok(()))) {
            Ok(())
        } else {
            initial.latch_root_refusal_v1();
            Err(RootObservationErrorV1::Service)
        }
    }

    fn stage_inner_v1(
        &self,
        writers: &RootCurrentWritersOriginalV1,
        original: &RootJournalFinancialOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<ResourceVector, E> {
        let inputs = writers.initial_open_receiving_data_v1()
            .map_err(|_| E::boundary())?;
        if !inputs.financial.same_original_data_v1(original)
            || !startup.same_financial_original_data_v1(original)
        {
            return Err(E::boundary());
        }
        let additional = super::initial_geometry::append_demand_v1(inputs.held, inputs.supplement)?;
        let complete = inputs.base.checked_add(additional).map_err(|_| E::geometry())?;
        if original.require_receiving_demand_under_upper_exclusion_v1(exclusion, complete).is_err() {
            return Err(E::Financial(original.clone()));
        }
        Ok(complete)
    }

    pub(super) fn require_complete_v1(&self) -> Result<(), RootObservationErrorV1> {
        if matches!(self.permit, Some(Ok(_))) && matches!(self.before, Some(Ok(()))) {
            Ok(())
        } else {
            Err(RootObservationErrorV1::Service)
        }
    }

    pub(super) fn completed_prefix_v1(&self) -> Result<ResourceVector, RootObservationErrorV1> {
        self.require_complete_v1()?;
        match &self.permit {
            Some(Ok(prefix)) => Ok(*prefix),
            _ => Err(RootObservationErrorV1::Service),
        }
    }

    pub(super) fn same_financial_v1(&self, financial: &RootJournalFinancialOriginalV1) -> bool {
        match &self.financial {
            Some(original) => original.same_original_data_v1(financial),
            None => false,
        }
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(Err(error)) = &self.permit {
            return Some(error);
        }
        self.before.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
    }
}
