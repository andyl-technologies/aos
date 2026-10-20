//! Transfers the same entered C18 between admission and its actual executor.
//!
//! This handoff performs no observation, debit, completion, disposal or reset.
//! The original remains active and retains its before observations and owed
//! afters. Reborrowing can therefore finish a refused prefix without requiring
//! that prefix to become healthy. Every effect-bearing method still checks the
//! same active native owner through its existing canonical guard.

use super::*;

impl ControllerOperationIntakeReceivingLoanV1<'_> {
    /// Parks only the actual unfinished Execution18 admission borrower.
    ///
    /// The owning Controller admission scope must retain this same native owner
    /// and reborrow it before canonical append or execution work. Dropping that
    /// owning scope while it remains entered still invokes the original fatal
    /// custody guard; this method does not permit disposal of a failed prefix.
    ///
    /// # Errors
    /// Refuses another purpose, a completed loan, Source entry, repeated handoff
    /// or an owner that was never entered by its genuine declared-C18 factory.
    #[doc(hidden)]
    pub fn park_execution_admission_v2(mut self) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.owner.purpose != OperationIntakePurposeV1::Execution
            || !self.owner.active
            || !self.owner.whole_declared
            || self.finished
            || self.delete_source_scope_entered
            || self.owner.delete_source_scope_open
            || self.owner.execution_admission_parked
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }

        self.owner.execution_admission_parked = true;
        self.execution_admission_handoff = true;
        Ok(())
    }
}

impl ControllerOperationIntakeOriginalV1 {
    /// Reborrows the same parked C18 without repeating native entry or funding.
    ///
    /// Association is checked even after a refused body so the original owed
    /// afters remain reachable. Healthy work additionally calls the unchanged
    /// `require_active_v1` guard; this borrower itself grants no native effect.
    ///
    /// # Errors
    /// Refuses a foreign writer/profile, another purpose, missing handoff,
    /// completed interval or a Source scope that has already been entered.
    #[doc(hidden)]
    pub fn resume_execution_admission_v2<'owner, P>(
        &'owner mut self,
        writer: &ControllerCoordinatorWriterV1<P>,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<ControllerOperationIntakeReceivingLoanV1<'owner>, ControllerBankLaunchErrorV1> {
        if self.purpose != OperationIntakePurposeV1::Execution
            || !self.active
            || !self.whole_declared
            || !self.execution_admission_parked
            || self.delete_source_scope_open
            || !Arc::ptr_eq(&self.identity, writer.fixed.identity())
            || !writer.fixed.has_original(&self.original)
            || !profile.has_same_baseline_original(&self.original)
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }

        self.execution_admission_parked = false;
        Ok(ControllerOperationIntakeReceivingLoanV1 {
            owner: self,
            finished: false,
            delete_source_scope_entered: false,
            execution_admission_handoff: false,
        })
    }
}

impl ControllerOperationIntakeOriginalV1 {
    pub(super) fn require_active_native_inner_v2<P>(
        &self,
        writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        finished: bool,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !Arc::ptr_eq(&self.identity, writer.fixed.identity())
            || !writer.fixed.has_original(&self.original)
            || !profile.has_same_baseline_original(&self.original)
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        launch.require_current_controller_v1(writer)?;
        self.require_funding_v2(writer, launch, profile)?;
        if finished || !self.active || self.entry.first.is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.original.operation_intakes.try_lock().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?
            .slot_mut(self.purpose).require_active()?;
        Ok(())
    }

    /// Checks the parked original through the same active native guard.
    ///
    /// This neither resumes work nor changes the loan or its accounting state.
    ///
    /// # Errors
    /// Refuses another purpose, missing actual handoff, failed/native-completed
    /// prefix, changed Controller writer, funding, launch or profile.
    #[doc(hidden)]
    pub fn require_parked_execution_admission_current_v2<P>(
        &self,
        writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.purpose != OperationIntakePurposeV1::Execution || !self.execution_admission_parked {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.require_active_native_inner_v2(writer, launch, profile, false)
    }
}

impl ControllerOperationIntakeReceivingLoanV1<'_> {
    pub(crate) fn require_execution_storage_floor_original_v2<P>(
        &self,
        expected: &Arc<ControllerReceivingOriginalV1>,
        writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.owner.purpose != OperationIntakePurposeV1::Execution
            || !Arc::ptr_eq(&self.owner.original, expected)
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.require_active_v1(writer, launch, profile)
    }
}
