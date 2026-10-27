//! Enters the original Execution18 before public compilation and acceptance.
//!
//! The accepted-operation decoder remains the sole issuer of execution input.
//! Before acceptance, this loan permits only complete receiving checks and the
//! independently owed C post. Its handoff retains the same entered native owner
//! in the Controller admission scope; resumption performs no new native entry.

use super::*;

/// Borrows the entered C18 before a canonical operation identifier exists.
///
/// This loan cannot borrow an Environment or Source writer, authorize Host work
/// or return accepted execution context. Those ports remain on the existing
/// accepted loan, obtained only after the canonical protected acceptance join.
#[must_use]
pub struct ControllerExecutionAdmissionReceivingLoanV2<'owner> {
    pub(super) journal_identity: &'owner crate::journal::ExecutionObservationJournalIdentityV4,
    pub(super) native: ControllerOperationIntakeReceivingLoanV1<'owner>,
    accepted: &'owner mut Option<Result<Option<PublicMutationEffectHistoryV1>, ReconcilerError>>,
    append_demand: &'owner mut Option<Result<ResourceVector, crate::journal::JournalAppendReceivingDemandErrorV1>>,
    binding: &'owner mut Option<Result<(), ResourceReservationErrorV1>>,
    pub(super) entry: &'owner Option<Result<(), ResourceReservationErrorV1>>,
    pub(super) post: &'owner mut Option<Result<(), ResourceReservationErrorV1>>,
    evidence: &'owner mut EnvironmentExecutionEvidenceOriginalV1,
    pub(super) clock: &'owner mut ControllerExecutionClockOriginalV1,
    active: &'owner mut bool,
    predurable_entered: &'owner mut bool,
    predurable_prefix: &'owner mut Option<ResourceVector>,
    pub(super) prefix: ResourceVector,
    environment_failure: &'owner mut Option<crate::protected_domain_journal::ProtectedDomainJournalErrorV1>,
    pub(super) cleanup: &'owner mut super::no_apply_cleanup::ControllerExecutionCleanupOriginalV2,
}

impl ControllerExecutionOperationOriginalV1 {
    pub(super) fn begin_native_engine_v2<'owner>(
        &'owner mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        prefix: ResourceVector,
    ) -> Result<ControllerExecutionAdmissionReceivingLoanV2<'owner>, ResourceReservationErrorV1> {
        if self.active || self.accepted.is_some() || self.post.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let native = bank.begin_execution_whole_declared_v1(
            &mut self.native, controller, profile, Demand::from_demand_v1(prefix),
        )?;
        self.active = true;
        self.entry = Some(bank.require_operation_intake_current_v1(&native, controller, profile));
        Ok(ControllerExecutionAdmissionReceivingLoanV2 {
            journal_identity: &self.journal_identity,
            native,
            accepted: &mut self.accepted,
            append_demand: &mut self.append_demand,
            binding: &mut self.binding,
            entry: &self.entry,
            post: &mut self.post,
            evidence: &mut self.evidence,
            clock: &mut self.clock,
            active: &mut self.active,
            predurable_entered: &mut self.predurable_entered,
            predurable_prefix: &mut self.predurable_prefix,
            prefix,
            environment_failure: &mut self.environment_failure,
            cleanup: &mut self.cleanup,
        })
    }

    /// Begins the same configured C18 before public authorization or Exec decode.
    ///
    /// `complete` is the concrete full public/compiler/native representation
    /// requirement from the installed caller. It cannot select capacity: the
    /// same bank consumes its existing declaration through the native engine.
    /// The caller retains the returned loan even when its native entry refused,
    /// and runs its independently owed post before reporting that refusal.
    ///
    /// # Errors
    /// Refuses overlap, another admission, unavailable original funding or a
    /// complete requirement beyond the genuine declared Execution18 capacity.
    #[doc(hidden)]
    pub fn begin_public_admission_once_v2<'owner>(
        &'owner mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        complete: aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1,
    ) -> Result<ControllerExecutionAdmissionReceivingLoanV2<'owner>, ResourceReservationErrorV1> {
        if self.predurable_entered || self.predurable_prefix.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.predurable_entered = true;
        self.predurable_prefix = Some(complete.demand_v1());
        self.begin_native_engine_v2(bank, controller, profile, complete.demand_v1())
    }

    /// Reborrows only this actual parked pre-admission native interval.
    ///
    /// No native observation or traffic debit repeats here. Every healthy body
    /// still checks the original retained entry and the same current bank cut;
    /// a refused entry can use the borrower only to finish its owed post.
    ///
    /// # Errors
    /// Refuses a foreign journal/profile, missing native handoff, accepted or
    /// completed interval, or absence of the retained complete admission quote.
    #[doc(hidden)]
    pub fn resume_public_admission_v2<'owner>(
        &'owner mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<ControllerExecutionAdmissionReceivingLoanV2<'owner>, ResourceReservationErrorV1> {
        if !self.active || !self.predurable_entered || self.accepted.is_some() || self.post.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let prefix = self.predurable_prefix.ok_or(ResourceReservationErrorV1::Conflict)?;
        let native = bank.resume_execution_admission_native_v2(&mut self.native, controller, profile)?;
        Ok(ControllerExecutionAdmissionReceivingLoanV2 {
            journal_identity: &self.journal_identity,
            native,
            accepted: &mut self.accepted,
            append_demand: &mut self.append_demand,
            binding: &mut self.binding,
            entry: &self.entry,
            post: &mut self.post,
            evidence: &mut self.evidence,
            clock: &mut self.clock,
            active: &mut self.active,
            predurable_entered: &mut self.predurable_entered,
            predurable_prefix: &mut self.predurable_prefix,
            prefix,
            environment_failure: &mut self.environment_failure,
            cleanup: &mut self.cleanup,
        })
    }
}

impl<'owner> ControllerExecutionAdmissionReceivingLoanV2<'owner> {
    // Only this owner can split its private original fields. The returned
    // cleanup borrower keeps the actual native Source/C loan and every
    // disposal destination; no field visibility or effect port is widened.
    pub(super) fn borrow_cleanup_source_once_v2<'scope>(
        &'scope mut self,
        bank: &ControllerResourceBankOpeningV1,
        source: &'scope mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<ControllerExecutionCleanupSourceLoanV2<'scope, 'owner>, ResourceReservationErrorV1> {
        let source = bank.borrow_execution_source_scope_v1(source, &mut self.native, controller, profile)?;
        Ok(ControllerExecutionCleanupSourceLoanV2::from_actual_admission_v2(
            source, self.cleanup, self.post, self.prefix, self.append_demand,
            self.journal_identity, self.evidence, self.accepted, self.clock, self.active,
        ))
    }

    /// Checks complete public/native receiving before any additional growth.
    ///
    /// # Errors
    /// Refuses a failed entry, completed post, foreign current cut or a reached
    /// requirement beyond the same already-consumed C18 declaration.
    pub fn require_complete_v2(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        complete: aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !matches!(self.entry, Some(Ok(()))) || self.post.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        bank.require_execution_complete_v1(&mut self.native, controller, profile, complete)?;
        self.prefix = self.prefix.componentwise_max(complete.demand_v1());
        *self.predurable_prefix = Some(self.prefix);
        Ok(())
    }

    pub(crate) fn prefix_demand_v2(&self) -> ResourceVector {
        self.prefix
    }

    /// Retains the same entered native owner across the canonical Journal scope.
    ///
    /// This performs no completion or disposal and grants no execution work.
    ///
    /// # Errors
    /// Refuses a non-admission borrower, completed post or changed native phase.
    pub fn park_public_admission_v2(self) -> Result<(), ResourceReservationErrorV1> {
        if !*self.predurable_entered || self.post.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        *self.predurable_prefix = Some(self.prefix);
        self.native.park_execution_admission_v2().map_err(Into::into)
    }

    /// Runs every independently prepaid C post after a refused admission body.
    pub fn finish_without_source_v2(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) {
        if self.post.is_none() {
            *self.post = Some(bank.finish_operation_intake_native_once_v1(
                &mut self.native, controller, profile,
            ));
        }
    }

    pub(super) fn bind_accepted_v2(
        self,
        controller: &Journal,
        operation: OperationId,
        expected: Option<&PublicMutationEffectHistoryV1>,
    ) -> Result<ControllerExecutionOperationReceivingLoanV1<'owner>, ResourceReservationErrorV1> {
        if matches!(self.entry, Some(Ok(()))) {
            *self.accepted = Some(match expected {
                Some(_) => crate::reconciler::accepted_execution_effect_from_journal_v3(controller, operation),
                None => crate::reconciler::accepted_create_execution_effect_from_journal_v1(controller, operation),
            });
            *self.binding = Some(if self.accepted.as_ref().is_some_and(|result| {
                matches!(result, Ok(Some(actual)) if expected.is_none_or(|expected| actual == expected))
            }) { Ok(()) } else { Err(ResourceReservationErrorV1::Conflict) });
        }
        // The accepted decoder, rather than a caller-selected operation ID,
        // supplies the sole execution input used by the existing Source loan.
        *self.predurable_entered = false;
        *self.predurable_prefix = None;
        Ok(ControllerExecutionOperationReceivingLoanV1 {
            operation,
            journal_identity: self.journal_identity,
            native: self.native,
            accepted: self.accepted,
            append_demand: self.append_demand,
            binding: self.binding,
            entry: self.entry,
            post: self.post,
            evidence: self.evidence,
            clock: self.clock,
            active: self.active,
            prefix: self.prefix,
            environment_failure: self.environment_failure,
        })
    }
}

impl ControllerExecutionOperationOriginalV1 {
    pub(crate) fn require_public_admission_current_v2(
        &self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !self.active || !self.predurable_entered || self.accepted.is_some()
            || self.post.is_some() || !matches!(self.entry, Some(Ok(())))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        bank.require_parked_execution_admission_current_v2(&self.native, controller, profile)
    }
}
