//! Splits the accepted C18 borrower from its predurable retirement obligation.
//!
//! The immutable compiler/plan/row originals stay resident during Source and
//! execution work. Only the actual same-operation positive Source/C disposal
//! token permits their retirement, before that token completes native disposal.

use super::*;

/// Retains the complete public prefix beside its same accepted C18 borrower.
///
/// This is an upper-memory retirement obligation, not a completion or effect
/// proof. Only the same Source/C18 positive-disposal token permits retirement.
#[must_use = "retire the complete prefix before completing native disposal"]
pub struct ControllerExecutionAdmissionRetirementV2<'original> {
    pub(super) prefix: &'original mut ExecutionPublicAdmissionPrefixV2,
    retired: &'original mut bool,
    pub(super) operation: OperationId,
    pub(super) active: bool,
}

impl ControllerExecutionAdmissionRetirementV2<'_> {
    /// Retires all positive public/compiler/native destinations before disposal.
    ///
    /// # Errors
    /// Refuses a different operation, failed public prefix or missing genuine
    /// acceptance. Refusal leaves every original in place and permits no reset.
    pub fn retire_before_native_disposal_v2(
        &mut self,
        disposal: &ControllerExecutionPositiveDisposalV1<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !self.active || disposal.operation_v1() != self.operation || self.prefix.first.is_some()
            || self.prefix.journal_identity.as_ref().is_none_or(|identity| {
                !identity.is_same_original_v4(disposal.journal_identity)
            })
            || !matches!(self.prefix.accepted_outcome,
                Some(Ok(crate::AcceptOutcome::Accepted(operation) | crate::AcceptOutcome::Replay(operation)))
                if operation == self.operation)
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }

        // Every retained transaction/authorization/peer native owner is gone
        // before the caller may complete the still-borrowed native token.
        drop(std::mem::replace(self.prefix, ExecutionPublicAdmissionPrefixV2::new()));
        *self.retired = true;
        self.active = false;
        Ok(())
    }
}

impl Drop for ControllerExecutionAdmissionRetirementV2<'_> {
    fn drop(&mut self) {
        if self.active {
            // A live native disposal token cannot outlive its upper-prefix
            // obligation, even when a caller neglects the must-use contract.
            std::process::abort();
        }
    }
}

impl ExecutionPublicAdmissionScopeV2 {
    pub(crate) fn retain_acceptance_once_v2(
        &mut self,
        returned: Result<crate::AcceptOutcome, crate::ControllerServiceError>,
    ) {
        if !matches!(self.prefix.prepared_outcome, Some(Ok(()))) || self.retired {
            self.prefix.first.get_or_insert(First::Acceptance);
        }
        if self.prefix.accepted_outcome.is_some() {
            self.prefix.first.get_or_insert(First::Reentry);
            return;
        }
        if returned.is_err() {
            self.prefix.first.get_or_insert(First::Acceptance);
        }
        self.prefix.accepted_outcome = Some(returned);
    }

    /// Resumes the actual preadmission C18 after its exact durable acceptance.
    ///
    /// The returned borrower uses the sole existing protected accepted decoder.
    /// No native before, slot entry, disposal or spent baseline is repeated.
    /// The separate retirement obligation keeps every public original live
    /// until the actual same-operation Source/C18 positive posts complete.
    ///
    /// # Errors
    /// Refuses missing/changed acceptance, context, same-bank currentness,
    /// receiving capacity or original native custody. Every reached owner and
    /// negative cause remains in this same scope.
    pub fn resume_accepted_once_v2<'original>(
        &'original mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        operation: OperationId,
        expected: &PublicMutationEffectHistoryV1,
        runtime_fixed: Demand,
    ) -> Result<(
        ControllerExecutionOperationReceivingLoanV1<'original>,
        ControllerExecutionAdmissionRetirementV2<'original>,
    ), ResourceReservationErrorV1> {
        if self.prefix.first.is_some() || self.retired
            || !matches!(self.prefix.prepared_outcome, Some(Ok(())))
            || self.prefix.plan.as_ref().is_none_or(|plan| plan.operation_id() != operation)
            || !matches!(self.prefix.accepted_outcome,
                Some(Ok(crate::AcceptOutcome::Accepted(actual) | crate::AcceptOutcome::Replay(actual)))
                if actual == operation)
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if self.prefix.handoff_geometry.is_some() || self.prefix.handoff_entry.is_some() {
            self.prefix.first.get_or_insert(First::Reentry);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.require_accepted_availability_handoff_v2()?;
        self.prefix.handoff_geometry = Some((|| {
            let additional = accepted_receiving_demand_v1(controller)?
                .checked_add(ControllerExecutionClockOriginalV1::fixed_demand_v1()
                    .ok_or(ResourceReservationErrorV1::Conflict)?)?
                .checked_add(runtime_fixed.demand_v1())?
                .checked_add(EnvironmentExecutionEvidenceOriginalV1::fixed_demand_v1()
                    .ok_or(ResourceReservationErrorV1::Conflict)?)?;
            self.financial.predurable_prefix.ok_or(ResourceReservationErrorV1::Conflict)?
                .checked_add(additional).map_err(Into::into)
        })());
        let Some(complete) = self.prefix.handoff_geometry.as_ref()
            .and_then(|result| result.as_ref().ok()).copied()
        else {
            self.prefix.first.get_or_insert(First::HandoffGeometry);
            return Err(ResourceReservationErrorV1::Conflict);
        };

        let mut admission = match self.financial.resume_public_admission_v2(bank, controller, profile) {
            Ok(admission) => {
                self.prefix.handoff_entry = Some(Ok(()));
                admission
            }
            Err(cause) => {
                self.prefix.handoff_entry = Some(Err(cause));
                self.prefix.first.get_or_insert(First::Handoff);
                return Err(ResourceReservationErrorV1::Conflict);
            }
        };
        self.prefix.handoff_funding = Some(admission.require_complete_v2(
            bank, controller, profile, Demand::from_demand_v1(complete),
        ));
        if !matches!(self.prefix.handoff_funding, Some(Ok(()))) {
            self.prefix.handoff_park = Some(admission.park_public_admission_v2());
            self.prefix.first.get_or_insert(First::Handoff);
            return Err(ResourceReservationErrorV1::Conflict);
        }

        let accepted = admission.bind_accepted_v2(controller, operation, Some(expected))?;
        let retirement = ControllerExecutionAdmissionRetirementV2 {
            prefix: &mut self.prefix,
            retired: &mut self.retired,
            operation,
            active: true,
        };
        Ok((accepted, retirement))
    }
}
