//! Retains fresh operation funding after complete first-local reconciliation.
//!
//! The old recovery and all three inventory owners stay resident. This owner
//! pays new Delete and Execution subdivisions from the same remaining baseline;
//! it never adopts the predecessor's claims. Funding alone permits neither
//! ordinary service nor a native effect. Enrollment needs fresh Source, C and
//! original-horizon bookends before either funded original can leave custody.

use super::*;
use crate::controller_execution_operation::ControllerExecutionOperationOriginalV1;
use crate::controller_resource_reservation::operation_intake::ControllerOperationIntakeDemandDataV1 as Demand;
use crate::public_mutation_compiler::delete_admission::ControllerDeleteAuthorizationOriginalV1;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerRecoveredEnrollmentReceivingV2 as Native;
use aos_sandbox_broker::source_receiving::SourceRecoveredEnrollmentCurrentnessOriginalV2 as SourceNative;

#[derive(Clone, Copy)]
enum First {
    Entry,
    Delete,
    Execution,
    Horizon,
    Native,
    Clock,
    Source,
    Publication,
    Body,
    SourceAfter,
    ControllerAfter,
    SourceDisposal,
    FinalClock,
    Completion,
    DeleteBinding,
    ExecutionBinding,
}

/// Retains actual new funding and every partial enrollment refusal.
///
/// An empty owner is inert. Its only funding entry borrows the genuine complete
/// first-local conjunction and same bank; no decoded inventory or capacity
/// vector can substitute for those originals. Partial funding stays held.
#[doc(hidden)]
#[must_use = "retain funded intakes and all reached enrollment originals"]
#[derive(Default)]
pub struct OperatorFirstLocalOrdinaryEnrollmentOriginalV2 {
    attempted: bool,
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    delete: Option<Result<ControllerDeleteAuthorizationOriginalV1, ResourceReservationErrorV1>>,
    execution: Option<Result<ControllerExecutionOperationOriginalV1, ResourceReservationErrorV1>>,
    horizon: Option<Result<RootContinuationHorizonDataV1, ResourceReservationErrorV1>>,
    native: Option<Result<Native, ResourceReservationErrorV1>>,
    clock: Option<Clock>,
    source: Option<Result<SourceNative, ResourceReservationErrorV1>>,
    publication: Option<Result<(), ResourceReservationErrorV1>>,
    body: Option<Result<(), ResourceReservationErrorV1>>,
    source_after: Option<Result<(), crate::JournalError>>,
    controller_after: Option<Result<(), ResourceReservationErrorV1>>,
    source_disposal: Option<Result<(), ResourceReservationErrorV1>>,
    final_clock_native: crate::controller::RetainedControllerProtectedClockAttemptV1,
    final_clock: Option<Result<RawPairedClockSample, crate::JournalError>>,
    final_comparison: Option<Result<(), crate::JournalError>>,
    completion: Option<Result<(), ResourceReservationErrorV1>>,
    delete_binding: Option<Result<(), ResourceReservationErrorV1>>,
    execution_binding: Option<Result<(), ResourceReservationErrorV1>>,
    first: Option<First>,
}

impl OperatorFirstLocalOrdinaryEnrollmentOriginalV2 {
    /// Permanently funds both new operation originals on the same residual.
    ///
    /// Image declarations remain maxima. Each actual lower funding entrance
    /// debits the complete resident and flight amounts before native-owner
    /// construction. The completed-recovery resident quote is already charged;
    /// it is checked here without adding, subtracting or crediting it again.
    /// No ordinary readiness or effect authority follows from this method.
    ///
    /// # Errors
    /// Refuses reentry, substituted or incomplete reconciliation, changed
    /// Source/C/profile, missing declarations or insufficient remaining budget.
    /// A failed second funding attempt preserves the actual first original.
    fn fund_once_v2(
        &mut self,
        complete: &OperatorFirstLocalReconciliationCompleteV2<'_, '_>,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
        execution_runtime_resident: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.attempted {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.attempted = true;

        let profile = complete.profile_original_v2();
        self.entry = Some((|| {
            complete.require_same_completed_v2(bank, controller, profile, source)?;
            let _already_charged =
                complete.completed_resident_demand_with_bank_v2(bank, controller)?;
            Ok(())
        })());
        if !matches!(self.entry, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }

        self.delete = Some((|| {
            let resident = ControllerDeleteAuthorizationOriginalV1::resident_demand_v2()?;
            let native = bank.fund_recovered_delete_intake_once_v2(
                controller,
                profile,
                complete.completed_native_v2()?,
                Demand::from_demand_v1(resident),
            )?;
            Ok(ControllerDeleteAuthorizationOriginalV1::from_funded_intake_v2(native))
        })());
        if !matches!(self.delete, Some(Ok(_))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }

        self.execution = Some((|| {
            let resident = ControllerExecutionOperationOriginalV1::resident_demand_v2(
                execution_runtime_resident,
            )?;
            let native = bank.fund_recovered_execution_intake_once_v2(
                controller,
                profile,
                complete.completed_native_v2()?,
                Demand::from_demand_v1(resident),
            )?;
            Ok(ControllerExecutionOperationOriginalV1::from_funded_intake_v2(native, controller))
        })());
        if !matches!(self.execution, Some(Ok(_))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }

        Ok(())
    }

    fn fixed_demand_v2() -> Result<ResourceVector, ResourceReservationErrorV1> {
        // These actual payloads already have their own resident suppliers.
        // Keep this owner's discriminants, control/results and constructor
        // copies, then price only the genuinely new clock suppliers below.
        let covered = std::mem::size_of::<ControllerDeleteAuthorizationOriginalV1>()
            .checked_add(std::mem::size_of::<ControllerExecutionOperationOriginalV1>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Native>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<SourceNative>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Clock>()))
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<
                    crate::controller::RetainedControllerProtectedClockAttemptV1,
                >())
            })
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_sub(covered)
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, bytes)
            .checked_add(Clock::controller_authorization_receiving_demand_v1()?)?
            .checked_add(
                crate::controller::RetainedControllerProtectedClockAttemptV1::receiving_demand_v1(
                )?,
            )?)
    }

    /// Runs fresh enrollment bookends after both actual intake debits.
    ///
    /// The same residual pays this finite native purpose. Earlier recovery and
    /// intake highwaters stay charged; their resident quotes are never added
    /// again as new demand. Every entered Source/C/final-clock destination is
    /// attempted independently, and a refusal retains both funded originals.
    ///
    /// # Errors
    /// Refuses substituted reconciliation, partial funding, exhausted remaining
    /// budget, changed Source/C, failed native observations or original expiry.
    pub fn enroll_once_v2(
        &mut self,
        complete: &OperatorFirstLocalReconciliationCompleteV2<'_, '_>,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        execution_runtime_resident: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        let funded = self.fund_once_v2(
            complete,
            bank,
            controller,
            source,
            execution_runtime_resident,
        );
        self.latch_v2();
        funded?;

        let profile = complete.profile_original_v2();
        self.horizon = Some(
            complete
                .original_horizon_v2()
                .map_err(|_| ResourceReservationErrorV1::Conflict)
                .and_then(|(original, cutoff, wall)| {
                    Ok(
                        RootContinuationHorizonDataV1::from_original_data_v1(original, cutoff)?
                            .with_wall_expiry_data_v1(wall),
                    )
                }),
        );
        self.latch_v2();
        self.native = Some((|| {
            self.horizon
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            bank.begin_recovered_enrollment_receiving_once_v2(
                controller,
                profile,
                complete.completed_native_v2()?,
                Self::fixed_demand_v2()?,
            )
        })());
        self.latch_v2();
        if !self.native.as_ref().is_some_and(|result| {
            result
                .as_ref()
                .is_ok_and(|native| native.require_prepaid_owed_observation_v2().is_ok())
        }) {
            return Err(ResourceReservationErrorV1::Conflict);
        }

        self.body = Some((|| {
            if self.first.is_some() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let horizon = *self
                .horizon
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            self.clock = Some(Clock::new_controller_authorization_v1(horizon));
            self.clock
                .as_mut()
                .ok_or(ResourceReservationErrorV1::Conflict)?
                .check_next_once_v1()?;

            self.source = Some(
                bank.begin_source_recovered_enrollment_v2(
                    self.native
                        .as_mut()
                        .and_then(|result| result.as_mut().ok())
                        .ok_or(ResourceReservationErrorV1::Conflict)?,
                    controller,
                    source,
                    profile,
                    Self::fixed_demand_v2()?,
                ),
            );
            let pair = self
                .source
                .as_mut()
                .and_then(|result| result.as_mut().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            bank.require_source_recovered_enrollment_current_v2(
                pair,
                self.native
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?,
                controller,
                source,
                profile,
            )?;
            complete.require_same_source_v2(source)?;

            // Publish only after fresh Source and original-horizon checks.
            // The same native owner retains both funded rows and the actual
            // append/readback prefix; every entered after remains owed below.
            self.publication = Some(bank.publish_recovered_intake_pair_once_v2(
                self.native
                    .as_mut()
                    .and_then(|result| result.as_mut().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?,
                controller,
                profile,
            ));
            if matches!(self.publication, Some(Ok(()))) {
                Ok(())
            } else {
                Err(ResourceReservationErrorV1::Conflict)
            }
        })());
        self.latch_v2();

        if let Some(Ok(pair)) = self.source.as_mut() {
            self.source_after = Some(
                source
                    .journal()
                    .finish_source_recovered_enrollment_native_v2(pair),
            );
        }
        self.latch_v2();
        self.controller_after = Some((|| {
            let native = self
                .native
                .as_mut()
                .and_then(|result| result.as_mut().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            bank.finish_recovered_enrollment_native_once_v2(native, controller, profile)
        })());
        self.latch_v2();
        if let Some(Ok(pair)) = self.source.as_mut() {
            self.source_disposal = Some((|| {
                let native = self
                    .native
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                bank.dispose_source_recovered_enrollment_v2(
                    pair, native, controller, source, profile,
                )
            })());
        }
        self.latch_v2();

        // The whole fixed receipt already paid this destination. An earlier
        // body/native failure cannot demand another healthy turn or skip it.
        self.final_clock = Some(self.final_clock_native.observe_once_v1());
        if let Some(Ok(sample)) = self.final_clock.as_ref() {
            self.final_comparison = Some(
                self.clock
                    .as_ref()
                    .ok_or(crate::JournalError::ProtectedBoundary)
                    .and_then(|clock| clock.require_final_sample_v1(*sample)),
            );
        }
        self.latch_v2();

        self.completion = Some((|| {
            if self.first.is_some()
                || !matches!(self.body, Some(Ok(())))
                || !matches!(self.source_after, Some(Ok(())))
                || !matches!(self.controller_after, Some(Ok(())))
                || !matches!(self.source_disposal, Some(Ok(())))
                || !matches!(self.final_comparison, Some(Ok(())))
            {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let native = self
                .native
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            bank.require_recovered_enrollment_completed_v2(native, controller, profile)?;
            complete.require_same_completed_v2(bank, controller, profile, source)
        })());
        self.latch_v2();
        if !matches!(self.completion, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }

        // Only the complete upper Source/clock conjunction may bind these
        // actual originals to the lower completed enrollment association.
        // A refused second binding leaves the first bound original in custody.
        self.delete_binding = Some((|| {
            let native = self.native.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            self.delete.as_mut().and_then(|result| result.as_mut().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?
                .bind_recovered_enrollment_once_v2(bank, native, controller, profile)
        })());
        self.latch_v2();
        if !matches!(self.delete_binding, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }

        self.execution_binding = Some((|| {
            let native = self.native.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            self.execution.as_mut().and_then(|result| result.as_mut().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?
                .bind_recovered_enrollment_once_v2(bank, native, controller, profile)
        })());
        self.latch_v2();
        if !matches!(self.execution_binding, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    // Rejoins the actual native enrollment after its complete upper bookends.
    pub(crate) fn completed_native_for_ordinary_sessions_v2(
        &self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<&Native, ResourceReservationErrorV1> {
        if self.first.or_else(|| self.selected_v2()).is_some()
            || !matches!(self.completion, Some(Ok(())))
            || !matches!(self.delete_binding, Some(Ok(())))
            || !matches!(self.execution_binding, Some(Ok(())))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }

        let native = self.native.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        bank.require_recovered_enrollment_completed_v2(native, controller, profile)?;
        Ok(native)
    }

    /// Borrows both actual completed operation owners before atomic placement.
    ///
    /// A failed or incomplete prefix exposes neither owner for placement.
    #[must_use]
    pub fn completed_operation_originals_v2(
        &self,
    ) -> Option<(&ControllerDeleteAuthorizationOriginalV1, &ControllerExecutionOperationOriginalV1)> {
        if self.first.or_else(|| self.selected_v2()).is_some()
            || !matches!(self.completion, Some(Ok(())))
            || !matches!(self.delete_binding, Some(Ok(())))
            || !matches!(self.execution_binding, Some(Ok(())))
        {
            return None;
        }
        Some((self.delete.as_ref()?.as_ref().ok()?, self.execution.as_ref()?.as_ref().ok()?))
    }

    /// Moves the actual enrolled operation originals once after all bookends.
    ///
    /// The enrollment, recovery, inventory and Source owners remain resident.
    /// No decoded funding record or successful Boolean can construct this pair.
    /// A failed or incomplete prefix releases neither original.
    pub fn take_completed_operation_originals_once_v2(
        &mut self,
    ) -> Option<(ControllerDeleteAuthorizationOriginalV1, ControllerExecutionOperationOriginalV1)> {
        self.completed_operation_originals_v2()?;

        match (self.delete.take(), self.execution.take()) {
            (Some(Ok(delete)), Some(Ok(execution))) => Some((delete, execution)),
            (delete, execution) => {
                self.delete = delete;
                self.execution = execution;
                None
            }
        }
    }

    fn selected_v2(&self) -> Option<First> {
        if matches!(self.entry, Some(Err(_))) {
            return Some(First::Entry);
        }
        if matches!(self.delete, Some(Err(_))) {
            return Some(First::Delete);
        }
        if matches!(self.execution, Some(Err(_))) {
            return Some(First::Execution);
        }
        if matches!(self.horizon, Some(Err(_))) {
            return Some(First::Horizon);
        }
        if matches!(self.publication, Some(Err(_))) {
            return Some(First::Publication);
        }
        if self.native.as_ref().is_some_and(|result| {
            result
                .as_ref()
                .map_or(true, |native| native.failure_v2().is_some())
        }) {
            return Some(First::Native);
        }
        if self
            .clock
            .as_ref()
            .is_some_and(|clock| clock.failure().is_some())
        {
            return Some(First::Clock);
        }
        if self.source.as_ref().is_some_and(|result| {
            result
                .as_ref()
                .map_or(true, |source| source.failure_v2().is_some())
        }) {
            return Some(First::Source);
        }
        if matches!(self.body, Some(Err(_))) {
            return Some(First::Body);
        }
        if matches!(self.source_after, Some(Err(_))) {
            return Some(First::SourceAfter);
        }
        if matches!(self.controller_after, Some(Err(_))) {
            return Some(First::ControllerAfter);
        }
        if matches!(self.source_disposal, Some(Err(_))) {
            return Some(First::SourceDisposal);
        }
        if self.final_clock_native.failure().is_some()
            || matches!(self.final_clock, Some(Err(_)))
            || matches!(self.final_comparison, Some(Err(_)))
        {
            return Some(First::FinalClock);
        }
        if matches!(self.completion, Some(Err(_))) {
            return Some(First::Completion);
        }
        if matches!(self.delete_binding, Some(Err(_))) {
            return Some(First::DeleteBinding);
        }
        if matches!(self.execution_binding, Some(Err(_))) {
            return Some(First::ExecutionBinding);
        }
        None
    }

    fn latch_v2(&mut self) {
        if self.first.is_none() {
            self.first = self.selected_v2();
        }
    }

    /// Borrows the rich native profile cause at its original selected frontier.
    ///
    /// Later profile posts cannot replace an earlier Source or body failure.
    #[must_use]
    pub fn native_profile_failure_view_v2(
        &self,
    ) -> Option<aos_sandbox_broker::controller_receiving::profile::ControllerProfileFailureViewV1<'_>>
    {
        if !matches!(
            self.first.or_else(|| self.selected_v2()),
            Some(First::Native)
        ) {
            return None;
        }
        self.native
            .as_ref()?
            .as_ref()
            .ok()?
            .profile_failure_view_v2()
    }

    /// Borrows the selected publication cause from the same retained writer.
    ///
    /// Earlier funding, Source or clock failures retain their original choice.
    #[must_use]
    pub fn failure_with_controller_v2<'cause>(
        &'cause self,
        controller: &'cause Journal,
    ) -> Option<&'cause (dyn Error + 'static)> {
        if matches!(self.first.or_else(|| self.selected_v2()), Some(First::Publication)) {
            if let (Some(Ok(native)), Ok(writer)) = (
                self.native.as_ref(),
                controller.controller_coordinator_for_bank_read_v1(),
            ) {
                if let Some(cause) = native.publication_failure_source_v1(writer) {
                    return Some(cause);
                }
            }
        }
        self.failure_v2()
    }

    /// Borrows the earliest actual funding refusal without releasing custody.
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first.or_else(|| self.selected_v2())? {
            First::Entry => self.entry.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Delete => self.delete.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Execution => self
                .execution
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Horizon => self
                .horizon
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Native => match self.native.as_ref()? {
                Err(cause) => Some(cause),
                Ok(native) => native.failure_v2(),
            },
            First::Clock => self.clock.as_ref()?.failure(),
            First::Source => match self.source.as_ref()? {
                Err(cause) => Some(cause),
                Ok(source) => source.failure_v2(),
            },
            First::Publication => self.native.as_ref()?.as_ref().ok()?.failure_v2()
                .or_else(|| self.publication.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Body => self.body.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::SourceAfter => self
                .source_after
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::ControllerAfter => self
                .controller_after
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::SourceDisposal => self
                .source_disposal
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::FinalClock => self
                .final_clock_native
                .failure()
                .or_else(|| {
                    self.final_clock
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                })
                .or_else(|| {
                    self.final_comparison
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            First::Completion => self
                .completion
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::DeleteBinding => self.delete_binding.as_ref()?.as_ref().err()
                .map(|cause| cause as _),
            First::ExecutionBinding => self.execution_binding.as_ref()?.as_ref().err()
                .map(|cause| cause as _),
        }
    }
}

impl OperatorFirstLocalOrdinaryEnrollmentOriginalV2 {
    /// Lends completed enrollment solely to the new Stop metadata payer.
    ///
    /// No old Recover clock grants a new effect scope. Fresh Stop Source/C
    /// bookends and its exact native funding publication remain mandatory.
    pub(crate) fn completed_lifecycle_stop_enrollment_v3<'owner>(&'owner self,
        bank: &ControllerResourceBankOpeningV1, controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<&'owner Native, ResourceReservationErrorV1> {
        if self.first.or_else(|| self.selected_v2()).is_some()
            || !matches!(self.completion, Some(Ok(())))
            || !matches!(self.delete_binding, Some(Ok(())))
            || !matches!(self.execution_binding, Some(Ok(())))
        { return Err(ResourceReservationErrorV1::Conflict); }
        let native = self.native.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        bank.require_recovered_enrollment_completed_v2(native, controller, profile)?;
        Ok(native)
    }
}
