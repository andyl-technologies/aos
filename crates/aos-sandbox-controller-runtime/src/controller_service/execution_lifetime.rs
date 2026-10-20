//! Retains the same execution lifetime producer for Stream, PTY and Capture.
//!
//! The first paid pre-spawn sample stays fixed across parsing and signing.
//! Capture signs the prepared DATA before its terminal bookend; Stream keeps
//! the same original through content5 construction. Historical reads never
//! re-enter either once-only verification slot.

use std::error::Error;

use aos_sandbox::{EffectFailure, Journal};
use aos_sandbox::controller_execution_operation::ControllerExecutionReadReceivingLoanV1;
use aos_sandbox::runtime_scope::CurrentAssignmentTarget;
use aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector, RawPairedClockSample};
use aos_sandbox_protocol::ProtocolValidationError;
use aos_sandbox_protocol::storage_capture_lifetime::StorageCaptureExecutionLifetimeDataV2;

type Bank = aos_sandbox::ControllerResourceBankOpeningV1;
type Profile = aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1;

#[derive(Debug, thiserror::Error)]
#[error("the original paid execution lifetime is unavailable")]
pub(super) struct Closed;

fn closed() -> EffectFailure { EffectFailure::Retryable(Closed.to_string()) }
use aos_sandbox::controller_execution_spec_attempt::{ControllerExecutionSpecAttemptV1,
    ControllerExecutionSpecAttemptErrorV1};
use aos_sandbox::runtime_scope::{CurrentRuntimeScopeError, OriginalAssignmentCaptureLifetimeV2};
use aos_sandbox_core::ExecutionSpecV1;

#[derive(Default)]
pub(super) struct ExecutionLifetimeOriginalV5 {
    funding: Option<Result<(), aos_sandbox::ResourceReservationErrorV1>>,
    specification_attempt: Option<aos_sandbox_core::ObjectDigest>,
    owner: Option<Result<OriginalAssignmentCaptureLifetimeV2, CurrentRuntimeScopeError>>,
    first: Option<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
    before: Option<Result<(), CurrentRuntimeScopeError>>,
    specification: Option<Result<ExecutionSpecV1, ControllerExecutionSpecAttemptErrorV1>>,
    after: Option<Result<(), CurrentRuntimeScopeError>>,
}

impl ExecutionLifetimeOriginalV5 {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare_once<T>(&mut self, assignment: &CurrentAssignmentTarget,
        controller: &mut Journal, specification: &ControllerExecutionSpecAttemptV1,
        receiving: &mut ControllerExecutionReadReceivingLoanV1<'_, '_>, bank: &Bank,
        profile: &Profile, clock: &mut T) -> Result<(), EffectFailure>
    where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>
    {
        if self.funding.is_some() { return Err(closed()); }
        let encoded = specification.specification_bytes().len();
        let model = aos_sandbox_protocol::execution_spec_attempt::execution_spec_validation_model_memory_bytes_v2(encoded)
            .ok_or_else(closed)?;
        let scratch = aos_sandbox_protocol::storage_capture_lifetime::StorageCaptureExecutionLifetimeDataV2::receiving_memory_bytes_v2(encoded)
            .and_then(|bytes| bytes.checked_add(model)).and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(closed)?;
        let demand = assignment.capture_lifetime_receiving_demand_v2(controller).ok_or_else(closed)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, scratch)).map_err(|_| closed())?;
        self.funding = Some(receiving.admit_stage_v1(bank, controller, profile,
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(demand)));
        if !matches!(self.funding, Some(Ok(()))) { return Err(closed()); }

        // Retain the complete preparation Result before entering either verifier.
        self.owner = Some(assignment.prepare_capture_lifetime_v2());
        if self.owner.as_ref().is_none_or(Result::is_err) { return Err(closed()); }
        self.first = Some(clock());
        if !matches!(self.first, Some(Ok(_))) { return Err(closed()); }
        let owner = self.owner.as_mut().and_then(|result| result.as_mut().ok()).ok_or_else(closed)?;
        self.before = Some(owner.observe_once_v2(assignment, controller, clock));
        if !matches!(self.before, Some(Ok(()))) { return Err(closed()); }
        self.specification_attempt = Some(specification.record_digest());
        self.specification = Some(specification.decoded_specification());
        if self.specification.as_ref().is_none_or(Result::is_err) { return Err(closed()); }
        Ok(())
    }

    pub(super) fn finish_once<T>(&mut self, assignment: &CurrentAssignmentTarget,
        controller: &mut Journal, clock: &mut T) -> Result<(), EffectFailure>
    where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>
    {
        if self.after.is_some() || !matches!(self.before, Some(Ok(()))) { return Err(closed()); }
        let owner = self.owner.as_mut().and_then(|result| result.as_mut().ok()).ok_or_else(closed)?;
        self.after = Some(owner.require_current_v2(assignment, controller, clock));
        if matches!(self.after, Some(Ok(()))) { Ok(()) } else { Err(closed()) }
    }

    pub(super) fn owner(&self) -> Result<&OriginalAssignmentCaptureLifetimeV2, Closed> {
        if self.preparation_failure().is_some() || self.post_failure().is_some() { return Err(Closed); }
        self.owner.as_ref().and_then(|result| result.as_ref().ok()).ok_or(Closed)
    }

    pub(super) fn first_pre_spawn(&self) -> Result<RawPairedClockSample, Closed> {
        self.first.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(Closed)
    }

    pub(super) fn specification(&self) -> Result<&ExecutionSpecV1, Closed> {
        self.specification.as_ref().and_then(|result| result.as_ref().ok()).ok_or(Closed)
    }

    /// Constructs comparison DATA from the actual retained first verifier/spec.
    ///
    /// This does not complete either Native bookend or grant Guest execution.
    /// The caller retains the result in its same paid original and requires
    /// `completed()` before publishing content5 or a Capture admission anchor.
    pub(super) fn prepared_data_for_parent_v5(
        &self, specification: &ControllerExecutionSpecAttemptV1,
        parent_plan: &aos_sandbox_core::BrokerAuthorizationPlan,
    ) -> Result<StorageCaptureExecutionLifetimeDataV2, ProtocolValidationError> {
        let invalid = || ProtocolValidationError::InvalidField("original execution lifetime");
        let original = self.owner().map_err(|_| invalid())?;
        let decoded = self.specification().map_err(|_| invalid())?;
        if specification.execution() != decoded.execution()
            || self.specification_attempt != Some(specification.record_digest())
            || !matches!(parent_plan.protocol(),
                aos_sandbox_core::ProtocolId::HostBroker | aos_sandbox_core::ProtocolId::StorageBroker)
        { return Err(invalid()); }
        let origins = original.origins_data_v2(self.first_pre_spawn().map_err(|_| invalid())?,
            parent_plan.expires_seconds()).map_err(|_| invalid())?;
        StorageCaptureExecutionLifetimeDataV2::from_pre_spawn_sources_data_v2(
            decoded, specification.create_operation(), specification.create_operation(),
            specification.accepted_request_digest(), parent_plan.assignment(), &origins)
    }

    pub(super) fn entered(&self) -> bool { self.owner.is_some() }

    pub(super) fn completed(&self) -> bool {
        matches!(self.before, Some(Ok(()))) && matches!(self.after, Some(Ok(())))
            && self.preparation_failure().is_none() && self.post_failure().is_none()
    }

    pub(super) fn preparation_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.funding.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.owner.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.first.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| if matches!(self.before, Some(Err(_))) {
                self.owner.as_ref().and_then(|result| result.as_ref().ok()).and_then(|owner| owner.failure_v2())
                    .or_else(|| self.before.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            } else { None })
            .or_else(|| self.specification.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }

    pub(super) fn post_failure(&self) -> Option<&(dyn Error + 'static)> {
        if !matches!(self.after, Some(Err(_))) { return None; }
        self.owner.as_ref().and_then(|result| result.as_ref().ok()).and_then(|owner| owner.failure_v2())
            .or_else(|| self.after.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }
}
