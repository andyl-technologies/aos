//! Holds the original execution intake through authenticated Host execution.
//!
//! The accepted Controller operation, exclusive Source interval and fixed
//! Environment evidence stay live across output registration, Host argument
//! preparation and acceptance, specification admission and first observation.
//! Completion crosses the existing effect boundary only after the actual Host
//! continuation and both independent Source/Controller posts have completed.

use aos_sandbox_controller_domain::controller_execution_output_settlement::read_current_controller_output_settlement_v1;
use aos_sandbox_controller_domain::controller_execution_preissue::{
    load_controller_execution_output_attempt_v1, preissue_accepted_execution_source_v1,
    revalidate_historical_execution_preissue_source_v1,
};
use aos_sandbox_controller_domain::execution_parent_resource::current_execution_parent_resource_from_journal_v1;
use aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError;
use aos_sandbox_controller_domain::{EffectFailure, Journal};
use aos_sandbox_protocol::domain_ledger::effect_history::PublicMutationEffectHistoryV1;
use aos_sandbox_model::{ExecutionId, OperationId, SandboxId};

use super::execution_output_reserve::sign_current_host_output_reserve_v1;
use super::ProductionEffectExecutor;

mod periodic;
pub(super) use periodic::observe_periodic_v4;
mod public_admission;
mod no_apply;
mod applying;
pub(super) use public_admission::{take_public_custody_once_v2, retain_public_custody_v2,
    admit_public_availability_once_v2};

pub(super) fn take_no_apply_completion_v2(executor: &mut ProductionEffectExecutor)
    -> Option<aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionNoApplyCompletionV2> {
    executor.execution_original.as_mut()?.no_apply_completion.take()
}

/// Advances the accepted Create through its original provisional output attempt.
///
/// An absent original starts its one reserve under the same real Source/C18;
/// an existing original follows its exact replay/query path. This orchestration
/// already includes Host authorization and the first genuine observation.
///
/// # Errors
///
/// Returns a retryable failure when current protected sources, Host custody,
/// or authenticated settlement cannot be verified.
pub(super) fn observe(
    executor: &mut ProductionEffectExecutor,
    operation: OperationId,
    context: &PublicMutationEffectHistoryV1,
    controller: &mut Journal,
) -> Result<super::execution::ControllerExecutionCompletionV1, EffectFailure> {
    advance(executor, operation, context, controller)
}

/// Makes or recovers the one provisional Host output reservation for Create.
///
/// # Errors
///
/// Returns a retryable failure when any current source, signed Host exchange,
/// or protected Controller settlement remains unavailable.
pub(super) fn apply(
    executor: &mut ProductionEffectExecutor,
    operation: OperationId,
    context: &PublicMutationEffectHistoryV1,
    controller: &mut Journal,
) -> Result<super::execution::ControllerExecutionCompletionV1, EffectFailure> {
    advance(executor, operation, context, controller)
}

/// Retains the actual execution-original and reached Runtime source/results.
///
/// Only the same Bank/Controller/profile claim constructs this state. The
/// purpose18 original remains resident between positive operations; failures
/// retain their real causes and cannot recreate or rearm it.
pub(super) struct ControllerExecutionOriginalV1 {
    financial: Option<aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionRuntimeCustodyV2>,
    availability: Box<aos_sandbox_broker_session_security::ExecutionAvailabilitySessionIoOriginalV2>,
    availability_scope: Option<Result<(), aos_sandbox_controller_domain::JournalError>>,
    availability_body: Option<Result<aos_sandbox_controller_domain::AcceptOutcome, aos_sandbox_controller_domain::ResourceReservationErrorV1>>,
    no_apply: Box<aos_sandbox_broker_session_security::HostExecutionNoApplySessionIoOriginalV2>,
    no_apply_native: Box<aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionNoApplyOriginalV2>,
    no_apply_body: Option<Result<(), EffectFailure>>,
    no_apply_completion: Option<aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionNoApplyCompletionV2>,
    output_preparation: Option<Result<aos_sandbox_controller_domain::controller_execution_preissue::ControllerExecutionPreissueV1, EffectFailure>>,
    applying_geometry: Option<Result<aos_sandbox_model::ResourceVector, applying::Error>>,
    applying_funding: Option<Result<(), aos_sandbox_controller_domain::ResourceReservationErrorV1>>,
    applying_gate: Option<Result<u32, applying::Error>>,
    inputs: Box<super::attachment_target::ControllerAttachmentSourceOriginalV1>,
    parent: Option<Result<aos_sandbox_controller_domain::execution_parent_resource::ExecutionParentResourceSourceV1,
        aos_sandbox_controller_domain::execution_parent_resource::ExecutionParentResourceSourceErrorV1>>,
    receipt: Option<Result<aos_sandbox_controller_domain::controller_execution_argument_receipt::AuthenticatedControllerHostArgumentObservationV1,
        aos_sandbox_controller_domain::controller_execution_argument_receipt::ControllerExecutionArgumentReceiptErrorV1>>,
    specification: Option<Result<aos_sandbox_controller_domain::controller_execution_spec_attempt::ControllerExecutionSpecAttemptV1,
        aos_sandbox_controller_domain::controller_execution_spec_attempt::ControllerExecutionSpecAttemptErrorV1>>,
    body: Option<Result<super::execution::ControllerExecutionCompletionV1, EffectFailure>>,
    periodic: Option<Box<periodic::PeriodicExecutionOriginalV4>>,
    periodic_cursor: Option<ExecutionId>,
}

impl ControllerExecutionOriginalV1 {
    // Fixed destinations are prepaid by RuntimeFixed before the first constructor.
    pub(in crate::controller_service) fn inactive_receiving_bytes_v1() -> Option<usize> {
        use crate::controller_service::effects::resident_geometry::{boxed_bytes, sum_bytes};
        sum_bytes([
            boxed_bytes::<aos_sandbox_broker_session_security::ExecutionAvailabilitySessionIoOriginalV2>(),
            boxed_bytes::<aos_sandbox_broker_session_security::HostExecutionNoApplySessionIoOriginalV2>(),
            boxed_bytes::<aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionNoApplyOriginalV2>(),
            boxed_bytes::<super::attachment_target::ControllerAttachmentSourceOriginalV1>(),
        ])
    }

    fn availability_failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let financial = || self.financial.as_ref().and_then(|custody| custody.failure_v2());
        if self.availability_scope.as_ref().is_some_and(Result::is_err) {
            return financial().or_else(|| self.availability_scope.as_ref()?
                .as_ref().err().map(|cause| cause as _));
        }
        if self.availability.original_failure_selected_v2() {
            return financial().or_else(|| self.availability.failure_v2());
        }
        self.availability.failure_v2().or_else(|| self.availability_body.as_ref()?
            .as_ref().err().map(|cause| cause as _))
    }

    pub(super) fn resident_demand_v1() -> Result<aos_sandbox_model::ResourceVector, EffectFailure> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| retryable("execution original geometry overflows"))?;
        // The canonical purpose reservation remains permanently held by the
        // same C original even between flights. Each Session forecast includes
        // its actual prior native/materialized history before new growth.
        // Per-turn raw/model owners retire before the exclusive slot is reused.
        Ok(aos_sandbox_model::ResourceVector::ZERO
            .with(aos_sandbox_model::ResourceDimension::MemoryBytes, bytes))
    }

    pub(in crate::controller_service) fn claim_once_v1(
        bank: &aos_sandbox_controller_domain::ControllerResourceBankOpeningV1, controller: &mut Journal,
        profile: &aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<Self, EffectFailure> {
        let resident = Self::resident_demand_v1()?;
        let financial = aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionOperationOriginalV1::claim_once_v1(
            bank, controller, profile,
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(resident),
        ).map_err(|_| retryable("original execution subdivision is unavailable"))?;
        Ok(Self::from_funded_original_v2(financial))
    }

    pub(super) fn from_funded_original_v2(
        financial: aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionOperationOriginalV1,
    ) -> Self {
        Self { financial: Some(aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionRuntimeCustodyV2::from_original_v2(financial)),
            availability: Box::new(aos_sandbox_broker_session_security::ExecutionAvailabilitySessionIoOriginalV2::new()),
            availability_scope: None, availability_body: None,
            no_apply: Box::new(aos_sandbox_broker_session_security::HostExecutionNoApplySessionIoOriginalV2::new()),
            no_apply_native: Box::new(aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionNoApplyOriginalV2::new()),
            no_apply_body: None, no_apply_completion: None, output_preparation: None,
            applying_geometry: None, applying_funding: None, applying_gate: None,
            inputs: Box::new(super::attachment_target::ControllerAttachmentSourceOriginalV1::new()),
            parent: None, receipt: None, specification: None, body: None,
            periodic: None, periodic_cursor: None }
    }

    /// Lends the same unused native C18 to a genuinely completed Recover scope.
    pub(in crate::controller_service) fn borrow_cleanup_financial_v2(&mut self)
        -> Result<&mut aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionRuntimeCustodyV2,
            aos_sandbox_controller_domain::ResourceReservationErrorV1>
    {
        if self.body.is_some() || self.periodic.is_some() || self.no_apply_completion.is_some()
            || self.availability_failure_v2().is_some() || self.output_preparation.is_some()
            || self.parent.is_some() || self.receipt.is_some() || self.specification.is_some()
        {
            return Err(aos_sandbox_controller_domain::ResourceReservationErrorV1::Conflict);
        }
        self.financial.as_mut().ok_or(aos_sandbox_controller_domain::ResourceReservationErrorV1::Conflict)
    }
}

fn advance(
    executor: &mut ProductionEffectExecutor,
    operation: OperationId,
    context: &PublicMutationEffectHistoryV1,
    controller: &mut Journal,
) -> Result<super::execution::ControllerExecutionCompletionV1, EffectFailure> {
    let bank = executor.resource_bank.as_ref()
        .ok_or_else(|| retryable("original Controller bank is unavailable"))?;
    let bank = bank.lock().map_err(|_| retryable("original Controller bank is poisoned"))?;
    let profile = executor.execution_profile.as_ref()
        .ok_or_else(|| retryable("original execution profile is unavailable"))?;
    let directory = executor.execution_credential_directory.as_deref()
        .ok_or_else(|| retryable("original startup credential locator is unavailable"))?;
    let host_identity = executor.attachment_host.as_ref()
        .ok_or_else(|| retryable("trusted Host service identity is unavailable"))?;
    let signer = executor.broker_plan_signer.as_ref()
        .ok_or_else(|| retryable("Controller broker signer is unavailable"))?;
    if executor.execution_original.is_none() {
        executor.execution_original = Some(ControllerExecutionOriginalV1::claim_once_v1(
            &bank, controller, profile,
        )?);
    }
    let original = executor.execution_original.as_mut()
        .ok_or_else(|| retryable("original execution custody is unavailable"))?;
    if original.body.is_some() || original.periodic.is_some() || original.no_apply_completion.is_some()
        || original.availability_failure_v2().is_some() {
        // A completed result is consumed only by the actual effect continuation;
        // any retained negative/pending body blocks replacement execution.
        return Err(retryable("original execution interval already entered"));
    }
    let fixed = super::attachment_target::ControllerAttachmentSourceOriginalV1::fixed_receiving_demand_v1(
        host_identity, directory,
    ).ok_or_else(|| retryable("execution source fixed geometry overflows"))?;
    let financial = original.financial.as_mut()
        .ok_or_else(|| retryable("original execution is lent to public compilation"))?;
    let (mut loan, mut retirement) = financial.begin_once_v2(&bank, controller, profile, operation, context,
        aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(fixed))
        .map_err(|_| retryable("original execution intake refused"))?;
    let accepted = loan.accepted_v1().cloned();
    let prepared = (|| {
        let actual = accepted.as_ref().ok_or_else(|| retryable("protected accepted execution differs"))?;
        loan.prepare_fixed_controller_records_v1(&bank, controller, profile)
            .map_err(|_| retryable("Controller source/append representation was refused"))?;
        let (sandbox, execution) = if let Some(retirement) = retirement.as_mut() {
            retirement.prepare_accepted_create_source_once_v2(&mut loan, &bank, controller, profile)
                .map_err(|_| retryable("original accepted Execution bind source was refused"))?;
            let source = retirement.accepted_create_source_data_v2()
                .map_err(|_| retryable("original accepted Execution bind source is unavailable"))?;
            (source.assignment_manifest_v2().manifest().sandbox(), source.execution_v2())
        } else {
            accepted_target(controller, operation, actual)?
        };
        let assignment = prepare_current_runtime_inputs_v4(&mut original.inputs, &mut original.parent,
            &mut loan, &bank, controller, profile, host_identity, executor.node, directory,
            actual.project(), sandbox)?;
        Ok((assignment, execution))
    })();
    let (assignment, execution) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            loan.finish_without_source_v1(&bank, controller, profile);
            original.body = Some(Err(error));
            // The original failed inputs and prearmed C posts remain live until
            // this termination; no negative native prefix is silently dropped.
            std::process::abort();
        }
    };
    let source_error = match loan.prepare_source_once_v1(&bank, &mut executor.source_domains, controller, profile) {
        Ok(mut source) => {
            let body = (|| {
                let parent = original.parent.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or_else(|| retryable("actual execution Parent is absent"))?;
                source.prepare_environment_v1(&bank, controller, profile, &assignment, parent, execution)
                    .map_err(|error| retryable(error.to_string()))?;
                let (mut environment, mut receiving, clock_original) = source.environment_and_receiving_v1()
                    .map_err(|error| retryable(error.to_string()))?;
                let mut clock = || clock_original.sample_v1();
                // The kernel's durable EffectApplying precedes this paid
                // lifecycle advance. Retain that exact intent before first35;
                // the broader accepted-source decoder alone is insufficient.
                original.applying_geometry = Some(applying::demand(controller, operation));
                let demand = original.applying_geometry.as_ref().and_then(|value| value.as_ref().ok())
                    .copied().ok_or_else(|| retryable("execution Applying geometry is unavailable"))?;
                original.applying_funding = Some(receiving.admit_stage_v1(&bank, controller, profile,
                    aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(demand)));
                if !matches!(original.applying_funding, Some(Ok(()))) {
                    return Err(retryable("execution Applying model exceeds its original subdivision"));
                }
                original.applying_gate = Some(applying::require_applying(controller, operation, context));
                if !matches!(original.applying_gate, Some(Ok(_))) {
                    return Err(retryable("execution has no exact durable Applying intent"));
                }
                let parent = original.parent.as_ref().and_then(|v| v.as_ref().ok())
                    .ok_or_else(|| retryable("actual execution Parent is absent"))?;
                let attempt = load_controller_execution_output_attempt_v1(controller, execution)
                    .map_err(|error| retryable(error.to_string()))?;
                original.output_preparation = Some(prepare_registered_output(&executor.sessions, signer, operation, execution,
                    controller, &assignment, &mut environment, parent, attempt, &mut receiving, &bank, profile, &mut clock));
                if original.output_preparation.as_ref().is_some_and(Result::is_err) {
                    // The output error is retained, never interpreted as a
                    // terminal proof. This same healthy Source/C18 and actual
                    // Host Session must complete the entire NoApply programme.
                    original.no_apply_body = Some(no_apply::run_active_once_v2(
                        &executor.sessions, controller, &bank, profile, &mut receiving,
                        &original.availability, &mut original.no_apply, &mut original.no_apply_native,
                    ));
                    return Err(retryable("execution output stopped before Host argument acceptance"));
                }
                let preissue = original.output_preparation.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or_else(|| retryable("original output preparation is absent"))?;
                let mut sessions = executor.sessions.lock().map_err(|_| retryable("broker session lock is poisoned"))?;
                let super::ControllerBrokerSessions { host, storage, .. } = &mut *sessions;
                let host = host.as_mut().ok_or_else(|| retryable("actual Host Session is absent"))?;
                let storage = storage.as_mut().ok_or_else(|| retryable("actual Storage Session is absent"))?;
                if host.accepted_execution_argument_v2().is_none() {
                    host.prepare_execution_argument_v2(&mut receiving, &bank, controller, profile,
                        |coordinates, controller| super::execution_argument_observe::sign_current_host_execution_argument_v2(
                            controller, &assignment, &mut environment, parent, execution, operation, signer,
                            super::execution_argument_observe::ExecutionArgumentSigningPhaseV2::Prepare,
                            coordinates, &mut clock,
                        ))?;
                    host.accept_execution_argument_v2(&mut receiving, &bank, controller, profile,
                        |coordinates, preparation, controller| super::execution_argument_observe::sign_current_host_execution_argument_v2(
                            controller, &assignment, &mut environment, parent, execution, operation, signer,
                            super::execution_argument_observe::ExecutionArgumentSigningPhaseV2::Accept(preparation),
                            coordinates, &mut clock,
                        ))?;
                }
                let outcome = host.accepted_execution_argument_v2()
                    .ok_or_else(|| retryable("original completed59 outcome is absent"))?;
                original.receipt = Some(aos_sandbox_controller_domain::controller_execution_argument_receipt::retain_authenticated_controller_host_argument_receipt_v2(
                    controller, &assignment, &mut environment, parent, execution, operation, outcome, &mut clock,
                ));
                let observation = original.receipt.as_ref().and_then(|v| v.as_ref().ok())
                    .ok_or_else(|| retryable("fresh59 Controller receipt was refused"))?;
                original.specification = Some(aos_sandbox_controller_domain::controller_execution_spec_attempt::retain_controller_execution_spec_attempt_v1(
                    controller, &assignment, &mut environment, parent, observation, execution, operation, &mut clock,
                    &mut receiving, &bank, profile,
                ));
                let specification = original.specification.as_ref().and_then(|v| v.as_ref().ok())
                    .ok_or_else(|| retryable("actual canonical specification was refused"))?;
                // No Guest process has been spawned here. Candidate freshness
                // starts only after the actual signed59 and canonical spec are
                // retained; it is consumed once by the following Reserve60.
                let mode = aos_sandbox_controller_domain::controller_execution_preissue::execution_preissue_io_mode_v3(controller, &preissue)
                    .map_err(|error| retryable(error.to_string()))?;
                if mode == aos_sandbox_api::aos::sandbox::v1::ExecutionIoMode::EXECUTION_IO_MODE_DETACHED_CAPTURE {
                    super::execution_output_storage_registration::advance_original_capture_candidate_on_storage_v3(
                        storage, operation, controller, &assignment, &mut environment, parent,
                        &preissue, signer, &mut clock, &mut receiving, &bank, profile)?;
                    storage.reserve_current_capture_v4(controller, &assignment, &mut environment,
                        parent, &preissue, specification, signer, &mut receiving, &bank, profile, &mut clock)?;
                }
                // Runtime owns this actual lower bridge; it independently requires the
                // SAME resident Host59/live Agent and the actual held Storage protocol.
                // Neither the receipt nor informational preissue supplies that grant.
                super::execution_authorize::authorize_and_observe_v2(operation, context, controller,
                    &assignment, &mut environment, parent, specification, host, storage, signer,
                    &mut receiving, &bank, profile, observation, &mut clock)
            })();
            original.body = Some(body);
            source.finish_native_once_v1(&bank, controller, profile);
            let no_apply = matches!(original.no_apply_body, Some(Ok(())));
            if (!no_apply && original.body.as_ref().is_none_or(|v| v.is_err())) || source.failure().is_some() {
                // Diagnostics follow the actual returned transaction marker;
                // a later post cannot replace the first retained native cause.
                if let Ok(sessions) = executor.sessions.lock() {
                    let _host_cause = sessions.host.as_ref()
                        .and_then(|host| host.execution_input_failure_v1());
                    let _storage_cause = sessions.storage.as_ref()
                        .and_then(|storage| storage.output_registration_failure());
                    let _capture_cause = sessions.storage.as_ref()
                        .and_then(|storage| storage.capture_admission_failure_v3());
                }
                // No success/Apply/terminal is fabricated. All reached owners and the
                // original body error remain resident until this fail-closed endpoint.
                std::process::abort();
            }
            // This token checks both independent native posts while every actual
            // Session/input owner is still held. No resource credit returns before
            // the exact completed upper destinations have retired.
            let disposal = match source.prepare_positive_disposal_v1(&bank, controller, profile) {
                Ok(disposal) => disposal,
                Err(_) => std::process::abort(),
            };
            if no_apply {
                let disposed = match original.no_apply.retire_no_apply_before_native_disposal_v2(
                    &mut original.no_apply_native, &disposal,
                ) {
                    Ok(disposed) => disposed,
                    Err(_) => std::process::abort(),
                };
                {
                    let mut sessions = match executor.sessions.lock() {
                        Ok(sessions) => sessions,
                        Err(_) => std::process::abort(),
                    };
                    let super::ControllerBrokerSessions { host, storage, .. } = &mut *sessions;
                    let Some(host) = host.as_mut() else { std::process::abort() };
                    let Some(storage) = storage.as_mut() else { std::process::abort() };
                    if host.retire_no_apply_inputs_v2(&disposed, &disposal, execution).is_err()
                        || storage.retire_no_apply_output_inputs_v2(&disposed, &disposal, execution).is_err() {
                        std::process::abort();
                    }
                }
                if original.availability.retire_positive_v2(&disposal).is_err() {
                    std::process::abort();
                }
                original.availability_scope = None;
                original.availability_body = None;
                drop(std::mem::replace(&mut *original.inputs,
                    super::attachment_target::ControllerAttachmentSourceOriginalV1::new()));
                original.parent = None;
                original.receipt = None;
                original.specification = None;
                original.output_preparation = None;
                original.applying_geometry = None;
                original.applying_funding = None;
                original.applying_gate = None;
                if let Some(mut retirement) = retirement.take() {
                    if retirement.retire_before_native_disposal_v2(&disposal).is_err() {
                        std::process::abort();
                    }
                }
                drop(accepted);
                drop(assignment);
                // The returned diagnostic is not terminal authority. Drop its
                // owned String with the rest of this upper prefix before D+.
                original.body = None;
                original.no_apply_body = None;
                let completed = match disposal.complete_no_apply_after_disposal_v2(disposed) {
                    Ok(completed) => completed,
                    Err(_) => std::process::abort(),
                };
                original.no_apply_completion = Some(completed);
                // The sealed witness, rather than this diagnostic, selects
                // the kernel's no-append terminal handoff.
                return Err(retryable("the exact NoApply terminal awaits kernel handoff"));
            }
            {
                let mut sessions = match executor.sessions.lock() {
                    Ok(sessions) => sessions,
                    Err(_) => std::process::abort(),
                };
                let super::ControllerBrokerSessions { host, storage, .. } = &mut *sessions;
                let Some(host) = host.as_mut() else { std::process::abort() };
                let Some(storage) = storage.as_mut() else { std::process::abort() };
                // Runtime owns the actual Apply/first Observe interval and its held
                // Storage response; only that completed stage can retire those owners.
                if host.retire_execution_authorize_v2(&disposal, execution).is_err()
                    || host.retire_execution_inputs_v1(&disposal, execution).is_err()
                    || storage.retire_execution_output_inputs_v1(&disposal, execution).is_err()
                {
                    std::process::abort();
                }
            }
            if original.availability_body.is_some() {
                if original.availability.retire_positive_v2(&disposal).is_err() {
                    std::process::abort();
                }
                original.availability_scope = None;
                original.availability_body = None;
            }
            *original.inputs = super::attachment_target::ControllerAttachmentSourceOriginalV1::new();
            original.parent = None;
            original.receipt = None;
            original.specification = None;
            original.output_preparation = None;
            original.applying_geometry = None;
            original.applying_funding = None;
            original.applying_gate = None;
            drop(accepted);
            drop(assignment);
            if let Some(mut retirement) = retirement.take() {
                if retirement.retire_before_native_disposal_v2(&disposal).is_err() {
                    std::process::abort();
                }
            }
            disposal.complete_after_disposal_v1();
            let completion = match original.body.take() {
                Some(Ok(completion)) => completion,
                _ => std::process::abort(),
            };
            return Ok(completion);
        }
        Err(error) => error,
    };
    // The failed borrowing result has ended before the same original runs its
    // independently prepaid C posts. Entered Source custody finishes above.
    loan.finish_without_source_v1(&bank, controller, profile);
    original.body = Some(Err(retryable(source_error.to_string())));
    std::process::abort();
}

#[allow(clippy::too_many_arguments)]
fn prepare_registered_output<T>(
    sessions: &super::SharedControllerBrokerSessions,
    signer: &super::plan_signer::ControllerBrokerPlanSignerV1,
    operation: OperationId, execution: ExecutionId, controller: &mut Journal,
    assignment: &aos_sandbox_controller_domain::runtime_scope::CurrentAssignmentTarget,
    environment: &mut aos_sandbox_controller_domain::environment::EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &aos_sandbox_controller_domain::execution_parent_resource::ExecutionParentResourceSourceV1,
    attempt: Option<aos_sandbox_controller_domain::controller_execution_preissue::ControllerExecutionOutputAttemptV1>,
    receiving: &mut aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionReadReceivingLoanV1<'_, '_>,
    bank: &aos_sandbox_controller_domain::ControllerResourceBankOpeningV1,
    profile: &aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1,
    clock: &mut T,
) -> Result<aos_sandbox_controller_domain::controller_execution_preissue::ControllerExecutionPreissueV1, EffectFailure>
where T: FnMut() -> Result<aos_sandbox_model::RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let settled = if attempt.is_some() {
        read_current_controller_output_settlement_v1(
            controller,
            assignment,
            execution,
            operation,
            clock,
        )
        .map_err(|error| retryable(error.to_string()))?
        .is_some()
    } else {
        false
    };
    if settled {
        let preissue = attempt
            .as_ref()
            .ok_or_else(|| retryable("original Host output attempt is absent"))?
            .source()
            .preissue();
        let signer = signer;
        super::execution_output_storage_registration::advance_registration_v3(
            sessions,
            operation,
            controller,
            assignment,
            environment,
            parent,
            preissue,
            signer,
            clock, receiving, bank, profile,
        )?;
        return Ok(preissue.clone());
    }

    let (observation, preissue, mismatched_reply) = if let Some(attempt) = attempt {
        let preissue = attempt.source().preissue().clone();
        revalidate_historical_execution_preissue_source_v1(
            controller,
            assignment,
            environment,
            parent,
            &preissue,
            clock,
        )
        .map_err(|error| retryable(error.to_string()))?;
        let signer = signer;
        let mut sessions = sessions
            .lock()
            .map_err(|_| retryable("broker session lock is poisoned"))?;
        let host = sessions
            .host
            .as_mut()
            .ok_or_else(|| retryable("Host session is unavailable"))?;
        let observation = match host.drain_execution_output_for(receiving, bank, controller, profile, &attempt)? {
            Some(observation) => observation,
            None => host.query_execution_output(receiving, bank, controller, profile, &attempt, signer)?,
        };
        drop(sessions);

        (
            observation,
            preissue,
            retryable("another execution owns the retained Host output reply"),
        )
    } else {
        let preissue = preissue_accepted_execution_source_v1(
            controller,
            assignment,
            environment,
            parent,
            execution,
            operation,
            clock,
        )
        .map_err(|error| retryable(error.to_string()))?;
        let signer = signer;
        let mut sessions = sessions
            .lock()
            .map_err(|_| retryable("broker session lock is poisoned"))?;
        let host = sessions
            .host
            .as_mut()
            .ok_or_else(|| retryable("Host session is unavailable"))?;
        let observation = host.reserve_execution_output(receiving, bank, controller, profile, |coordinates, controller| {
            sign_current_host_output_reserve_v1(
                controller,
                assignment,
                environment,
                parent,
                &preissue,
                signer,
                coordinates,
                clock,
            )
        })?;
        drop(sessions);

        (
            observation,
            preissue,
            EffectFailure::Permanent(
                "Host output reply differs from the accepted Create".to_owned(),
            ),
        )
    };

    if !observation.matches(execution, operation) {
        return Err(mismatched_reply);
    }
    revalidate_historical_execution_preissue_source_v1(
        controller,
        assignment,
        environment,
        parent,
        &preissue,
        clock,
    )
    .map_err(|error| retryable(error.to_string()))?;
    let settlement = observation
        .settle(controller, assignment, clock)
        .map_err(|error| retryable(error.to_string()))?;
    if settlement.is_none() {
        return Err(retryable("original Host output attempt is not committed"));
    }
    let signer = signer;
    super::execution_output_storage_registration::advance_registration_v3(
        sessions,
        operation,
        controller,
        assignment,
        environment,
        parent,
        &preissue,
        signer,
        clock, receiving, bank, profile,
    )?;
    Ok(preissue)
}

fn accepted_target(
    controller: &Journal,
    operation: OperationId,
    context: &PublicMutationEffectHistoryV1,
) -> Result<(SandboxId, ExecutionId), EffectFailure> {
    aos_sandbox_controller_domain::reconciler::accepted_execution_target_from_journal_v1(
        controller, operation, context,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_current_runtime_inputs_v4(
    inputs: &mut super::attachment_target::ControllerAttachmentSourceOriginalV1,
    parent: &mut Option<Result<aos_sandbox_controller_domain::execution_parent_resource::ExecutionParentResourceSourceV1,
        aos_sandbox_controller_domain::execution_parent_resource::ExecutionParentResourceSourceErrorV1>>,
    loan: &mut aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionOperationReceivingLoanV1<'_>,
    bank: &aos_sandbox_controller_domain::ControllerResourceBankOpeningV1, controller: &mut Journal,
    profile: &aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1,
    host_identity: &aos_sandbox_controller_domain::runtime_scope::HostServiceIdentity,
    node: aos_sandbox_model::NodeId, directory: &std::ffi::OsStr,
    project: aos_sandbox_model::ProjectId, sandbox: SandboxId,
) -> Result<aos_sandbox_controller_domain::runtime_scope::CurrentAssignmentTarget, EffectFailure> {
    inputs.prepare_configuration_once(host_identity, node, directory);
        let dynamic = inputs.acquisition_receiving_demand_v1(controller)
            .ok_or_else(|| retryable("execution source dynamic geometry is unavailable"))?;
        let complete = loan.prefix_demand_v1().checked_add(dynamic)
            .map_err(|_| retryable("execution source complete geometry overflows"))?;
        loan.require_complete_v1(&bank, controller, profile,
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(complete))
            .map_err(|_| retryable("execution source exceeds the same declaration"))?;
        inputs.capture_prepared_source_once(controller, sandbox);
        let assignment = inputs.take_completed_once()
            .ok_or_else(|| retryable("protected Runtime source is unavailable"))?.into_assignment_target();
        *parent = Some(current_execution_parent_resource_from_journal_v1(
            controller, project, sandbox, node,
        ));
        if parent.as_ref().is_none_or(|v| v.is_err()) {
            return Err(retryable("protected execution Parent is unavailable"));
        }
    Ok(assignment)
}

fn retryable(message: impl Into<String>) -> EffectFailure {
    EffectFailure::Retryable(message.into())
}
