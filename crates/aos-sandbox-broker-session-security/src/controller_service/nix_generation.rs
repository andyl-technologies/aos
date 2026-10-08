//! Retains one image-paid original Start intake in the actual Storage Session.
//!
//! The attempt is a subslot of the actual Storage inventory Session owner. The
//! selected caller commits I before current-Start growth, then archives every
//! acquisition, input-capture and independent closure result before projecting
//! Retryable. Input capture does not invoke Root, Source16 or the compiler.
//! The original generation tail remains private and uncalled until genuine
//! current-policy operation payment exists. Intake pays neither Storage57 nor
//! physical Clone, completed Start, public readiness or Drain.

use std::sync::Arc;

use aos_sandbox::production_operation_compiler::{
    ControllerNixGenerationOriginalV1, CurrentRetainedNixStartV2,
    NixGenerationOriginalErrorV1, NixStartContinuationErrorV2,
    StorageGenerationPreparationDraftV1,
};
use aos_sandbox::{EffectFailure, EffectObservation, EffectPlan, EffectReceipt};
use aos_sandbox_protocol::authorization_artifact::SignedBrokerPlan;
use aos_sandbox_core::OperationId;

use super::nix_inputs::{NixLocalInputCutV2, NixLocalInputErrorV2};
use super::resident_custody::{ControllerResidentCauseV1, ControllerWorkerCustodyV1};
use super::ProductionEffectExecutor;
use crate::controller_service::authority_effect::ControllerStorageGenerationExchangeV1;
use crate::controller_service::plan_signer::ControllerBrokerPlanSignerError;

#[derive(Debug, thiserror::Error)]
enum GenerationFailureV1 {
    #[error("original Start currentness failed: {0}")]
    Current(#[from] NixStartContinuationErrorV2),
    #[error("original generation capture failed: {0}")]
    Origin(#[from] NixGenerationOriginalErrorV1),
    #[error("complete physical input cut failed: {0}")]
    Inputs(#[from] NixLocalInputErrorV2),
    #[error("same Storage Session failed: {0}")]
    Session(#[from] crate::BrokerSessionSecurityError),
    #[error("selected exchange failed: {0}")]
    Exchange(EffectFailure),
    #[error("actual plan signing error remains resident")]
    Signer,
    #[error("actual selected exchange error remains resident")]
    ExchangeResult,
    #[error("actual Prepared projection error remains resident")]
    ResponseResult,
    #[error("actual original intake result remains resident")]
    IntakeResult,
    #[error("selected Prepared response failed: {0}")]
    Response(#[from] aos_sandbox_protocol::ProtocolValidationError),
    #[error("original generation attempt is closed")]
    Closed,
}

pub(crate) struct NixGenerationAttemptV1 {
    operation: OperationId,
    step: u32,
    origin: Option<ControllerNixGenerationOriginalV1>,
    draft: Option<StorageGenerationPreparationDraftV1>,
    signed: Option<Result<SignedBrokerPlan, ControllerBrokerPlanSignerError>>,
    exchange: ControllerStorageGenerationExchangeV1,
    response: Option<Result<
        aos_sandbox_protocol::semantics::CatalogBindingV1,
        aos_sandbox_protocol::ProtocolValidationError,
    >>,
    first: Option<GenerationFailureV1>,
    postcheck_debt: Option<GenerationFailureV1>,
    clock_debt: Option<NixStartContinuationErrorV2>,
    intake: Option<aos_sandbox::NixOriginalStartIntakeAttemptV1>,
    intake_preparation: Option<Result<(), aos_sandbox::ResourceReservationErrorV1>>,
    intake_entry: Option<Result<(), aos_sandbox::ResourceReservationErrorV1>>,
    intake_input: Option<Result<(), ()>>,
    intake_closure: Option<Result<(), aos_sandbox::ResourceReservationErrorV1>>,
}

impl NixGenerationAttemptV1 {
    fn new(operation: OperationId, step: u32) -> Self {
        Self {
            operation,
            step,
            origin: None,
            draft: None,
            signed: None,
            exchange: ControllerStorageGenerationExchangeV1::default(),
            response: None,
            first: None,
            postcheck_debt: None,
            clock_debt: None,
            intake: None,
            intake_preparation: None,
            intake_entry: None,
            intake_input: None,
            intake_closure: None,
        }
    }

    fn terminate_current(
        &mut self,
        current: &mut CurrentRetainedNixStartV2<'_>,
        worker: &ControllerWorkerCustodyV1,
        cause: GenerationFailureV1,
    ) -> ! {
        self.retain_cause(cause);
        if let Err(error) = current.observe_original_clock_after_failure() {
            self.clock_debt.get_or_insert(error);
        }
        worker.terminate(ControllerResidentCauseV1::NixGeneration)
    }

    fn terminate_cut(
        &mut self,
        cut: &mut NixLocalInputCutV2<'_, '_>,
        worker: &ControllerWorkerCustodyV1,
        cause: GenerationFailureV1,
    ) -> ! {
        self.retain_cause(cause);
        if let Err(error) = cut.observe_original_clock_after_failure() {
            self.clock_debt.get_or_insert(error);
        }
        worker.terminate(ControllerResidentCauseV1::NixGeneration)
    }

    fn retain_cause(&mut self, cause: GenerationFailureV1) {
        if self.first.is_none() {
            self.first = Some(cause);
        } else {
            self.postcheck_debt.get_or_insert(cause);
        }
    }

    fn terminate_parked_action(
        &mut self,
        cut: &mut NixLocalInputCutV2<'_, '_>,
        worker: &ControllerWorkerCustodyV1,
    ) -> ! {
        if let Err(error) = cut.observe_original_clock_after_failure() {
            self.clock_debt.get_or_insert(error);
        }
        worker.terminate(ControllerResidentCauseV1::NixGeneration)
    }
}

pub(super) fn observe(
    executor: &mut ProductionEffectExecutor,
    operation: OperationId,
    step: u32,
) -> Result<EffectObservation, EffectFailure> {
    let mut sessions = executor.sessions.lock().map_err(|_| {
        EffectFailure::Permanent("original Session owner lock is poisoned".to_owned())
    })?;
    let Some(storage) = sessions.storage.as_mut() else {
        return Ok(EffectObservation::Absent);
    };
    let (slot, _) = storage.nix_generation_loan()?;
    if let Some(attempt) = slot.as_ref() {
        if attempt.operation != operation || attempt.step != step {
            return Err(EffectFailure::Permanent(
                "another original generation remains resident".to_owned(),
            ));
        }
        if attempt.first.is_some() || attempt.postcheck_debt.is_some() || attempt.clock_debt.is_some() {
            return Err(EffectFailure::Permanent(
                "original generation failure and debt remain resident".to_owned(),
            ));
        }
    }
    // Prepared is only a prerequisite. It is never an Applied Effect receipt.
    Ok(EffectObservation::Absent)
}

pub(super) fn prepare(
    executor: &mut ProductionEffectExecutor,
    operation: OperationId,
    step: u32,
    plan: &EffectPlan,
    journal: &mut aos_sandbox::journal::Journal,
) -> Result<EffectReceipt, EffectFailure> {
    let selector = executor.nix_start.as_ref().map(Arc::clone).ok_or_else(|| {
        EffectFailure::Permanent("genuine Nix startup is absent".to_owned())
    })?;
    let bank = executor.resource_bank.as_ref().map(Arc::clone).ok_or_else(|| {
        EffectFailure::Permanent("original Nix intake enrollment is absent".to_owned())
    })?;
    let profile = executor.nix_generation_profile.as_ref().map(Arc::clone).ok_or_else(|| {
        EffectFailure::Permanent("original Nix intake profile is absent".to_owned())
    })?;
    let shared = Arc::clone(&executor.sessions);
    let mut sessions = shared.lock().map_err(|_| {
        EffectFailure::Permanent("original Session owner lock is poisoned".to_owned())
    })?;
    if sessions.nix_resolve.is_some() || sessions.nix_input_source.is_some() {
        return Err(EffectFailure::Permanent(
            "the original Nix input owner is already occupied".to_owned(),
        ));
    }
    let storage = sessions.storage.as_mut().ok_or_else(|| {
        EffectFailure::Permanent("original Storage inventory Session is absent".to_owned())
    })?;
    let (slot, _session) = storage.nix_generation_loan()?;
    if slot.is_some() {
        return Err(EffectFailure::Permanent(
            "original generation cannot be replaced or resent".to_owned(),
        ));
    }
    *slot = Some(NixGenerationAttemptV1::new(operation, step));
    let Some(attempt) = slot.as_mut() else {
        return Err(EffectFailure::Permanent("original generation slot is unavailable".to_owned()));
    };
    attempt.intake = Some(aos_sandbox::NixOriginalStartIntakeAttemptV1::begin(Arc::clone(&bank)));
    let NixGenerationAttemptV1 {
        intake, intake_preparation, intake_entry, intake_input, intake_closure, first, ..
    } = attempt;
    let Some(intake) = intake.as_mut() else {
        return Err(EffectFailure::Permanent("original intake destination is unavailable".to_owned()));
    };
    *intake_preparation = Some(intake.prepare_once(
        journal, &mut executor.source_domains, &profile, executor.first_global_prefix.as_ref(),
    ));
    if matches!(intake_preparation, Some(Err(_))) {
        *first = Some(GenerationFailureV1::IntakeResult);
        return Err(EffectFailure::Retryable(
            "original Nix intake failure and independent posts remain resident".to_owned(),
        ));
    }

    // The sole loan and the complete acquisition live outside I. The actual
    // Session retains I; no self-reference, copy or second evaluator is used.
    let loan = match intake.borrow_original_start(
        &bank, journal, &mut executor.source_domains, &profile, operation, step, plan,
    ) {
        Ok(loan) => {
            *intake_entry = Some(Ok(()));
            loan
        }
        Err(error) => {
            *intake_entry = Some(Err(error));
            *first = Some(GenerationFailureV1::IntakeResult);
            return Err(EffectFailure::Retryable(
                "original Nix intake entry failure remains resident".to_owned(),
            ));
        }
    };
    let mut acquisition = selector.borrow_paid_current_retained_start_v2(journal, loan);
    let mut input = aos_sandbox::policy_compiler::CurrentNixPreflightAttemptV1::empty();
    *intake_input = acquisition.capture_current_nix_preflight_once(
        &mut executor.source_domains, &mut input,
    );

    // Consume the external Source borrow before returning its owning native
    // Results to the same Session I. Closure then runs independent posts and
    // the unchanged original D clock LAST, even after input capture refusal.
    let originals = input.into_retained_originals();
    *intake_closure = Some(acquisition.close_with_input_into_intake(
        &mut executor.source_domains, originals,
    ));
    if matches!(intake_closure, Some(Err(_))) {
        *first = Some(GenerationFailureV1::IntakeResult);
    }
    Err(EffectFailure::Retryable(
        "paid original Nix input is retained; Root preflight and operation reservation remain required".to_owned(),
    ))
}

// Preserves the original generation tail while its genuine operation lender
// is unavailable. It has no installed caller and may not run on intake alone.
#[allow(dead_code)]
fn prepare_unpaid_generation_tail(
    executor: &mut ProductionEffectExecutor,
    operation: OperationId,
    step: u32,
    plan: &EffectPlan,
    journal: &mut aos_sandbox::journal::Journal,
) -> Result<EffectReceipt, EffectFailure> {
    let selector = executor.nix_start.as_ref().map(Arc::clone).ok_or_else(|| {
        EffectFailure::Permanent("genuine Nix startup is absent".to_owned())
    })?;
    let shared = Arc::clone(&executor.sessions);
    let mut sessions = shared.lock().map_err(|_| {
        EffectFailure::Permanent("original Session owner lock is poisoned".to_owned())
    })?;
    let worker = sessions.storage_terminal.as_ref().and_then(std::sync::Weak::upgrade)
        .ok_or_else(|| {
            EffectFailure::Permanent("original worker destination is absent".to_owned())
        })?;
    if sessions.nix_resolve.is_some() || sessions.nix_input_source.is_some() {
        return Err(EffectFailure::Permanent(
            "the original Nix input owner is already occupied".to_owned(),
        ));
    }
    let super::ControllerBrokerSessions {
        storage, nix_input_source, ..
    } = &mut *sessions;
    let storage = storage.as_mut().ok_or_else(|| {
        EffectFailure::Permanent("original Storage inventory Session is absent".to_owned())
    })?;
    let (slot, session) = storage.nix_generation_loan()?;
    if slot.is_some() {
        return Err(EffectFailure::Permanent(
            "original generation cannot be replaced or resent".to_owned(),
        ));
    }
    *slot = Some(NixGenerationAttemptV1::new(operation, step));
    let Some(attempt) = slot.as_mut() else {
        worker.terminate(ControllerResidentCauseV1::NixGeneration);
    };
    let _unwind = super::resident_custody::AbortControllerCustodyUnwindV1;
    let mut current = match selector.borrow_current_retained_start_v2(journal, operation, step, plan) {
        Ok(current) => current,
        Err(error) => {
            attempt.first = Some(GenerationFailureV1::Current(error));
            worker.terminate(ControllerResidentCauseV1::NixGeneration);
        }
    };
    if let Err(error) = selector.retain_storage_generation_origin_into(
        current.recipe_artifact(), &mut attempt.origin,
    ) {
        attempt.terminate_current(&mut current, &worker, error.into());
    }
    if let Err(error) = current.recheck() {
        attempt.terminate_current(&mut current, &worker, error.into());
    }
    let source = match super::nix_inputs::open_fixed_input_source_v2(&mut current) {
        Ok(source) => source,
        Err(error) => attempt.terminate_current(&mut current, &worker, error.into()),
    };
    *nix_input_source = Some(source);
    let Some(source) = nix_input_source.as_ref() else {
        attempt.terminate_current(&mut current, &worker, GenerationFailureV1::Closed);
    };
    let mut cut = match super::nix_inputs::pin_local_inputs_v2(&mut current, source) {
        Ok(cut) => cut,
        Err(error) => {
            attempt.terminate_current(&mut current, &worker, error.into());
        }
    };
    // This guard is younger than the successful complete cut, so unwinding
    // cannot destroy its original input OFDs before the same worker aborts.
    let _cut_unwind = super::resident_custody::AbortControllerCustodyUnwindV1;
    macro_rules! checked {
        ($value:expr) => {
            match $value {
                Ok(value) => value,
                Err(error) => attempt.terminate_cut(&mut cut, &worker, error.into()),
            }
        };
    }
    let request_id = checked!(session.nix_generation_request_id());
    let Some(origin) = attempt.origin.as_mut() else {
        attempt.terminate_cut(&mut cut, &worker, GenerationFailureV1::Closed);
    };
    checked!(cut.retain_storage_generation_prepare_into(origin, request_id, &mut attempt.draft));
    let Some(draft) = attempt.draft.as_ref() else {
        attempt.terminate_cut(&mut cut, &worker, GenerationFailureV1::Closed);
    };
    let Some(signer) = executor.broker_plan_signer.as_ref() else {
        attempt.terminate_cut(&mut cut, &worker, GenerationFailureV1::Closed);
    };

    checked!(cut.recheck());
    attempt.signed = Some(signer.sign_plan(draft.plan().clone(), draft.observed().wall_seconds()));
    if attempt.signed.as_ref().is_some_and(Result::is_err) {
        attempt.first = Some(GenerationFailureV1::Signer);
    }
    checked!(cut.recheck());
    if attempt.first.is_some() {
        attempt.terminate_parked_action(&mut cut, &worker);
    }
    let Some(Ok(signed)) = attempt.signed.as_ref() else {
        attempt.terminate_cut(&mut cut, &worker, GenerationFailureV1::Signer);
    };
    let deadline = cut.original_deadline_boottime_nanoseconds();
    attempt.exchange.prepare_into(session, draft, signed, request_id, deadline);
    if attempt.exchange.failure().is_some() {
        attempt.first = Some(GenerationFailureV1::ExchangeResult);
    }
    checked!(cut.recheck());
    if attempt.first.is_some() {
        attempt.terminate_parked_action(&mut cut, &worker);
    }
    if let Err(error) = attempt.exchange.drive(session) {
        attempt.terminate_cut(&mut cut, &worker, GenerationFailureV1::Exchange(error));
    }
    // The full signed outcome remains inside the same exchange before every
    // physical/currentness check or response projection.
    checked!(cut.recheck());
    let Some(outcome) = attempt.exchange.outcome() else {
        attempt.terminate_cut(&mut cut, &worker, GenerationFailureV1::Closed);
    };
    attempt.response = Some(crate::storage_create_preparation::generation_prepared_parts(
        outcome, draft,
    ));
    if attempt.response.as_ref().is_some_and(Result::is_err) {
        attempt.first = Some(GenerationFailureV1::ResponseResult);
    }
    checked!(cut.recheck());
    if attempt.first.is_some() {
        attempt.terminate_parked_action(&mut cut, &worker);
    }
    drop(cut);
    drop(current);
    Err(EffectFailure::Retryable(
        "Storage Prepared is retained; physical Clone, Apply and publication remain required".to_owned(),
    ))
}
