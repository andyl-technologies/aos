//! Drives one original pending Start to a non-authorizing Storage Prepared result.
//!
//! The attempt is a subslot of the actual Storage inventory Session owner. The
//! same worker retains the signed origin, draft, signing and transport results;
//! short loans keep the actual Controller writer and every local input pinned.
//! No physical Clone, completed Start, public readiness or Drain is implied.

use std::sync::Arc;

use aos_sandbox::production_operation_compiler::{
    ControllerNixGenerationOriginalV1, CurrentRetainedNixStartV2,
    NixGenerationOriginalErrorV1, NixStartContinuationErrorV2,
    StorageGenerationPreparationDraftV1,
};
use aos_sandbox::{EffectFailure, EffectObservation, EffectPlan, EffectReceipt, SignedBrokerPlan};
use aos_sandbox_core::OperationId;

use super::nix_inputs::{NixLocalInputCutV2, NixLocalInputErrorV2};
use super::{ControllerResidentCauseV1, ControllerWorkerCustodyV1, ProductionEffectExecutor};
use crate::controller_authority_effect::ControllerStorageGenerationExchangeV1;
use crate::controller_plan_signer::ControllerBrokerPlanSignerError;

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
    let _unwind = super::AbortControllerCustodyUnwindV1;
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
    let _cut_unwind = super::AbortControllerCustodyUnwindV1;
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
