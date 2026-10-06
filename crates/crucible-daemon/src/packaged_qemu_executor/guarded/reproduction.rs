//! Authenticated completed assignments used as fresh reproduction sources.
//!
//! A durable completed record supplies the original semantic identity. Its
//! resources and observation are independently checked before a new physical
//! service is reserved. The source execution identity is provenance, never a
//! second active execution or a renewed source deadline.

use super::*;
use crate::assignment_ledger::AttemptRuntimeState;
use crate::{AssignmentLedger, AttemptExecutionKey, AttemptExecutionRuntimeBasis};
use crucible_api::host_operational::HostOperationalError;
use crucible_campaign::AttemptStartMode;

pub(crate) struct CompletedReproductionBasis {
    input: crate::AttemptExecutionInput,
    execution: crate::CrucibleAttemptExecution,
    request: SubmitAttemptRequest,
    runtime_basis: AttemptExecutionRuntimeBasis,
}

impl CompletedReproductionBasis {
    pub(crate) fn input(&self) -> &crate::AttemptExecutionInput {
        &self.input
    }

    pub(crate) fn source(&self) -> &ScenarioDefForm {
        self.execution.scenario()
    }

    pub(crate) fn request(&self) -> &SubmitAttemptRequest {
        &self.request
    }

    pub(crate) fn runtime_basis(&self) -> AttemptExecutionRuntimeBasis {
        self.runtime_basis
    }
}

impl GuardedCampaignOwner {
    pub(crate) fn completed_reproduction_basis(
        &self,
        request: &SubmitAttemptRequest,
        expected: ObservationId,
    ) -> Result<CompletedReproductionBasis, Box<dyn std::error::Error + Send + Sync>> {
        let authority = self
            .inner
            ._quota
            .clone()
            .ok_or(HostOperationalError::Unavailable)?;
        let budget = crucible::owned_decode::DecodeBudget::for_store(authority)?;
        let _scope = budget.enter();
        if request.start_mode() != AttemptStartMode::Execute {
            return Err(Box::new(HostOperationalError::Unavailable));
        }
        // Repository closure validation occurs without the actor lock. The
        // operational ledger then proves this exact result was genuinely
        // reconciled; caller-supplied identity alone cannot create a source.
        let validation = self.inner.admission.validate(request);
        budget.check()?;
        validation.map_err(|reason| HostOperationalError::InvalidMessage {
            message: format!("completed reproduction source rejected: {reason:?}"),
        })?;
        let validation = self.inner.admission.validate_completion(request, expected);
        budget.check()?;
        validation.map_err(|reason| HostOperationalError::InvalidMessage {
            message: format!("completed reproduction observation rejected: {reason:?}"),
        })?;
        let key = AttemptExecutionKey::for_request(request);
        let state = self
            .inner
            .actor
            .with_supervisor(|actor| Ok(actor.ledger().load_attempt(key)))??;
        let Some(AttemptRuntimeState::Completed {
            execution_basis,
            execution,
            observation,
            ..
        }) = state
        else {
            return Err(Box::new(HostOperationalError::Unavailable));
        };
        if execution_basis != request.execution_basis_digest() || observation != expected {
            return Err(Box::new(HostOperationalError::Unavailable));
        }
        let store = CampaignExecutorStore::new(self.inner.repository.clone());
        let input = crate::resolve_attempt_execution_input_with_resources(
            &store,
            key,
            request.resources(),
        )?;
        let execution_form = crate::decode_crucible_attempt_execution_with_resources(
            &store,
            &input,
            request.resources(),
        )?;
        budget.check()?;
        Ok(CompletedReproductionBasis {
            input,
            execution: execution_form,
            request: request.clone(),
            runtime_basis: AttemptExecutionRuntimeBasis::new(key, execution),
        })
    }
}
