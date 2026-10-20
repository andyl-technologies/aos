//! Shares the sole canonical admission body for borrowed Controller Journal work.
//!
//! Ordinary entry points delegate immediately; scoped Host entry retains the
//! genuine Start native owner through this same validation and commit engine.

use super::*;

impl CoreJournalMutationV2<'_, '_> {
    pub(in crate::reconciler) fn accept_inner(
        &mut self,
        plan: &OperationPlan,
        maximum_pending_operations: Option<usize>,
    ) -> Result<AcceptOutcome, ReconcilerError> {
        self.ensure_ledger_validated()?;
        match self
            .journal
            .check_idempotency(&plan.idempotency_key, plan.request_digest)
        {
            IdempotencyOutcome::Replay(operation_id) => {
                if observe_reservation::is_adopted_child(&self.journal, operation_id)? {
                    return Err(ReconcilerError::OperationAlreadyExists);
                }
                self.validate_operation_gate_relation(operation_id)?;
                let recorded = self.load_operation(operation_id)?;
                let recorded_authorization = self
                    .journal
                    .get(
                        RecordNamespace::PublicOperationAuthorization,
                        operation_id.as_bytes(),
                    )
                    .map(PublicOperationAuthorizationV1::decode)
                    .transpose()?;
                let planned_public_operation = plan.public_operation.as_ref().map(|public| {
                    if plan.effects.is_empty() {
                        public.durable_completed()
                    } else {
                        public.durable()
                    }
                });
                if recorded.runtime_intent_digest()
                    != plan
                        .runtime_authority
                        .as_ref()
                        .map(RuntimeAuthorityIntentV1::digest)
                    || recorded.public_operation() != planned_public_operation
                    || recorded_authorization.as_ref()
                        != plan
                            .public_operation
                            .as_ref()
                            .map(PublicOperationAdmissionV1::authorization)
                {
                    return Err(ReconcilerError::IdempotencyConflict);
                }
                let recorded_local_completion = recorded.effect_count() == 0
                    && recorded.state() == OperationState::Succeeded
                    && !recorded.ownership_gated()
                    && recorded.runtime_intent_digest().is_none();
                let planned_local_completion =
                    plan.effects.is_empty() && !plan.local_records.is_empty();
                if recorded_local_completion != planned_local_completion {
                    return Err(ReconcilerError::IdempotencyConflict);
                }
                if recorded_local_completion
                    && self
                        .journal
                        .get(RecordNamespace::DesiredState, &plan.desired_key)
                        != Some(plan.desired_value.as_slice())
                {
                    return Err(ReconcilerError::IdempotencyConflict);
                }
                for local in &plan.local_records {
                    if self.journal.get(local.namespace(), local.key()) != local.value() {
                        return Err(ReconcilerError::IdempotencyConflict);
                    }
                }
                #[cfg(target_os = "linux")]
                nix_admission::require_exact_nix_replay_plan_v2(&self.journal, operation_id, plan)?;
                return Ok(AcceptOutcome::Replay(operation_id));
            }
            IdempotencyOutcome::Conflict => return Err(ReconcilerError::IdempotencyConflict),
            IdempotencyOutcome::Vacant => {}
        }
        #[cfg(target_os = "linux")]
        self.journal.require_git_coverage_new_admission_v1()?;
        if self
            .journal
            .get(RecordNamespace::Operation, plan.operation_id.as_bytes())
            .is_some()
        {
            return Err(ReconcilerError::OperationAlreadyExists);
        }
        if observe_reservation::claims_operation(&self.journal, plan.operation_id)? {
            return Err(ReconcilerError::OperationAlreadyExists);
        }
        // A second admission cannot replace another operator's terminal
        // acknowledgment, even if a previously compiled plan is retained.
        if plan.local_records.iter().any(|record| {
            crate::operator_abandon_ack::is_acknowledgment_record_v1(record)
                && self.journal.get(record.namespace(), record.key()).is_some()
        }) {
            return Err(ReconcilerError::IdempotencyConflict);
        }
        if let Some(maximum) = maximum_pending_operations {
            // Corrupt operation state must never be treated as spare capacity.
            if self.pending_operation_count()? >= maximum {
                return Err(ReconcilerError::AdmissionBackpressure);
            }
        }

        let records = admission_records::prepare_admission_records_v1(&mut self.journal, plan)?;
        let transaction = JournalTransaction::new(OperationId::new().into_bytes(), records)
            .map_err(JournalError::from)?;
        #[cfg(target_os = "linux")]
        self.commit_core_recipe_v1(&transaction,
            provisioning::CoreCommitRecipeV1::admission(plan))?;
        #[cfg(not(target_os = "linux"))]
        self.journal.commit(&transaction)?;
        Ok(AcceptOutcome::Accepted(plan.operation_id))
    }
}
