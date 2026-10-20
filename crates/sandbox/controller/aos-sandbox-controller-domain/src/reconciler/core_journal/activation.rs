//! Shares the sole canonical activation body for borrowed Controller Journal work.
//!
//! Ordinary entry points delegate immediately; scoped Host entry retains the
//! genuine Start native owner through this same validation and commit engine.

use super::*;

impl CoreJournalMutationV2<'_, '_> {
    pub(in crate::reconciler) fn activate_ownership_gate_inner(
        &mut self,
        operation_id: OperationId,
        activation: AuthorityPublicationActivationV1,
        wall_seconds: Option<i64>,
    ) -> Result<OwnershipGateActivationOutcome, ReconcilerError> {
        self.ensure_ledger_validated()?;
        let AuthorityPublicationActivationPartsV1 {
            records: publication_records,
            sandbox,
            assignment_digest,
            source_draft_digest,
            ownership_authority,
            publication_digest,
            lease_generation,
            lease_digest,
            receipt_action,
            receipt_request_id,
            receipt_claim_digest,
            prepared,
        } = activation.into_parts();
        let operation = self.load_operation(operation_id)?;
        let gate = self
            .load_and_validate_ownership_gate(operation_id, operation)?
            .ok_or(ReconcilerError::OwnershipGateNotFound)?;
        let durable_plan = match &gate {
            OwnershipGateStatusV1::Pending(plan)
            | OwnershipGateStatusV1::Activated { plan, .. } => plan,
        };
        let claim_assignment = durable_plan.claim().assignment();
        if sandbox != claim_assignment.sandbox()
            || assignment_digest != claim_assignment.digest()
            || source_draft_digest != durable_plan.publication_draft_digest()
            || &ownership_authority != durable_plan.expected_authority()
            || receipt_action != durable_plan.claim().action()
            || receipt_request_id != *durable_plan.claim().request_id()
            || receipt_claim_digest != durable_plan.claim().digest()
        {
            return Err(ReconcilerError::OwnershipActivationConflict);
        }
        let plan = match gate {
            OwnershipGateStatusV1::Pending(plan) => plan,
            OwnershipGateStatusV1::Activated {
                publication_digest: prior_publication,
                lease_generation: prior_generation,
                lease_digest: prior_lease,
                ..
            } if prior_publication == publication_digest
                && prior_generation == lease_generation
                && prior_lease == lease_digest =>
            {
                return Ok(OwnershipGateActivationOutcome::Replay);
            }
            OwnershipGateStatusV1::Activated { .. } => {
                return Err(ReconcilerError::OwnershipActivationConflict);
            }
        };
        AuthorityPublicationStore::new(&mut self.journal)
            .validate_gate_successor(&prepared)
            .map_err(|_| ReconcilerError::OwnershipPublicationNotSuccessor)?;
        self.validate_gated_effects_for_activation(operation_id, operation.effect_count())?;
        let runtime_records = if operation.runtime_intent_digest().is_some()
            || self
                .journal
                .records(RecordNamespace::RuntimeAuthority)
                .next()
                .is_some()
        {
            let store =
                RuntimeAuthorityStore::load(&mut self.journal, RuntimeAuthorityLimits::default())?;
            if operation.runtime_intent_digest().is_none() && store.current(sandbox)?.is_some() {
                return Err(ReconcilerError::InvalidPlan(
                    "a current runtime holder requires an explicit successor intent",
                ));
            }
            store.prepare_activation(
                operation_id,
                plan.request_digest(),
                plan.publication_draft(),
                &prepared,
            )?
        } else {
            Vec::new()
        };
        let activated = OwnershipGateStatusV1::Activated {
            plan,
            publication_digest,
            lease_generation,
            lease_digest,
        };
        let mut records = Vec::from(publication_records);
        records.extend(runtime_records);
        let operation = transition_operation(operation, OperationState::Accepted, wall_seconds)?;
        records.push(JournalRecord::put(
            RecordNamespace::Operation,
            operation_id.into_bytes().to_vec(),
            encode_operation_record(operation),
        ));
        records.push(JournalRecord::put(
            RecordNamespace::OwnershipGate,
            operation_id.into_bytes().to_vec(),
            encode_ownership_gate(&activated)?,
        ));
        let transaction = JournalTransaction::new(OperationId::new().into_bytes(), records)
            .map_err(JournalError::from)?;
        #[cfg(target_os = "linux")]
        self.commit_core_recipe_v1(&transaction,
            provisioning::CoreCommitRecipeV1::activation(operation_id, &prepared))?;
        #[cfg(not(target_os = "linux"))]
        self.journal.commit(&transaction)?;
        Ok(OwnershipGateActivationOutcome::Activated)
    }
}
