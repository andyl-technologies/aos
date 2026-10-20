//! Shares the canonical Effect/Operation row writer below ordinary and closed Host execution.

use super::*;

impl CoreJournalMutationV2<'_, '_> {
    pub(in crate::reconciler) fn store_operation(
        &mut self,
        operation_id: OperationId,
        state: OperationState,
        effect_count: u32,
        wall_seconds: Option<i64>,
    ) -> Result<(), ReconcilerError> {
        let operation = self.load_operation(operation_id)?;
        if operation.effect_count() != effect_count {
            return Err(ReconcilerError::CorruptLedger(
                "operation effect count changed during transition",
            ));
        }
        let operation = transition_operation(operation, state, wall_seconds)?;
        let record = JournalRecord::put(
            RecordNamespace::Operation,
            operation_id.into_bytes().to_vec(),
            encode_operation_record(operation),
        );
        self.commit_records(vec![record])
    }

    pub(in crate::reconciler) fn store_effect(
        &mut self,
        operation_id: OperationId,
        step: u32,
        record: &EffectLedgerRecord,
        operation_effect_count: Option<u32>,
        wall_seconds: Option<i64>,
        complete_private_operation: bool,
    ) -> Result<(), ReconcilerError> {
        // An executor may append project-admission metadata while retaining this
        // writer. Re-read that exact Effect before writing the retry diagnostic;
        // a record captured before dispatch must not erase terminal custody.
        let current = self
            .journal
            .get(RecordNamespace::Effect, &effect_key(operation_id, step))
            .ok_or(ReconcilerError::CorruptLedger("missing effect record"))?;
        #[cfg(target_os = "linux")]
        if q04_effect_subgate(current)
            .map_err(ReconcilerError::from)?
            .is_some()
        {
            // The selected same-flight CAS is the only writer for this
            // Applying subgate. A generic retry/result must not erase it or
            // turn policy admission into Applied/public Create completion.
            return Err(ReconcilerError::CorruptLedger(
                "Q04 policy admission requires its original closed transition",
            ));
        }
        let current = decode_effect(current)
            .map_err(ReconcilerError::from)?
            .into_parts();
        if current.0 != *record.plan()
            || record
                .project_admission()
                .is_some_and(|metadata| Some(metadata) != current.3.as_ref())
        {
            return Err(ReconcilerError::CorruptLedger(
                "Effect changed during executor transition",
            ));
        }
        let retained = {
            // The replacement moves before the complete clone, including its
            // overridden metadata. The unused clone field dies at this cut.
            let metadata = current.3;
            let cloned = record.clone().into_parts();
            EffectLedgerRecord::from_parts((cloned.0, cloned.1, cloned.2, metadata))
        };
        let mut records = vec![JournalRecord::put(
            RecordNamespace::Effect,
            effect_key(operation_id, step).to_vec(),
            encode_effect(&retained).map_err(ReconcilerError::from)?,
        )];
        let operation = self.load_operation(operation_id)?;
        if let Some(effect_count) = operation_effect_count {
            if operation.effect_count() != effect_count {
                return Err(ReconcilerError::CorruptLedger(
                    "operation effect count changed during transition",
                ));
            }
            let state = match record.state() {
                EffectState::Applying { .. } => OperationState::Applying,
                EffectState::PermanentlyBlocked { .. } => OperationState::PermanentlyBlocked,
                EffectState::Applied { .. } if complete_private_operation
                    && operation.public_operation().is_none()
                    && operation.ownership_gated() => OperationState::Succeeded,
                EffectState::Planned | EffectState::Applied { .. } => {
                    return Err(ReconcilerError::CorruptLedger(
                        "invalid coupled operation transition",
                    ));
                }
            };
            let operation = transition_operation(operation, state, wall_seconds)?;
            records.push(JournalRecord::put(
                RecordNamespace::Operation,
                operation_id.into_bytes().to_vec(),
                encode_operation_record(operation),
            ));
        } else if operation.public_operation().is_some() {
            let operation = transition_operation(operation, operation.state(), wall_seconds)?;
            records.push(JournalRecord::put(
                RecordNamespace::Operation,
                operation_id.into_bytes().to_vec(),
                encode_operation_record(operation),
            ));
        }
        self.commit_records(records)
    }

    pub(in crate::reconciler) fn commit_records(&mut self, records: Vec<JournalRecord>) -> Result<(), ReconcilerError> {
        let transaction = JournalTransaction::new(OperationId::new().into_bytes(), records)
            .map_err(JournalError::from)?;
        #[cfg(target_os = "linux")]
        self.commit_core_recipe_v1(&transaction,
            provisioning::CoreCommitRecipeV1::child_transition())?;
        #[cfg(not(target_os = "linux"))]
        self.journal.commit(&transaction)?;
        Ok(())
    }

}
