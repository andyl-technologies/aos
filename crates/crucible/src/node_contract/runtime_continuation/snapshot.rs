//! Bounded extraction of complete runtime state without serializing local authority.

use super::*;

impl NodeRuntime {
    /// Captures the complete represented runtime ledger at a separately authenticated cut.
    ///
    /// This method does not establish native suspension or complete world capture.
    /// The installed capture adapter must authenticate unchanged native state and
    /// bind the resulting bytes to the selected coordinator capture schema.
    ///
    /// # Errors
    /// Rejects unpublished runtimes or encoded state above the configured ceiling.
    pub fn runtime_snapshot(
        &self,
        capture_cut: Position,
        capture_ordinal: U64,
        maximum_record_bytes: usize,
    ) -> Result<RuntimeSnapshot, RuntimeError> {
        if !self.activated {
            return Err(RuntimeError::NotActivated);
        }
        // Source ledgers are already bounded by runtime admission. Count native
        // payload representations before cloning their potentially large buffers.
        let per_entry = maximum_record_bytes
            .checked_div(
                self.operations
                    .len()
                    .saturating_add(self.input_batches.len())
                    .max(1),
            )
            .ok_or(RuntimeError::ResourceLimit)?;
        for operation in self.operations.values() {
            if let RetainedResult::Complete(outcome) | RetainedResult::Acknowledged(outcome) =
                &operation.result
            {
                restore::bounded_record(outcome, per_entry)?;
            }
        }
        for input in self.input_batches.values() {
            restore::bounded_record(&input.batch.payloads(), per_entry)?;
            if let Some(provenance) = &input.provenance {
                restore::bounded_record(provenance.saved(), per_entry)?;
            }
        }
        let snapshot = extract_snapshot(self, capture_cut, capture_ordinal);
        restore::bounded_record(&snapshot, maximum_record_bytes)?;
        Ok(snapshot)
    }
}

fn extract_snapshot(
    runtime: &NodeRuntime,
    capture_cut: Position,
    capture_ordinal: U64,
) -> RuntimeSnapshot {
    RuntimeSnapshot {
        schema_version: if runtime
            .input_batches
            .values()
            .any(|input| input.provenance.is_some())
        {
            2
        } else {
            1
        },
        source_activation: runtime.barrier.record().into(),
        capture_cut,
        capture_ordinal,
        owners: runtime
            .owners
            .values()
            .map(|owner| SavedRuntimeOwner {
                identity: owner.identity.clone(),
                lifecycle: owner.lifecycle,
                operation: owner.operation.clone(),
                domains: owner.domains.iter().cloned().collect(),
            })
            .collect(),
        operations: runtime
            .operations
            .values()
            .map(|operation| SavedRuntimeOperation {
                operation: operation.admission.token.operation.clone(),
                route: operation.admission.token.route.clone(),
                request: operation.admission.request.clone(),
                input_batch: operation
                    .admission
                    .inputs
                    .as_ref()
                    .map(|inputs| inputs.batch().clone()),
                result: match &operation.result {
                    RetainedResult::Pending => SavedRuntimeResult::Pending,
                    RetainedResult::Complete(outcome) => {
                        SavedRuntimeResult::Complete(outcome.clone())
                    }
                    RetainedResult::Failed(failure) => SavedRuntimeResult::Failed(failure.clone()),
                    RetainedResult::Acknowledged(outcome) => {
                        SavedRuntimeResult::Acknowledged(outcome.clone())
                    }
                },
                close_submission: operation.close_submission.clone(),
                submission_effects: operation.submission_effects.clone(),
                scheduling_commit: operation.scheduling_commit.as_ref().map(|commit| {
                    SavedSchedulingCommit {
                        node: commit.node().clone(),
                        operation: commit.operation().clone(),
                        retained_outputs: commit.retained_outputs().to_vec(),
                    }
                }),
            })
            .collect(),
        inputs: runtime
            .input_batches
            .values()
            .map(|input| SavedRuntimeInput {
                node: input.batch.node().clone(),
                stage_operation: input.batch.stage_operation().clone(),
                batch: input.batch.batch().clone(),
                owners: input.batch.owners().to_vec(),
                cutoff: input.batch.cutoff(),
                inventory: input.batch.inventory().clone(),
                deliveries: input.batch.deliveries().to_vec(),
                payloads: input.batch.payloads().to_vec(),
                provenance: input.provenance.as_ref().map(|value| value.saved().clone()),
                acknowledgement: input.acknowledgement.clone(),
                failure: input.failure.clone(),
                committed: input.committed,
                coordinator_committed: input.commit.is_some(),
            })
            .collect(),
    }
}

impl RuntimeSnapshot {
    /// Lists original native operation and staging custody awaiting acknowledgement.
    pub fn pending_acknowledgements(&self) -> Vec<Id> {
        let mut pending: Vec<_> = self
            .operations
            .iter()
            .filter(|operation| matches!(operation.result, SavedRuntimeResult::Complete(_)))
            .map(|operation| operation.operation.clone())
            .chain(
                self.inputs
                    .iter()
                    .filter(|input| !input.committed && input.failure.is_none())
                    .map(|input| input.stage_operation.clone()),
            )
            .collect();
        pending.sort();
        pending
    }
}
