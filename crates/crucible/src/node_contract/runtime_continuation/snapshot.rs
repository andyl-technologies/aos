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
        if self.terminal.is_some() || self.has_fault_scope() || self.condition_stop.is_some() {
            // Legacy extraction cannot omit original terminal or fault custody.
            return Err(RuntimeError::UnsupportedFacet);
        }
        self.checked_runtime_snapshot(capture_cut, capture_ordinal, maximum_record_bytes)
    }

    /// Captures explicit edition-three original terminal custody as facts only.
    ///
    /// Selected installed capture codecs must independently authenticate complete
    /// native and coordinator state. This read never finalizes assertions or
    /// recreates a usable barrier from serialized source facts.
    ///
    /// # Errors
    /// Refuses absent terminal custody, unpublished worlds or finite byte limits.
    pub fn terminal_runtime_snapshot(
        &self,
        capture_cut: Position,
        capture_ordinal: U64,
        maximum_record_bytes: usize,
    ) -> Result<RuntimeSnapshot, RuntimeError> {
        if self.terminal.is_none() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        self.checked_runtime_snapshot(capture_cut, capture_ordinal, maximum_record_bytes)
    }

    /// Captures explicit edition-four original admitted fault operation custody.
    ///
    /// This data read never applies a transition or reissues its authority.
    /// Installed fault-bearing archive codecs must independently authenticate
    /// the whole original native controller, journal and coordinator closure.
    ///
    /// # Errors
    /// Refuses absent selected native fault scope, terminal mixing and finite byte limits.
    pub fn fault_runtime_snapshot(
        &self,
        capture_cut: Position,
        capture_ordinal: U64,
        maximum_record_bytes: usize,
    ) -> Result<RuntimeSnapshot, RuntimeError> {
        if self.terminal.is_some() || !self.has_fault_scope() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        self.checked_runtime_snapshot(capture_cut, capture_ordinal, maximum_record_bytes)
    }

    /// Captures explicit edition-six original condition stop/report/resume custody.
    ///
    /// This read preserves the independent live effect fence and original
    /// control history as data. It never evaluates a condition, issues native
    /// control, verifies a fresh store or substitutes a horizon for EOF.
    /// Selected archive codecs must authenticate the complete original native
    /// bodies and coordinator state before any fresh permission is restored.
    ///
    /// # Errors
    /// Refuses absent condition custody, mixed terminal/fault state, incomplete
    /// original control, unpublished worlds or exhausted finite byte limits.
    pub fn condition_runtime_snapshot(
        &self,
        capture_cut: Position,
        capture_ordinal: U64,
        maximum_record_bytes: usize,
    ) -> Result<RuntimeSnapshot, RuntimeError> {
        if self.condition_stop.is_none() || self.terminal.is_some() || self.has_fault_scope() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let snapshot =
            self.checked_runtime_snapshot(capture_cut, capture_ordinal, maximum_record_bytes)?;
        condition::validate(&snapshot)?;
        Ok(snapshot)
    }

    fn checked_runtime_snapshot(
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
        let per_entry = if self.condition_stop.is_some() {
            condition_wire::preflight(self, maximum_record_bytes)?;
            maximum_record_bytes
        } else {
            maximum_record_bytes
                .checked_div(
                    self.operations
                        .len()
                        .saturating_add(self.input_batches.len())
                        .max(1),
                )
                .ok_or(RuntimeError::ResourceLimit)?
        };
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
        if let Some(terminal) = &self.terminal {
            restore::bounded_record(&terminal.saved, maximum_record_bytes)?;
        }
        if let Some(condition) = &self.condition_stop {
            restore::bounded_record(&condition.saved, maximum_record_bytes)?;
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
        schema_version: if runtime.condition_stop.is_some() {
            6
        } else if runtime.has_fault_scope() {
            4
        } else if runtime.terminal.is_some() {
            3
        } else if runtime
            .input_batches
            .values()
            .any(|input| input.provenance.is_some())
        {
            2
        } else {
            1
        },
        source_activation: runtime.barrier.record().into(),
        terminal: runtime
            .terminal
            .as_ref()
            .map(|terminal| terminal.saved.clone()),
        condition_stop: runtime
            .condition_stop
            .as_ref()
            .map(|state| state.saved.clone()),
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
