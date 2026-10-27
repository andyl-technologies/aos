//! Extracts reference-only original ledgers without changing native capture support.

use super::*;

impl NodeRuntime {
    /// Reads the actual activated scheduler beside retained original lineage.
    ///
    /// This reference-only view grants no capture, restoration or scheduling
    /// permission. It never constructs a scheduler or settles pending work.
    /// Selected archive and native callbacks remain independent requirements.
    ///
    /// # Errors
    /// Refuses foreign activation, absent lineage or scheduler, terminal/external
    /// combinations, invalid cuts and unsupported scheduler editions.
    pub fn original_lineage_scheduler_snapshot(
        &self,
        activation: &WorldActivation,
        capture_cut: Position,
        capture_ordinal: U64,
    ) -> Result<crate::node_scheduling::SchedulingSnapshot, RuntimeError> {
        self.validate_activation(activation)?;
        if self.terminal.is_some()
            || self.condition_stop.is_some()
            || !self
                .input_batches
                .values()
                .any(|input| input.lineage.is_some())
            || self.input_batches.values().any(|input| {
                input
                    .batch
                    .deliveries()
                    .iter()
                    .any(|delivery| delivery.external_root.is_some())
            })
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let snapshot = self
            .scheduler
            .as_ref()
            .ok_or(RuntimeError::NotActivated)?
            .snapshot(capture_cut, capture_ordinal)
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?;
        if snapshot.schema_version != 1
            || snapshot.original_epochs.is_some()
            || !snapshot.external_closed_prefixes.is_empty()
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        Ok(snapshot)
    }

    /// Reads complete Runtime7 historical ledgers after finite copy preflight.
    ///
    /// This read does not suspend native owners or qualify world capture. Legacy
    /// capture remains unsupported for lineage-bearing worlds. A selected archive
    /// must separately retain exact bodies and authenticate unchanged native state.
    ///
    /// # Errors
    /// Refuses unpublished worlds, absent lineage, unsupported terminal/external
    /// combinations, malformed original rows or finite record/body/role limits.
    pub fn original_lineage_runtime_snapshot(
        &self,
        capture_cut: Position,
        capture_ordinal: U64,
        limits: OriginalInputLineageLimits,
        maximum_record_bytes: usize,
    ) -> Result<OriginalLineageRuntimeRecord, RuntimeError> {
        if !self.activated {
            return Err(RuntimeError::NotActivated);
        }
        if self.terminal.is_some()
            || self.condition_stop.is_some()
            || !self
                .input_batches
                .values()
                .any(|input| input.lineage.is_some())
            || self.input_batches.values().any(|input| {
                input
                    .batch
                    .deliveries()
                    .iter()
                    .any(|delivery| delivery.external_root.is_some())
            })
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        preflight_objects(self, limits)?;
        record_validation::bounded_metadata(
            &snapshot_credit::SnapshotView {
                runtime: self,
                cut: capture_cut,
                ordinal: capture_ordinal,
            },
            maximum_record_bytes,
        )?;
        #[cfg(test)]
        snapshot_credit::note_metadata_copy_attempt();

        let mut owners = reserve(self.owners.len())?;
        for owner in self.owners.values() {
            owners.push(SavedRuntimeOwner {
                identity: owner.identity.clone(),
                lifecycle: owner.lifecycle,
                operation: owner.operation.clone(),
                domains: owner.domains.iter().cloned().collect(),
            });
        }
        let mut operations = reserve(self.operations.len())?;
        for operation in self.operations.values() {
            operations.push(saved_operation(operation));
        }
        let mut inputs = reserve(self.input_batches.len())?;
        for input in self.input_batches.values() {
            inputs.push(saved_input(input, limits)?);
        }
        let record = OriginalLineageRuntimeRecord {
            schema_version: 7,
            source_activation: self.barrier.record().into(),
            capture_cut,
            capture_ordinal,
            owners,
            operations,
            inputs,
        };
        record.validate_metadata(limits, maximum_record_bytes)?;
        Ok(record)
    }

    /// Borrows original typed input bodies for an independently verified capture.
    ///
    /// The iterator preserves full-role occurrences. It allocates no body copy,
    /// issues no capture or execution permission and never infers dependency rows.
    pub fn original_lineage_capture_objects(&self) -> impl Iterator<Item = &InputPayload> {
        self.input_batches.values().flat_map(|input| {
            input
                .batch
                .payloads()
                .iter()
                .chain(input.provenance.iter().flat_map(|proof| proof.objects()))
                .chain(input.lineage.iter().flat_map(|lineage| {
                    lineage
                        .publications()
                        .iter()
                        .flat_map(|claim| &claim.objects)
                }))
        })
    }
}

fn preflight_objects(
    runtime: &NodeRuntime,
    mut available: OriginalInputLineageLimits,
) -> Result<(), RuntimeError> {
    for object in runtime.original_lineage_capture_objects() {
        available.maximum_objects = available
            .maximum_objects
            .checked_sub(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        available.maximum_bytes = available
            .maximum_bytes
            .checked_sub(object.bytes.len())
            .ok_or(RuntimeError::ResourceLimit)?;
        object
            .reference
            .verify(&object.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    }
    for input in runtime.input_batches.values() {
        if let Some(lineage) = &input.lineage {
            for claim in lineage.publications() {
                let derived = geometry::validate_claim_geometry(
                    claim,
                    OriginalInputLineageLimits {
                        maximum_edges: available.maximum_edges,
                        ..OriginalInputLineageLimits::default()
                    },
                )?;
                let direct = claim.rows.iter().try_fold(0usize, |sum, row| {
                    sum.checked_add(row.dependencies.len())
                        .ok_or(RuntimeError::ResourceLimit)
                })?;
                available.maximum_edges = available
                    .maximum_edges
                    .checked_sub(direct.max(derived))
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
    }
    Ok(())
}

fn saved_input(
    input: &super::super::inputs::RetainedInput,
    limits: OriginalInputLineageLimits,
) -> Result<OriginalLineageInputRecord, RuntimeError> {
    let provenance = input.provenance.as_ref().map(|proof| {
        let saved = proof.saved();
        OriginalLineageProvenanceRecord {
            schema_version: saved.schema_version,
            node: saved.node.clone(),
            stage_operation: saved.stage_operation.clone(),
            batch: saved.batch.clone(),
            inventory: saved.inventory.clone(),
            roots: saved.roots.clone(),
            objects: saved
                .objects
                .iter()
                .map(|object| object.reference.clone())
                .collect(),
        }
    });
    Ok(OriginalLineageInputRecord {
        node: input.batch.node().clone(),
        stage_operation: input.batch.stage_operation().clone(),
        batch: input.batch.batch().clone(),
        owners: input.batch.owners().to_vec(),
        cutoff: input.batch.cutoff(),
        inventory: input.batch.inventory().clone(),
        deliveries: input.batch.deliveries().to_vec(),
        payloads: input
            .batch
            .payloads()
            .iter()
            .map(|object| object.reference.clone())
            .collect(),
        provenance,
        lineage: input
            .lineage
            .as_ref()
            .map(|lineage| lineage.saved_reference_view(limits))
            .transpose()?,
        acknowledgement: input.acknowledgement.clone(),
        failure: input.failure.clone(),
        committed: input.committed,
        coordinator_committed: input.commit.is_some(),
    })
}

fn saved_operation(operation: &super::super::RetainedOperation) -> SavedRuntimeOperation {
    SavedRuntimeOperation {
        operation: operation.admission.token.operation.clone(),
        route: operation.admission.token.route.clone(),
        request: operation.admission.request.clone(),
        input_batch: operation
            .admission
            .inputs
            .as_ref()
            .map(|input| input.batch().clone()),
        result: match &operation.result {
            RetainedResult::Pending => SavedRuntimeResult::Pending,
            RetainedResult::Complete(outcome) => SavedRuntimeResult::Complete(outcome.clone()),
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
    }
}

fn reserve<T>(count: usize) -> Result<Vec<T>, RuntimeError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    Ok(values)
}
