//! Projects the actual reactive inventory with its pending modeled work intact.

use super::*;

impl ReactiveModel17Data {
    pub(in crate::reference_packet) fn capture_boundary17_construction_counter_scratch_data()
    -> usize {
        std::mem::size_of::<ConnectedInventoryData<'static>>()
            + std::mem::size_of::<std::slice::Iter<'static, OriginalStage>>()
            + std::mem::size_of::<Option<&'static OriginalCommit>>()
            + std::mem::size_of::<
                crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
            >()
            + std::mem::size_of::<[usize; 4]>()
    }

    pub(in crate::reference_packet) fn capture_boundary17_construction_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        self.observe_settled_history_metadata_data(&mut observer)?;
        let facts = observer.finish();
        let inventory =
            crate::retained_metadata::serialization_storage::actual_serialization_storage_data(
                &ConnectedInventoryData(&self.0),
                facts,
                maximum,
            )?;
        let mut peak = serialization_work(&inventory)?;
        // Local authentication validates actual connection IDs, then hashes
        // every retained Stage/Commit record and its original reply evidence.
        peak = peak
            .checked_add(
                crate::retained_metadata::requested_storage::tree_storage_data(
                    1,
                    self.0.definition.connections.len(),
                    std::mem::size_of::<&crucible_node_format::Id>(),
                    std::mem::align_of::<&crucible_node_format::Id>(),
                )?,
            )
            .ok_or_else(invalid)?;
        let hash_strings = "blake3-256".len() + "cnp.blob.v1".len() + 64;
        for stage in &self.0.stages {
            let record =
                crate::retained_metadata::serialization_storage::actual_serialization_storage_data(
                    &stage.record,
                    facts,
                    maximum,
                )?;
            peak = peak
                .checked_add(serialization_work(&record)?)
                .and_then(|bytes| bytes.checked_add(hash_strings + "application/json".len()))
                .and_then(|bytes| {
                    stage
                        .reply
                        .evidence
                        .len()
                        .checked_mul(hash_strings)
                        .and_then(|hashes| bytes.checked_add(hashes))
                })
                .ok_or_else(invalid)?;
            if let Some(commit) = &stage.commit {
                let record = crate::retained_metadata::serialization_storage::actual_serialization_storage_data(&commit.record, facts, maximum)?;
                peak = peak
                    .checked_add(serialization_work(&record)?)
                    .and_then(|bytes| bytes.checked_add(hash_strings + "application/json".len()))
                    .and_then(|bytes| {
                        commit
                            .reply
                            .evidence
                            .len()
                            .checked_mul(hash_strings)
                            .and_then(|hashes| bytes.checked_add(hashes))
                    })
                    .ok_or_else(invalid)?;
            }
        }
        if peak > maximum {
            return Err(invalid());
        }
        Ok(peak)
    }

    pub(in crate::reference_packet) fn capture_boundary17_data(
        &self,
        maximum_model_bytes: usize,
    ) -> Result<
        crate::reference_packet::continuation_models::PacketModelCaptureBoundaryData,
        ProviderError,
    > {
        self.authenticate_settled_adoption_eligibility_data()?;
        let state = &self.0;
        let mut earliest = state.publications.iter().map(|row| row.publication).min();
        for reaction in &state.reactions {
            let completion = if state.definition.output.is_some() {
                reaction.evaluation.reaction_publication(U64::new(16))?
            } else {
                reaction.evaluation
            };
            earliest = Some(earliest.map_or(completion, |prior| prior.min(completion)));
        }
        let inventory = ConnectedInventoryData(state);
        crate::connection::serialized_credit(&inventory, maximum_model_bytes)?;
        Ok(
            crate::reference_packet::continuation_models::PacketModelCaptureBoundaryData {
                local_cursor: state.reached,
                gate_closed: state.gate_closed,
                retained_outputs: state.outputs.len(),
                earliest_pending_completion: earliest,
                inventory_hash: canonical::json_hash(
                    "source-owned.packet-connected-inventory/4",
                    &inventory,
                )?,
            },
        )
    }
}

fn serialization_work(
    row: &crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
) -> Result<usize, ProviderError> {
    row.dom_and_canonical_scratch_bytes
        .checked_add(row.canonical_output_requested_bytes)
        .and_then(|bytes| bytes.checked_add(row.serializer_temporary_requested_bytes))
        .ok_or_else(invalid)
}
