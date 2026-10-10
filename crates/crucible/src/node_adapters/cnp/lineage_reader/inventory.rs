//! Stages only runtime-sealed ordered source associations under selected input.

use super::{
    control::{ReaderState, content},
    readiness::{refused, unknown},
};
use crate::node_contract::{InputProvenanceClosure, OperationFailure, OriginalInputLineage};
use crate::node_scheduling::{InputPayload, NativeInputAcknowledgement, RuntimeInputBatch};
use crucible_node_contract::*;
use crucible_node_provider::reference_lineage::*;
use std::collections::BTreeMap;

pub(super) struct SelectedInputInventory {
    pub(super) inventory: InputLineageInventory,
    pub(super) objects: Vec<InputPayload>,
}

impl ReaderState {
    pub(super) fn stage_lineage_inputs(
        &mut self,
        original: &RuntimeInputBatch,
        provenance: &InputProvenanceClosure,
        lineage: &OriginalInputLineage,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        let source = lineage.original();
        if !std::rc::Rc::ptr_eq(
            &source.activation().authority,
            &original.activation().authority,
        ) || source.activation().record() != original.activation().record()
            || source.node() != original.node()
            || source.owners() != original.owners()
            || source.stage_operation() != original.stage_operation()
            || source.batch() != original.batch()
            || source.inventory() != original.inventory()
            || source.cutoff() != original.cutoff()
            || source.deliveries() != original.deliveries()
            || source.payloads() != original.payloads()
            || lineage.publications().len() != original.deliveries().len()
        {
            return Err(refused("original runtime input lineage scope changed"));
        }
        if self.input_lineages.len() >= self.maximum_operations
            && !self.input_lineages.contains_key(original.stage_operation())
        {
            return Err(refused("original input lineage custody credit exhausted"));
        }
        self.input_lineages
            .entry(original.stage_operation().clone())
            .or_insert_with(|| lineage.retained_copy());
        self.stage_inputs(original, Some(provenance))
    }

    pub(super) fn preflight_selected_input(
        &self,
        objects: &[InputPayload],
        inventory: &InputLineageInventory,
        envelopes: [(&ContentRef, &[u8]); 2],
    ) -> Result<(), OperationFailure> {
        let mut edges = self
            .boundary_dependencies
            .values()
            .try_fold(512usize, |total, row| total.checked_add(row.len()))
            .and_then(|total| total.checked_add(inventory.entries.len() * 5))
            .ok_or_else(|| refused("original input custody edge credit"))?;
        for row in &inventory.dependencies {
            if let Some(old) = self.boundary_dependencies.get(&row.object) {
                if old != &row.dependencies {
                    return Err(refused(
                        "original input conflicts with authenticated codec row",
                    ));
                }
            } else {
                edges = edges
                    .checked_add(row.dependencies.len())
                    .ok_or_else(|| refused("original input edge overflow"))?;
            }
        }
        let mut count = self
            .boundary_evidence
            .len()
            .checked_add(8)
            .ok_or_else(|| refused("original input custody role credit"))?;
        let mut bytes = self
            .boundary_evidence
            .values()
            .try_fold(512 * 1024usize, |total, object| {
                total.checked_add(object.bytes.len())
            })
            .ok_or_else(|| refused("original input custody byte credit"))?;
        for object in objects {
            if let Some(old) = self.boundary_evidence.get(&object.reference) {
                if old != object {
                    return Err(refused("original input body conflicts with retained role"));
                }
            } else {
                count = count
                    .checked_add(1)
                    .ok_or_else(|| refused("original input role overflow"))?;
                bytes = bytes
                    .checked_add(object.bytes.len())
                    .ok_or_else(|| refused("original input body overflow"))?;
            }
        }
        for (reference, body) in envelopes {
            reference
                .verify(body)
                .map_err(|error| unknown(error.into()))?;
            if !self.boundary_evidence.contains_key(reference) {
                count = count
                    .checked_add(1)
                    .ok_or_else(|| refused("original input envelope role overflow"))?;
                bytes = bytes
                    .checked_add(body.len())
                    .ok_or_else(|| refused("original input envelope byte overflow"))?;
            }
        }
        if count > 4096 || bytes > 16 * 1024 * 1024 || edges > 65_536 {
            return Err(refused(
                "complete original input custody cannot be reserved",
            ));
        }
        Ok(())
    }

    pub(super) fn selected_inventory(
        &self,
        original: &RuntimeInputBatch,
        public: &InputBatch,
    ) -> Result<SelectedInputInventory, OperationFailure> {
        let mut inventory = InputLineageInventory {
            schema_version: 1,
            execution_owner_id: public.execution_owner_id.clone(),
            owner_generation: self.bootstrap.authority.owner_generation,
            input_epoch: public.input_epoch.clone(),
            batch_id: public.batch_id.clone(),
            batch_sequence: public.batch_sequence,
            entries: Vec::new(),
            dependencies: Vec::new(),
        };
        if !public.events.is_empty() {
            let lineage = self
                .input_lineages
                .get(original.stage_operation())
                .ok_or_else(|| refused("original producer association omitted"))?;
            let mut declared = BTreeMap::new();
            for claim in lineage.publications() {
                for (object, row) in claim.objects.iter().zip(&claim.rows) {
                    if declared
                        .insert(&object.reference, (object, row))
                        .is_some_and(|(old, old_row)| old != object || old_row != row)
                    {
                        return Err(refused("original input role conflict before allocation"));
                    }
                }
            }
            let mut bytes = 0usize;
            let mut edges = 0usize;
            for (object, row) in declared.values() {
                bytes = bytes
                    .checked_add(object.bytes.len())
                    .ok_or_else(|| refused("original input byte credit"))?;
                edges = edges
                    .checked_add(row.dependencies.len())
                    .ok_or_else(|| refused("original input edge credit"))?;
            }
            // Each delivered Event is bounded by the independently closed native
            // input codec. Reserve its whole worst-case body before projection.
            let delivered_bytes = public
                .events
                .len()
                .checked_mul(65_536)
                .ok_or_else(|| refused("delivered role credit"))?;
            if declared
                .len()
                .checked_add(public.events.len())
                .is_none_or(|count| count > 4096)
                || bytes
                    .checked_add(delivered_bytes)
                    .is_none_or(|count| count > 64 * 1024 * 1024)
                || edges
                    .checked_add(public.events.len() * 2)
                    .is_none_or(|count| count > 65_536)
            {
                return Err(refused("complete selected original input credit"));
            }
        }
        let mut bodies = BTreeMap::new();
        let mut rows = BTreeMap::new();
        if !public.events.is_empty() {
            let lineage = self
                .input_lineages
                .get(original.stage_operation())
                .ok_or_else(|| refused("original producer association omitted"))?;
            for (delivered, claim) in public.events.iter().zip(lineage.publications()) {
                for (object, row) in claim.objects.iter().zip(&claim.rows) {
                    if bodies
                        .insert(object.reference.clone(), object.clone())
                        .is_some_and(|old| old != *object)
                        || rows
                            .insert(row.object.clone(), row.dependencies.clone())
                            .is_some_and(|old| old != row.dependencies)
                    {
                        return Err(refused("original producer typed row conflict"));
                    }
                }
                let (reference, bytes) = content(delivered).map_err(unknown)?;
                let mut dependencies =
                    vec![delivered.payload.clone(), delivered.provenance_ref.clone()];
                dependencies.sort();
                dependencies.dedup();
                let object = InputPayload {
                    reference: reference.clone(),
                    bytes,
                };
                if bodies
                    .insert(reference.clone(), object.clone())
                    .is_some_and(|old| old != object)
                    || rows
                        .insert(reference.clone(), dependencies.clone())
                        .is_some_and(|old| old != dependencies)
                {
                    return Err(refused("original delivered typed row conflict"));
                }
                let origin = &claim.origin;
                inventory.entries.push(InputLineageEntry {
                    delivered: reference,
                    published: claim.published.clone(),
                    producer: InputLineageProducer {
                        owner_binding_hash: origin.owner_binding_hash.clone(),
                        execution_owner_id: origin.execution_owner_id.clone(),
                        session_id: origin.session_id.clone(),
                        world_binding_hash: origin.world_binding_hash.clone(),
                        activation_id: origin.activation_id.clone(),
                        world_generation: origin.world_generation,
                        incarnation_id: origin.incarnation_id.clone(),
                        owner_generation: origin.owner_generation,
                        operation_id: origin.operation_id.clone(),
                        grant_id: origin.grant_id.clone(),
                        observation_batch: origin.observation_batch.clone(),
                        stop_receipt: origin.stop_receipt.clone(),
                        measurement: origin.measurement.clone(),
                    },
                });
            }
        }
        inventory.dependencies = rows
            .into_iter()
            .map(|(object, dependencies)| InputLineageRow {
                object,
                dependencies,
            })
            .collect();
        inventory
            .validate_bodies(
                public,
                self.bootstrap.authority.owner_generation,
                |reference| {
                    bodies
                        .get(reference)
                        .map(|object| object.bytes.as_slice())
                        .ok_or(crucible_node_provider::ProviderError::Correlation(
                            "original selected input body omitted",
                        ))
                },
            )
            .map_err(unknown)?;
        // The source-native framing limit remains independent of proof/body
        // metadata credits. This geometry check grants no additional input bytes.
        Ok(SelectedInputInventory {
            inventory,
            objects: bodies.into_values().collect(),
        })
    }
}
