//! Retains authentic producer associations before native source-four staging.
//!
//! The opaque runtime lineage was issued through each original producer's native
//! validator. This consumer joins that same ordered lineage to its actual route,
//! world, complete cut and payloads before native staging. Retention shares the
//! same immutable runtime allocation; it cannot reconstruct or replace a child.

use super::*;

pub(super) fn same_batch(first: &RuntimeInputBatch, second: &RuntimeInputBatch) -> bool {
    first.activation().same_authority(second.activation())
        && first.node() == second.node()
        && first.stage_operation() == second.stage_operation()
        && first.batch() == second.batch()
        && first.owners() == second.owners()
        && first.cutoff() == second.cutoff()
        && first.inventory() == second.inventory()
        && first.deliveries() == second.deliveries()
        && first.payloads() == second.payloads()
}

impl PacketConnectedSemanticSource {
    pub(super) fn authenticate_lineage(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        batch: &RuntimeInputBatch,
        provenance: &InputProvenanceClosure,
        lineage: &OriginalInputLineage,
    ) -> Result<(), OperationFailure> {
        self.guard(&scope)?;
        let answer = (|| {
            self.batch_owner(batch)?;
            if !same_batch(batch, lineage.original())
                || !batch.activation().same_authority(provenance.activation())
                || provenance.node() != batch.node()
                || provenance.stage_operation() != batch.stage_operation()
                || provenance.batch() != batch.batch()
                || provenance.inventory() != batch.inventory()
                || lineage.publications().len() != batch.deliveries().len()
            {
                return Err(refused("connected opaque producer lineage scope changed"));
            }
            let coordinator = self.world.coordinator();
            let mut roots = Vec::new();
            for (delivery, claim) in batch.deliveries().iter().zip(lineage.publications()) {
                self.validate_delivery(delivery, batch.cutoff())?;
                let selected = coordinator
                    .participants
                    .iter()
                    .find(|selected| {
                        selected
                            .realization
                            .descriptors
                            .first()
                            .is_some_and(|descriptor| descriptor.id == delivery.producer)
                    })
                    .ok_or_else(|| refused("connected lineage original producer absent"))?;
                let binding = selected
                    .realization
                    .bindings
                    .first()
                    .ok_or_else(|| refused("connected lineage producer binding absent"))?;
                let owner = selected
                    .realization
                    .owner_bindings
                    .first()
                    .ok_or_else(|| refused("connected lineage producer owner absent"))?;
                let origin = &claim.origin;
                let event = &claim.event;
                if origin.owner_binding_hash != owner.identity().map_err(unknown)?
                    || origin.execution_owner_id != owner.owner.id
                    || origin.session_id != binding.authority.session_id
                    || origin.incarnation_id != binding.authority.incarnation_id
                    || origin.owner_generation != binding.authority.owner_generation
                    || origin.world_binding_hash != batch.activation().record().world_binding_hash
                    || origin.activation_id != batch.activation().record().activation_id
                    || origin.world_generation != batch.activation().record().generation
                    || origin.grant_id != origin.operation_id
                    || origin.measurement != delivery.provenance_ref
                    || origin.observation_batch != origin.measurement
                    || origin.stop_receipt != origin.measurement
                    || event.id != delivery.publication_id
                    || event.source != delivery.producer_endpoint
                    || event.source_sequence != delivery.native_sequence
                    || event.payload != delivery.payload
                    || event.position != delivery.publication
                    || event.publication_position != delivery.publication
                    || event.delivery_position.is_some()
                    || event.stage != EventStage::Publication
                    || event.provenance_ref != delivery.provenance_ref
                    || event.causal_parent_ids
                        != crucible_node_transport::reference_packet::connected::causal_parent_ids(
                            &delivery.causal_parents,
                        )
                        .map_err(unknown)?
                    || !event.extensions.is_empty()
                {
                    return Err(refused(
                        "connected complete original producer association changed",
                    ));
                }
                for object in &claim.objects {
                    object.reference.verify(&object.bytes).map_err(unknown)?;
                }
                if !provenance.objects().iter().any(|object| {
                    object.reference == origin.measurement
                        && claim.objects.iter().any(|original| original == object)
                }) {
                    return Err(refused("connected original producer proof omitted"));
                }
                roots.push(origin.measurement.clone());
            }
            roots.sort();
            roots.dedup();
            if roots != provenance.roots() {
                return Err(refused("connected complete producer root roster changed"));
            }

            let mut retained = self
                .input_lineage
                .try_borrow_mut()
                .map_err(|_| refused("connected original lineage borrow busy"))?;
            if let Some(original) = retained
                .iter()
                .find(|old| old.original().stage_operation() == batch.stage_operation())
            {
                if !same_batch(original.original(), batch)
                    || original.publications() != lineage.publications()
                {
                    return Err(refused(
                        "connected original staging lineage cannot be replaced",
                    ));
                }
            } else {
                if retained.len() >= self.installation.maximum_operations
                    || retained.len() == retained.capacity()
                {
                    return Err(refused(
                        "connected preallocated original lineage slots exhausted",
                    ));
                }
                retained.push(lineage.retained_copy());
            }
            Ok(())
        })();
        self.guard(&scope)?;
        answer
    }
}
