//! Derives the exact route's proof sidecar from already authenticated original rows.

use super::*;
use std::collections::{BTreeMap, BTreeSet};

impl NodeRuntime {
    pub(in crate::node_contract::runtime) fn provenance_from_original_lineage(
        &self,
        batch: &RuntimeInputBatch,
        lineage: &OriginalInputLineage,
    ) -> Result<InputProvenanceClosure, RuntimePollFailure> {
        let invalid = || RuntimePollFailure::Admission(RuntimeError::InvalidReceipt);
        let exhausted = || RuntimePollFailure::Admission(RuntimeError::ResourceLimit);
        let original = lineage.original();
        if !original.activation().same_authority(batch.activation())
            || original.node() != batch.node()
            || original.stage_operation() != batch.stage_operation()
            || original.batch() != batch.batch()
            || original.owners() != batch.owners()
            || original.cutoff() != batch.cutoff()
            || original.inventory() != batch.inventory()
            || original.deliveries() != batch.deliveries()
            || original.payloads() != batch.payloads()
            || lineage.publications().len() != batch.deliveries().len()
        {
            return Err(invalid());
        }

        let mut available = InputProvenanceLimits::default();
        for retained in self.input_batches.values() {
            if let Some(provenance) = &retained.provenance {
                available.maximum_objects = available
                    .maximum_objects
                    .checked_sub(provenance.objects().len())
                    .ok_or_else(exhausted)?;
                for object in provenance.objects() {
                    available.maximum_bytes = available
                        .maximum_bytes
                        .checked_sub(object.bytes.len())
                        .ok_or_else(exhausted)?;
                }
            }
        }

        // Borrow the authenticated inventory first. Complete aggregate credit
        // precedes every byte copy, including duplicate roots shared by peers.
        let mut objects = BTreeMap::<&ContentRef, &InputPayload>::new();
        let mut roots = BTreeSet::new();
        for (claim, delivery) in lineage.publications().iter().zip(batch.deliveries()) {
            if claim.origin.measurement != delivery.provenance_ref
                || !claim
                    .objects
                    .iter()
                    .any(|object| object.reference == delivery.provenance_ref)
            {
                return Err(invalid());
            }
            roots.insert(delivery.provenance_ref.clone());
            for object in &claim.objects {
                if let Some(prior) = objects.get(&object.reference) {
                    if prior.bytes != object.bytes {
                        return Err(invalid());
                    }
                    continue;
                }
                if objects.keys().any(|reference| {
                    reference.hash == object.reference.hash
                        && reference.length != object.reference.length
                }) {
                    return Err(invalid());
                }
                available.maximum_objects = available
                    .maximum_objects
                    .checked_sub(1)
                    .ok_or_else(exhausted)?;
                available.maximum_bytes = available
                    .maximum_bytes
                    .checked_sub(object.bytes.len())
                    .ok_or_else(exhausted)?;
                objects.insert(&object.reference, object);
            }
        }

        let mut owned = Vec::new();
        owned
            .try_reserve_exact(objects.len())
            .map_err(|_| exhausted())?;
        for object in objects.into_values() {
            owned.push(object.clone());
        }
        Ok(InputProvenanceClosure::from_validated(
            batch,
            roots.into_iter().collect(),
            owned,
        ))
    }
}
