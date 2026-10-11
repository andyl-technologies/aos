//! Credits historical Runtime7 metadata before any original-body reader is used.

use super::*;
use crucible_node_contract::Validate;
use std::io::{self, Write};

impl OriginalLineageRuntimeRecord {
    /// Checks closed edition, input association geometry and aggregate references.
    ///
    /// This check performs no body read and grants no native permission. A selected
    /// codec must separately authenticate every original body, actual source
    /// scope and fresh producer/consumer mapping before world readiness.
    ///
    /// # Errors
    /// Refuses other editions, missing lineage, malformed scope/rows, combined
    /// unsupported external input or exceeded encoded/role/byte/edge credits.
    pub fn validate_metadata(
        &self,
        limits: OriginalInputLineageLimits,
        maximum_record_bytes: usize,
    ) -> Result<(), RuntimeError> {
        if self.schema_version != 7 || !self.inputs.iter().any(|input| input.lineage.is_some()) {
            return Err(RuntimeError::UnsupportedFacet);
        }
        bounded_metadata(self, maximum_record_bytes)?;
        let mut available = limits;
        for input in &self.inputs {
            if input
                .deliveries
                .iter()
                .any(|delivery| delivery.external_root.is_some())
            {
                return Err(RuntimeError::UnsupportedFacet);
            }
            charge_references(&input.payloads, &mut available)?;
            if let Some(provenance) = &input.provenance {
                if provenance.schema_version != 1
                    || provenance.node != input.node
                    || provenance.stage_operation != input.stage_operation
                    || provenance.batch != input.batch
                    || provenance.inventory != input.inventory
                    || provenance.roots.windows(2).any(|pair| pair[0] >= pair[1])
                    || provenance
                        .roots
                        .iter()
                        .any(|root| provenance.objects.binary_search(root).is_err())
                {
                    return Err(RuntimeError::InvalidReceipt);
                }
                charge_references(&provenance.objects, &mut available)?;
            }
            if let Some(lineage) = &input.lineage {
                validate_lineage(input, lineage, &mut available)?;
            }
        }
        Ok(())
    }
}

fn validate_lineage(
    input: &OriginalLineageInputRecord,
    lineage: &SavedOriginalInputLineage,
    available: &mut OriginalInputLineageLimits,
) -> Result<(), RuntimeError> {
    let source = &lineage.source;
    if lineage.schema_version != 1
        || input.provenance.is_none()
        || source.node != input.node
        || source.stage_operation != input.stage_operation
        || source.batch != input.batch
        || source.cutoff != input.cutoff
        || source.inventory != input.inventory
        || source.owners.is_empty()
        || source
            .owners
            .iter()
            .any(|owner| !source.source_activation.owners.contains(owner))
        || lineage.publications.len() != input.deliveries.len()
        || lineage.publications.len() > 64
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    for publication in &lineage.publications {
        let origin = &publication.origin;
        if origin.world_binding_hash != source.source_activation.world_binding_hash
            || origin.activation_id != source.source_activation.activation_id
            || origin.world_generation != source.source_activation.generation
            || !source.source_activation.owners.iter().any(|owner| {
                owner.owner == origin.execution_owner_id
                    && owner.incarnation == origin.incarnation_id
                    && owner.generation == origin.owner_generation
            })
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        if publication.rows.len() != publication.objects.len()
            || publication
                .rows
                .iter()
                .zip(&publication.objects)
                .any(|(row, reference)| row.object != *reference)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let derived = geometry::validate_reference_rows(
            &publication.rows,
            [
                &publication.published,
                &publication.origin.observation_batch,
                &publication.origin.stop_receipt,
                &publication.origin.measurement,
            ],
            *available,
        )?;
        let direct = publication.rows.iter().try_fold(0usize, |total, row| {
            total
                .checked_add(row.dependencies.len())
                .ok_or(RuntimeError::ResourceLimit)
        })?;
        available.maximum_edges = available
            .maximum_edges
            .checked_sub(direct.max(derived))
            .ok_or(RuntimeError::ResourceLimit)?;
        charge_references(&publication.objects, available)?;
    }
    Ok(())
}

fn charge_references(
    references: &[ContentRef],
    available: &mut OriginalInputLineageLimits,
) -> Result<(), RuntimeError> {
    if references.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(RuntimeError::InvalidReceipt);
    }
    available.maximum_objects = available
        .maximum_objects
        .checked_sub(references.len())
        .ok_or(RuntimeError::ResourceLimit)?;
    for reference in references {
        reference
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let length =
            usize::try_from(reference.length.get()).map_err(|_| RuntimeError::ResourceLimit)?;
        available.maximum_bytes = available
            .maximum_bytes
            .checked_sub(length)
            .ok_or(RuntimeError::ResourceLimit)?;
    }
    Ok(())
}

struct MetadataCredit {
    remaining: usize,
}

impl Write for MetadataCredit {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("original Runtime7 metadata credit exhausted"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn bounded_metadata(
    value: &impl serde::Serialize,
    maximum_record_bytes: usize,
) -> Result<(), RuntimeError> {
    let mut sink = MetadataCredit {
        remaining: maximum_record_bytes,
    };
    serde_json::to_writer(&mut sink, value).map_err(|_| RuntimeError::ResourceLimit)
}
