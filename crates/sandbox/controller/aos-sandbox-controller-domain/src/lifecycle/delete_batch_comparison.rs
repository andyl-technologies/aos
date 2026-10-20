//! Compares an exact Delete batch with one independently reconstructed graph.
//!
//! Both the paid Controller producer and Root's own native reader use this
//! borrowed comparison. It creates no graph, writer, admission or effect grant.

use aos_sandbox_ledger_replay::delete_graph::{
    DeleteDependencyGraphDataV2, DeleteGraphSelectionDataV2,
};
use aos_sandbox_protocol::domain_ledger::{
    delete_batch::{DeleteBatchViewV1, native_value_digest, raw64, row_key, tombstone},
    lifecycle_model::{LifecycleModelError, LifecycleResourceV1 as Resource},
    provisioning_resources::{
        ProvisioningCompanionRetirementDataV2, ProvisioningResourceRowKindV1 as CompanionKind,
    },
};

use super::{LifecyclePublicMutationAdmissionErrorV1, delete_candidate_projection_generation_data_v2};

#[derive(Debug, thiserror::Error)]
pub(crate) enum DeleteGraphBatchComparisonErrorV2 {
    #[error(transparent)]
    Model(#[from] LifecycleModelError),
    #[error(transparent)]
    Projection(#[from] LifecyclePublicMutationAdmissionErrorV1),
    #[error(transparent)]
    Companion(#[from] aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningCompanionRetirementErrorV2),
    #[error("the complete Delete batch differs from the independently selected graph")]
    Changed,
}

/// Prices only this allocation-free comparison's simultaneously held carriers.
pub(crate) fn delete_graph_batch_comparison_bytes_v2() -> Option<usize> {
    use aos_sandbox_protocol::domain_ledger::provisioning_resources::{
        PROVISIONING_RESOURCE_KEY_BYTES_V1, PROVISIONING_RESOURCE_ROW_BYTES_V1,
    };
    std::mem::size_of::<Result<(), DeleteGraphBatchComparisonErrorV2>>()
        .checked_mul(3)?
        .checked_add(std::mem::size_of::<ProvisioningCompanionRetirementDataV2>().checked_mul(3)?)?
        .checked_add(PROVISIONING_RESOURCE_KEY_BYTES_V1.checked_mul(2)?)?
        .checked_add(PROVISIONING_RESOURCE_ROW_BYTES_V1.checked_mul(2)?)?
        .checked_add(std::mem::size_of::<sha2::Sha256>().checked_mul(2)?)?
        .checked_add(160)
}

/// Checks every selected resource, typed relation and companion against the graph.
///
/// The caller derives `selection` with the graph's sole closure/postorder engine
/// after paying its actual vectors. Authorization, native predecessors and six
/// owner cuts remain separate checks; no input here establishes their authority.
pub(crate) fn require_delete_graph_batch_data_v2(
    graph: &DeleteDependencyGraphDataV2,
    selection: &DeleteGraphSelectionDataV2,
    batch: DeleteBatchViewV1<'_>,
) -> Result<(), DeleteGraphBatchComparisonErrorV2> {
    let changed = || DeleteGraphBatchComparisonErrorV2::Changed;
    if batch.version() != 2
        || batch.project() != graph.project
        || batch.root()? != Resource::Sandbox(selection.root)
        || batch.count(0) != selection.resources.len()
        || batch.count(1) != 0
        || batch.count(2) != 0
        || batch.count(3) != selection.dependencies.len()
        || batch.count(4) != selection.postorder.len()
    {
        return Err(changed());
    }

    // The sole codec already checked exact ordering and resource uniqueness.
    // Equal cardinality and full membership exclude both omitted and extra rows.
    for row in batch.rows(0) {
        let resource = Resource::from_code(row[0], row[1..17].try_into().map_err(|_| changed())?)?;
        if selection.resources.binary_search(&resource).is_err() {
            return Err(changed());
        }
        let expected = graph.projections.iter().find(|original| original.resource == resource);
        if let Some(original) = expected {
            let generation = delete_candidate_projection_generation_data_v2(&original.record)?;
            require_write_data_v2(batch, row, &original.key, generation,
                native_value_digest(&original.original))?;
        } else {
            let mut found = false;
            for original in &graph.companions {
                let fields = original.fields_v1();
                let kind = if resource == Resource::Other(fields.assignment) {
                    Some(CompanionKind::Assignment)
                } else if resource == Resource::Other(fields.reservation) {
                    Some(CompanionKind::Reservation)
                } else {
                    None
                };
                if let Some(kind) = kind {
                    if found {
                        return Err(changed());
                    }
                    found = true;
                    require_write_data_v2(batch, row, &original.key_v1(kind), 1,
                        native_value_digest(&original.encode_v1(kind)))?;
                }
            }
            if !found {
                return Err(changed());
            }
        }
    }

    for (row, expected) in batch.rows(3).zip(&selection.dependencies) {
        if !same_resource(&row[..17], expected.edge.dependent())
            || !same_resource(&row[17..34], expected.edge.dependency())
            || row[34] != expected.class.code_v2()
        {
            return Err(changed());
        }
    }
    for (row, expected) in batch.rows(4).zip(&selection.postorder) {
        if !same_resource(row, *expected) {
            return Err(changed());
        }
    }

    let selected_companions = graph.companions.iter().filter(|original| {
        selection.resources.binary_search(&Resource::Other(original.fields_v1().assignment)).is_ok()
    });
    if batch.companions_v2().count() != selected_companions.clone().count() {
        return Err(changed());
    }
    for descriptor in batch.companions_v2() {
        let descriptor = descriptor?;
        let original = descriptor.original_v1();
        if !selected_companions.clone().any(|expected| *expected == original)
            || descriptor != ProvisioningCompanionRetirementDataV2::from_data_v2(
                original, batch.operation(), batch.transaction())?
        {
            return Err(changed());
        }
    }
    Ok(())
}

fn require_write_data_v2(
    batch: DeleteBatchViewV1<'_>,
    row: &[u8],
    key: &[u8],
    generation: u64,
    digest: [u8; 32],
) -> Result<(), DeleteGraphBatchComparisonErrorV2> {
    if row_key(row, 0) != key
        || raw64(&row[20..28]) != generation
        || row[28..60] != digest
        || row[68..100] != native_value_digest(&tombstone(batch, row))
    {
        return Err(DeleteGraphBatchComparisonErrorV2::Changed);
    }
    Ok(())
}

fn same_resource(encoded: &[u8], resource: Resource) -> bool {
    encoded.len() == 17 && encoded[0] == resource.code() && encoded[1..] == resource.as_bytes()[..]
}

#[cfg(test)]
mod tests;
