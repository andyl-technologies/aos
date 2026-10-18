//! Checks current Host17 facts without consulting or creating live authority.

use super::*;
use crucible_node_contract::Validate;

pub(super) fn validate_limits(
    limits: HostSchedulingContinuationLimits,
) -> Result<(), RuntimeError> {
    let ceiling = OriginalInputLineageLimits::default();
    if limits.maximum_record_bytes == 0
        || limits.maximum_record_bytes > 64 * 1024 * 1024
        || limits.lineage.maximum_objects > ceiling.maximum_objects
        || limits.lineage.maximum_bytes > ceiling.maximum_bytes
        || limits.lineage.maximum_edges > ceiling.maximum_edges
    {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(())
}

pub(super) fn validate_record(
    record: &HostSchedulingRestoredContinuationRecord17,
    limits: HostSchedulingContinuationLimits,
) -> Result<(), RuntimeError> {
    if record.schema_version != 17
        || record.scheduling.schema_version != 1
        || record.scheduling.original_epochs.is_some()
        || !record.scheduling.external_closed_prefixes.is_empty()
    {
        return Err(RuntimeError::UnsupportedFacet);
    }
    credit(record, limits.maximum_record_bytes).map_err(|_| RuntimeError::ResourceLimit)?;
    super::host_role::validate_host_role_data(&record.source, &record.runtime, &record.scheduling)?;
    record
        .runtime
        .validate_metadata(limits.lineage, limits.maximum_record_bytes)?;
    record
        .source
        .descriptor
        .validate()
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    record
        .source
        .binding
        .validate()
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    record
        .source
        .owner
        .validate()
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    validate_domains(&record.source.domains).map_err(|_| RuntimeError::InvalidReceipt)?;

    let runtime = &record.runtime;
    let scheduling = &record.scheduling;
    let activation = &runtime.source_activation;
    if runtime.capture_cut != scheduling.capture_cut
        || runtime.capture_ordinal != scheduling.capture_ordinal
        || activation.world_binding_hash != scheduling.world_binding_hash
        || activation.activation_id != scheduling.source_activation_id
        || activation.generation != scheduling.source_generation
        || activation.boundary != scheduling.source_boundary
        || runtime.owners.len() != activation.owners.len()
        || runtime.owners.len() != scheduling.source_owners.len()
        || runtime
            .owners
            .windows(2)
            .any(|pair| pair[0].identity.owner >= pair[1].identity.owner)
        || runtime
            .operations
            .windows(2)
            .any(|pair| pair[0].operation >= pair[1].operation)
        || runtime
            .inputs
            .windows(2)
            .any(|pair| pair[0].stage_operation >= pair[1].stage_operation)
        || runtime
            .owners
            .iter()
            .zip(&activation.owners)
            .any(|(saved, source)| &saved.identity != source)
        || runtime
            .owners
            .iter()
            .zip(&scheduling.source_owners)
            .any(|(saved, source)| {
                saved.identity.owner != source.owner
                    || saved.identity.incarnation != source.incarnation
                    || saved.identity.generation != source.generation
            })
    {
        return Err(RuntimeError::InvalidReceipt);
    }

    let policy = record.admission_policy;
    if policy.maximum_nodes < 4
        || policy.maximum_owners < 4
        || policy.maximum_retained_outputs == 0
        || runtime.owners.len() > policy.maximum_owners
        || runtime
            .operations
            .len()
            .checked_add(runtime.inputs.len())
            .is_none_or(|count| count > policy.maximum_operations)
        || scheduling.used_operations.len() > policy.maximum_operations
        || scheduling.used_input_batches.len() > policy.maximum_operations
    {
        return Err(RuntimeError::ResourceLimit);
    }

    let ancestry = &record.ancestry;
    ancestry
        .parent_archive_index
        .validate()
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    ancestry
        .first_host
        .validate()
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if ancestry
        .first_semantic
        .windows(2)
        .any(|pair| pair[0].node >= pair[1].node)
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    for semantic in &ancestry.first_semantic {
        semantic
            .node
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        semantic
            .object
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    }
    if ancestry
        .first_semantic
        .iter()
        .any(|row| row.node == record.source.descriptor.id)
        || ancestry.first_host == ancestry.parent_archive_index
        || ancestry.first_semantic.iter().any(|row| {
            row.object == ancestry.first_host || row.object == ancestry.parent_archive_index
        })
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    // Exact graph/owner correspondence is checked against the signed outer
    // roster by the cold loader; this local codec does not invent that roster.
    validate_objects(record, limits.lineage)
}

fn validate_objects(
    record: &HostSchedulingRestoredContinuationRecord17,
    mut remaining: OriginalInputLineageLimits,
) -> Result<(), RuntimeError> {
    if record
        .objects
        .windows(2)
        .any(|pair| pair[0].reference >= pair[1].reference)
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    for object in &record.objects {
        remaining.maximum_objects = remaining
            .maximum_objects
            .checked_sub(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        remaining.maximum_bytes = remaining
            .maximum_bytes
            .checked_sub(object.bytes.len())
            .ok_or(RuntimeError::ResourceLimit)?;
        object
            .reference
            .verify(&object.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    }
    // Walk the closed reference rows directly instead of allocating a second
    // deduplication inventory beside the already retained typed record.
    let required = || {
        record.runtime.inputs.iter().flat_map(|input| {
            input
                .payloads
                .iter()
                .chain(
                    input
                        .provenance
                        .iter()
                        .flat_map(|proof| proof.objects.iter()),
                )
                .chain(input.lineage.iter().flat_map(|lineage| {
                    lineage
                        .publications
                        .iter()
                        .flat_map(|publication| publication.objects.iter())
                }))
        })
    };
    for reference in required() {
        if record
            .objects
            .binary_search_by(|object| object.reference.cmp(reference))
            .is_err()
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    for object in &record.objects {
        if !required().any(|reference| reference == &object.reference) {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    Ok(())
}
