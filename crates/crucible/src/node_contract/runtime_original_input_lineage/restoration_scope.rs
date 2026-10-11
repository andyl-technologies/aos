//! Checks complete inert source and native scope geometry without allocating bodies.

use super::*;

pub(super) fn validate_source(
    runtime: &NodeRuntime,
    record: &OriginalLineageRuntimeRecord,
    scheduling: &SchedulingSnapshot,
    target: &ActivationRecord,
) -> Result<(), RuntimeError> {
    if !runtime
        .owners
        .values()
        .map(|owner| &owner.identity)
        .eq(target.owners.iter())
        || scheduling.schema_version != 1
        || record.capture_cut != scheduling.capture_cut
        || record.capture_ordinal != scheduling.capture_ordinal
        || record.source_activation.world_binding_hash != scheduling.world_binding_hash
        || record.source_activation.activation_id != scheduling.source_activation_id
        || record.source_activation.generation != scheduling.source_generation
        || record.source_activation.boundary != scheduling.source_boundary
        || target.world_binding_hash != record.source_activation.world_binding_hash
        || target.boundary != record.capture_cut
        || target.generation <= record.source_activation.generation
        || target.activation_id == record.source_activation.activation_id
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    if record.owners.len() > runtime.limits.maximum_owners
        || record
            .operations
            .len()
            .checked_add(record.inputs.len())
            .is_none_or(|count| count > runtime.limits.maximum_operations)
        || record.owners.len() != record.source_activation.owners.len()
        || record.owners.len() != target.owners.len()
        || record
            .owners
            .windows(2)
            .any(|pair| pair[0].identity.owner >= pair[1].identity.owner)
        || record
            .operations
            .windows(2)
            .any(|pair| pair[0].operation >= pair[1].operation)
        || record
            .inputs
            .windows(2)
            .any(|pair| pair[0].stage_operation >= pair[1].stage_operation)
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    if record
        .owners
        .iter()
        .zip(&record.source_activation.owners)
        .any(|(saved, source)| &saved.identity != source)
        || scheduling.source_owners.len() != record.owners.len()
        || scheduling
            .source_owners
            .iter()
            .zip(&record.owners)
            .any(|(source, saved)| {
                source.owner != saved.identity.owner
                    || source.incarnation != saved.identity.incarnation
                    || source.generation != saved.identity.generation
            })
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    for operation in &record.operations {
        if !runtime.snapshots.contains_key(&operation.route.node)
            || operation.route.owners.is_empty()
            || operation
                .route
                .owners
                .iter()
                .any(|owner| !record.source_activation.owners.contains(owner))
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    for operation in &record.operations {
        if let SavedRuntimeResult::Complete(outcome) | SavedRuntimeResult::Acknowledged(outcome) =
            &operation.result
            && (outcome.operation != operation.operation
                || outcome.node != operation.route.node
                || outcome.owners != operation.route.owners
                || outcome.scheduling.as_ref().is_some_and(|observation| {
                    observation.node != operation.route.node
                        || observation.owners != operation.route.owners
                }))
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    for input in &record.inputs {
        if !runtime.snapshots.contains_key(&input.node)
            || input.owners.is_empty()
            || input
                .owners
                .iter()
                .any(|owner| !record.source_activation.owners.contains(owner))
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    Ok(())
}

pub(super) fn validate_native_scope(
    runtime: &NodeRuntime,
    source: &ContentRef,
    record: &OriginalLineageRuntimeRecord,
    target: &ActivationRecord,
    scope: &OriginalLineageNativeScope,
) -> Result<(), RuntimeError> {
    if scope.coordinator_schema != 7
        || &scope.source_record != source
        || scope.source_capture != record.source_activation
        || &scope.target != target
        || scope.owners.len() != record.owners.len()
        || scope.journals.len() != runtime.snapshots.len()
        || scope.first_scopes.len()
            != record
                .inputs
                .iter()
                .filter(|input| input.lineage.is_some())
                .count()
        || scope
            .journals
            .windows(2)
            .any(|pair| pair[0].node >= pair[1].node)
        || scope.proof.length.get() == 0
        || scope.proof.validate().is_err()
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    for (mapping, original) in scope.owners.iter().zip(&record.owners) {
        if mapping.source != original.identity
            || mapping.target.owner != mapping.source.owner
            || !target.owners.contains(&mapping.target)
            || mapping.source == mapping.target
            || mapping.target.generation <= mapping.source.generation
            || mapping.target.incarnation == mapping.source.incarnation
            || scope
                .owners
                .iter()
                .filter(|other| other.target == mapping.target)
                .count()
                != 1
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    if scope
        .first_scopes
        .iter()
        .zip(
            record
                .inputs
                .iter()
                .filter_map(|input| input.lineage.as_ref().map(|lineage| &lineage.source)),
        )
        .any(|(supplied, original)| supplied != original)
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    let acknowledged = record
        .inputs
        .iter()
        .filter(|input| input.acknowledgement.is_some());
    if scope.input_acknowledgements.len() != acknowledged.clone().count()
        || scope
            .input_acknowledgements
            .windows(2)
            .any(|pair| pair[0].stage_operation >= pair[1].stage_operation)
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    for (fresh, saved) in scope.input_acknowledgements.iter().zip(acknowledged) {
        let original = saved
            .acknowledgement
            .as_ref()
            .ok_or(RuntimeError::InvalidReceipt)?;
        let node = runtime
            .snapshots
            .get(&saved.node)
            .ok_or(RuntimeError::UnknownNode)?;
        if fresh.node != original.node
            || fresh.owners != node.route.owners
            || fresh.stage_operation != original.stage_operation
            || fresh.batch != original.batch
            || fresh.cutoff != original.cutoff
            || fresh.inventory != original.inventory
            || fresh.proof_ref.length.get() == 0
            || fresh.proof_ref.validate().is_err()
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    for (journal, node) in scope.journals.iter().zip(runtime.snapshots.keys()) {
        if &journal.node != node
            || !strict(&journal.operations)
            || !strict(&journal.pending_operations)
            || !strict(&journal.acknowledged_operations)
            || !strict(&journal.input_stages)
            || !journal.operations.iter().eq(record
                .operations
                .iter()
                .filter(|entry| &entry.route.node == node)
                .map(|entry| &entry.operation))
            || !journal.pending_operations.iter().eq(record
                .operations
                .iter()
                .filter(|entry| {
                    &entry.route.node == node && matches!(entry.result, SavedRuntimeResult::Pending)
                })
                .map(|entry| &entry.operation))
            || !journal.acknowledged_operations.iter().eq(record
                .operations
                .iter()
                .filter(|entry| {
                    &entry.route.node == node
                        && matches!(entry.result, SavedRuntimeResult::Acknowledged(_))
                })
                .map(|entry| &entry.operation))
            || !journal.input_stages.iter().eq(record
                .inputs
                .iter()
                .filter(|input| &input.node == node)
                .map(|input| &input.stage_operation))
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    Ok(())
}

fn strict(values: &[Id]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
