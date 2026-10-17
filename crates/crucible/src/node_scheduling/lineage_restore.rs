//! Prepares exact coordinator custody from an opaque Runtime7 restoration context.
//!
//! The authenticated scheduler hash precedes graph/row validation. This path
//! never creates a legacy RuntimeSnapshot or a public native-proof constructor.
//! Its returned paused coordinator cannot issue permissions before publication.

use super::*;
use crate::node_contract::{
    OriginalLineageRestoration, OriginalLineageRuntimeRecord, SavedRuntimeResult,
};

impl PreparedSchedulingRestore {
    pub(crate) fn validate_original_lineage_context(
        &self,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), SchedulingError> {
        context
            .validate_original_scheduler(&self.snapshot)
            .map_err(|_| SchedulingError::UnresolvedCustody)?;
        if &self.target != context.target() {
            return Err(SchedulingError::ForeignActivation);
        }
        Ok(())
    }

    /// Prepares the exact original scheduler beneath independently checked Tape2 custody.
    ///
    /// Full original reservations, input buffers and native ACKs are compared
    /// without projecting Runtime7 into an older grammar. The opaque context
    /// already binds actual producer/consumer journals and the target runtime.
    ///
    /// # Errors
    /// Refuses another source scheduler, combined formats, missing native journals,
    /// widened permissions, changed original inputs or unsupported owner geometry.
    pub(crate) fn prepare_original_lineage(
        graph: &AdmittedGraph,
        snapshot: SchedulingSnapshot,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<Self, SchedulingError> {
        context
            .validate_original_scheduler(&snapshot)
            .map_err(|_| SchedulingError::UnresolvedCustody)?;
        validate_snapshot(graph, context.target(), &snapshot)?;
        if snapshot.schema_version != 1
            || snapshot.original_epochs.is_some()
            || !snapshot.external_closed_prefixes.is_empty()
        {
            return Err(SchedulingError::UnresolvedCustody);
        }
        validate_runtime_rows(graph, context.record(), &snapshot)?;
        let acknowledged = snapshot
            .input_batches
            .iter()
            .filter(|batch| batch.acknowledgement.is_some());
        let mut acknowledgements = Vec::new();
        acknowledgements
            .try_reserve_exact(acknowledged.clone().count())
            .map_err(|_| SchedulingError::CapacityExceeded)?;
        for batch in acknowledged {
            let ack = context
                .input_acknowledgements()
                .iter()
                .find(|ack| ack.stage_operation == batch.stage_operation)
                .ok_or(SchedulingError::UnresolvedCustody)?;
            let owners: Vec<_> = context
                .target()
                .owners
                .iter()
                .filter(|owner| {
                    batch
                        .owners
                        .iter()
                        .any(|source| source.owner == owner.owner)
                })
                .cloned()
                .collect();
            if ack.node != batch.node
                || ack.batch != batch.batch
                || ack.inventory != batch.inventory
                || ack.cutoff != batch.cutoff
                || ack.owners != owners
            {
                return Err(SchedulingError::UnresolvedCustody);
            }
            acknowledgements.push(ack.clone());
        }
        Ok(Self {
            target: context.target().clone(),
            snapshot,
            input_acknowledgements: acknowledgements,
            epochs: None,
        })
    }
}

fn validate_runtime_rows(
    graph: &AdmittedGraph,
    runtime: &OriginalLineageRuntimeRecord,
    scheduling: &SchedulingSnapshot,
) -> Result<(), SchedulingError> {
    for owner in &runtime.owners {
        let admitted = graph
            .owner(&owner.identity.owner)
            .ok_or(SchedulingError::UnresolvedCustody)?;
        if owner.domains != admitted.owner.state_domain_ids {
            return Err(SchedulingError::UnresolvedCustody);
        }
    }
    for operation in &runtime.operations {
        let binding = graph
            .binding(&operation.route.node)
            .ok_or(SchedulingError::UnknownNode)?;
        let original = runtime
            .source_activation
            .owners
            .iter()
            .find(|owner| owner.owner == binding.compatibility.execution_owner.id)
            .ok_or(SchedulingError::UnresolvedCustody)?;
        if operation.route.owners.as_slice() != std::slice::from_ref(original)
            || !scheduling.used_operations.contains(&operation.operation)
        {
            return Err(SchedulingError::UnresolvedCustody);
        }
        if let Some(batch) = &operation.input_batch {
            let input = runtime
                .inputs
                .iter()
                .find(|input| &input.batch == batch)
                .ok_or(SchedulingError::UnresolvedCustody)?;
            if input.node != operation.route.node || !input.committed || input.failure.is_some() {
                return Err(SchedulingError::UnresolvedCustody);
            }
        }
        if let Some(commit) = &operation.scheduling_commit {
            let outcome = match &operation.result {
                SavedRuntimeResult::Complete(outcome)
                | SavedRuntimeResult::Acknowledged(outcome) => outcome,
                _ => return Err(SchedulingError::UnresolvedCustody),
            };
            if commit.operation != operation.operation
                || commit.node != operation.route.node
                || commit.retained_outputs != outcome.retained_outputs
            {
                return Err(SchedulingError::UnresolvedCustody);
            }
        } else if matches!(operation.result, SavedRuntimeResult::Acknowledged(_)) {
            return Err(SchedulingError::UnresolvedCustody);
        }
        if matches!(
            operation.result,
            SavedRuntimeResult::Pending | SavedRuntimeResult::Complete(_)
        ) && operation.scheduling_commit.is_none()
            && !scheduling
                .reservations
                .iter()
                .any(|row| row.operation == operation.operation)
        {
            return Err(SchedulingError::UnresolvedCustody);
        }
    }
    for reservation in &scheduling.reservations {
        let operation = runtime
            .operations
            .iter()
            .find(|operation| operation.operation == reservation.operation)
            .ok_or(SchedulingError::UnresolvedCustody)?;
        if operation.route.node != reservation.node
            || operation.route.owners.len() != 1
            || operation.route.owners[0].owner != reservation.owner
            || operation.input_batch != reservation.input_batch
            || saved_permission(&operation.request)? != reservation.permission
            || operation.scheduling_commit.is_some()
            || matches!(operation.result, SavedRuntimeResult::Acknowledged(_))
        {
            return Err(SchedulingError::UnresolvedCustody);
        }
    }
    for input in &runtime.inputs {
        let binding = graph
            .binding(&input.node)
            .ok_or(SchedulingError::UnknownNode)?;
        let original = runtime
            .source_activation
            .owners
            .iter()
            .find(|owner| owner.owner == binding.compatibility.execution_owner.id)
            .ok_or(SchedulingError::UnresolvedCustody)?;
        if input.owners.as_slice() != std::slice::from_ref(original)
            || !scheduling.used_operations.contains(&input.stage_operation)
            || !scheduling.used_input_batches.contains(&input.batch)
            || input.committed
                && (!input.coordinator_committed
                    || input.acknowledgement.is_none()
                    || input.failure.is_some())
            || input.coordinator_committed
                && (input.acknowledgement.is_none() || input.failure.is_some())
        {
            return Err(SchedulingError::UnresolvedCustody);
        }
        if let Some(acknowledgement) = &input.acknowledgement
            && (acknowledgement.node != input.node
                || acknowledgement.stage_operation != input.stage_operation
                || acknowledgement.batch != input.batch
                || acknowledgement.owners != input.owners
                || acknowledgement.cutoff != input.cutoff
                || acknowledgement.inventory != input.inventory)
        {
            return Err(SchedulingError::UnresolvedCustody);
        }
    }
    for batch in &scheduling.input_batches {
        let input = runtime
            .inputs
            .iter()
            .find(|input| input.stage_operation == batch.stage_operation)
            .ok_or(SchedulingError::UnresolvedCustody)?;
        if input.node != batch.node
            || input.batch != batch.batch
            || input.owners != batch.owners
            || input.cutoff != batch.cutoff
            || input.inventory != batch.inventory
            || input.deliveries != batch.deliveries
            || input.acknowledgement != batch.acknowledgement
            || !input
                .payloads
                .iter()
                .eq(batch.payloads.iter().map(|payload| &payload.reference))
        {
            return Err(SchedulingError::UnresolvedCustody);
        }
    }
    validate_owner_reservations(runtime)
}

fn validate_owner_reservations(
    runtime: &OriginalLineageRuntimeRecord,
) -> Result<(), SchedulingError> {
    let mut owners = BTreeMap::new();
    let mut domains = BTreeMap::new();
    for (operation, route) in runtime
        .operations
        .iter()
        .filter_map(|operation| {
            let reserved = match &operation.result {
                SavedRuntimeResult::Acknowledged(_) => false,
                SavedRuntimeResult::Failed(failure) => {
                    failure.effects != crate::node_contract::EffectKnowledge::None
                }
                SavedRuntimeResult::Pending | SavedRuntimeResult::Complete(_) => true,
            };
            reserved.then_some((&operation.operation, operation.route.owners.as_slice()))
        })
        .chain(runtime.inputs.iter().filter_map(|input| {
            (!input.committed
                && !input.failure.as_ref().is_some_and(|failure| {
                    failure.effects == crate::node_contract::EffectKnowledge::None
                }))
            .then_some((&input.stage_operation, input.owners.as_slice()))
        }))
    {
        for identity in route {
            let owner = runtime
                .owners
                .iter()
                .find(|owner| owner.identity == *identity)
                .ok_or(SchedulingError::UnresolvedCustody)?;
            if owners.insert(&identity.owner, operation).is_some() {
                return Err(SchedulingError::UnresolvedCustody);
            }
            for domain in &owner.domains {
                if domains
                    .insert(domain, operation)
                    .is_some_and(|previous| previous != operation)
                {
                    return Err(SchedulingError::UnresolvedCustody);
                }
            }
        }
    }
    if runtime.owners.iter().any(|owner| {
        owner.operation.as_ref() != owners.get(&owner.identity.owner).copied()
            || owner.operation.is_some()
                && !matches!(
                    owner.lifecycle,
                    crate::node_contract::Lifecycle::Executing
                        | crate::node_contract::Lifecycle::FailedContained
                        | crate::node_contract::Lifecycle::Quarantined
                )
    }) {
        return Err(SchedulingError::UnresolvedCustody);
    }
    Ok(())
}

fn saved_permission(request: &OperationRequest) -> Result<SavedPermission, SchedulingError> {
    match request {
        OperationRequest::ExactRun {
            start,
            limit,
            boundary_policy,
        } => Ok(SavedPermission::ExactRun {
            start: *start,
            limit: *limit,
            input_blocked_park: *boundary_policy
                == crate::node_contract::ExactBoundaryPolicy::InputBlockedPark,
        }),
        OperationRequest::BoundarySettle { start, limit } => Ok(SavedPermission::BoundarySettle {
            start: *start,
            limit: *limit,
        }),
        OperationRequest::QuantumBegin {
            window,
            start,
            end,
            input_batch,
            host_budget,
        } => Ok(SavedPermission::Quantum {
            window: window.clone(),
            start: *start,
            end: *end,
            input_batch: input_batch.clone(),
            host_budget_ns: U64::new(
                u64::try_from(host_budget.as_nanos())
                    .map_err(|_| SchedulingError::CapacityExceeded)?,
            ),
        }),
        _ => Err(SchedulingError::UnresolvedCustody),
    }
}
