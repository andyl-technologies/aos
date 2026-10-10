//! Complete ledger validation and post-publication fresh local continuation.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{MAX_ARRAY_ELEMENTS, Validate, canonical};

use super::*;
use crate::node_admission::AdmittedGraph;
use crate::node_scheduling::{
    InputCustodyCommit, RuntimeInputBatch, SavedPermission, SchedulingCommit,
};

#[cfg(test)]
#[path = "restore_tests.rs"]
mod tests;

/// Retains a checked inactive native runtime continuation until complete publication.
pub struct PreparedRuntimeRestore {
    target: ActivationRecord,
    snapshot: RuntimeSnapshot,
    native: VerifiedNativeContinuation,
    runtime_input_acknowledgements: BTreeMap<Id, NativeInputAcknowledgement>,
}

impl PreparedRuntimeRestore {
    pub(crate) fn validate_source(
        graph: &AdmittedGraph,
        scheduling: &SchedulingSnapshot,
        snapshot: &RuntimeSnapshot,
        limits: RuntimeLimits,
        maximum_record_bytes: usize,
    ) -> Result<(), RuntimeError> {
        validate_snapshot(
            graph,
            None,
            scheduling,
            snapshot,
            limits,
            maximum_record_bytes,
        )
    }

    pub(crate) fn validate_saved(
        graph: &AdmittedGraph,
        target: &ActivationRecord,
        scheduling: &SchedulingSnapshot,
        snapshot: &RuntimeSnapshot,
        limits: RuntimeLimits,
        maximum_record_bytes: usize,
    ) -> Result<(), RuntimeError> {
        validate_snapshot(
            graph,
            Some(target),
            scheduling,
            snapshot,
            limits,
            maximum_record_bytes,
        )
    }

    /// Authenticates original ledger continuity before any local permission is reminted.
    ///
    /// # Errors
    /// Rejects changed bindings, stale source incarnations, incomplete owner or
    /// operation rosters, changed committed inventories, missing input buffers,
    /// resource excess or unavailable native unchanged-cut continuation proof.
    pub(crate) fn prepare(
        graph: &AdmittedGraph,
        target: &ActivationRecord,
        scheduling: &SchedulingSnapshot,
        mut snapshot: RuntimeSnapshot,
        verifier: &mut dyn NativeRuntimeContinuationVerifier,
        limits: RuntimeLimits,
        maximum_record_bytes: usize,
    ) -> Result<Self, RuntimeError> {
        validate_snapshot(
            graph,
            Some(target),
            scheduling,
            &snapshot,
            limits,
            maximum_record_bytes,
        )?;
        if snapshot.schema_version == 6 {
            // Static source indexes never create a fresh control fence. The
            // selected native gate first reopens the authenticated whole DAG
            // beneath actual restored custody, then core rechecks its exact
            // historical marker and complete byte-bearing dependency closure.
            if scheduling.schema_version != 4 {
                return Err(RuntimeError::UnsupportedFacet);
            }
            let saved = verifier.reopen_condition_continuation(
                &snapshot,
                scheduling,
                target,
                maximum_record_bytes,
            )?;
            condition::validate_reopened(&snapshot, &saved, limits, maximum_record_bytes)?;
            for operation in &mut snapshot.operations {
                if let OperationRequest::DebugConditionV1(request) = &mut operation.request
                    && let crate::node_contract::ConditionControlRequest::Stop { barrier, .. } =
                        request.as_mut()
                {
                    // Attach original bodies without changing canonical source
                    // request bytes, context, IDs or any historical ACK fact.
                    **barrier = saved.record.clone();
                }
            }
            snapshot.condition_stop = Some(saved);
        }
        if snapshot.schema_version >= 2
            && snapshot
                .inputs
                .iter()
                .any(|input| input.provenance.is_some())
        {
            verifier.verify_input_provenance(&snapshot, scheduling, target)?;
        }
        if snapshot.schema_version == 3 {
            verifier.verify_terminal_continuation(&snapshot, scheduling, target)?;
        }
        if snapshot.schema_version == 4 {
            if scheduling.schema_version == 2 {
                return Err(RuntimeError::UnsupportedFacet);
            }
            verifier.verify_fault_continuation(&snapshot, scheduling, target)?;
        }
        let epochs = if scheduling.schema_version == 4 {
            if snapshot.schema_version != 6 {
                return Err(RuntimeError::UnsupportedFacet);
            }
            None
        } else if scheduling.schema_version == 3 {
            // Fault edition three has no inherited epoch rows. Its separate
            // installed verifier authenticates the original controller scope.
            if snapshot.schema_version != 4 {
                return Err(RuntimeError::UnsupportedFacet);
            }
            None
        } else {
            verifier.preserve_scheduling_epochs(&snapshot, scheduling, target)?
        };
        if let Some(epochs) = &epochs {
            crate::node_scheduling::validate_restored_scheduling_epochs(
                graph, scheduling, target, epochs,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        } else if !matches!(scheduling.schema_version, 1 | 3 | 4) {
            return Err(RuntimeError::InvalidReceipt);
        }
        let evidence = verifier.verify_runtime_continuation(&snapshot, scheduling, target)?;
        evidence
            .proof
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if evidence.proof.length.get() == 0 {
            return Err(RuntimeError::InvalidReceipt);
        }
        let runtime_input_acknowledgements = validate_fresh_acknowledgements(
            graph,
            target,
            &snapshot,
            &evidence.input_acknowledgements,
        )?;
        let input_acknowledgements = scheduling
            .input_batches
            .iter()
            .filter(|batch| batch.acknowledgement.is_some())
            .map(|batch| {
                runtime_input_acknowledgements
                    .get(&batch.stage_operation)
                    .cloned()
                    .ok_or(RuntimeError::InvalidReceipt)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let native = VerifiedNativeContinuation {
            target: target.clone(),
            scheduler_hash: scheduling
                .continuation_hash()
                .map_err(|_| RuntimeError::InvalidReceipt)?,
            reservations: scheduling.reservations.clone(),
            input_batches: scheduling.input_batches.clone(),
            input_acknowledgements,
            proof: evidence.proof,
            epochs,
        };
        Ok(Self {
            target: target.clone(),
            snapshot,
            native,
            runtime_input_acknowledgements,
        })
    }

    /// Borrows accepted native continuity proof without exposing execution authority.
    pub fn native_continuation(&self) -> &VerifiedNativeContinuation {
        &self.native
    }

    /// Installs original ledgers atomically beneath one fresh published world.
    ///
    /// Completed native operations are never submitted again. Their restored
    /// tokens recover the same cached result and, where already committed, only
    /// the original idempotent native acknowledgement. Pending operations recover
    /// their original native polling identity under newly authenticated custody.
    ///
    /// # Errors
    /// Rejects changed activation, an already populated runtime, native evidence
    /// that no longer validates, or incomplete original owner/input custody.
    pub(crate) fn install(
        self,
        runtime: &mut NodeRuntime,
        activation: &WorldActivation,
    ) -> Result<(), RuntimeError> {
        runtime.validate_activation(activation)?;
        if activation.record() != &self.target
            || !runtime.operations.is_empty()
            || !runtime.input_batches.is_empty()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut inputs = BTreeMap::new();
        for input in &self.snapshot.inputs {
            let route = runtime
                .snapshots
                .get(&input.node)
                .ok_or(RuntimeError::UnknownNode)?
                .route
                .clone();
            let batch = RuntimeInputBatch {
                activation: activation.clone(),
                node: input.node.clone(),
                stage_operation: input.stage_operation.clone(),
                batch: input.batch.clone(),
                owners: route.owners,
                cutoff: input.cutoff,
                inventory: input.inventory.clone(),
                deliveries: input.deliveries.clone(),
                payloads: input.payloads.clone(),
            };
            let acknowledgement = self
                .runtime_input_acknowledgements
                .get(&input.stage_operation)
                .cloned();
            let commit = input.coordinator_committed.then(|| InputCustodyCommit {
                activation: activation.clone(),
                node: input.node.clone(),
                stage_operation: input.stage_operation.clone(),
                batch: input.batch.clone(),
                inventory: input.inventory.clone(),
                cutoff: input.cutoff,
            });
            inputs.insert(
                input.stage_operation.clone(),
                inputs::RetainedInput {
                    batch,
                    provenance: input
                        .provenance
                        .clone()
                        .map(|saved| InputProvenanceClosure::restore_validated(activation, saved)),
                    acknowledgement,
                    failure: input.failure.clone(),
                    committed: input.committed,
                    commit,
                },
            );
        }

        let mut operations = BTreeMap::new();
        for original in &self.snapshot.operations {
            let route = runtime
                .snapshots
                .get(&original.route.node)
                .ok_or(RuntimeError::UnknownNode)?
                .route
                .clone();
            let token = OperationToken {
                authority: Rc::clone(&runtime.authority),
                operation: original.operation.clone(),
                route: route.clone(),
            };
            let input = original
                .input_batch
                .as_ref()
                .map(|batch| {
                    inputs
                        .values()
                        .find(|input| input.batch.batch() == batch)
                        .map(|input| Rc::new(input.batch.retained_copy()))
                        .ok_or(RuntimeError::InvalidReceipt)
                })
                .transpose()?;
            let admission = OperationAdmission {
                token,
                request: original.request.clone(),
                activation: activation.clone(),
                inputs: input,
            };
            let result = match &original.result {
                SavedRuntimeResult::Pending => RetainedResult::Pending,
                SavedRuntimeResult::Failed(failure) => RetainedResult::Failed(failure.clone()),
                SavedRuntimeResult::Complete(outcome)
                | SavedRuntimeResult::Acknowledged(outcome) => {
                    let mut outcome = outcome.clone();
                    outcome.owners = route.owners.clone();
                    if let Some(observation) = &mut outcome.scheduling {
                        observation.owners = route.owners.clone();
                    }
                    if !valid_outcome(&admission, &outcome) {
                        return Err(RuntimeError::InvalidReceipt);
                    }
                    if matches!(original.result, SavedRuntimeResult::Acknowledged(_)) {
                        RetainedResult::Acknowledged(outcome)
                    } else {
                        RetainedResult::Complete(outcome)
                    }
                }
            };
            let scheduling_commit =
                original
                    .scheduling_commit
                    .as_ref()
                    .map(|commit| SchedulingCommit {
                        activation: activation.clone(),
                        node: commit.node.clone(),
                        operation: commit.operation.clone(),
                        retained_outputs: commit.retained_outputs.clone(),
                    });
            operations.insert(
                original.operation.clone(),
                RetainedOperation {
                    admission,
                    result,
                    close_submission: original.close_submission.clone(),
                    submission_effects: original.submission_effects.clone(),
                    scheduling_commit,
                },
            );
        }

        let mut owners = BTreeMap::new();
        for saved in &self.snapshot.owners {
            let fresh = runtime
                .owners
                .get(&saved.identity.owner)
                .ok_or(RuntimeError::InvalidRoute)?;
            owners.insert(
                saved.identity.owner.clone(),
                OwnerCustody {
                    identity: fresh.identity.clone(),
                    domains: fresh.domains.clone(),
                    operation: saved.operation.clone(),
                    lifecycle: saved.lifecycle,
                },
            );
        }

        // The prepared world is still inaccessible to dispatch. Retain every
        // reminted ledger before invoking native callbacks so a failed rebind
        // transfers the complete original custody to the owning supervisor.
        runtime.input_batches = inputs;
        runtime.operations = operations;
        runtime.owners = owners;
        runtime.terminal = self
            .snapshot
            .terminal
            .clone()
            .map(|saved| crate::node_contract::terminal::TerminalState { saved });
        runtime.condition_stop = self.snapshot.condition_stop.clone().map(|saved| {
            crate::node_contract::condition_debug::ConditionStopState {
                saved,
                // Historical durability and ACK survive unchanged. A fresh
                // opaque permit still requires the current trusted publisher
                // to reopen every original result root before ACK or resume.
                publication_verified_for: None,
            }
        });

        for (node_id, native) in &mut runtime.nodes {
            let node_operations: Vec<_> = runtime
                .operations
                .values()
                .filter(|operation| &operation.admission.token.route.node == node_id)
                .map(|operation| operation.admission.clone())
                .collect();
            let node_inputs: Vec<_> = runtime
                .input_batches
                .values()
                .filter(|input| input.batch.node() == node_id)
                .map(|input| Rc::new(input.batch.retained_copy()))
                .collect();
            if !node_operations.is_empty() || !node_inputs.is_empty() {
                native
                    .install_restored_custody(
                        activation,
                        &self.snapshot,
                        &node_operations,
                        &node_inputs,
                    )
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
            }
            for operation in runtime
                .operations
                .values()
                .filter(|operation| &operation.admission.token.route.node == node_id)
            {
                if let RetainedResult::Complete(outcome) | RetainedResult::Acknowledged(outcome) =
                    &operation.result
                {
                    native
                        .validate_outcome(&operation.admission, outcome)
                        .map_err(|_| RuntimeError::InvalidReceipt)?;
                }
            }
            for input in runtime
                .input_batches
                .values()
                .filter(|input| input.batch.node() == node_id)
            {
                if let Some(acknowledgement) = &input.acknowledgement {
                    native
                        .validate_input_acknowledgement(&input.batch, acknowledgement)
                        .map_err(|_| RuntimeError::InvalidReceipt)?;
                }
            }
        }

        Ok(())
    }
}

fn validate_snapshot(
    graph: &AdmittedGraph,
    target: Option<&ActivationRecord>,
    scheduling: &SchedulingSnapshot,
    snapshot: &RuntimeSnapshot,
    limits: RuntimeLimits,
    maximum_record_bytes: usize,
) -> Result<(), RuntimeError> {
    bounded_record(snapshot, maximum_record_bytes)?;
    terminal::validate(snapshot)?;
    condition::validate(snapshot)?;
    let faults = snapshot
        .operations
        .iter()
        .any(|operation| matches!(operation.request, OperationRequest::FaultInjectionV1(_)));
    if !matches!(snapshot.schema_version, 1..=4 | 6)
        || (faults && snapshot.schema_version != 4)
        || (snapshot.schema_version == 6) != snapshot.condition_stop.is_some()
        || (snapshot.schema_version == 6 && faults)
        || (snapshot.schema_version == 3) != snapshot.terminal.is_some()
        || (snapshot.schema_version < 3
            && (snapshot.schema_version == 2)
                != snapshot
                    .inputs
                    .iter()
                    .any(|input| input.provenance.is_some()))
        || snapshot.capture_cut != scheduling.capture_cut
        || snapshot.capture_ordinal != scheduling.capture_ordinal
        || snapshot.source_activation.world_binding_hash != *graph.world_binding_hash()
        || snapshot.source_activation.world_binding_hash != scheduling.world_binding_hash
        || snapshot.source_activation.activation_id != scheduling.source_activation_id
        || snapshot.source_activation.generation != scheduling.source_generation
        || snapshot.source_activation.boundary != scheduling.source_boundary
        || target.is_some_and(|target| {
            snapshot.capture_cut != target.boundary
                || target.generation <= snapshot.source_activation.generation
                || target.activation_id == snapshot.source_activation.activation_id
        })
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    input_provenance::validate_saved_inputs(&snapshot.inputs)?;
    if snapshot.owners.len() > limits.maximum_owners
        || snapshot
            .operations
            .len()
            .checked_add(snapshot.inputs.len())
            .is_none_or(|count| count > limits.maximum_operations)
        || snapshot.inputs.len() > MAX_ARRAY_ELEMENTS
    {
        return Err(RuntimeError::ResourceLimit);
    }
    let source_owners: Vec<_> = scheduling
        .source_owners
        .iter()
        .map(|source| OwnerIdentity {
            owner: source.owner.clone(),
            incarnation: source.incarnation.clone(),
            generation: source.generation,
        })
        .collect();
    let expected: Vec<_> = graph.owners().map(|owner| owner.owner.id.clone()).collect();
    if snapshot.source_activation.owners != source_owners
        || snapshot
            .owners
            .iter()
            .map(|owner| owner.identity.clone())
            .collect::<Vec<_>>()
            != source_owners
        || source_owners
            .iter()
            .map(|owner| owner.owner.clone())
            .collect::<Vec<_>>()
            != expected
    {
        return Err(RuntimeError::InvalidRoute);
    }
    for owner in &snapshot.owners {
        let binding = graph
            .owner(&owner.identity.owner)
            .ok_or(RuntimeError::InvalidRoute)?;
        if owner.domains != binding.owner.state_domain_ids
            || matches!(owner.lifecycle, Lifecycle::Prepared | Lifecycle::Unrealized)
        {
            return Err(RuntimeError::InvalidRoute);
        }
        if let Some(target) = target {
            let fresh = target
                .owners
                .iter()
                .find(|fresh| fresh.owner == owner.identity.owner)
                .ok_or(RuntimeError::InvalidRoute)?;
            if fresh.generation <= owner.identity.generation
                || source_owners
                    .iter()
                    .any(|source| source.incarnation == fresh.incarnation)
            {
                return Err(RuntimeError::InvalidRoute);
            }
        }
    }
    ordered_unique(
        snapshot
            .operations
            .iter()
            .map(|operation| &operation.operation),
    )?;
    ordered_unique(snapshot.inputs.iter().map(|input| &input.stage_operation))?;
    let mut batch_ids = BTreeSet::new();
    for input in &snapshot.inputs {
        validate_input(graph, &source_owners, input, scheduling, limits)?;
        if !batch_ids.insert(input.batch.clone())
            || snapshot
                .operations
                .iter()
                .any(|operation| operation.operation == input.stage_operation)
        {
            return Err(RuntimeError::DuplicateOperation);
        }
    }
    for operation in &snapshot.operations {
        validate_operation(
            graph,
            &source_owners,
            operation,
            snapshot,
            scheduling,
            limits,
        )?;
    }
    for reservation in &scheduling.reservations {
        let operation = snapshot
            .operations
            .iter()
            .find(|operation| operation.operation == reservation.operation)
            .ok_or(RuntimeError::OutstandingObligations)?;
        if operation.route.node != reservation.node
            || operation.input_batch != reservation.input_batch
            || saved_permission(&operation.request)? != reservation.permission
            || operation.scheduling_commit.is_some()
            || matches!(operation.result, SavedRuntimeResult::Acknowledged(_))
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    for batch in &scheduling.input_batches {
        let input = snapshot
            .inputs
            .iter()
            .find(|input| input.stage_operation == batch.stage_operation)
            .ok_or(RuntimeError::OutstandingObligations)?;
        if input.node != batch.node
            || input.batch != batch.batch
            || input.owners != batch.owners
            || input.cutoff != batch.cutoff
            || input.inventory != batch.inventory
            || input.deliveries != batch.deliveries
            || input.payloads != batch.payloads
            || input.acknowledgement != batch.acknowledgement
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    validate_reservation_closure(snapshot)
}

fn validate_operation(
    graph: &AdmittedGraph,
    source_owners: &[OwnerIdentity],
    operation: &SavedRuntimeOperation,
    snapshot: &RuntimeSnapshot,
    scheduling: &SchedulingSnapshot,
    limits: RuntimeLimits,
) -> Result<(), RuntimeError> {
    operation
        .operation
        .validate()
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    // Finalization is admitted by the original fenced whole-world barrier,
    // rather than a scheduling grant. The selected terminal validator above
    // authenticates its single original request and complete saved custody.
    let terminal_operation = snapshot.terminal.as_ref().is_some_and(|terminal| {
        terminal.submitted
            && terminal.record.operation == operation.operation
            && terminal.record.node == operation.route.node
            && matches!(
                operation.request,
                OperationRequest::FinalizeAssertions { .. }
            )
    });
    let condition_operation = snapshot.condition_stop.as_ref().is_some_and(|saved| {
        saved.submitted
            && operation.route.node == saved.record.node
            && (operation.operation == saved.record.operation
                || saved.resume_operation.as_ref() == Some(&operation.operation))
            && matches!(operation.request, OperationRequest::DebugConditionV1(_))
    });
    if operation.route.owners != source_route(graph, source_owners, &operation.route.node)?
        || !scheduling.used_operations.contains(&operation.operation)
    {
        return Err(RuntimeError::InvalidRoute);
    }
    if let Some(batch) = &operation.input_batch {
        let input = snapshot
            .inputs
            .iter()
            .find(|input| &input.batch == batch)
            .ok_or(RuntimeError::OutstandingObligations)?;
        if !input.committed || input.node != operation.route.node || input.failure.is_some() {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    let outcome = match &operation.result {
        SavedRuntimeResult::Complete(outcome) | SavedRuntimeResult::Acknowledged(outcome) => {
            Some(outcome)
        }
        _ => None,
    };
    if let Some(outcome) = outcome
        && (outcome.operation != operation.operation
            || outcome.node != operation.route.node
            || outcome.owners != operation.route.owners
            || outcome.retained_outputs.len() > limits.maximum_retained_outputs
            || outcome.scheduling.as_ref().is_some_and(|observation| {
                observation.node != outcome.node || observation.owners != outcome.owners
            }))
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    if let Some(commit) = &operation.scheduling_commit {
        let outcome = outcome.ok_or(RuntimeError::InvalidReceipt)?;
        if commit.operation != operation.operation
            || commit.node != operation.route.node
            || commit.retained_outputs != outcome.retained_outputs
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    } else if matches!(operation.result, SavedRuntimeResult::Acknowledged(_))
        && !terminal_operation
        && !condition_operation
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    if matches!(
        operation.result,
        SavedRuntimeResult::Pending | SavedRuntimeResult::Complete(_)
    ) && operation.scheduling_commit.is_none()
        && !terminal_operation
        && !condition_operation
        && !scheduling
            .reservations
            .iter()
            .any(|reservation| reservation.operation == operation.operation)
    {
        return Err(RuntimeError::OutstandingObligations);
    }
    Ok(())
}

fn validate_input(
    graph: &AdmittedGraph,
    source_owners: &[OwnerIdentity],
    input: &SavedRuntimeInput,
    scheduling: &SchedulingSnapshot,
    limits: RuntimeLimits,
) -> Result<(), RuntimeError> {
    if input.owners != source_route(graph, source_owners, &input.node)?
        || !scheduling.used_operations.contains(&input.stage_operation)
        || !scheduling.used_input_batches.contains(&input.batch)
        || input.deliveries.len() > limits.maximum_retained_outputs
        || input.payloads.len() > limits.maximum_retained_outputs
        || input.committed
            && (!input.coordinator_committed
                || input.acknowledgement.is_none()
                || input.failure.is_some())
        || input.coordinator_committed
            && (input.acknowledgement.is_none() || input.failure.is_some())
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    let inventory_bytes = canonical::canonical_json(
        &serde_json::to_value(&input.deliveries).map_err(|_| RuntimeError::InvalidReceipt)?,
    )
    .map_err(|_| RuntimeError::InvalidReceipt)?;
    input
        .inventory
        .verify(&inventory_bytes)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let needed: BTreeSet<_> = input
        .deliveries
        .iter()
        .map(|delivery| delivery.payload.clone())
        .collect();
    let supplied: BTreeSet<_> = input
        .payloads
        .iter()
        .map(|payload| payload.reference.clone())
        .collect();
    if needed != supplied || supplied.len() != input.payloads.len() {
        return Err(RuntimeError::InvalidReceipt);
    }
    for payload in &input.payloads {
        payload
            .reference
            .verify(&payload.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    }
    if let Some(ack) = &input.acknowledgement {
        if ack.node != input.node
            || ack.stage_operation != input.stage_operation
            || ack.batch != input.batch
            || ack.owners != input.owners
            || ack.cutoff != input.cutoff
            || ack.inventory != input.inventory
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        ack.proof_ref
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    }
    Ok(())
}

fn validate_reservation_closure(snapshot: &RuntimeSnapshot) -> Result<(), RuntimeError> {
    let mut required = BTreeMap::new();
    let mut reserved_domains = BTreeMap::new();
    for operation in &snapshot.operations {
        let reserved = match &operation.result {
            SavedRuntimeResult::Acknowledged(_) => false,
            SavedRuntimeResult::Failed(failure) => failure.effects != EffectKnowledge::None,
            SavedRuntimeResult::Pending | SavedRuntimeResult::Complete(_) => true,
        };
        if reserved {
            reserve_saved_route(
                snapshot,
                &operation.route.owners,
                &operation.operation,
                &mut required,
                &mut reserved_domains,
            )?;
        }
    }
    for input in &snapshot.inputs {
        let reserved = !input.committed
            && !input
                .failure
                .as_ref()
                .is_some_and(|failure| failure.effects == EffectKnowledge::None);
        if reserved {
            reserve_saved_route(
                snapshot,
                &input.owners,
                &input.stage_operation,
                &mut required,
                &mut reserved_domains,
            )?;
        }
    }
    for owner in &snapshot.owners {
        if owner.operation.as_ref() != required.get(&owner.identity.owner)
            || owner.operation.is_some()
                && !matches!(
                    owner.lifecycle,
                    Lifecycle::Executing | Lifecycle::FailedContained | Lifecycle::Quarantined
                )
        {
            return Err(RuntimeError::OutstandingObligations);
        }
    }
    Ok(())
}

fn reserve_saved_route(
    snapshot: &RuntimeSnapshot,
    route: &[OwnerIdentity],
    operation: &Id,
    reserved_owners: &mut BTreeMap<Id, Id>,
    reserved_domains: &mut BTreeMap<Id, Id>,
) -> Result<(), RuntimeError> {
    let mut route_domains = BTreeSet::new();
    for identity in route {
        let owner = snapshot
            .owners
            .iter()
            .find(|owner| owner.identity == *identity)
            .ok_or(RuntimeError::InvalidRoute)?;
        if reserved_owners
            .insert(identity.owner.clone(), operation.clone())
            .is_some()
        {
            return Err(RuntimeError::OwnerBusy);
        }
        route_domains.extend(owner.domains.iter().cloned());
    }

    // Distinct native owners can still mutate the same modeled state domain.
    // Coalesce a single operation's route, but preserve exclusion across grants.
    for domain in route_domains {
        if reserved_domains.insert(domain, operation.clone()).is_some() {
            return Err(RuntimeError::OwnerBusy);
        }
    }
    Ok(())
}

fn validate_fresh_acknowledgements(
    graph: &AdmittedGraph,
    target: &ActivationRecord,
    snapshot: &RuntimeSnapshot,
    acknowledgements: &[NativeInputAcknowledgement],
) -> Result<BTreeMap<Id, NativeInputAcknowledgement>, RuntimeError> {
    let expected: Vec<_> = snapshot
        .inputs
        .iter()
        .filter(|input| input.acknowledgement.is_some())
        .map(|input| input.stage_operation.clone())
        .collect();
    if acknowledgements
        .iter()
        .map(|ack| ack.stage_operation.clone())
        .collect::<Vec<_>>()
        != expected
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    let mut result = BTreeMap::new();
    for ack in acknowledgements {
        let input = snapshot
            .inputs
            .iter()
            .find(|input| input.stage_operation == ack.stage_operation)
            .ok_or(RuntimeError::InvalidReceipt)?;
        if ack.node != input.node
            || ack.batch != input.batch
            || ack.cutoff != input.cutoff
            || ack.inventory != input.inventory
            || ack.owners != source_route(graph, &target.owners, &input.node)?
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        ack.proof_ref
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if ack.proof_ref.length.get() == 0 {
            return Err(RuntimeError::InvalidReceipt);
        }
        result.insert(ack.stage_operation.clone(), ack.clone());
    }
    Ok(result)
}

fn source_route(
    graph: &AdmittedGraph,
    owners: &[OwnerIdentity],
    node: &Id,
) -> Result<Vec<OwnerIdentity>, RuntimeError> {
    let binding = graph.binding(node).ok_or(RuntimeError::UnknownNode)?;
    let ids: BTreeSet<_> = [
        &binding.compatibility.execution_owner.id,
        &binding.compatibility.capture_owner.id,
    ]
    .into_iter()
    .collect();
    let route: Vec<_> = owners
        .iter()
        .filter(|owner| ids.contains(&owner.owner))
        .cloned()
        .collect();
    if route.len() != ids.len() {
        return Err(RuntimeError::InvalidRoute);
    }
    Ok(route)
}

fn saved_permission(request: &OperationRequest) -> Result<SavedPermission, RuntimeError> {
    match request {
        OperationRequest::FaultInjectionV1(request) => Ok(SavedPermission::FaultInjectionV1 {
            request: request.clone(),
        }),
        OperationRequest::ExactRun {
            start,
            limit,
            boundary_policy,
        } => Ok(SavedPermission::ExactRun {
            start: *start,
            limit: *limit,
            input_blocked_park: *boundary_policy == ExactBoundaryPolicy::InputBlockedPark,
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
                u64::try_from(host_budget.as_nanos()).map_err(|_| RuntimeError::ResourceLimit)?,
            ),
        }),
        _ => Err(RuntimeError::InvalidTiming),
    }
}

fn ordered_unique<'a>(ids: impl Iterator<Item = &'a Id>) -> Result<(), RuntimeError> {
    let mut previous = None;
    for id in ids {
        id.validate().map_err(|_| RuntimeError::InvalidReceipt)?;
        if previous.is_some_and(|previous| previous >= id) {
            return Err(RuntimeError::DuplicateOperation);
        }
        previous = Some(id);
    }
    Ok(())
}

pub(super) fn bounded_record(
    record: &impl Serialize,
    maximum_bytes: usize,
) -> Result<(), RuntimeError> {
    struct Counter {
        remaining: usize,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.remaining = self
                .remaining
                .checked_sub(bytes.len())
                .ok_or_else(|| std::io::Error::other("runtime snapshot allocation ceiling"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(
        Counter {
            remaining: maximum_bytes,
        },
        record,
    )
    .map_err(|_| RuntimeError::ResourceLimit)
}
