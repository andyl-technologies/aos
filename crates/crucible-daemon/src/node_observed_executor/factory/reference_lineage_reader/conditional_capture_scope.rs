//! Authenticates the declared conditional cut against signed native originals.
//!
//! Runtime7 records are historical data. This installed fixture checks the
//! actual admitted world, exact original requests, producer bodies, input ACKs
//! and pending permissions before a separate signed capture can be attempted.

use crucible::{
    node_adapters::transcript::TranscriptAction,
    node_admission::AdmittedGraph,
    node_contract::{
        OperationRequest, OriginalLineageRuntimeRecord, SavedRuntimeResult, Submission,
    },
    node_scheduling::{SavedPermission, SchedulingSnapshot},
    node_state::{StateError, StateErrorCode},
};
use crucible_node_contract::{Event, Id, Phase, Position, U64, canonical};

use super::conditional_profile::ConditionalProfile;

/// Checks six acknowledged windows and three genuinely accepted future windows.
pub(super) fn authenticate(
    profile: &ConditionalProfile,
    graph: &AdmittedGraph,
    runtime: &OriginalLineageRuntimeRecord,
) -> Result<(), StateError> {
    let actual_host = crucible_node_provider::conformance::measure_executable(
        std::path::Path::new("/proc/self/exe"),
    )
    .map_err(refused)?;
    if actual_host != profile.host
        || graph.world() != &profile.world
        || graph.node_ids().count() != 3
        || profile
            .bindings
            .iter()
            .any(|binding| graph.binding(&binding.compatibility.node_id) != Some(binding))
        || profile
            .owners
            .iter()
            .any(|owner| graph.owner(&owner.owner.id) != Some(owner))
        || runtime.schema_version != 7
        || runtime.source_activation != (&profile.activation).into()
        || runtime.capture_cut != position(2000)
        || runtime.capture_ordinal != U64::new(6)
        || runtime.operations.len() != 9
        || runtime.inputs.len() != 9
        || runtime.owners.len() != 3
    {
        return Err(refused(
            "changed installed host, complete world or declared cut",
        ));
    }

    for binding in &profile.bindings {
        let node = &binding.compatibility.node_id;
        let original = profile
            .history
            .originals
            .get(node)
            .ok_or_else(|| refused("authenticated original tape is absent"))?;
        let owner = profile
            .activation
            .owners
            .iter()
            .find(|owner| owner.owner == binding.compatibility.execution_owner.id)
            .ok_or_else(|| refused("actual source-capture owner is absent"))?;
        let custody = runtime
            .owners
            .iter()
            .find(|entry| entry.identity == *owner)
            .ok_or_else(|| refused("original owner custody is absent"))?;
        let pending = identity(format!("run/{node}/2"))?;
        if custody.operation.as_ref() != Some(&pending) {
            return Err(refused(
                "owner no longer retains its original pending permission",
            ));
        }

        for quantum in 0..3 {
            let operation = identity(format!("run/{node}/{quantum}"))?;
            let batch = identity(format!("batch/{node}/{quantum}"))?;
            let stage = identity(format!("stage/{node}/{quantum}"))?;
            let entry = runtime
                .operations
                .iter()
                .find(|entry| entry.operation == operation)
                .ok_or_else(|| refused("declared original operation is absent"))?;
            let begin = original
                .transcript()
                .records
                .iter()
                .find(|record| {
                    record.request.action == TranscriptAction::Begin
                        && record.request.identity == operation
                })
                .ok_or_else(|| refused("signed original Begin is absent"))?;
            let metadata = begin.request.request_metadata().map_err(refused)?;
            if metadata.operation.as_ref() != Some(&entry.request)
                || entry.route.node != *node
                || entry.route.owners.as_slice() != std::slice::from_ref(owner)
                || entry.input_batch.as_ref() != Some(&batch)
                || entry.submission_effects.is_some()
            {
                return Err(refused(
                    "original request, owners or input association changed",
                ));
            }
            if quantum == 2 {
                if entry.result != SavedRuntimeResult::Pending
                    || entry.close_submission.is_some()
                    || entry.scheduling_commit.is_some()
                {
                    return Err(refused("future original permission was closed or replaced"));
                }
            } else {
                let SavedRuntimeResult::Acknowledged(outcome) = &entry.result else {
                    return Err(refused("consumed original window is not acknowledged"));
                };
                let commit = entry
                    .scheduling_commit
                    .as_ref()
                    .ok_or_else(|| refused("original scheduling commit is absent"))?;
                if entry.close_submission != Some(Submission::Accepted)
                    || outcome.node != *node
                    || outcome.operation != operation
                    || outcome.owners.as_slice() != std::slice::from_ref(owner)
                    || commit.node != *node
                    || commit.operation != operation
                    || commit.retained_outputs != outcome.retained_outputs
                {
                    return Err(refused("original completed output or ACK custody changed"));
                }
                let observation = outcome
                    .scheduling
                    .as_ref()
                    .ok_or_else(|| refused("actual completed scheduling observation is absent"))?;
                let [publication] = observation.publications.as_slice() else {
                    return Err(refused("native source publication roster differs"));
                };
                let claim = profile
                    .history
                    .publications
                    .iter()
                    .find(|claim| {
                        claim.origin.operation_id == operation
                            && claim.origin.execution_owner_id == owner.owner
                    })
                    .ok_or_else(|| refused("inspected original producer claim is absent"))?;
                let bytes = profile
                    .history
                    .objects
                    .get(&claim.published)
                    .ok_or_else(|| refused("original producer Event bytes are absent"))?;
                let event: Event =
                    serde_json::from_value(canonical::parse_json(bytes, 65_536).map_err(refused)?)
                        .map_err(refused)?;
                if publication.publication_id != event.id
                    || publication.endpoint != event.source
                    || publication.native_sequence != event.source_sequence
                    || publication.publication != event.publication_position
                    || publication.payload != event.payload
                    || profile.history.objects.get(&event.payload)
                        != Some(&publication.payload_bytes)
                    || observation.proof_ref != claim.origin.measurement
                    || !publication.causal_parents.is_empty()
                    || !event.causal_parent_ids.is_empty()
                {
                    return Err(refused(
                        "original native FIFO, Event or complete body differs",
                    ));
                }
            }

            let input = runtime
                .inputs
                .iter()
                .find(|input| {
                    input.node == *node && input.stage_operation == stage && input.batch == batch
                })
                .ok_or_else(|| refused("original input stage is absent"))?;
            let ack = input
                .acknowledgement
                .as_ref()
                .ok_or_else(|| refused("actual original input ACK is absent"))?;
            if input.owners.as_slice() != std::slice::from_ref(owner)
                || input.cutoff != position(quantum * 1000 + 1)
                || input.failure.is_some()
                || !input.committed
                || !input.coordinator_committed
                || ack.node != *node
                || ack.stage_operation != stage
                || ack.batch != batch
                || ack.owners != input.owners
                || ack.cutoff != input.cutoff
                || ack.inventory != input.inventory
                || input.deliveries.len() != input.payloads.len()
            {
                return Err(refused(
                    "original input or accepted ACK association differs",
                ));
            }
            if input.deliveries.is_empty() {
                if input.lineage.is_some() || input.provenance.is_some() {
                    return Err(refused("empty original cut acquired invented lineage"));
                }
            } else {
                let expected = profile
                    .history
                    .inputs
                    .iter()
                    .find(|lineage| {
                        lineage.source.node == *node && lineage.source.stage_operation == stage
                    })
                    .ok_or_else(|| refused("inspected original consumer association is absent"))?;
                if input.lineage.as_ref() != Some(expected)
                    || expected.source.inventory != input.inventory
                    || expected.publications.len() != input.deliveries.len()
                {
                    return Err(refused("FIRST producer/consumer lineage was relabelled"));
                }
                for ((delivery, payload), claim) in input
                    .deliveries
                    .iter()
                    .zip(&input.payloads)
                    .zip(&expected.publications)
                {
                    let bytes = profile
                        .history
                        .objects
                        .get(&claim.published)
                        .ok_or_else(|| refused("original delivered Event is absent"))?;
                    let event: Event = serde_json::from_value(
                        canonical::parse_json(bytes, 65_536).map_err(refused)?,
                    )
                    .map_err(refused)?;
                    if delivery.publication_id != event.id
                        || delivery.producer != event.source.node_id
                        || delivery.producer_endpoint != event.source
                        || delivery.native_sequence != event.source_sequence
                        || delivery.publication != event.publication_position
                        || delivery.payload != event.payload
                        || payload != &event.payload
                        || delivery.provenance_ref != claim.origin.measurement
                    {
                        return Err(refused("ordered original producer/FIFO/body join changed"));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Joins the actual scheduler's three outstanding permissions to Runtime7.
pub(super) fn authenticate_scheduler(
    profile: &ConditionalProfile,
    runtime: &OriginalLineageRuntimeRecord,
    scheduler: &SchedulingSnapshot,
) -> Result<(), StateError> {
    // Every pending Begin still owns its staged deliveries: only authenticated
    // consumption removes them from the scheduler, never Stage or acceptance.
    let pending_count = runtime
        .inputs
        .iter()
        .filter(|input| {
            runtime.operations.iter().any(|operation| {
                operation.result == SavedRuntimeResult::Pending
                    && operation.route.node == input.node
                    && operation.input_batch.as_ref() == Some(&input.batch)
            })
        })
        .try_fold(0usize, |count, input| {
            count
                .checked_add(input.deliveries.len())
                .filter(|count| *count <= 64)
                .ok_or_else(|| refused("pending scheduler delivery credit exhausted"))
        })?;
    if scheduler.schema_version != 1
        || scheduler.original_epochs.is_some()
        || !scheduler.external_closed_prefixes.is_empty()
        || scheduler.ordering_profile != profile.world.ordering_profile
        || scheduler.world_binding_hash != runtime.source_activation.world_binding_hash
        || scheduler.source_activation_id != runtime.source_activation.activation_id
        || scheduler.source_generation != runtime.source_activation.generation
        || scheduler.source_boundary != runtime.source_activation.boundary
        || scheduler.capture_cut != runtime.capture_cut
        || scheduler.capture_ordinal != runtime.capture_ordinal
        || scheduler.source_owners.len() != 3
        || scheduler.positions.len() != 3
        || scheduler.reservations.len() != 3
        || scheduler.input_batches.len() != 3
        || scheduler.used_operations.len() != 18
        || scheduler.used_input_batches.len() != 9
        || scheduler.pending_deliveries.len() != pending_count
        || scheduler
            .pending_deliveries
            .windows(2)
            .any(|pair| pair[0].key() >= pair[1].key())
    {
        return Err(refused(
            "changed scheduler edition, activation or pending roster",
        ));
    }
    for owner in &profile.activation.owners {
        if !scheduler.source_owners.iter().any(|saved| {
            saved.owner == owner.owner
                && saved.incarnation == owner.incarnation
                && saved.generation == owner.generation
        }) || !scheduler
            .positions
            .iter()
            .any(|saved| saved.owner == owner.owner && saved.position == runtime.capture_cut)
        {
            return Err(refused(
                "scheduler owner or original reached boundary changed",
            ));
        }
    }
    for operation in &runtime.operations {
        if !scheduler.used_operations.contains(&operation.operation) {
            return Err(refused("scheduler omitted an original used operation"));
        }
        if operation.result != SavedRuntimeResult::Pending {
            continue;
        }
        let reservation = scheduler
            .reservations
            .iter()
            .find(|saved| saved.operation == operation.operation)
            .ok_or_else(|| refused("original pending scheduler reservation is absent"))?;
        let OperationRequest::QuantumBegin {
            window,
            start,
            end,
            input_batch,
            host_budget,
        } = &operation.request
        else {
            return Err(refused("original pending permission changed grammar"));
        };
        let budget = u64::try_from(host_budget.as_nanos()).map_err(refused)?;
        let expected = SavedPermission::Quantum {
            window: window.clone(),
            start: *start,
            end: *end,
            input_batch: input_batch.clone(),
            host_budget_ns: U64::new(budget),
        };
        if reservation.node != operation.route.node
            || operation.route.owners.len() != 1
            || reservation.owner != operation.route.owners[0].owner
            || reservation.permission != expected
            || reservation.input_batch != operation.input_batch
            || *start != runtime.capture_cut
            || *end != Position::new(U64::new(3000), U64::new(0), Phase::Publication)
        {
            return Err(refused(
                "scheduler replaced or widened the original q2 permission",
            ));
        }
        let input = runtime
            .inputs
            .iter()
            .find(|input| input.node == operation.route.node && input.batch == *input_batch)
            .ok_or_else(|| refused("pending original runtime input is absent"))?;
        let saved = scheduler
            .input_batches
            .iter()
            .find(|saved| saved.node == input.node && saved.batch == input.batch)
            .ok_or_else(|| refused("pending original scheduler input is absent"))?;
        if saved.owner != reservation.owner
            || saved.stage_operation != input.stage_operation
            || saved.owners != input.owners
            || saved.cutoff != input.cutoff
            || saved.inventory != input.inventory
            || saved.deliveries != input.deliveries
            || input
                .deliveries
                .iter()
                .any(|delivery| !scheduler.pending_deliveries.contains(delivery))
            || saved.payloads.len() != input.payloads.len()
            || saved
                .payloads
                .iter()
                .zip(&input.payloads)
                .any(|(body, reference)| {
                    body.reference != *reference || reference.verify(&body.bytes).is_err()
                })
            || saved.acknowledgement != input.acknowledgement
            || saved.activated_by.as_ref() != Some(&operation.operation)
            || !saved.consumed.is_empty()
        {
            return Err(refused(
                "scheduler input, native ACK or consumed prefix changed",
            ));
        }
    }
    // StageInput and Run admissions both remain in the original used-ID set.
    // The exact eighteen-ID roster includes every original stage and quantum.
    for input in &runtime.inputs {
        if !scheduler.used_input_batches.contains(&input.batch)
            || !scheduler.used_operations.contains(&input.stage_operation)
        {
            return Err(refused(
                "scheduler omitted an original input batch or Stage ID",
            ));
        }
    }
    Ok(())
}

fn position(tick: u64) -> Position {
    Position::new(U64::new(tick), U64::new(0), Phase::BoundaryControl)
}

fn identity(value: String) -> Result<Id, StateError> {
    Id::new(value).map_err(refused)
}

pub(super) fn refused(error: impl std::fmt::Display) -> StateError {
    StateError::new(
        StateErrorCode::NativeEvidence,
        "installed conditional Runtime7",
        error.to_string(),
    )
}
