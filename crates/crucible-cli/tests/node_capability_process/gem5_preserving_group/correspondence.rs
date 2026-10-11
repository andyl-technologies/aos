//! Checks twin suffix correspondence against each side's unchanged runtime custody.
//!
//! These checks consume archive data only. They do not authenticate native bodies,
//! issue continuation authority, or replace the installed archive verifier.

use super::*;
use crucible_core::{
    node_admission::{ConnectionDelivery, ConnectionPolicy, VisibilityConversion},
    node_contract::{OperationRequest, SavedRuntimeInput, SavedRuntimeOperation},
    node_scheduling::{NativeSchedulingObservation, event::Delivery},
};
use crucible_node_contract::{Endpoint, Position};
use std::collections::{BTreeMap, BTreeSet};

#[path = "correspondence_tests.rs"]
mod tests;

type Checked<T> = Result<T, &'static str>;
type PublicationKey = (Id, Endpoint, crucible_node_contract::U64);

struct PublicationCustody<'a> {
    operation: &'a SavedRuntimeOperation,
    observation: &'a NativeSchedulingObservation,
    publication: &'a NativePublication,
}

struct Side<'a> {
    publications: BTreeMap<Id, PublicationCustody<'a>>,
    inputs: &'a [SavedRuntimeInput],
    operations: &'a [SavedRuntimeOperation],
}

struct SelectedRoute {
    connection: Id,
    producer: Endpoint,
    consumer: Endpoint,
    policy: ContentRef,
    latency_ps: crucible_node_contract::U64,
}

impl SelectedRoute {
    fn from_scenario(scenario: &NodeScenario) -> Checked<Self> {
        let [connection] = scenario.world.connections.as_slice() else {
            return Err("fixture requires its one original Script-to-Block route");
        };
        let body = scenario
            .content
            .iter()
            .find(|body| body.reference == connection.policy_ref)
            .ok_or("original connection policy body missing")?;
        connection
            .policy_ref
            .verify(&body.bytes)
            .map_err(|_| "connection policy body changed")?;
        let policy: ConnectionPolicy = serde_json::from_slice(&body.bytes)
            .map_err(|_| "original connection policy grammar changed")?;
        if policy.visibility != VisibilityConversion::Direct
            || connection.producer.node_id.as_str() != "source-a"
            || connection.consumer.node_id.as_str() != "disk-a"
        {
            return Err("fixture connection is outside its closed direct route");
        }
        let ConnectionDelivery::Fixed { latency_ps } = policy.delivery;
        Ok(Self {
            connection: connection.id.clone(),
            producer: connection.producer.clone(),
            consumer: connection.consumer.clone(),
            policy: connection.policy_ref.clone(),
            latency_ps,
        })
    }

    fn validate(&self, delivery: &Delivery) -> Checked<()> {
        let expected = crucible_core::node_scheduling::event::direct_delivery(
            delivery.publication,
            self.latency_ps,
            None,
        )
        .map_err(|_| "original delivery coordinate invalid")?;
        if delivery.connection_id.as_ref() != Some(&self.connection)
            || delivery.connection_policy_ref.as_ref() != Some(&self.policy)
            || delivery.external_root.is_some()
            || delivery.producer_endpoint != self.producer
            || delivery.consumer_endpoint != self.consumer
            || delivery.delivery != expected
        {
            return Err("original routed delivery changed");
        }
        Ok(())
    }
}

fn inspect<'a>(
    runtime: &'a RuntimeSnapshot,
    rows: &[(Id, NativePublication)],
) -> Checked<Side<'a>> {
    if runtime.schema_version != 1 || runtime.condition_stop.is_some() || runtime.terminal.is_some()
    {
        return Err("comparator requires its plain four-owner runtime selection");
    }
    let mut side = Side {
        publications: BTreeMap::new(),
        inputs: &runtime.inputs,
        operations: &runtime.operations,
    };
    let mut operations = BTreeSet::new();
    for operation in &runtime.operations {
        if !operations.insert(&operation.operation) {
            return Err("duplicate original operation");
        }
        let SavedRuntimeResult::Acknowledged(outcome) = &operation.result else {
            return Err("unacknowledged original operation");
        };
        if outcome.operation != operation.operation
            || outcome.node != operation.route.node
            || outcome.owners != operation.route.owners
        {
            return Err("foreign original outcome owner or operation");
        }
        let Some(observation) = &outcome.scheduling else {
            if !outcome.retained_outputs.is_empty() {
                return Err("original outputs lack native observation");
            }
            continue;
        };
        let commit = operation
            .scheduling_commit
            .as_ref()
            .ok_or("original scheduling commit missing")?;
        let outputs: Vec<_> = observation
            .publications
            .iter()
            .map(|publication| publication.publication_id.clone())
            .collect();
        if observation.node != outcome.node
            || observation.owners != outcome.owners
            || commit.node != outcome.node
            || commit.operation != outcome.operation
            || commit.retained_outputs != outcome.retained_outputs
            || outputs != outcome.retained_outputs
        {
            return Err("original publication commitment changed");
        }
        for publication in &observation.publications {
            let (start, limit) = exact_interval(&operation.request)?;
            let evaluation = publication
                .evaluation
                .ok_or("exact original output evaluation missing")?;
            if evaluation < start || evaluation >= limit {
                return Err("original publication evaluation outside exact permission");
            }
            publication
                .payload
                .verify(&publication.payload_bytes)
                .map_err(|_| "original publication body changed")?;
            if publication.endpoint.node_id != outcome.node
                || side
                    .publications
                    .insert(
                        publication.publication_id.clone(),
                        PublicationCustody {
                            operation,
                            observation,
                            publication,
                        },
                    )
                    .is_some()
            {
                return Err("foreign or duplicate original publication");
            }
        }

        match (&operation.input_batch, &observation.input_progress) {
            (Some(batch), Some(progress)) if batch == &progress.batch => {
                let input = unique_input(&runtime.inputs, batch)?;
                if input.node != outcome.node
                    || input.owners != outcome.owners
                    || progress.proof_ref != observation.proof_ref
                    || progress.consumed.len() > input.deliveries.len()
                {
                    return Err("foreign original consumption frontier");
                }
                for (identity, delivery) in progress.consumed.iter().zip(&input.deliveries) {
                    if identity.producer != delivery.producer
                        || identity.source_sequence != delivery.source_sequence
                        || delivery.delivery > observation.reached
                    {
                        return Err("original consumed prefix changed");
                    }
                }
            }
            (None, None) => {}
            _ => return Err("original operation and input progress disagree"),
        }
    }

    let mut batches = BTreeSet::new();
    let mut staging_operations = BTreeSet::new();
    for input in &runtime.inputs {
        if !batches.insert(&input.batch)
            || !staging_operations.insert(&input.stage_operation)
            || operations.contains(&input.stage_operation)
        {
            return Err("duplicate original input batch or staging operation");
        }
        validate_input(&side, input)?;
    }
    let mut suffix_ids = BTreeSet::new();
    for (node, publication) in rows {
        let original = side
            .publications
            .get(&publication.publication_id)
            .ok_or("suffix publication lacks original operation")?;
        if !suffix_ids.insert(&publication.publication_id)
            || node != &original.operation.route.node
            || publication != original.publication
        {
            return Err("suffix publication differs from original native custody");
        }
    }
    Ok(side)
}

fn unique_input<'a>(inputs: &'a [SavedRuntimeInput], batch: &Id) -> Checked<&'a SavedRuntimeInput> {
    let mut matching = inputs.iter().filter(|input| &input.batch == batch);
    let input = matching.next().ok_or("original consumed batch missing")?;
    if matching.next().is_some() {
        return Err("ambiguous original consumed batch");
    }
    Ok(input)
}

fn validate_input(side: &Side<'_>, input: &SavedRuntimeInput) -> Checked<()> {
    if input.provenance.is_some() {
        return Err("plain Host Block fixture does not select an input provenance sidecar");
    }
    let ack = input
        .acknowledgement
        .as_ref()
        .ok_or("original staging ACK missing")?;
    if !input.committed
        || !input.coordinator_committed
        || input.failure.is_some()
        || ack.stage_operation != input.stage_operation
        || ack.batch != input.batch
        || ack.node != input.node
        || ack.owners != input.owners
        || ack.cutoff != input.cutoff
        || ack.inventory != input.inventory
    {
        return Err("original staging custody changed");
    }
    let inventory = canonical::canonical_json(
        &serde_json::to_value(&input.deliveries)
            .map_err(|_| "input inventory serialization failed")?,
    )
    .map_err(|_| "input inventory canonicalization failed")?;
    input
        .inventory
        .verify(&inventory)
        .map_err(|_| "original input inventory changed")?;
    if input
        .deliveries
        .windows(2)
        .any(|pair| pair[0].key() >= pair[1].key())
    {
        return Err("original delivery order changed");
    }
    let expected_payloads: BTreeSet<_> = input
        .deliveries
        .iter()
        .map(|delivery| &delivery.payload)
        .collect();
    let mut actual_payloads = BTreeSet::new();
    for payload in &input.payloads {
        if !actual_payloads.insert(&payload.reference) {
            return Err("duplicate original input payload");
        }
        payload
            .reference
            .verify(&payload.bytes)
            .map_err(|_| "input payload body changed")?;
    }
    if expected_payloads != actual_payloads {
        return Err("original input payload roster changed");
    }
    for delivery in &input.deliveries {
        let custody = side
            .publications
            .get(&delivery.publication_id)
            .ok_or("original delivery producer operation missing")?;
        let publication = custody.publication;
        let payloads: Vec<_> = input
            .payloads
            .iter()
            .filter(|payload| payload.reference == delivery.payload)
            .collect();
        if delivery.producer != custody.operation.route.node
            || delivery.consumer != input.node
            || delivery.consumer_endpoint.node_id != input.node
            || delivery.producer_endpoint != publication.endpoint
            || delivery.provenance_ref != custody.observation.proof_ref
            || delivery.native_sequence != publication.native_sequence
            || delivery.publication != publication.publication
            || delivery.evaluation != publication.evaluation
            || delivery.causal_parents != publication.causal_parents
            || delivery.payload != publication.payload
            || delivery.delivery >= input.cutoff
            || payloads.len() != 1
            || payloads[0].bytes != publication.payload_bytes
        {
            return Err("original full delivery association changed");
        }
    }
    Ok(())
}

fn own_parent<'a>(
    side: &Side<'a>,
    operation: &SavedRuntimeOperation,
    observation: &NativeSchedulingObservation,
    position: Position,
) -> Checked<&'a Delivery> {
    let batch = operation
        .input_batch
        .as_ref()
        .ok_or("original consumer batch missing")?;
    let progress = observation
        .input_progress
        .as_ref()
        .ok_or("original consumer progress missing")?;
    let input = unique_input(side.inputs, batch)?;
    let mut matching = input
        .deliveries
        .iter()
        .take(progress.consumed.len())
        .filter(|delivery| delivery.delivery == position);
    let delivery = matching
        .next()
        .ok_or("causal edge outside producing operation consumed prefix")?;
    if matching.next().is_some() || input.node != operation.route.node {
        return Err("ambiguous or foreign operation-bound causal edge");
    }
    Ok(delivery)
}

fn exact_interval(request: &OperationRequest) -> Checked<(Position, Position)> {
    match request {
        OperationRequest::ExactRun { start, limit, .. }
        | OperationRequest::BoundarySettle { start, limit } => Ok((*start, *limit)),
        _ => Err("historical pending response lacks exact original interval"),
    }
}

fn parent<'a>(
    side: &Side<'a>,
    producing: &PublicationCustody<'_>,
    position: Position,
) -> Checked<&'a Delivery> {
    let evaluation = producing
        .publication
        .evaluation
        .ok_or("Block response evaluation missing")?;
    if position > evaluation {
        return Err("response parent follows original evaluation");
    }
    if producing.operation.input_batch.is_some() {
        return own_parent(side, producing.operation, producing.observation, position);
    }

    // The scheduler retires a fully consumed batch before a later grant can
    // complete its pending Block request. The native9 archive reader separately
    // checks the retained pending body; this branch checks only its earlier
    // acknowledged runtime-consumption relationship, never native authority.
    let (start, limit) = exact_interval(&producing.operation.request)?;
    if evaluation < start || evaluation >= limit {
        return Err("pending response evaluation outside original grant");
    }
    let mut original = None;
    for consumer in side.operations {
        if consumer.operation == producing.operation.operation
            || consumer.route.node != producing.operation.route.node
            || consumer.input_batch.is_none()
            || consumer
                .route
                .owners
                .iter()
                .map(|owner| &owner.owner)
                .ne(producing
                    .operation
                    .route
                    .owners
                    .iter()
                    .map(|owner| &owner.owner))
        {
            continue;
        }
        let SavedRuntimeResult::Acknowledged(outcome) = &consumer.result else {
            continue;
        };
        let Some(observation) = &outcome.scheduling else {
            continue;
        };
        let (consumer_start, consumer_limit) = exact_interval(&consumer.request)?;
        if observation.reached < consumer_start
            || observation.reached > consumer_limit
            || observation.reached > start
        {
            continue;
        }
        let Ok(delivery) = own_parent(side, consumer, observation, position) else {
            continue;
        };
        if delivery.delivery > observation.reached || original.replace(delivery).is_some() {
            return Err("ambiguous historical original consumption");
        }
    }
    original.ok_or("causal edge lacks earlier acknowledged original consumption")
}

fn key(custody: &PublicationCustody<'_>) -> PublicationKey {
    (
        custody.operation.route.node.clone(),
        custody.publication.endpoint.clone(),
        custody.publication.native_sequence,
    )
}

fn same_semantics(left: &NativePublication, right: &NativePublication) -> bool {
    left.endpoint == right.endpoint
        && left.native_sequence == right.native_sequence
        && left.publication == right.publication
        && left.evaluation == right.evaluation
        && left.causal_parents == right.causal_parents
        && left.payload == right.payload
        && left.payload_bytes == right.payload_bytes
}

fn compare_sides(
    left: &Side<'_>,
    right: &Side<'_>,
    route: &SelectedRoute,
) -> Checked<BTreeMap<Id, Id>> {
    let mut right_by_fifo = BTreeMap::new();
    for custody in right.publications.values() {
        if right_by_fifo.insert(key(custody), custody).is_some() {
            return Err("ambiguous original native FIFO");
        }
    }
    let mut correspondence = BTreeMap::new();
    for custody in left.publications.values() {
        let other = right_by_fifo
            .remove(&key(custody))
            .ok_or("twin original publication missing")?;
        if !same_semantics(custody.publication, other.publication) {
            return Err("twin publication or causal positions changed");
        }
        correspondence.insert(
            custody.publication.publication_id.clone(),
            other.publication.publication_id.clone(),
        );
    }
    if !right_by_fifo.is_empty() {
        return Err("twin contains foreign original publication");
    }

    for side in [left, right] {
        for input in side.inputs {
            for delivery in &input.deliveries {
                route.validate(delivery)?;
            }
        }
    }
    for custody in left.publications.values() {
        let publication = custody.publication;
        let other = &right.publications[&correspondence[&publication.publication_id]];
        let expected_parents = usize::from(custody.operation.route.node == route.consumer.node_id);
        if publication.causal_parents.len() != expected_parents {
            return Err("closed fixture causal edge missing or foreign");
        }
        for position in &publication.causal_parents {
            let original = parent(left, custody, *position)?;
            let target = parent(right, other, *position)?;
            if correspondence.get(&original.publication_id) != Some(&target.publication_id)
                || original.producer != target.producer
                || original.consumer != target.consumer
                || original.source_sequence != target.source_sequence
                || original.native_sequence != target.native_sequence
                || original.evaluation != target.evaluation
                || original.causal_parents != target.causal_parents
                || original.publication != target.publication
                || original.delivery != target.delivery
                || original.payload != target.payload
            {
                return Err("twin original routed causal edge changed");
            }
        }
    }
    Ok(correspondence)
}

/// Checks complete retained suffix correspondence for the closed four-owner fixture.
///
/// # Errors
/// Refuses missing or changed original operation, publication, input, ACK or
/// causal-edge custody, unsupported fixture scope, or unequal twin semantics.
pub(super) fn compare(
    scenario: &NodeScenario,
    left: &(RuntimeSnapshot, Vec<(Id, NativePublication)>),
    right: &(RuntimeSnapshot, Vec<(Id, NativePublication)>),
) -> Checked<BTreeMap<Id, Id>> {
    let route = SelectedRoute::from_scenario(scenario)?;
    let source = inspect(&left.0, &left.1)?;
    let target = inspect(&right.0, &right.1)?;
    let correspondence = compare_sides(&source, &target, &route)?;
    if left.1.len() != right.1.len() {
        return Err("twin suffix count changed");
    }
    for ((left_node, left_output), (right_node, right_output)) in left.1.iter().zip(&right.1) {
        if left_node != right_node
            || correspondence.get(&left_output.publication_id) != Some(&right_output.publication_id)
        {
            return Err("twin suffix original order changed");
        }
    }
    Ok(correspondence)
}
