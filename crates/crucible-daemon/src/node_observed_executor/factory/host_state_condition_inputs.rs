//! Closed Block publication and original stopped-consumer input association.
//!
//! This installed codec has one output lane and one direct recipient per Block
//! producer. Its complete committed native publication prefix is regenerated
//! from original runtime operations and checked against both saved counters.
//! Native FIFO identities remain separate from common recipient sequences.

use super::*;
use crucible::node_admission::{ConnectionDelivery, VisibilityConversion};
use crucible::node_contract::{OwnerIdentity, SavedRuntimeOperation};
use crucible::node_scheduling::{NativePublication, NativeSchedulingObservation, event::Delivery};
use crucible_node_contract::{Direction, Endpoint, U64};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockReceipt {
    schema_version: u16,
    profile: String,
    node: Id,
    owners: Vec<OwnerIdentity>,
    boundary: Position,
    native: ContentRef,
    native_sequence: U64,
    #[serde(deserialize_with = "required_nullable")]
    input: Option<(Id, ContentRef, U64)>,
    pending_causes: ContentRef,
}

// Native receipts always carry this key, including an explicit null. An absent
// key cannot substitute for authentic no-input custody.
fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

// Complete results with an authentic scheduling commit may still retain their
// native output ACK handle. This prefix preserves that held custody rather than
// claiming that every producer operation has already been acknowledged.

struct OriginalPublication<'a> {
    operation: &'a SavedRuntimeOperation,
    observation: &'a NativeSchedulingObservation,
    publication: &'a NativePublication,
}

impl InstalledHostStateFactory {
    pub(in super::super) fn authenticate_condition_inputs(
        &self,
        graph: &AdmittedGraph,
        runtime: &RuntimeSnapshot,
        scheduler: &SchedulingSnapshot,
        content: &VerifiedStateContent,
    ) -> Result<(), StateError> {
        for selected in self.selections.values() {
            if !matches!(
                selected.kind,
                InstalledNodeKind::HostIo {
                    profile: super::super::super::io::InstalledHostIoProfile::Block { .. }
                }
            ) {
                continue;
            }
            let originals = original_prefix(graph, runtime, scheduler, &selected.node)?;
            for input in &runtime.inputs {
                let Some(provenance) = &input.provenance else {
                    continue;
                };
                if !matches!(
                    self.selection(&input.node)?.kind,
                    InstalledNodeKind::HostConditionDebugPreserving { .. }
                ) || provenance.node != input.node
                    || provenance.stage_operation != input.stage_operation
                    || provenance.batch != input.batch
                    || provenance.inventory != input.inventory
                {
                    return Err(refusal(
                        "condition original native input proof scope changed",
                    ));
                }
                for object in &provenance.objects {
                    if content.get(&object.reference) != Some(object.bytes.as_slice()) {
                        return Err(refusal("condition original input proof body absent"));
                    }
                }
                for delivery in input
                    .deliveries
                    .iter()
                    .filter(|d| d.producer == selected.node)
                {
                    authenticate_delivery(self, graph, runtime, content, &originals, delivery)?;
                    if !provenance.roots.contains(&delivery.provenance_ref)
                        || !provenance
                            .objects
                            .iter()
                            .any(|body| body.reference == delivery.provenance_ref)
                    {
                        return Err(refusal(
                            "condition original input native proof root changed",
                        ));
                    }
                }
            }
            // Pending rows and native-staged rows use the same original tuple
            // predicate; a representation cannot weaken production provenance.
            for delivery in scheduler
                .pending_deliveries
                .iter()
                .chain(
                    scheduler
                        .input_batches
                        .iter()
                        .flat_map(|input| &input.deliveries),
                )
                .filter(|delivery| delivery.producer == selected.node)
            {
                authenticate_delivery(self, graph, runtime, content, &originals, delivery)?;
            }
        }
        Ok(())
    }
}

fn original_prefix<'a>(
    graph: &AdmittedGraph,
    runtime: &'a RuntimeSnapshot,
    scheduler: &SchedulingSnapshot,
    producer: &Id,
) -> Result<Vec<OriginalPublication<'a>>, StateError> {
    let descriptor = graph
        .descriptor(producer)
        .ok_or_else(|| refusal("condition original Block descriptor absent"))?;
    let mut lanes = descriptor.ports.iter().flat_map(|port| {
        port.lanes
            .iter()
            .filter(|lane| lane.direction == Direction::Output)
            .map(move |lane| Endpoint {
                node_id: producer.clone(),
                port_id: port.id.clone(),
                lane_id: lane.id.clone(),
            })
    });
    let endpoint = lanes
        .next()
        .ok_or_else(|| refusal("condition Block output lane absent"))?;
    if lanes.next().is_some() {
        return Err(refusal(
            "condition Block prefix has unsupported output-lane merge",
        ));
    }
    let mut count = 0usize;
    for operation in runtime
        .operations
        .iter()
        .filter(|op| &op.route.node == producer)
    {
        let outcome = match &operation.result {
            SavedRuntimeResult::Complete(outcome) | SavedRuntimeResult::Acknowledged(outcome) => {
                outcome
            }
            _ => return Err(refusal("condition original Block prefix is unresolved")),
        };
        let observation = outcome
            .scheduling
            .as_ref()
            .ok_or_else(|| refusal("condition original Block observation absent"))?;
        let commit = operation
            .scheduling_commit
            .as_ref()
            .ok_or_else(|| refusal("condition original Block output commitment absent"))?;
        if observation.node != *producer
            || commit.node != *producer
            || commit.operation != operation.operation
            || commit.retained_outputs != outcome.retained_outputs
            || observation
                .publications
                .iter()
                .map(|p| &p.publication_id)
                .ne(commit.retained_outputs.iter())
        {
            return Err(refusal(
                "condition original Block terminal commitment changed",
            ));
        }
        count = count
            .checked_add(observation.publications.len())
            .filter(|count| *count <= 4096)
            .ok_or_else(|| refusal("condition original publication credit exhausted"))?;
    }
    let mut originals = Vec::new();
    originals.try_reserve_exact(count).map_err(state_error)?;
    for operation in runtime
        .operations
        .iter()
        .filter(|op| &op.route.node == producer)
    {
        let outcome = match &operation.result {
            SavedRuntimeResult::Complete(outcome) | SavedRuntimeResult::Acknowledged(outcome) => {
                outcome
            }
            _ => return Err(refusal("condition original Block prefix is unresolved")),
        };
        let observation = outcome
            .scheduling
            .as_ref()
            .ok_or_else(|| refusal("condition original Block observation absent"))?;
        for publication in &observation.publications {
            originals.push(OriginalPublication {
                operation,
                observation,
                publication,
            });
        }
    }
    originals.sort_by_key(|original| original.publication.native_sequence);
    for (index, original) in originals.iter().enumerate() {
        if original.publication.endpoint != endpoint
            || original.publication.native_sequence.get() != index as u64
            || originals[..index].iter().any(|previous| {
                previous.publication.publication_id == original.publication.publication_id
            })
        {
            return Err(refusal(
                "condition original Block publication prefix is incomplete or ambiguous",
            ));
        }
    }
    let saved = scheduler
        .producers
        .iter()
        .find(|saved| &saved.node == producer)
        .ok_or_else(|| refusal("condition original common producer counter absent"))?;
    let lane = scheduler
        .native_sequences
        .iter()
        .find(|saved| saved.endpoint == endpoint);
    if saved.next_sequence != Some(U64::new(count as u64))
        || lane.map(|saved| saved.last_sequence)
            != originals
                .last()
                .map(|original| original.publication.native_sequence)
    {
        return Err(refusal(
            "condition original native/common publication counters differ",
        ));
    }
    Ok(originals)
}

fn authenticate_delivery(
    factory: &InstalledHostStateFactory,
    graph: &AdmittedGraph,
    runtime: &RuntimeSnapshot,
    content: &VerifiedStateContent,
    originals: &[OriginalPublication<'_>],
    delivery: &Delivery,
) -> Result<(), StateError> {
    let (sequence, original) = originals
        .iter()
        .enumerate()
        .find(|(_, original)| original.publication.publication_id == delivery.publication_id)
        .ok_or_else(|| refusal("condition original Block publication absent"))?;
    let publication = original.publication;
    let mut routes = factory
        .scenario
        .world
        .connections
        .iter()
        .filter(|route| route.producer == publication.endpoint);
    let route = routes
        .next()
        .ok_or_else(|| refusal("condition original response connection absent"))?;
    if routes.next().is_some() {
        return Err(refusal(
            "condition Block prefix has unsupported recipient fanout",
        ));
    }
    let policy = graph
        .connection_policy(&route.id)
        .ok_or_else(|| refusal("condition original response policy absent"))?;
    if policy.visibility != VisibilityConversion::Direct
        || policy.delivery
            != (ConnectionDelivery::Fixed {
                latency_ps: U64::new(0),
            })
    {
        return Err(refusal("condition original direct response policy changed"));
    }
    let expected = crucible::node_scheduling::event::direct_delivery(
        publication.publication,
        U64::new(0),
        None,
    )
    .map_err(state_error)?;
    if delivery.connection_id.as_ref() != Some(&route.id)
        || delivery.connection_policy_ref.as_ref() != Some(&route.policy_ref)
        || delivery.external_root.is_some()
        || delivery.producer != publication.endpoint.node_id
        || delivery.consumer != route.consumer.node_id
        || delivery.producer_endpoint != publication.endpoint
        || delivery.consumer_endpoint != route.consumer
        || delivery.source_sequence.get() != sequence as u64
        || delivery.native_sequence != publication.native_sequence
        || delivery.publication != publication.publication
        || delivery.evaluation != publication.evaluation
        || delivery.delivery != expected
        || delivery.payload != publication.payload
        || delivery.causal_parents != publication.causal_parents
        || delivery.provenance_ref != original.observation.proof_ref
        || content.get(&publication.payload) != Some(publication.payload_bytes.as_slice())
    {
        return Err(refusal(
            "condition complete original response Delivery changed",
        ));
    }
    let mut associations = runtime.operations.iter().filter(|operation| {
        operation.route.node == delivery.producer
            && match &operation.result {
                SavedRuntimeResult::Complete(outcome)
                | SavedRuntimeResult::Acknowledged(outcome) => outcome
                    .scheduling
                    .as_ref()
                    .is_some_and(|observation| observation.proof_ref == delivery.provenance_ref),
                _ => false,
            }
    });
    if associations.next().map(|operation| &operation.operation)
        != Some(&original.operation.operation)
        || associations.next().is_some()
    {
        return Err(refusal(
            "condition native receipt terminal association is ambiguous",
        ));
    }
    let bytes = content
        .get(&delivery.provenance_ref)
        .ok_or_else(|| refusal("condition original native receipt body absent"))?;
    delivery.provenance_ref.verify(bytes).map_err(state_error)?;
    let receipt: BlockReceipt = serde_json::from_slice(bytes).map_err(state_error)?;
    if receipt.schema_version != 1
        || receipt.profile != crucible::node_adapters::HOST_EXACT_PROFILE
        || receipt.node != original.operation.route.node
        || receipt.owners != original.operation.route.owners
        || receipt.boundary != original.observation.reached
        || Some(receipt.native_sequence.get())
            != original
                .observation
                .publications
                .iter()
                .map(|publication| publication.native_sequence.get())
                .max()
                .and_then(|sequence| sequence.checked_add(1))
        || receipt.native == receipt.pending_causes
        || content.get(&receipt.native).is_none()
        || content.get(&receipt.pending_causes).is_none()
    {
        return Err(refusal(
            "condition original native receipt owner/input/boundary changed",
        ));
    }
    authenticate_receipt_input(runtime, original, &receipt)?;
    Ok(())
}

// A later grant may retain a completely consumed native staging handle. It
// cannot substitute another acknowledged batch for the operation's own input.
fn authenticate_receipt_input(
    runtime: &RuntimeSnapshot,
    original: &OriginalPublication<'_>,
    receipt: &BlockReceipt,
) -> Result<(), StateError> {
    let Some((batch, inventory, consumed)) = &receipt.input else {
        return if original.operation.input_batch.is_none()
            && original.observation.input_progress.is_none()
        {
            Ok(())
        } else {
            Err(refusal("condition original operation input receipt absent"))
        };
    };
    let input = runtime
        .inputs
        .iter()
        .find(|input| {
            input.node == receipt.node && input.batch == *batch && input.inventory == *inventory
        })
        .ok_or_else(|| refusal("condition original receipt input inventory changed"))?;
    if !input.committed
        || input.failure.is_some()
        || input.acknowledgement.is_none()
        || input.owners != original.operation.route.owners
        || consumed.get() > input.deliveries.len() as u64
    {
        return Err(refusal(
            "condition original receipt input owner or ACK changed",
        ));
    }
    let matches_progress =
        |observation: &NativeSchedulingObservation| {
            observation.input_progress.as_ref().is_some_and(|progress| {
                progress.batch == *batch
                    && progress.consumed.len() as u64 == consumed.get()
                    && progress.consumed.iter().zip(&input.deliveries).all(
                        |(identity, delivery)| {
                            identity.producer == delivery.producer
                                && identity.source_sequence == delivery.source_sequence
                        },
                    )
            })
        };
    if let Some(operation_batch) = &original.operation.input_batch {
        if operation_batch != batch || !matches_progress(original.observation) {
            return Err(refusal(
                "condition operation-bound consumed input frontier changed",
            ));
        }
    } else if consumed.get() != input.deliveries.len() as u64
        || original.observation.input_progress.is_some()
        || !runtime.operations.iter().any(|operation| {
            operation.route == original.operation.route
                && operation.input_batch.as_ref() == Some(batch)
                && match &operation.result {
                    SavedRuntimeResult::Complete(outcome)
                    | SavedRuntimeResult::Acknowledged(outcome) => {
                        outcome.scheduling.as_ref().is_some_and(|observation| {
                            observation.reached <= receipt.boundary && matches_progress(observation)
                        })
                    }
                    _ => false,
                }
        })
    {
        return Err(refusal(
            "condition retained historical batch lacks original complete frontier",
        ));
    }
    Ok(())
}

// This data-only control invokes the same closed receipt decoder on a genuine
// original body and a freshly hashed body with its required input key removed.
#[cfg(test)]
pub(super) fn verify_required_input_key(body: &[u8]) -> Result<(), StateError> {
    let _: BlockReceipt = serde_json::from_slice(body).map_err(state_error)?;
    let mut changed: serde_json::Value = serde_json::from_slice(body).map_err(state_error)?;
    changed
        .as_object_mut()
        .ok_or_else(|| refusal("actual Block receipt is not an object"))?
        .remove("input")
        .ok_or_else(|| refusal("actual Block receipt input key absent"))?;
    let bytes = canonical::canonical_json(&changed).map_err(state_error)?;
    let reference = canonical::content_ref(&bytes, "application/json").map_err(state_error)?;
    reference.verify(&bytes).map_err(state_error)?;
    let failure = serde_json::from_slice::<BlockReceipt>(&bytes)
        .err()
        .ok_or_else(|| refusal("missing original Block input key was accepted"))?;
    if !failure.to_string().contains("missing field `input`") {
        return Err(refusal(
            "missing Block input key failed at a different predicate",
        ));
    }
    Ok(())
}
