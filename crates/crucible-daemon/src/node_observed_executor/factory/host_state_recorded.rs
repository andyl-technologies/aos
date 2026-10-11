//! Complete original external FIFO and consumed ledger authentication.

use super::*;
use crucible::node_adapters::RecordedIngressDefinition;
use crucible::node_scheduling::event::Delivery;
use crucible_node_contract::U64;

impl InstalledHostStateFactory {
    pub(super) fn authenticate_recorded_provenance(
        &self,
        graph: &AdmittedGraph,
        runtime: &RuntimeSnapshot,
        content: &VerifiedStateContent,
    ) -> Result<(), StateError> {
        let selected = self
            .selections
            .values()
            .next()
            .ok_or_else(|| refusal("recorded source selection absent"))?;
        let descriptor = graph
            .descriptor(&selected.node)
            .ok_or_else(|| refusal("recorded source descriptor absent"))?;
        let definition = super::super::recorded_ingress::from_content(descriptor, &self.objects)
            .map_err(state_error)?;
        for input in &runtime.inputs {
            let provenance = input
                .provenance
                .as_ref()
                .ok_or_else(|| refusal("recorded original proof buffers absent"))?;
            if input.node != selected.node
                || provenance.node != input.node
                || provenance.stage_operation != input.stage_operation
                || provenance.batch != input.batch
                || provenance.inventory != input.inventory
                || provenance.schema_version != 1
                || provenance.roots.as_slice() != std::slice::from_ref(definition.root())
                || provenance.objects.len() != definition.objects().len()
            {
                return Err(refusal("recorded original consumer proof scope differs"));
            }
            for original in definition.objects() {
                if content.get(&original.reference) != Some(original.bytes.as_slice())
                    || !provenance.objects.iter().any(|object| object == original)
                {
                    return Err(refusal("recorded original complete proof body differs"));
                }
            }
            for delivery in &input.deliveries {
                authenticate_delivery(graph, &definition, delivery)?;
                let original = definition
                    .source()
                    .inputs
                    .iter()
                    .find(|original| original.event == delivery.publication_id)
                    .ok_or_else(|| refusal("recorded staged original event absent"))?;
                if delivery.external_root.as_ref() != Some(&definition.source().endpoint)
                    || delivery.producer_endpoint != definition.source().endpoint
                    || delivery.consumer_endpoint != definition.source().endpoint
                    || delivery.native_sequence != original.sequence
                    || delivery.publication != original.publication
                    || delivery.payload != original.payload.reference
                    || delivery.provenance_ref != *definition.root()
                    || delivery.connection_id.is_some()
                    || delivery.connection_policy_ref.is_some()
                    || !delivery.causal_parents.is_empty()
                    || !input
                        .payloads
                        .iter()
                        .any(|payload| payload == &original.payload)
                {
                    return Err(refusal(
                        "recorded original staged FIFO/body association differs",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) fn recorded_consumed(
        &self,
        runtime: &RuntimeSnapshot,
        definition: &RecordedIngressDefinition,
    ) -> Result<usize, StateError> {
        let node = &definition.source().endpoint.node_id;
        let mut consumed = std::collections::BTreeSet::new();
        for input in runtime.inputs.iter().filter(|input| &input.node == node) {
            let prefix = runtime
                .operations
                .iter()
                .filter(|operation| &operation.route.node == node)
                .filter_map(|operation| match &operation.result {
                    crucible::node_contract::SavedRuntimeResult::Complete(outcome)
                    | crucible::node_contract::SavedRuntimeResult::Acknowledged(outcome) => {
                        outcome.scheduling.as_ref()
                    }
                    _ => None,
                })
                .filter_map(|observation| observation.input_progress.as_ref())
                .filter(|progress| progress.batch == input.batch)
                .map(|progress| progress.consumed.len())
                .max()
                .unwrap_or(0);
            if prefix > input.deliveries.len() {
                return Err(refusal("recorded original consumed inventory overflow"));
            }
            for delivery in input.deliveries.iter().take(prefix) {
                let index = definition
                    .source()
                    .inputs
                    .iter()
                    .position(|original| original.event == delivery.publication_id)
                    .ok_or_else(|| refusal("recorded consumed event has no source identity"))?;
                if !consumed.insert(index) {
                    return Err(refusal("recorded original arrival consumed twice"));
                }
            }
        }
        if consumed.iter().copied().ne(0..consumed.len()) {
            return Err(refusal(
                "recorded consumption forgot an original FIFO arrival",
            ));
        }
        Ok(consumed.len())
    }

    pub(super) fn authenticate_recorded_coordinator(
        &self,
        graph: &AdmittedGraph,
        runtime: &RuntimeSnapshot,
        scheduler: &SchedulingSnapshot,
    ) -> Result<(), StateError> {
        let selected = self
            .selections
            .values()
            .next()
            .ok_or_else(|| refusal("recorded selection absent"))?;
        let descriptor = graph
            .descriptor(&selected.node)
            .ok_or_else(|| refusal("recorded descriptor absent"))?;
        let definition = super::super::recorded_ingress::from_content(descriptor, &self.objects)
            .map_err(state_error)?;
        if graph.coordinator_policy().external_inputs.as_slice()
            != std::slice::from_ref(&definition.source().endpoint)
            || scheduler.external_closed_prefixes.len() != 1
            || scheduler.external_closed_prefixes[0].endpoint != definition.source().endpoint
            || scheduler.external_closed_prefixes[0].closed_before
                != definition.source().closed_before
        {
            return Err(refusal("recorded original external closure differs"));
        }
        for delivery in &scheduler.pending_deliveries {
            authenticate_delivery(graph, &definition, delivery)?;
        }
        for input in &runtime.inputs {
            for delivery in &input.deliveries {
                authenticate_delivery(graph, &definition, delivery)?;
            }
        }
        let cursor = self.recorded_consumed(runtime, &definition)?;
        let mut pending = scheduler
            .pending_deliveries
            .iter()
            .filter(|delivery| {
                delivery.external_root.as_ref() == Some(&definition.source().endpoint)
            })
            .map(|delivery| &delivery.publication_id)
            .collect::<std::collections::BTreeSet<_>>();
        if pending.len() != scheduler.pending_deliveries.len() {
            return Err(refusal(
                "recorded original pending inventory duplicates or foreign arrivals",
            ));
        }
        // Staging transfers buffers but does not consume the original arrival.
        // The scheduler can retain that same arrival while native custody owns
        // its staged copy. Match both complete rows before treating them as one
        // original; distinct native staging of the same arrival still refuses.
        let mut staged = std::collections::BTreeSet::new();
        for input in runtime
            .inputs
            .iter()
            .filter(|input| input.node == selected.node)
        {
            let consumed = runtime
                .operations
                .iter()
                .filter(|operation| operation.route.node == input.node)
                .filter_map(|operation| match &operation.result {
                    crucible::node_contract::SavedRuntimeResult::Complete(outcome)
                    | crucible::node_contract::SavedRuntimeResult::Acknowledged(outcome) => {
                        outcome.scheduling.as_ref()
                    }
                    _ => None,
                })
                .filter_map(|observation| observation.input_progress.as_ref())
                .filter(|progress| progress.batch == input.batch)
                .map(|progress| progress.consumed.len())
                .max()
                .unwrap_or(0);
            for delivery in input.deliveries.iter().skip(consumed) {
                if !staged.insert(&delivery.publication_id) {
                    return Err(refusal(
                        "recorded original arrival has duplicate native staging",
                    ));
                }
                let original_batch = scheduler
                    .input_batches
                    .iter()
                    .find(|batch| {
                        batch.node == input.node
                            && batch.stage_operation == input.stage_operation
                            && batch.batch == input.batch
                            && batch.inventory == input.inventory
                            && batch.owners == input.owners
                            && batch.deliveries == input.deliveries
                            && batch.payloads == input.payloads
                            && batch.acknowledgement == input.acknowledgement
                    })
                    .ok_or_else(|| {
                        refusal("recorded original staged coordinator custody differs")
                    })?;
                if original_batch.consumed.len() != consumed {
                    return Err(refusal("recorded original staged consumption differs"));
                }
                if let Some(original) = scheduler
                    .pending_deliveries
                    .iter()
                    .find(|original| original.publication_id == delivery.publication_id)
                    && original != delivery
                {
                    return Err(refusal(
                        "recorded original pending and staged bodies differ",
                    ));
                }
                pending.insert(&delivery.publication_id);
            }
        }
        let expected = definition.source().inputs[cursor..]
            .iter()
            .map(|input| &input.event)
            .collect::<std::collections::BTreeSet<_>>();
        if pending != expected {
            return Err(refusal(
                "recorded scheduler omitted or replaced an original unconsumed arrival",
            ));
        }
        Ok(())
    }
}

// Initial source enrollment submits the whole closed FIFO before native work.
// Its common sequence is that original index; native FIFO identity is separate.
fn authenticate_delivery(
    graph: &AdmittedGraph,
    definition: &RecordedIngressDefinition,
    delivery: &Delivery,
) -> Result<(), StateError> {
    let endpoint = &definition.source().endpoint;
    let lane = graph
        .port_policy(&endpoint.node_id, &endpoint.port_id)
        .and_then(|port| {
            port.lanes
                .iter()
                .find(|lane| lane.lane_id == endpoint.lane_id)
        })
        .ok_or_else(|| refusal("recorded original external lane absent"))?;
    let grid = match lane.visibility {
        crucible::node_admission::LaneVisibility::Exact => None,
        crucible::node_admission::LaneVisibility::Quantized {
            quantum_ps,
            phase_ps,
            ..
        } => Some(
            crucible_node_contract::QuantumGrid::new(quantum_ps, phase_ps).map_err(state_error)?,
        ),
    };
    let (index, original) = definition
        .source()
        .inputs
        .iter()
        .enumerate()
        .find(|(_, original)| original.event == delivery.publication_id)
        .ok_or_else(|| refusal("recorded pending original event absent"))?;
    let expected_delivery =
        crucible::node_scheduling::event::direct_delivery(original.publication, U64::new(0), grid)
            .map_err(state_error)?;
    if delivery.connection_id.is_some()
        || delivery.connection_policy_ref.is_some()
        || delivery.external_root.as_ref() != Some(endpoint)
        || delivery.provenance_ref != *definition.root()
        || delivery.producer != endpoint.node_id
        || delivery.consumer != endpoint.node_id
        || delivery.producer_endpoint != *endpoint
        || delivery.consumer_endpoint != *endpoint
        || delivery.source_sequence.get() != index as u64
        || delivery.native_sequence != original.sequence
        || delivery.evaluation.is_some()
        || !delivery.causal_parents.is_empty()
        || delivery.publication != original.publication
        || delivery.delivery != expected_delivery
        || delivery.payload != original.payload.reference
    {
        return Err(refusal("recorded original complete arrival differs"));
    }
    Ok(())
}
