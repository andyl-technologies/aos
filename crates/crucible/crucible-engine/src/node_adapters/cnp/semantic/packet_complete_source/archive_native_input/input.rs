//! Checks complete original Input custody without constructing a live input cut.

use super::*;
use crate::node_scheduling::event::Delivery;
use crucible_node_transport::{
    input_commit::CommittedDeliveryV1, reference_packet::connected::causal_parent_ids,
};

impl NativeInputData<'_> {
    pub(super) fn input_population(
        &self,
        common: &ArchivedSemanticCustody,
    ) -> Result<(), OperationFailure> {
        for original in self.host.custody.controller.values() {
            if original.request.method != Method::Input {
                continue;
            }
            let _request = self.input_request(&original.request)?;
            let context =
                PacketInputContext::decode(&original.request.extensions).map_err(unknown)?;
            let input = required_input_row(&common.inputs, &context.cut().stage_operation_id)?;
            let response = match &context {
                PacketInputContext::Stage { .. } => input.response.as_ref(),
                PacketInputContext::Commit { .. } => input
                    .commitment
                    .as_ref()
                    .and_then(|commitment| commitment.response.as_ref()),
            }
            .ok_or_else(|| refused("cold original Input has unresolved common custody"))?;
            let (_, expected) = self.input_root(response)?;
            if expected != &original.request {
                return Err(refused(
                    "cold original Input is omitted or replaced in common custody",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn original_batch(&self, batch: &ArchivedBatch) -> Result<(), OperationFailure> {
        let node = self.selection.node_data()?;
        let definition = self
            .selection
            .reactive_definition_data()?
            .ok_or_else(|| refused("cold input has no original reactive definition"))?;
        if batch.node != self.host.node
            || &batch.node != node
            || batch.owners.len() != 1
            || batch.owners[0].owner != self.host.execution_owner
            || batch.deliveries.len() > 4
            || batch.payloads.len() > 4
        {
            return Err(refused("cold input owner or finite population differs"));
        }
        let mut previous = None;
        for delivery in &batch.deliveries {
            validate_delivery(definition, delivery, batch.cutoff)?;
            let key = delivery.key();
            if previous.as_ref().is_some_and(|old| old >= &key) {
                return Err(refused("cold input canonical delivery order differs"));
            }
            let payload = batch
                .payloads
                .iter()
                .find(|payload| payload.reference == delivery.payload)
                .ok_or_else(|| refused("cold original delivery payload absent"))?;
            if payload.bytes.len() > 32 {
                return Err(refused("cold original delivery exceeds octet bound"));
            }
            payload.reference.verify(&payload.bytes).map_err(unknown)?;
            if self.content.get(&payload.reference) != Some(payload.bytes.as_slice()) {
                return Err(refused(
                    "cold original payload differs from archive closure",
                ));
            }
            previous = Some(key);
        }
        if batch.payloads.iter().any(|payload| {
            !batch
                .deliveries
                .iter()
                .any(|delivery| delivery.payload == payload.reference)
        }) {
            return Err(refused("cold input retains an unrelated payload"));
        }
        Ok(())
    }

    pub(super) fn find_stage(
        &self,
        batch: &ArchivedBatch,
    ) -> Result<NativeObject<'_, PacketStageRecord>, OperationFailure> {
        let mut found = None;
        for original in self.host.custody.controller.values() {
            if original.request.method != Method::Input {
                continue;
            }
            let _request = self.input_request(&original.request)?;
            let context =
                PacketInputContext::decode(&original.request.extensions).map_err(unknown)?;
            let PacketInputContext::Stage { cut } = context else {
                continue;
            };
            if cut.stage_operation_id != batch.stage_operation
                || cut.batch_id != batch.batch
                || cut.delivery_inventory != batch.inventory
            {
                continue;
            }
            if found.is_some() {
                return Err(refused("cold original stage is ambiguous"));
            }
            let response = self.input_response(&original.request)?;
            let (root, _) = self.input_root(&response)?;
            let staged = self.object::<PacketStageRecord>(&root)?;
            if staged.original != original.request {
                return Err(refused(
                    "cold ancestry stage points to another original request",
                ));
            }
            found = Some(staged);
        }
        found.ok_or_else(|| refused("cold first ancestry stage absent"))
    }

    pub(super) fn input(&self, input: &ArchivedInput) -> Result<(), OperationFailure> {
        self.original_batch(&input.original)?;
        let response = input
            .response
            .as_ref()
            .ok_or_else(|| refused("cold input staging response absent"))?;
        let (root, original) = self.input_root(response)?;
        let request = self.input_request(original)?;
        let staged: NativeObject<'_, PacketStageRecord> = self.object(&root)?;
        self.stage(&staged, &input.original)?;
        if *request != input.request
            || staged.original != *original
            || input.watermark != staged.cut.batch_sequence
        {
            return Err(refused("cold common stage request or watermark differs"));
        }
        let ack = input
            .acknowledgement
            .as_ref()
            .ok_or_else(|| refused("cold complete input acknowledgement absent"))?;
        if ack.stage_operation != input.original.stage_operation
            || ack.batch != input.original.batch
            || ack.node != input.original.node
            || ack.owners != input.original.owners
            || ack.cutoff != input.original.cutoff
            || ack.inventory != input.original.inventory
            || ack.proof_ref != *root
        {
            return Err(refused("cold input acknowledgement changes original stage"));
        }
        if let Some(commitment) = &input.commitment {
            let saved = &commitment.original;
            if saved.activation != input.original.activation
                || saved.node != input.original.node
                || saved.stage_operation != input.original.stage_operation
                || saved.batch != input.original.batch
                || saved.inventory != input.original.inventory
                || saved.cutoff != input.original.cutoff
                || !commitment.context.is_empty()
            {
                return Err(refused(
                    "cold input commitment changes original coordinator cut",
                ));
            }
            let committed_response = commitment
                .response
                .as_ref()
                .ok_or_else(|| refused("cold input commitment response absent"))?;
            let (commit_root, commit_original) = self.input_root(committed_response)?;
            if commit_original.request_id.0.as_ref() != Some(&commitment.request_id)
                || commit_original.extensions != commitment.extensions
                || *self.input_request(commit_original)? != input.request
            {
                return Err(refused("cold input commitment original envelope differs"));
            }
            let committed: NativeObject<'_, PacketCommitRecord> = self.object(&commit_root)?;
            if committed.original != *commit_original {
                return Err(refused(
                    "cold common commitment points to another native original",
                ));
            }
            self.commit(&committed, &staged, &root, response)?;
        }
        Ok(())
    }

    fn input_response(
        &self,
        envelope: &Envelope,
    ) -> Result<NativeObject<'_, InputResult>, OperationFailure> {
        let original = self.original(envelope)?;
        let request = self.input_request(envelope)?;
        let response = original
            .response
            .as_ref()
            .ok_or_else(|| refused("cold Input original response absent"))?;
        let reply_charge = self.charge_envelope(response)?;
        let Some(MethodResult::Input(result)) =
            decode_response(&RequestBody::Input((*request).clone()), &response.body)
                .map_err(unknown)?
                .result
        else {
            return Err(refused("cold Input completed result absent"));
        };
        Ok(NativeObject {
            value: result,
            _charge: reply_charge,
        })
    }

    pub(super) fn input_root(
        &self,
        response: &InputResult,
    ) -> Result<(NativeObject<'_, ContentRef>, &Envelope), OperationFailure> {
        let receipt: NativeObject<'_, ControlReceipt> = self.object(&response.custody_receipt)?;
        receipt.validate().map_err(unknown)?;
        let original = self
            .host
            .custody
            .controller
            .get(&receipt.request_id)
            .ok_or_else(|| refused("cold input control receipt original absent"))?;
        if *self.input_response(&original.request)? != *response {
            return Err(refused(
                "cold input response differs from actual original reply",
            ));
        }
        let request = self.input_request(&original.request)?;
        let context = PacketInputContext::decode(&original.request.extensions).map_err(unknown)?;
        let cut = context.cut();
        let custody: NativeObject<'_, InputCustodyRecord> = self.object(&receipt.record_ref)?;
        custody.validate().map_err(unknown)?;
        let root = custody
            .evidence_refs
            .first()
            .ok_or_else(|| refused("cold input complete native proof absent"))?;
        if receipt.kind != ControlReceiptKind::InputCustody
            || receipt.issuer != ReceiptIssuer::Provider
            || receipt.session_id != cut.session_id
            || receipt.incarnation_id != cut.incarnation_id
            || receipt.operation_id.is_some()
            || receipt.owner_ids != [cut.execution_owner_id.clone()]
            || receipt.world_generation != cut.world_generation
            || !receipt.extensions.is_empty()
            || custody.execution_owner_id != cut.execution_owner_id
            || custody.owner_generation != cut.owner_generation
            || custody.input_epoch != cut.input_epoch
            || custody.input_watermark != cut.batch_sequence
            || custody.batch_hashes != [cut.batch_hash.clone()]
            || custody.evidence_refs.len() != 1
            || custody.pending_inventory != *root
            || response.inventory_hash != root.hash
            || response.input_watermark != cut.batch_sequence
            || !custody.extensions.is_empty()
        {
            return Err(refused("cold input full control custody receipt differs"));
        }
        if request.events.len() != response.accepted_event_ids.len()
            || response
                .accepted_event_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || response
                .accepted_event_ids
                .iter()
                .any(|id| !request.events.iter().any(|event| &event.id == id))
        {
            return Err(refused("cold input accepted event population differs"));
        }
        let bytes = NodeRuntime::capture_reference_storage(root).map_err(unknown)?;
        let scratch = self
            .scratch
            .get()
            .checked_add(bytes)
            .ok_or_else(|| refused("cold input reference scratch overflow"))?;
        self.retained
            .checked_add(scratch)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| refused("cold input reference storage exhausted"))?;
        self.observe_construction(scratch)?;
        self.scratch.set(scratch);
        let charge = NativeScratch {
            total: &self.scratch,
            bytes,
        };
        let cloned = root.clone();
        if NodeRuntime::capture_reference_storage(&cloned).map_err(unknown)? > bytes {
            return Err(refused("cold input cloned reference exceeds precharge"));
        }
        Ok((
            NativeObject {
                value: cloned,
                _charge: charge,
            },
            &original.request,
        ))
    }

    pub(super) fn stage(
        &self,
        record: &PacketStageRecord,
        batch: &ArchivedBatch,
    ) -> Result<(), OperationFailure> {
        self.original_batch(batch)?;
        let request = self.input_request(&record.original)?;
        let context = PacketInputContext::decode(&record.original.extensions).map_err(unknown)?;
        let PacketInputContext::Stage { cut } = &context else {
            return Err(refused("cold stage original context differs"));
        };
        let activation = self.activation_before(record.original.sequence)?;
        context
            .authenticate(&record.original, &request, self.selection(), &activation)
            .map_err(unknown)?;
        let binding = self
            .selection()
            .realization
            .bindings
            .first()
            .ok_or_else(|| refused("cold input historical binding absent"))?;
        let expected = PacketInputCut {
            schema_version: 4,
            session_id: binding.authority.session_id.clone(),
            incarnation_id: binding.authority.incarnation_id.clone(),
            node_id: batch.node.clone(),
            execution_owner_id: self.host.execution_owner.clone(),
            owner_generation: binding.authority.owner_generation,
            activation_id: batch.activation.activation_id.clone(),
            world_generation: batch.activation.generation,
            world_binding_hash: batch.activation.world_binding_hash.clone(),
            stage_operation_id: batch.stage_operation.clone(),
            batch_id: batch.batch.clone(),
            batch_sequence: request.batch_sequence,
            input_epoch: binding.authority.input_epoch.clone(),
            batch_hash: request.batch_hash.clone(),
            delivery_inventory: batch.inventory.clone(),
            cutoff: batch.cutoff,
        };
        if record.schema != "source-owned.packet-staged-bytes/4"
            || record.native_pid.get() != u64::from(self.pid())
            || record.cut != *cut
            || *cut != expected
            || record.batch
                != request
                    .verified_batch(&self.host.execution_owner)
                    .map_err(unknown)?
            || record.batch.identity().map_err(unknown)? != cut.batch_hash
            || record.batch.events.len() != batch.deliveries.len()
            || record.deliveries.len() != batch.deliveries.len()
            || record
                .deliveries
                .iter()
                .zip(&batch.deliveries)
                .any(|(native, common)| !same_delivery_data(native, common))
            || record.payloads.len() != batch.deliveries.len()
        {
            return Err(refused("cold staged native cut or complete batch differs"));
        }
        let inventory: NativeObject<'_, Vec<Delivery>> = self.object(&cut.delivery_inventory)?;
        if *inventory != batch.deliveries {
            return Err(refused("cold staged delivery inventory differs"));
        }
        for ((delivery, event), bytes) in batch
            .deliveries
            .iter()
            .zip(&record.batch.events)
            .zip(&record.payloads)
        {
            if bytes.as_slice().len() > 32
                || event.schema_version != 1
                || event.id != delivery.publication_id
                || event.source != delivery.producer_endpoint
                || event.destination != delivery.consumer_endpoint
                || event.source_sequence != delivery.native_sequence
                || event.provenance_ref != delivery.provenance_ref
                || event.position != delivery.delivery
                || event.publication_position != delivery.publication
                || event.delivery_position != Some(delivery.delivery)
                || event.payload != delivery.payload
                || event.stage != EventStage::Delivery
                || !event.extensions.is_empty()
                || event.causal_parent_ids
                    != causal_parent_ids(&delivery.causal_parents).map_err(unknown)?
            {
                return Err(refused("cold staged event full causal lineage differs"));
            }
            let payload = batch
                .payloads
                .iter()
                .find(|body| body.reference == delivery.payload)
                .ok_or_else(|| refused("cold staged original payload absent"))?;
            if payload.bytes != bytes.as_slice() {
                return Err(refused("cold staged payload differs from original batch"));
            }
            delivery.payload.verify(bytes.as_slice()).map_err(unknown)?;
        }
        Ok(())
    }

    fn commit(
        &self,
        record: &PacketCommitRecord,
        stage: &PacketStageRecord,
        stage_root: &ContentRef,
        stage_response: &InputResult,
    ) -> Result<(), OperationFailure> {
        let request = self.input_request(&record.original)?;
        let context = PacketInputContext::decode(&record.original.extensions).map_err(unknown)?;
        let PacketInputContext::Commit {
            cut,
            input_request_id,
            staging_receipt,
        } = &context
        else {
            return Err(refused("cold commit original context differs"));
        };
        let activation = self.activation_before(record.original.sequence)?;
        context
            .authenticate(&record.original, &request, self.selection(), &activation)
            .map_err(unknown)?;
        let request_id = record
            .original
            .request_id
            .0
            .as_ref()
            .ok_or_else(|| refused("cold commit original id absent"))?;
        if record.schema != "source-owned.packet-consumed-input/4"
            || record.native_pid.get() != u64::from(self.pid())
            || record.cut != *cut
            || *cut != stage.cut
            || record.staged_record != *stage_root
            || record.staging_receipt != *staging_receipt
            || stage_response.custody_receipt != *staging_receipt
            || stage.original.request_id.0.as_ref() != Some(input_request_id)
            || stage.original.sequence >= record.original.sequence
            || stage.batch
                != request
                    .verified_batch(&self.host.execution_owner)
                    .map_err(unknown)?
            || record.reactions.len() != stage.batch.events.len()
        {
            return Err(refused(
                "cold consumed input changes original stage or receipt",
            ));
        }
        for (reaction, ((event, payload), delivery)) in record.reactions.iter().zip(
            stage
                .batch
                .events
                .iter()
                .zip(&stage.payloads)
                .zip(&stage.deliveries),
        ) {
            if reaction.input_event != event.id
                || reaction.input_producer != delivery.producer
                || reaction.input_sequence != delivery.source_sequence
                || reaction.stage_operation != stage.cut.stage_operation_id
                || &reaction.commit_request != request_id
                || reaction.payload != *payload
                || reaction.parent != event.position
                || reaction.evaluation
                    != (Position {
                        phase: Phase::Reaction,
                        ..event.position
                    })
            {
                return Err(refused(
                    "cold consumed input exact reaction projection differs",
                ));
            }
        }
        Ok(())
    }
}

pub(super) fn required_input_row<'a>(
    inputs: &'a std::collections::BTreeMap<Id, ArchivedInput>,
    stage_operation: &Id,
) -> Result<&'a ArchivedInput, OperationFailure> {
    inputs
        .get(stage_operation)
        .ok_or_else(|| refused("cold common custody omits an original native Input"))
}

// These are distinct Rust DTOs for the same closed delivery grammar. Compare
// every retained field without allocating a converted Vec or roundtrip DOM.
fn same_delivery_data(native: &CommittedDeliveryV1, common: &Delivery) -> bool {
    let Delivery {
        connection_id,
        connection_policy_ref,
        external_root,
        provenance_ref,
        publication_id,
        producer,
        consumer,
        producer_endpoint,
        consumer_endpoint,
        source_sequence,
        native_sequence,
        evaluation,
        causal_parents,
        publication,
        delivery,
        payload,
    } = common;
    let CommittedDeliveryV1 {
        connection_id: native_connection,
        connection_policy_ref: native_policy,
        external_root: native_root,
        provenance_ref: native_provenance,
        publication_id: native_publication_id,
        producer: native_producer,
        consumer: native_consumer,
        producer_endpoint: native_producer_endpoint,
        consumer_endpoint: native_consumer_endpoint,
        source_sequence: native_source_sequence,
        native_sequence: native_native_sequence,
        evaluation: native_evaluation,
        causal_parents: native_parents,
        publication: native_publication,
        delivery: native_delivery,
        payload: native_payload,
    } = native;

    native_connection.0.as_ref() == connection_id.as_ref()
        && native_policy.0.as_ref() == connection_policy_ref.as_ref()
        && native_root.0.as_ref() == external_root.as_ref()
        && native_provenance == provenance_ref
        && native_publication_id == publication_id
        && native_producer == producer
        && native_consumer == consumer
        && native_producer_endpoint == producer_endpoint
        && native_consumer_endpoint == consumer_endpoint
        && native_source_sequence == source_sequence
        && native_native_sequence == native_sequence
        && native_evaluation.0.as_ref() == evaluation.as_ref()
        && native_parents == causal_parents
        && native_publication == publication
        && native_delivery == delivery
        && native_payload == payload
}

fn validate_delivery(
    definition: &PacketConnectedDefinition,
    delivery: &Delivery,
    cutoff: Position,
) -> Result<(), OperationFailure> {
    let route = definition
        .connections
        .iter()
        .find(|route| delivery.connection_id.as_ref() == Some(&route.id))
        .ok_or_else(|| refused("cold input undeclared original connection"))?;
    let arrival = delivery
        .publication
        .time_ps
        .checked_add(route.delay_ps)
        .map_err(unknown)?;
    let expected = Position::new(
        arrival,
        if route.delay_ps.get() == 0 {
            delivery.publication.microstep
        } else {
            U64::new(0)
        },
        Phase::Delivery,
    );
    if delivery.connection_policy_ref.as_ref() != Some(&route.policy)
        || delivery.external_root.is_some()
        || delivery.producer_endpoint != route.producer
        || delivery.consumer_endpoint != route.consumer
        || delivery.producer != route.producer.node_id
        || delivery.consumer != route.consumer.node_id
        || delivery.publication.phase != Phase::Publication
        || delivery.delivery != expected
        || delivery.delivery >= cutoff
        || delivery.native_sequence.get() == 0
        || delivery.evaluation.is_none_or(|evaluation| {
            evaluation.phase != Phase::Reaction
                || evaluation >= delivery.publication
                || delivery
                    .causal_parents
                    .iter()
                    .any(|parent| parent > &evaluation)
        })
        || delivery
            .causal_parents
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || delivery
            .delivery
            .microstep
            .get()
            .checked_add(1)
            .is_none_or(|next| next >= 16)
    {
        return Err(refused(
            "cold input complete causal route or delivery cut differs",
        ));
    }
    delivery.payload.validate().map_err(unknown)?;
    delivery.provenance_ref.validate().map_err(unknown)
}

// These controls alter independently retained causal fields rather than merely
// roundtripping the record serializer.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn endpoint(node: &str) -> Endpoint {
        Endpoint {
            node_id: Id::new(node).unwrap(),
            port_id: Id::new("port").unwrap(),
            lane_id: Id::new("lane").unwrap(),
        }
    }

    fn fixture() -> (PacketConnectedDefinition, Delivery, Position) {
        let producer = endpoint("producer");
        let consumer = endpoint("consumer");
        let policy = canonical::content_ref(b"original policy", "application/json").unwrap();
        let route = crucible_node_transport::reference_packet::connected::PacketInputConnection {
            id: Id::new("connection").unwrap(),
            policy: policy.clone(),
            producer: producer.clone(),
            consumer: consumer.clone(),
            delay_ps: U64::new(2),
        };
        let publication = Position::new(U64::new(3), U64::new(1), Phase::Publication);
        let delivery = Delivery {
            connection_id: Some(route.id.clone()),
            connection_policy_ref: Some(policy),
            external_root: None,
            provenance_ref: canonical::content_ref(b"native provenance", "application/json")
                .unwrap(),
            publication_id: Id::new("event").unwrap(),
            producer: producer.node_id.clone(),
            consumer: consumer.node_id.clone(),
            producer_endpoint: producer,
            consumer_endpoint: consumer,
            source_sequence: U64::new(0),
            native_sequence: U64::new(1),
            evaluation: Some(Position::new(U64::new(3), U64::new(0), Phase::Reaction)),
            causal_parents: Vec::new(),
            publication,
            delivery: Position::new(U64::new(5), U64::new(0), Phase::Delivery),
            payload: canonical::content_ref(b"octet", "application/octet-stream").unwrap(),
        };
        (
            PacketConnectedDefinition {
                schema: "source-owned.packet-connected-program/4".into(),
                connections: vec![route],
                output: None,
            },
            delivery,
            Position::new(U64::new(6), U64::new(0), Phase::BoundaryControl),
        )
    }

    #[test]
    fn native_delivery_projection_preserves_nullable_policy_and_causal_membership() {
        let (_, delivery, _) = fixture();
        let mut native: CommittedDeliveryV1 =
            serde_json::from_value(serde_json::to_value(&delivery).unwrap()).unwrap();
        assert!(same_delivery_data(&native, &delivery));

        native.connection_policy_ref.0 = None;
        assert!(!same_delivery_data(&native, &delivery));
        native.connection_policy_ref.0 = delivery.connection_policy_ref.clone();
        native.causal_parents.push(delivery.publication);
        assert!(!same_delivery_data(&native, &delivery));
    }

    #[test]
    fn original_route_accepts_but_foreign_policy_and_cut_refuse() {
        let (definition, mut delivery, cutoff) = fixture();
        validate_delivery(&definition, &delivery, cutoff).unwrap();
        delivery.connection_policy_ref =
            Some(canonical::content_ref(b"foreign policy", "application/json").unwrap());
        assert!(validate_delivery(&definition, &delivery, cutoff).is_err());

        let (_, delivery, _) = fixture();
        assert!(validate_delivery(&definition, &delivery, delivery.delivery).is_err());
    }

    #[test]
    fn changed_causal_evaluation_or_delay_refuses() {
        let (definition, mut delivery, cutoff) = fixture();
        delivery.evaluation = Some(delivery.publication);
        assert!(validate_delivery(&definition, &delivery, cutoff).is_err());

        let (_, mut delivery, _) = fixture();
        delivery.delivery.microstep = U64::new(1);
        assert!(validate_delivery(&definition, &delivery, cutoff).is_err());
    }
}
