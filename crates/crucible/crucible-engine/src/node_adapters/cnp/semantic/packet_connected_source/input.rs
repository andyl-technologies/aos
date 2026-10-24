//! Complete original staging and consumption joins without semantic delivery.

use super::*;
use crate::node_scheduling::event::Delivery;
use crucible_node_transport::reference_packet::connected::{PacketReaction, causal_parent_ids};
use serde::de::DeserializeOwned;

impl PacketConnectedSemanticSource {
    pub(super) fn batch_owner(&self, batch: &RuntimeInputBatch) -> Result<(), OperationFailure> {
        self.local_owner()?;
        self.world
            .authenticate_record(batch.activation().record())?;
        if batch.node() != &self.installation.descriptor.id
            || batch.owners() != [self.owner()]
            || batch.deliveries().len() > 4
            || batch.payloads().len() > 4
        {
            return Err(refused(
                "connected packet complete original input owner/credit",
            ));
        }
        Ok(())
    }

    pub(super) fn map_input_batch(
        &self,
        batch: &RuntimeInputBatch,
        sequence: U64,
    ) -> Result<InputBatch, OperationFailure> {
        self.batch_owner(batch)?;
        self.authenticate_current_native()?;
        let mut previous = None;
        let mut events = Vec::with_capacity(batch.deliveries().len());
        for delivery in batch.deliveries() {
            self.validate_delivery(delivery, batch.cutoff())?;
            let key = delivery.key();
            if previous.as_ref().is_some_and(|old| old >= &key) {
                return Err(refused("connected input canonical delivery order"));
            }
            let payload = batch
                .payloads()
                .iter()
                .find(|body| body.reference == delivery.payload)
                .ok_or_else(|| refused("connected original input bytes absent"))?;
            if payload.bytes.len() > 32 {
                return Err(refused("connected input octet limit"));
            }
            payload.reference.verify(&payload.bytes).map_err(unknown)?;
            events.push(Event {
                schema_version: 1,
                id: delivery.publication_id.clone(),
                source: delivery.producer_endpoint.clone(),
                destination: delivery.consumer_endpoint.clone(),
                source_sequence: delivery.native_sequence,
                provenance_ref: delivery.provenance_ref.clone(),
                causal_parent_ids: causal_parent_ids(&delivery.causal_parents).map_err(unknown)?,
                stage: EventStage::Delivery,
                position: delivery.delivery,
                publication_position: delivery.publication,
                delivery_position: Some(delivery.delivery),
                payload: delivery.payload.clone(),
                extensions: Extensions::new(),
            });
            previous = Some(key);
        }
        let result = InputBatch {
            schema_version: 1,
            execution_owner_id: self.owner().owner,
            input_epoch: self.installation.binding.authority.input_epoch.clone(),
            batch_id: batch.batch().clone(),
            batch_sequence: sequence,
            events,
            extensions: Extensions::new(),
        };
        result.validate().map_err(unknown)?;
        self.authenticate_current_native()?;
        Ok(result)
    }

    pub(super) fn validate_delivery(
        &self,
        delivery: &Delivery,
        cutoff: Position,
    ) -> Result<(), OperationFailure> {
        let route = self
            .definition
            .connections
            .iter()
            .find(|route| delivery.connection_id.as_ref() == Some(&route.id))
            .ok_or_else(|| refused("connected input undeclared original route"))?;
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
            || delivery.consumer != self.installation.descriptor.id
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
            return Err(refused("connected input full causal route/cut changed"));
        }
        delivery.payload.validate().map_err(unknown)?;
        delivery.provenance_ref.validate().map_err(unknown)
    }

    pub(super) fn original_cut(
        &self,
        batch: &RuntimeInputBatch,
        request: &InputRequest,
    ) -> Result<PacketInputCut, OperationFailure> {
        self.batch_owner(batch)?;
        if self.map_input_batch(batch, request.batch_sequence)?
            != request
                .verified_batch(&self.owner().owner)
                .map_err(unknown)?
        {
            return Err(refused("connected original baseline input batch changed"));
        }
        let authority = &self.installation.binding.authority;
        let activation = batch.activation().record();
        let cut = PacketInputCut {
            schema_version: 4,
            session_id: authority.session_id.clone(),
            incarnation_id: authority.incarnation_id.clone(),
            node_id: batch.node().clone(),
            execution_owner_id: self.owner().owner,
            owner_generation: authority.owner_generation,
            activation_id: activation.activation_id.clone(),
            world_generation: activation.generation,
            world_binding_hash: activation.world_binding_hash.clone(),
            stage_operation_id: batch.stage_operation().clone(),
            batch_id: batch.batch().clone(),
            batch_sequence: request.batch_sequence,
            input_epoch: authority.input_epoch.clone(),
            batch_hash: request.batch_hash.clone(),
            delivery_inventory: batch.inventory().clone(),
            cutoff: batch.cutoff(),
        };
        cut.validate().map_err(unknown)?;
        if request.binding_hash != self.installation.owner.identity().map_err(unknown)?
            || request.owner_generation != cut.owner_generation
            || request.input_epoch != cut.input_epoch
            || !request.extensions.is_empty()
        {
            return Err(refused("connected original input binding changed"));
        }
        Ok(cut)
    }

    pub(super) fn stage_context(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        batch: &RuntimeInputBatch,
        request: &InputRequest,
    ) -> Result<(Extensions, Vec<InputPayload>), OperationFailure> {
        self.guard(&scope)?;
        credit::Prefix::InputStage.preflight(scope.controller)?;
        let cut = self.original_cut(batch, request)?;
        let inventory =
            canonical::canonical_json(&serde_json::to_value(batch.deliveries()).map_err(unknown)?)
                .map_err(unknown)?;
        batch.inventory().verify(&inventory).map_err(unknown)?;
        if inventory.len() > 65_536 {
            return Err(refused("connected input complete inventory credit"));
        }
        let mut payloads = Vec::with_capacity(batch.payloads().len() + 1);
        payloads.push(InputPayload {
            reference: batch.inventory().clone(),
            bytes: inventory,
        });
        for payload in batch.payloads() {
            if payload.bytes.len() > 32
                || !batch
                    .deliveries()
                    .iter()
                    .any(|delivery| delivery.payload == payload.reference)
            {
                return Err(refused(
                    "connected input copied payload outside original complete cut",
                ));
            }
            payload.reference.verify(&payload.bytes).map_err(unknown)?;
        }
        payloads.extend(batch.payloads().iter().cloned());
        self.guard(&scope)?;
        Ok((context(PacketInputContext::Stage { cut })?, payloads))
    }

    /// Joins the original response, control receipt and native content object.
    pub(super) fn input_root(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        response: &InputResult,
    ) -> Result<(ContentRef, crucible_node_transport::envelope::Envelope), OperationFailure> {
        self.guard(scope)?;
        let receipt: ControlReceipt = self.object(scope, &response.custody_receipt)?;
        receipt.validate().map_err(unknown)?;
        let original = scope
            .controller
            .original(&receipt.request_id)
            .ok_or_else(|| refused("connected input original request absent"))?;
        let reply = original
            .response
            .as_ref()
            .ok_or_else(|| refused("connected input original response absent"))?;
        let RequestBody::Input(request) =
            decode_request(original.request.method, &original.request.body).map_err(unknown)?
        else {
            return Err(refused("connected custody not original Input"));
        };
        if decode_response(&RequestBody::Input(request), &reply.body)
            .map_err(unknown)?
            .result
            != Some(MethodResult::Input(response.clone()))
        {
            return Err(refused("connected original Input response changed"));
        }
        let custody: InputCustodyRecord = self.object(scope, &receipt.record_ref)?;
        custody.validate().map_err(unknown)?;
        let context = PacketInputContext::decode(&original.request.extensions).map_err(unknown)?;
        let cut = context.cut();
        let root = custody
            .evidence_refs
            .first()
            .ok_or_else(|| refused("connected native input proof absent"))?;
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
            return Err(refused("connected full Input custody lineage changed"));
        }
        let mut ids = match decode_request(original.request.method, &original.request.body)
            .map_err(unknown)?
        {
            RequestBody::Input(request) => request
                .events
                .into_iter()
                .map(|event| event.id)
                .collect::<Vec<_>>(),
            _ => return Err(refused("connected Input original method changed")),
        };
        ids.sort();
        if ids != response.accepted_event_ids {
            return Err(refused("connected staging accepted population changed"));
        }
        self.guard(scope)?;
        Ok((root.clone(), original.request.clone()))
    }

    pub(super) fn object<T: DeserializeOwned>(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        reference: &ContentRef,
    ) -> Result<T, OperationFailure> {
        let bytes = scope.controller.content(reference).map_err(unknown)?;
        reference.verify(bytes).map_err(unknown)?;
        let value =
            canonical::parse_json(bytes, self.installation.maximum_result_bytes.min(65_536))
                .map_err(unknown)?;
        if canonical::canonical_json(&value).map_err(unknown)? != bytes {
            return Err(refused("connected source noncanonical complete body"));
        }
        serde_json::from_value(value).map_err(unknown)
    }

    pub(super) fn staging_ack(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        batch: &RuntimeInputBatch,
        response: &InputResult,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        let (root, envelope) = self.input_root(&scope, response)?;
        let staged = self.stage_record(&scope, &root)?;
        let RequestBody::Input(request) =
            decode_request(envelope.method, &envelope.body).map_err(unknown)?
        else {
            return Err(refused("connected original stage method"));
        };
        if staged.cut != self.original_cut(batch, &request)? {
            return Err(refused("connected stage changed opaque original cut"));
        }
        self.guard(&scope)?;
        Ok(NativeInputAcknowledgement {
            stage_operation: batch.stage_operation().clone(),
            batch: batch.batch().clone(),
            node: batch.node().clone(),
            owners: batch.owners().to_vec(),
            cutoff: batch.cutoff(),
            inventory: batch.inventory().clone(),
            proof_ref: root,
        })
    }

    pub(super) fn commitment(
        &self,
        batch: &RuntimeInputBatch,
        commit: &InputCustodyCommit,
    ) -> Result<(), OperationFailure> {
        self.batch_owner(batch)?;
        if !batch.activation().same_authority(commit.activation())
            || batch.activation().record() != commit.activation().record()
            || batch.node() != commit.node()
            || batch.stage_operation() != commit.stage_operation()
            || batch.batch() != commit.batch()
            || batch.inventory() != commit.inventory()
            || batch.cutoff() != commit.cutoff()
        {
            return Err(refused(
                "connected input changed original coordinator commitment",
            ));
        }
        Ok(())
    }

    pub(super) fn commit_context(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        batch: &RuntimeInputBatch,
        commit: &InputCustodyCommit,
        request: &InputRequest,
        staging: &InputResult,
    ) -> Result<(Extensions, Vec<InputPayload>), OperationFailure> {
        self.guard(&scope)?;
        credit::Prefix::InputCommit.preflight(scope.controller)?;
        self.commitment(batch, commit)?;
        let (root, original) = self.input_root(&scope, staging)?;
        let staged = self.stage_record(&scope, &root)?;
        if staged.cut != self.original_cut(batch, request)? {
            return Err(refused("connected commitment replaces original stage cut"));
        }
        let input_request_id = original
            .request_id
            .0
            .ok_or_else(|| refused("connected original stage identity absent"))?;
        self.guard(&scope)?;
        Ok((
            context(PacketInputContext::Commit {
                cut: staged.cut,
                input_request_id,
                staging_receipt: staging.custody_receipt.clone(),
            })?,
            Vec::new(),
        ))
    }

    pub(super) fn check_input_commit(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        batch: &RuntimeInputBatch,
        commit: &InputCustodyCommit,
        request: &InputRequest,
        staging: &InputResult,
        response: &InputResult,
    ) -> Result<(), OperationFailure> {
        self.commitment(batch, commit)?;
        let (root, _) = self.input_root(&scope, response)?;
        let consumed = self.commit_record(&scope, &root)?;
        let (stage_root, _) = self.input_root(&scope, staging)?;
        if consumed.cut != self.original_cut(batch, request)?
            || consumed.staged_record != stage_root
            || consumed.staging_receipt != staging.custody_receipt
        {
            return Err(refused(
                "connected original commit/cut/staging receipt changed",
            ));
        }
        self.guard(&scope)
    }
}

fn context(value: PacketInputContext) -> Result<Extensions, OperationFailure> {
    let mut extensions = Extensions::new();
    extensions.insert(
        PACKET_INPUT_FEATURE.into(),
        serde_json::to_value(value).map_err(unknown)?,
    );
    Ok(extensions)
}

pub(super) fn expected_reactions(stage: &PacketStageRecord, request: &Id) -> Vec<PacketReaction> {
    stage
        .batch
        .events
        .iter()
        .zip(&stage.payloads)
        .zip(&stage.deliveries)
        .map(|((event, payload), delivery)| PacketReaction {
            input_event: event.id.clone(),
            input_producer: delivery.producer.clone(),
            input_sequence: delivery.source_sequence,
            stage_operation: stage.cut.stage_operation_id.clone(),
            commit_request: request.clone(),
            payload: payload.clone(),
            parent: event.position,
            evaluation: Position {
                phase: Phase::Reaction,
                ..event.position
            },
        })
        .collect()
}
