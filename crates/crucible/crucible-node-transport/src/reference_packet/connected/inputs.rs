//! Original bounded staging bytes and distinct source-consumed reaction admission.

use super::super::{control::PacketControlSelection, input::PacketInputContext};
use super::*;
use crate::{
    bodies::*,
    envelope::{Method, RequestOrigin},
    input_commit::CommittedDeliveryV1,
};

/// Retains portable parent labels without flattening full causal positions.
///
/// # Errors
/// Refuses a label that cannot satisfy the canonical public identifier grammar.
pub fn causal_parent_ids(parents: &[Position]) -> Result<Vec<Id>, ProviderError> {
    let mut ids = parents
        .iter()
        .map(|position| {
            Id::new(format!(
                "packet-parent-{}-{}-{}",
                position.time_ps.get(),
                position.microstep.get(),
                position.phase as u16,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    ids.sort();
    ids.dedup();
    Ok(ids)
}

impl PacketConnectedProgram {
    /// Retains exact original bytes without consuming input or advancing modeled time.
    ///
    /// Repeated unchanged original requests return the same actual native reply.
    /// A different identity cannot replace an existing stream batch.
    ///
    /// # Errors
    /// Refuses changed originals, foreign connections or complete source credit overflow.
    // The complete original envelope/body/cut, installed source/activation and
    // actual borrowed inventory/payload bytes are validated together before retention.
    #[allow(clippy::too_many_arguments)]
    pub fn stage(
        &mut self,
        envelope: &Envelope,
        request: &InputRequest,
        context: &PacketInputContext,
        selection: &PacketControlSelection,
        active: &WorldActivateRequest,
        inventory: &[u8],
        payloads: &BTreeMap<ContentRef, Vec<u8>>,
    ) -> Result<&PacketInputReply, ProviderError> {
        self.current()?;
        let PacketInputContext::Stage { cut } = context else {
            return Err(ProviderError::Correlation("packet original staging action"));
        };
        context.authenticate(envelope, request, selection, active)?;
        let id = envelope
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "packet input original request absent",
            ))?;
        if let Some(index) = self
            .stages
            .iter()
            .position(|stage| stage.record.original.request_id.0.as_ref() == Some(id))
        {
            let original = &self.stages[index];
            if original
                .record
                .original
                .request_hash(RequestOrigin::Controller)?
                != envelope.request_hash(RequestOrigin::Controller)?
            {
                return Err(ProviderError::Conflict("packet original staging changed"));
            }
            return Ok(&original.reply);
        }
        let next = self
            .stages
            .last()
            .map_or(1, |stage| stage.record.cut.batch_sequence.get() + 1);
        let occupied = self
            .stages
            .iter()
            .map(|stage| stage.record.batch.events.len())
            .sum::<usize>();
        if self.gate_closed
            || !self.outputs.is_empty()
            || self
                .stages
                .last()
                .is_some_and(|stage| stage.commit.is_none())
            || self.stages.len() >= MAXIMUM_BATCHES
            || request.events.len() > 4
            || occupied + request.events.len() > MAXIMUM_EVENTS
            || cut.batch_sequence.get() != next
            || cut.cutoff <= self.reached
            || cut.cutoff.microstep.get() >= MAXIMUM_MICROSTEPS
            || self.stages.iter().any(|stage| {
                stage.record.cut.stage_operation_id == cut.stage_operation_id
                    || stage.record.cut.batch_id == cut.batch_id
                    || stage.commit.as_ref().is_some_and(|commit| {
                        commit.record.original.request_id.0.as_ref() == Some(id)
                    })
                    || stage
                        .record
                        .batch
                        .events
                        .iter()
                        .any(|old| request.events.iter().any(|event| event.id == old.id))
            })
        {
            return Err(ProviderError::Correlation(
                "packet complete original staging credit or stream",
            ));
        }
        cut.delivery_inventory.verify(inventory)?;
        let value = canonical::parse_json(inventory, MAXIMUM_RECORD)?;
        if canonical::canonical_json(&value)? != inventory {
            return Err(ProviderError::Frame(
                "packet complete delivery bytes are not canonical",
            ));
        }
        let deliveries: Vec<CommittedDeliveryV1> =
            serde_json::from_value(value).map_err(ContractError::from)?;
        if deliveries.len() != request.events.len() {
            return Err(ProviderError::Correlation(
                "packet original delivery population changed",
            ));
        }
        let mut bytes = Vec::with_capacity(request.events.len());
        let mut previous = None;
        for (delivery, event) in deliveries.iter().zip(&request.events) {
            let route = self
                .definition
                .connections
                .iter()
                .find(|route| delivery.connection_id.0.as_ref() == Some(&route.id))
                .ok_or(ProviderError::Correlation(
                    "packet undeclared original input connection",
                ))?;
            let expected_delivery = Position {
                time_ps: delivery.publication.time_ps.checked_add(route.delay_ps)?,
                microstep: if route.delay_ps.get() == 0 {
                    delivery.publication.microstep
                } else {
                    U64::new(0)
                },
                phase: Phase::Delivery,
            };
            let key = EventKey {
                position: delivery.delivery,
                consumer_node_id: delivery.consumer.clone(),
                producer_node_id: delivery.producer.clone(),
                source_sequence: delivery.source_sequence,
            };
            if delivery.connection_policy_ref.0.as_ref() != Some(&route.policy)
                || delivery.external_root.0.is_some()
                || delivery.producer_endpoint != route.producer
                || delivery.consumer_endpoint != route.consumer
                || delivery.producer != route.producer.node_id
                || delivery.consumer != cut.node_id
                || delivery.consumer != route.consumer.node_id
                || delivery.publication.phase != Phase::Publication
                || delivery.evaluation.0.is_none_or(|evaluation| {
                    evaluation.phase != Phase::Reaction
                        || evaluation >= delivery.publication
                        || delivery
                            .causal_parents
                            .iter()
                            .any(|parent| parent > &evaluation)
                })
                || delivery.delivery != expected_delivery
                || delivery.delivery < self.reached
                || delivery.delivery >= cut.cutoff
                || delivery
                    .delivery
                    .microstep
                    .get()
                    .checked_add(1)
                    .is_none_or(|next| next >= MAXIMUM_MICROSTEPS)
                || delivery.publication_id != event.id
                || delivery.producer_endpoint != event.source
                || delivery.consumer_endpoint != event.destination
                || delivery.native_sequence != event.source_sequence
                || delivery.native_sequence.get() == 0
                || delivery.provenance_ref != event.provenance_ref
                || delivery.publication != event.publication_position
                || Some(delivery.delivery) != event.delivery_position
                || delivery.delivery != event.position
                || delivery.payload != event.payload
                || event.stage != EventStage::Delivery
                || !event.extensions.is_empty()
                || event.causal_parent_ids != causal_parent_ids(&delivery.causal_parents)?
                || delivery
                    .causal_parents
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                || delivery
                    .causal_parents
                    .iter()
                    .any(|parent| parent >= &delivery.publication)
                || previous.as_ref().is_some_and(|prior| prior >= &key)
            {
                return Err(ProviderError::Correlation(
                    "packet complete delivery/causal association changed",
                ));
            }
            delivery.payload.validate()?;
            delivery.provenance_ref.validate()?;
            if self.definition.output.is_some() {
                Id::new(format!("packet-reaction-{}", event.id.as_str()))?;
            }
            let payload = payloads
                .get(&delivery.payload)
                .ok_or(ProviderError::Correlation(
                    "packet original staged bytes unavailable",
                ))?;
            if payload.len() > MAXIMUM_BYTES {
                return Err(ProviderError::ResourceExhausted(
                    "packet original input payload",
                ));
            }
            delivery.payload.verify(payload)?;
            bytes.push(Bytes::new(payload.clone()));
            previous = Some(key);
        }
        let batch = request.verified_batch(&cut.execution_owner_id)?;
        let record = PacketStageRecord {
            schema: "source-owned.packet-staged-bytes/4".into(),
            native_pid: U64::new(u64::from(self.native_pid)),
            original: envelope.clone(),
            cut: cut.clone(),
            batch,
            deliveries,
            payloads: bytes,
            inventory: self.inventory()?,
        };
        let (record_ref, record_bytes) = encode_record(&record)?;
        let reply = input_reply(envelope, cut, &record_ref, record_bytes)?;
        // All proof and callback population capacity is checked before retaining
        // the actual original bytes. No clock, reaction or publication changes.
        self.stages.push(OriginalStage {
            record,
            record_ref,
            reply,
            commit: None,
        });
        Ok(&self
            .stages
            .last()
            .ok_or(ProviderError::Frame("packet actual stage absent"))?
            .reply)
    }

    /// Admits the same original staged reaction population without executing it.
    ///
    /// # Errors
    /// Refuses missing or changed byte custody, source receipt, original request or cut.
    pub fn commit(
        &mut self,
        envelope: &Envelope,
        request: &InputRequest,
        context: &PacketInputContext,
        selection: &PacketControlSelection,
        active: &WorldActivateRequest,
    ) -> Result<&PacketInputReply, ProviderError> {
        self.current()?;
        let PacketInputContext::Commit {
            cut,
            input_request_id,
            staging_receipt,
        } = context
        else {
            return Err(ProviderError::Correlation(
                "packet original consumed action",
            ));
        };
        context.authenticate(envelope, request, selection, active)?;
        let index = self
            .stages
            .iter()
            .position(|stage| stage.record.original.request_id.0.as_ref() == Some(input_request_id))
            .ok_or(ProviderError::Correlation(
                "packet actual original staged request absent",
            ))?;
        if let Some(original) = &self.stages[index].commit {
            if original
                .record
                .original
                .request_hash(RequestOrigin::Controller)?
                != envelope.request_hash(RequestOrigin::Controller)?
            {
                return Err(ProviderError::Conflict(
                    "packet original commitment changed",
                ));
            }
            return Ok(&self.stages[index]
                .commit
                .as_ref()
                .ok_or(ProviderError::Frame(
                    "packet original consumed reply absent",
                ))?
                .reply);
        }
        let staged = &self.stages[index];
        if self.gate_closed
            || !self.outputs.is_empty()
            || index + 1 != self.stages.len()
            || &staged.record.cut != cut
            || &staged.reply.result.custody_receipt != staging_receipt
            || staged.record.batch != request.verified_batch(&cut.execution_owner_id)?
            || self.reactions.len() + staged.record.batch.events.len() > MAXIMUM_EVENTS
            || self.stages.iter().any(|stage| {
                stage.record.original.request_id == envelope.request_id
                    || stage.commit.as_ref().is_some_and(|commit| {
                        commit.record.original.request_id == envelope.request_id
                    })
            })
        {
            return Err(ProviderError::Correlation(
                "packet actual consumed byte/receipt scope changed",
            ));
        }
        let request_id = envelope
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "packet consumed original request absent",
            ))?;
        let reactions = staged
            .record
            .batch
            .events
            .iter()
            .zip(&staged.record.payloads)
            .zip(&staged.record.deliveries)
            .map(|((event, bytes), delivery)| PacketReaction {
                input_event: event.id.clone(),
                input_producer: delivery.producer.clone(),
                input_sequence: delivery.source_sequence,
                stage_operation: cut.stage_operation_id.clone(),
                commit_request: request_id.clone(),
                payload: bytes.clone(),
                parent: event.position,
                evaluation: Position {
                    phase: Phase::Reaction,
                    ..event.position
                },
            })
            .collect::<Vec<_>>();
        if reactions
            .iter()
            .any(|reaction| reaction.evaluation < self.reached)
        {
            return Err(ProviderError::Correlation(
                "packet consumed reaction precedes original cursor",
            ));
        }
        let record = PacketCommitRecord {
            schema: "source-owned.packet-consumed-input/4".into(),
            native_pid: U64::new(u64::from(self.native_pid)),
            original: envelope.clone(),
            staged_record: staged.record_ref.clone(),
            staging_receipt: staging_receipt.clone(),
            cut: cut.clone(),
            reactions: reactions.clone(),
            reached: self.reached,
        };
        let (record_ref, record_bytes) = encode_record(&record)?;
        let reply = input_reply(envelope, cut, &record_ref, record_bytes)?;
        self.stages[index].commit = Some(OriginalCommit {
            record,
            record_ref,
            reply,
        });
        self.reactions.extend(reactions);
        self.reactions.sort_by(|a, b| {
            (a.evaluation, &a.input_producer, a.input_sequence).cmp(&(
                b.evaluation,
                &b.input_producer,
                b.input_sequence,
            ))
        });
        Ok(&self.stages[index]
            .commit
            .as_ref()
            .ok_or(ProviderError::Frame("packet actual native commit absent"))?
            .reply)
    }
}

fn encode_record(value: &impl Serialize) -> Result<(ContentRef, Vec<u8>), ProviderError> {
    crate::connection::serialized_credit(value, MAXIMUM_RECORD)?;
    let bytes =
        canonical::canonical_json(&serde_json::to_value(value).map_err(ContractError::from)?)?;
    Ok((canonical::content_ref(&bytes, "application/json")?, bytes))
}

fn input_reply(
    original: &Envelope,
    cut: &PacketInputCut,
    native: &ContentRef,
    native_bytes: Vec<u8>,
) -> Result<PacketInputReply, ProviderError> {
    let custody = InputCustodyRecord {
        schema_version: 1,
        execution_owner_id: cut.execution_owner_id.clone(),
        owner_generation: cut.owner_generation,
        input_epoch: cut.input_epoch.clone(),
        input_watermark: cut.batch_sequence,
        batch_hashes: vec![cut.batch_hash.clone()],
        pending_inventory: native.clone(),
        evidence_refs: vec![native.clone()],
        extensions: Extensions::new(),
    };
    custody.validate()?;
    let (custody_ref, custody_bytes) = encode_record(&custody)?;
    let receipt = ControlReceipt {
        schema_version: 1,
        kind: ControlReceiptKind::InputCustody,
        session_id: cut.session_id.clone(),
        incarnation_id: cut.incarnation_id.clone(),
        request_id: original
            .request_id
            .0
            .clone()
            .ok_or(ProviderError::Frame("packet input receipt request absent"))?,
        operation_id: None,
        owner_ids: vec![cut.execution_owner_id.clone()],
        world_generation: cut.world_generation,
        record_ref: custody_ref.clone(),
        issuer: ReceiptIssuer::Provider,
        extensions: Extensions::new(),
    };
    receipt.validate()?;
    let (receipt_ref, receipt_bytes) = encode_record(&receipt)?;
    let crate::bodies::RequestBody::Input(request) = decode_request(Method::Input, &original.body)?
    else {
        return Err(ProviderError::Frame(
            "packet actual source input receipt method",
        ));
    };
    let mut accepted_event_ids = request
        .events
        .iter()
        .map(|event| event.id.clone())
        .collect::<Vec<_>>();
    accepted_event_ids.sort();
    Ok(PacketInputReply {
        result: InputResult {
            accepted_event_ids,
            input_watermark: cut.batch_sequence,
            custody_receipt: receipt_ref.clone(),
            inventory_hash: native.hash.clone(),
        },
        evidence: vec![
            (native.clone(), native_bytes),
            (custody_ref, custody_bytes),
            (receipt_ref, receipt_bytes),
        ],
    })
}
