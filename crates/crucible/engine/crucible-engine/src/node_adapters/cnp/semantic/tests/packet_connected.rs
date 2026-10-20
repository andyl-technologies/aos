//! Actual native consumed-byte and phased datagram mechanism controls.
//!
//! These component fixtures construct portable source-correlation data only.
//! They do not issue an admitted world, public Ready or class qualification and
//! cannot substitute for the separate connected three-child runtime collection.

#![cfg(test)]

use std::{collections::BTreeMap, os::unix::net::UnixDatagram};

use crucible_node_format::*;
use crucible_node_transport::{
    bodies::*,
    envelope::*,
    input_commit::CommittedDeliveryV1,
    reference_packet::{connected::*, control::PacketControlSelection, input::*},
};
use serde_json::Value;

use super::{
    packet_definition::Definition,
    packet_protocol::{Bootstrap, bytes, id, object, reference},
};

fn position(ps: u64, microstep: u64, phase: Phase) -> Position {
    Position::new(U64::new(ps), U64::new(microstep), phase)
}

struct Fixture {
    native: PacketConnectedProgram,
    oracle: UnixDatagram,
    selection: PacketControlSelection,
    active: WorldActivateRequest,
    stage: Envelope,
    request: InputRequest,
    context: PacketInputContext,
    inventory: Vec<u8>,
    payloads: BTreeMap<ContentRef, Vec<u8>>,
}

impl Fixture {
    fn new(relay: bool) -> Self {
        Self::with_timing(relay, 0, 0, 1)
    }

    fn with_timing(relay: bool, delay_ps: u64, microstep: u64, source_sequence: u64) -> Self {
        let producer = Endpoint {
            node_id: id("producer"),
            port_id: id("wire_tx"),
            lane_id: id("output"),
        };
        let consumer = Endpoint {
            node_id: id("packet"),
            port_id: id("wire_rx"),
            lane_id: id("input"),
        };
        let connection = PacketInputConnection {
            id: id("original-wire"),
            policy: reference(b"complete source connection policy"),
            producer: producer.clone(),
            consumer: consumer.clone(),
            delay_ps: U64::new(delay_ps),
        };
        let model = PacketConnectedDefinition {
            schema: "source-owned.packet-connected-program/4".into(),
            connections: vec![connection.clone()],
            output: relay.then(|| Endpoint {
                node_id: id("packet"),
                port_id: id("wire_tx"),
                lane_id: id("output"),
            }),
        };
        let definition = Definition::with_model(reference(b"component fixture executable"), &model);
        let selected = &definition.installation;
        let protocol = Bootstrap::new(&definition);
        let selection = PacketControlSelection {
            provider: protocol.manifest,
            realization: protocol.realization,
            realize: selected.realize.clone(),
            prepared_token: id("original-preparation"),
            admission: selected.admission.clone(),
            transaction: selected.transaction.clone(),
            gate: selected.gate.clone(),
            world: selected.world_binding_hash.clone(),
            admission_receipt: selected.admission_receipt.clone(),
        };
        let active = WorldActivateRequest {
            transaction_id: selection.transaction.clone(),
            activation_id: id("actual-component-activation"),
            world_generation: U64::new(1),
            prepared_token: selection.prepared_token.clone(),
            world_binding_hash: selection.world.clone(),
            gate_id: selection.gate.clone(),
            activation_manifest: reference(b"component correlation; no common authority"),
            extensions: Extensions::new(),
        };
        let payload_bytes = vec![0, 255, 17];
        let payload = canonical::content_ref(&payload_bytes, "application/octet-stream").unwrap();
        let publication = position(5, microstep, Phase::Publication);
        let delivery = position(
            5 + delay_ps,
            if delay_ps == 0 { microstep } else { 0 },
            Phase::Delivery,
        );
        let provenance = reference(b"component original producer provenance");
        let row = CommittedDeliveryV1 {
            connection_id: Nullable(Some(connection.id)),
            connection_policy_ref: Nullable(Some(connection.policy)),
            external_root: Nullable(None),
            provenance_ref: provenance.clone(),
            publication_id: id("original-packet"),
            producer: producer.node_id.clone(),
            consumer: consumer.node_id.clone(),
            producer_endpoint: producer.clone(),
            consumer_endpoint: consumer.clone(),
            source_sequence: U64::new(source_sequence),
            native_sequence: U64::new(1),
            evaluation: Nullable(Some(position(4, 0, Phase::Reaction))),
            causal_parents: vec![],
            publication,
            delivery,
            payload: payload.clone(),
        };
        let inventory = bytes(vec![row]);
        let inventory_ref =
            canonical::content_ref(&inventory, "application/vnd.crucible.input-inventory+json")
                .unwrap();
        let batch = InputBatch {
            schema_version: 1,
            execution_owner_id: selected.owner.owner.id.clone(),
            input_epoch: selected.binding.authority.input_epoch.clone(),
            batch_id: id("original-batch"),
            batch_sequence: U64::new(1),
            events: vec![Event {
                schema_version: 1,
                id: id("original-packet"),
                source: producer,
                destination: consumer,
                position: delivery,
                stage: EventStage::Delivery,
                publication_position: publication,
                delivery_position: Some(delivery),
                source_sequence: U64::new(1),
                causal_parent_ids: vec![],
                payload: payload.clone(),
                provenance_ref: provenance,
                extensions: Extensions::new(),
            }],
            extensions: Extensions::new(),
        };
        let context = PacketInputContext::Stage {
            cut: PacketInputCut {
                schema_version: 4,
                session_id: selected.binding.authority.session_id.clone(),
                incarnation_id: selected.binding.authority.incarnation_id.clone(),
                node_id: selected.descriptor.id.clone(),
                execution_owner_id: selected.owner.owner.id.clone(),
                owner_generation: selected.binding.authority.owner_generation,
                activation_id: active.activation_id.clone(),
                world_generation: active.world_generation,
                world_binding_hash: active.world_binding_hash.clone(),
                stage_operation_id: id("original-stage"),
                batch_id: batch.batch_id.clone(),
                batch_sequence: batch.batch_sequence,
                input_epoch: batch.input_epoch.clone(),
                batch_hash: batch.identity().unwrap(),
                delivery_inventory: inventory_ref,
                cutoff: position(6 + delay_ps, 0, Phase::BoundaryControl),
            },
        };
        let request = InputRequest {
            binding_hash: selected.owner.identity().unwrap(),
            owner_generation: context.cut().owner_generation,
            batch_id: batch.batch_id,
            batch_sequence: batch.batch_sequence,
            input_epoch: batch.input_epoch,
            batch_hash: context.cut().batch_hash.clone(),
            events: batch.events,
            extensions: Extensions::new(),
        };
        let stage = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(context.cut().session_id.clone())),
            incarnation_id: Nullable(Some(context.cut().incarnation_id.clone())),
            node_id: Nullable(Some(context.cut().node_id.clone())),
            execution_owner_id: Nullable(Some(context.cut().execution_owner_id.clone())),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(id("original-input"))),
            operation_id: Nullable(None),
            sequence: U64::new(2),
            method: Method::Input,
            body: object(&request),
            extensions: Extensions::from([(
                PACKET_INPUT_FEATURE.into(),
                serde_json::to_value(&context).unwrap(),
            )]),
        };
        let (socket, oracle) = UnixDatagram::pair().unwrap();
        oracle.set_nonblocking(true).unwrap();
        let mut native = PacketConnectedProgram::new(model, socket).unwrap();
        native.open_gate().unwrap();
        Self {
            native,
            oracle,
            selection,
            active,
            stage,
            request,
            context,
            inventory,
            payloads: BTreeMap::from([(payload, payload_bytes)]),
        }
    }

    fn stage(&mut self) -> ContentRef {
        self.native
            .stage(
                &self.stage,
                &self.request,
                &self.context,
                &self.selection,
                &self.active,
                &self.inventory,
                &self.payloads,
            )
            .unwrap()
            .result
            .custody_receipt
            .clone()
    }

    fn commitment(&self, receipt: ContentRef) -> (Envelope, PacketInputContext) {
        let context = PacketInputContext::Commit {
            cut: self.context.cut().clone(),
            input_request_id: self.stage.request_id.0.clone().unwrap(),
            staging_receipt: receipt,
        };
        let mut envelope = self.stage.clone();
        envelope.request_id = Nullable(Some(id("original-consumed")));
        envelope.sequence = U64::new(3);
        envelope.extensions = Extensions::from([(
            PACKET_INPUT_FEATURE.into(),
            serde_json::to_value(&context).unwrap(),
        )]);
        (envelope, context)
    }

    fn commit(&mut self) -> Envelope {
        let receipt = self.stage();
        let (envelope, context) = self.commitment(receipt);
        self.native
            .commit(
                &envelope,
                &self.request,
                &context,
                &self.selection,
                &self.active,
            )
            .unwrap();
        envelope
    }

    fn traces(&self) -> Vec<Value> {
        let mut buffer = [0; 65_536];
        let mut traces = Vec::new();
        loop {
            match self.oracle.recv(&mut buffer) {
                Ok(length) => {
                    traces.push(canonical::parse_json(&buffer[..length], buffer.len()).unwrap())
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("original native datagram oracle failed: {error}"),
            }
        }
        traces
    }
}

#[test]
fn delivery_equality_and_later_reaction_have_distinct_actual_native_steps() {
    let mut fixture = Fixture::new(true);
    fixture.commit();
    let delivery = position(5, 0, Phase::Delivery);
    let reaction = position(5, 0, Phase::Reaction);
    let excluded = fixture
        .native
        .run(
            id("delivery-excluded"),
            position(0, 0, Phase::BoundaryControl),
            delivery,
        )
        .unwrap();
    assert!(excluded.inventory.delivered_inputs.is_empty());
    assert_eq!(excluded.inventory.reactions_completed.get(), 0);
    assert!(fixture.traces().is_empty());

    fixture
        .native
        .retire(&id("delivery-excluded"), &[])
        .unwrap();
    let received = fixture
        .native
        .run(id("delivery-only"), delivery, reaction)
        .unwrap()
        .clone();
    assert_eq!(received.inventory.delivered_inputs.len(), 1);
    assert_eq!(received.inventory.reactions_completed.get(), 0);
    assert_eq!(received.inventory.reactions.len(), 1);
    assert!(received.inventory.publications.is_empty());
    let trace = fixture.traces();
    assert_eq!(trace.len(), 1);
    assert_eq!(trace[0]["action"], "delivery");
    assert_eq!(trace[0]["delivery"]["delivery_operation"], "delivery-only");
    assert_eq!(
        fixture
            .native
            .run(id("delivery-only"), delivery, reaction)
            .unwrap(),
        &received
    );
    assert!(fixture.traces().is_empty());
}

#[test]
fn common_sequence_zero_and_positive_delay_preserve_original_native_associations() {
    let mut fixture = Fixture::with_timing(true, 1, 3, 0);
    fixture.commit();
    let grant = fixture
        .native
        .run(
            id("delayed-original"),
            position(0, 0, Phase::BoundaryControl),
            position(7, 0, Phase::BoundaryControl),
        )
        .unwrap();
    let consumed = &grant.inventory.delivered_inputs[0];
    assert_eq!(consumed.reaction.parent, position(6, 0, Phase::Delivery));
    assert_eq!(consumed.reaction.input_sequence, U64::new(0));
    assert_eq!(
        grant.newborn[0].output.publication,
        position(6, 1, Phase::Publication)
    );
    assert_eq!(
        fixture
            .traces()
            .iter()
            .map(|trace| trace["action"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["delivery", "reaction", "publication"]
    );
}

#[test]
fn empty_prefix_still_requires_actual_native_staging_and_consumed_journal() {
    let mut fixture = Fixture::new(false);
    let mut batch = fixture
        .request
        .verified_batch(&fixture.context.cut().execution_owner_id)
        .unwrap();
    batch.events.clear();
    fixture.request.events.clear();
    fixture.request.batch_hash = batch.identity().unwrap();
    fixture.inventory = bytes(Vec::<CommittedDeliveryV1>::new());
    fixture.payloads.clear();
    let PacketInputContext::Stage { cut } = &mut fixture.context else {
        panic!("not staging");
    };
    cut.batch_hash = fixture.request.batch_hash.clone();
    cut.delivery_inventory = canonical::content_ref(
        &fixture.inventory,
        "application/vnd.crucible.input-inventory+json",
    )
    .unwrap();
    fixture.stage.body = object(&fixture.request);
    fixture.stage.extensions = Extensions::from([(
        PACKET_INPUT_FEATURE.into(),
        serde_json::to_value(&fixture.context).unwrap(),
    )]);
    let start = position(0, 0, Phase::BoundaryControl);
    let limit = position(5, 0, Phase::Reaction);
    assert!(
        fixture
            .native
            .run(id("empty-uncommitted"), start, limit)
            .is_err()
    );
    let receipt = fixture.stage();
    assert!(
        fixture
            .native
            .run(id("empty-staged-only"), start, limit)
            .is_err()
    );
    let (original, context) = fixture.commitment(receipt);
    let proof = fixture
        .native
        .commit(
            &original,
            &fixture.request,
            &context,
            &fixture.selection,
            &fixture.active,
        )
        .unwrap();
    let record: PacketCommitRecord = serde_json::from_slice(&proof.evidence[0].1).unwrap();
    assert_eq!(record.original, original);
    assert_eq!(record.cut, *context.cut());
    assert!(record.reactions.is_empty());

    let grant = fixture
        .native
        .run(id("actual-empty-prefix"), start, limit)
        .unwrap();
    assert_eq!(grant.inventory.commits.len(), 1);
    assert_eq!(grant.inventory.reached, limit);
    assert!(grant.inventory.delivered_inputs.is_empty());
    assert_eq!(grant.inventory.reactions_completed.get(), 0);
    assert!(grant.inventory.reactions.is_empty());
    assert!(grant.inventory.publications.is_empty());
    assert!(fixture.traces().is_empty());
}

#[test]
fn no_grant_without_actual_source_consumed_input() {
    let mut fixture = Fixture::new(true);
    let zero = position(0, 0, Phase::BoundaryControl);
    let end = position(6, 0, Phase::BoundaryControl);
    assert!(fixture.native.run(id("absent-input"), zero, end).is_err());
    fixture.stage();
    assert!(fixture.native.run(id("staging-only"), zero, end).is_err());
    assert!(fixture.traces().is_empty());
    assert_eq!(fixture.native.inventory().unwrap().reached, zero);
}

#[test]
fn actual_staged_bytes_and_commit_have_no_modeled_effect() {
    let mut fixture = Fixture::new(true);
    let receipt = fixture.stage();
    let reply = fixture
        .native
        .stage(
            &fixture.stage,
            &fixture.request,
            &fixture.context,
            &fixture.selection,
            &fixture.active,
            &fixture.inventory,
            &fixture.payloads,
        )
        .unwrap();
    assert_eq!(reply.result.custody_receipt, receipt);
    let (root, body) = &reply.evidence[0];
    root.verify(body).unwrap();
    let record: PacketStageRecord = serde_json::from_slice(body).unwrap();
    assert_eq!(record.payloads[0].as_slice(), &[0, 255, 17]);
    assert_eq!(record.original, fixture.stage);
    assert_eq!(record.native_pid.get(), u64::from(std::process::id()));

    let (envelope, context) = fixture.commitment(receipt);
    let result = fixture
        .native
        .commit(
            &envelope,
            &fixture.request,
            &context,
            &fixture.selection,
            &fixture.active,
        )
        .unwrap()
        .result
        .clone();
    assert_eq!(
        fixture
            .native
            .commit(
                &envelope,
                &fixture.request,
                &context,
                &fixture.selection,
                &fixture.active
            )
            .unwrap()
            .result,
        result
    );
    let inventory = fixture.native.inventory().unwrap();
    assert_eq!(inventory.reached, position(0, 0, Phase::BoundaryControl));
    assert_eq!(inventory.reactions_completed.get(), 0);
    assert_eq!(inventory.packet_effects.get(), 0);
    assert_eq!(inventory.reactions.len(), 1);
    assert!(inventory.delivered_inputs.is_empty());
    assert_eq!(
        inventory.reactions[0].commit_request,
        id("original-consumed")
    );
    assert!(fixture.traces().is_empty());
}

#[test]
fn reaction_and_next_microstep_publication_obey_separate_exclusive_cuts() {
    let mut fixture = Fixture::new(true);
    fixture.commit();
    let reaction = position(5, 0, Phase::Reaction);
    let publication = position(5, 1, Phase::Publication);
    let delivery = position(5, 1, Phase::Delivery);

    let excluded = fixture
        .native
        .run(
            id("exclude-equality"),
            position(0, 0, Phase::BoundaryControl),
            reaction,
        )
        .unwrap();
    assert_eq!(excluded.inventory.reactions_completed.get(), 0);
    assert_eq!(excluded.inventory.delivered_inputs.len(), 1);
    let delivery_trace = fixture.traces();
    assert_eq!(delivery_trace.len(), 1);
    assert_eq!(delivery_trace[0]["action"], "delivery");
    assert_eq!(
        delivery_trace[0]["delivery"]["delivery_operation"],
        "exclude-equality"
    );
    assert_eq!(
        delivery_trace[0]["delivery"]["reaction"]["parent"],
        serde_json::to_value(position(5, 0, Phase::Delivery)).unwrap()
    );
    fixture.native.retire(&id("exclude-equality"), &[]).unwrap();
    let evaluated = fixture
        .native
        .run(id("evaluate-only"), reaction, publication)
        .unwrap();
    assert_eq!(evaluated.inventory.reactions_completed.get(), 1);
    assert_eq!(evaluated.inventory.packet_effects.get(), 0);
    assert_eq!(evaluated.inventory.publications[0].publication, publication);
    assert!(evaluated.newborn.is_empty());
    let trace = fixture.traces();
    assert_eq!(trace.len(), 1);
    assert_eq!(trace[0]["action"], "reaction");
    assert_eq!(
        trace[0]["reaction"]["parent"],
        serde_json::to_value(position(5, 0, Phase::Delivery)).unwrap()
    );

    fixture.native.retire(&id("evaluate-only"), &[]).unwrap();
    let emitted = fixture
        .native
        .run(id("publish-next-step"), publication, delivery)
        .unwrap()
        .clone();
    assert_eq!(emitted.newborn.len(), 1);
    assert_eq!(emitted.newborn[0].output.publication, publication);
    assert_eq!(
        emitted.newborn[0].pending.reaction_operation,
        id("evaluate-only")
    );
    assert_eq!(emitted.newborn[0].output.operation, id("publish-next-step"));
    assert_eq!(emitted.newborn[0].output.payload.as_slice(), &[0, 255, 17]);
    let trace = fixture.traces();
    assert_eq!(trace.len(), 1);
    assert_eq!(trace[0]["action"], "publication");
    assert_eq!(
        trace[0]["publication"]["output"]["payload"],
        serde_json::to_value(Bytes::new(vec![0, 255, 17])).unwrap()
    );

    assert_eq!(
        fixture
            .native
            .run(id("publish-next-step"), publication, delivery)
            .unwrap(),
        &emitted
    );
    assert!(fixture.traces().is_empty());
    assert!(
        fixture
            .native
            .retire(&id("publish-next-step"), &[])
            .is_err()
    );
    fixture
        .native
        .retire(
            &id("publish-next-step"),
            &[id("packet-reaction-original-packet")],
        )
        .unwrap();
    assert!(
        fixture
            .native
            .inventory()
            .unwrap()
            .retained_outputs
            .is_empty()
    );
    assert_eq!(
        fixture.native.original(&id("publish-next-step")),
        Some(&emitted)
    );
}

#[test]
fn full_reaction_cut_survives_staging_without_boundary_zero_coercion() {
    let mut fixture = Fixture::new(false);
    let PacketInputContext::Stage { cut } = &mut fixture.context else {
        panic!("stage")
    };
    cut.cutoff = position(5, 0, Phase::Reaction);
    fixture.stage.extensions.insert(
        PACKET_INPUT_FEATURE.into(),
        serde_json::to_value(&fixture.context).unwrap(),
    );
    let receipt = fixture.stage();
    let (envelope, context) = fixture.commitment(receipt);
    fixture
        .native
        .commit(
            &envelope,
            &fixture.request,
            &context,
            &fixture.selection,
            &fixture.active,
        )
        .unwrap();
    assert_eq!(context.cut().cutoff, position(5, 0, Phase::Reaction));
    let excluded = fixture
        .native
        .run(
            id("exact-reaction-cut"),
            position(0, 0, Phase::BoundaryControl),
            context.cut().cutoff,
        )
        .unwrap();
    assert_eq!(excluded.inventory.reactions_completed.get(), 0);
    assert_eq!(excluded.inventory.delivered_inputs.len(), 1);
    assert_eq!(excluded.inventory.reactions.len(), 1);
    assert!(excluded.inventory.publications.is_empty());
    let trace = fixture.traces();
    assert_eq!(trace.len(), 1);
    assert_eq!(trace[0]["action"], "delivery");
}

#[test]
fn changed_commit_cut_or_receipt_cannot_consume_original_bytes() {
    for change in 0..2 {
        let mut fixture = Fixture::new(true);
        let receipt = fixture.stage();
        let (mut envelope, mut context) = fixture.commitment(receipt);
        let PacketInputContext::Commit {
            cut,
            staging_receipt,
            ..
        } = &mut context
        else {
            panic!("commit")
        };
        if change == 0 {
            cut.cutoff = position(6, 1, Phase::Reaction);
        } else {
            *staging_receipt = reference(b"foreign staging receipt");
        }
        envelope.extensions.insert(
            PACKET_INPUT_FEATURE.into(),
            serde_json::to_value(&context).unwrap(),
        );
        assert!(
            fixture
                .native
                .commit(
                    &envelope,
                    &fixture.request,
                    &context,
                    &fixture.selection,
                    &fixture.active
                )
                .is_err()
        );
        assert_eq!(fixture.native.inventory().unwrap().commits.len(), 0);
        assert!(fixture.traces().is_empty());
    }
}

#[test]
fn changed_actual_payload_bytes_refuse_during_mutation_interval() {
    let mut fixture = Fixture::new(true);
    fixture.payloads.values_mut().next().unwrap()[0] = 99;
    assert!(
        fixture
            .native
            .stage(
                &fixture.stage,
                &fixture.request,
                &fixture.context,
                &fixture.selection,
                &fixture.active,
                &fixture.inventory,
                &fixture.payloads
            )
            .is_err()
    );
    assert!(fixture.native.inventory().unwrap().stages.is_empty());
    assert!(fixture.traces().is_empty());
}

#[test]
fn undeclared_connection_and_false_zero_delay_refuse_before_stage() {
    for change in 0..2 {
        let mut fixture = Fixture::new(true);
        let mut rows: Vec<CommittedDeliveryV1> =
            serde_json::from_slice(&fixture.inventory).unwrap();
        if change == 0 {
            rows[0].connection_id = Nullable(Some(id("foreign-wire")));
        } else {
            rows[0].publication.time_ps = U64::new(4);
        }
        fixture.inventory = bytes(rows);
        let PacketInputContext::Stage { cut } = &mut fixture.context else {
            panic!("stage")
        };
        cut.delivery_inventory = canonical::content_ref(
            &fixture.inventory,
            "application/vnd.crucible.input-inventory+json",
        )
        .unwrap();
        fixture.stage.extensions.insert(
            PACKET_INPUT_FEATURE.into(),
            serde_json::to_value(&fixture.context).unwrap(),
        );
        assert!(
            fixture
                .native
                .stage(
                    &fixture.stage,
                    &fixture.request,
                    &fixture.context,
                    &fixture.selection,
                    &fixture.active,
                    &fixture.inventory,
                    &fixture.payloads
                )
                .is_err()
        );
        assert!(fixture.native.inventory().unwrap().stages.is_empty());
        assert!(fixture.traces().is_empty());
    }
}

#[test]
fn native_effect_failure_holds_same_unknown_original_without_reexecution() {
    let mut fixture = Fixture::new(true);
    fixture.commit();
    let zero = position(0, 0, Phase::BoundaryControl);
    let limit = position(6, 0, Phase::BoundaryControl);
    drop(fixture.oracle);
    assert!(
        fixture
            .native
            .run(id("failed-original"), zero, limit)
            .is_err()
    );
    assert!(
        !fixture
            .native
            .original(&id("failed-original"))
            .unwrap()
            .complete
    );
    assert!(
        fixture
            .native
            .run(id("failed-original"), zero, limit)
            .is_err()
    );
    assert!(
        fixture
            .native
            .run(id("replacement-forbidden"), zero, limit)
            .is_err()
    );
    assert!(
        fixture
            .native
            .original(&id("replacement-forbidden"))
            .is_none()
    );
}
