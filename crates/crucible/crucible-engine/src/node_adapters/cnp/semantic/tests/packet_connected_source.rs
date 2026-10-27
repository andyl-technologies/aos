//! Independent host projection checks against actual original native datagrams.
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

use super::super::packet_connected_source::{native_result_root, output_bound, project_grant};

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
fn host_projection_matches_actual_three_phase_datagrams_across_exclusive_cuts() {
    let mut fixture = Fixture::with_timing(true, 0, 2, 0);
    fixture.commit();
    assert!(fixture.traces().is_empty());
    let delivery = position(5, 2, Phase::Delivery);
    let reaction = position(5, 2, Phase::Reaction);
    let publication = position(5, 3, Phase::Publication);
    let after_publication = position(5, 3, Phase::Delivery);
    for (label, limit, expected_action) in [
        ("before-delivery", delivery, None),
        ("delivery-only", reaction, Some("delivery")),
        ("reaction-only", publication, Some("reaction")),
        ("publication-only", after_publication, Some("publication")),
    ] {
        let initial = fixture.native.inventory().unwrap();
        let projected = project_grant(&initial, &id(label), initial.reached, limit, true).unwrap();
        let actual = fixture
            .native
            .run(id(label), initial.reached, limit)
            .unwrap()
            .clone();
        assert_eq!(actual, projected);
        let traces = fixture.traces();
        assert_eq!(traces.len(), usize::from(expected_action.is_some()));
        if let Some(action) = expected_action {
            assert_eq!(traces[0]["action"], action);
        }
        if label == "delivery-only" {
            assert_eq!(actual.inventory.delivered_inputs.len(), 1);
            assert_eq!(
                actual.inventory.delivered_inputs[0].reaction.input_sequence,
                U64::new(0)
            );
            assert_eq!(actual.inventory.reactions_completed, U64::new(0));
            assert_eq!(actual.inventory.packet_effects, U64::new(0));
        }
        if label == "reaction-only" {
            assert!(actual.newborn.is_empty());
        }
        if label == "publication-only" {
            assert_eq!(actual.newborn[0].output.publication, publication);
            assert_eq!(actual.newborn[0].pending.reaction.parent, delivery);
            assert_eq!(actual.newborn[0].output.payload.as_slice(), [0, 255, 17]);
        }
    }
}

#[test]
fn host_projection_preserves_positive_delay_microstep_reset_and_sink_delivery() {
    let mut fixture = Fixture::with_timing(false, 7, 4, 0);
    fixture.commit();
    let initial = fixture.native.inventory().unwrap();
    assert_eq!(
        initial.reactions[0].parent,
        position(12, 0, Phase::Delivery)
    );
    let limit = position(12, 0, Phase::Reaction);
    let projected = project_grant(
        &initial,
        &id("sink-delivery"),
        initial.reached,
        limit,
        false,
    )
    .unwrap();
    let actual = fixture
        .native
        .run(id("sink-delivery"), initial.reached, limit)
        .unwrap()
        .clone();
    assert_eq!(actual, projected);
    assert_eq!(fixture.traces()[0]["action"], "delivery");
    assert_eq!(
        actual.inventory.delivered_inputs[0].reaction.input_sequence,
        U64::new(0)
    );
    assert_eq!(actual.inventory.reactions_completed, U64::new(0));
    assert!(actual.newborn.is_empty());
}

#[test]
fn empty_cut_requires_same_native_stage_and_commit_before_effect_free_grant() {
    let mut fixture = Fixture::new(true);
    fixture.request.events.clear();
    let batch = fixture
        .request
        .verified_batch(&fixture.context.cut().execution_owner_id);
    assert!(batch.is_err());
    let empty = InputBatch {
        schema_version: 1,
        execution_owner_id: fixture.context.cut().execution_owner_id.clone(),
        input_epoch: fixture.request.input_epoch.clone(),
        batch_id: fixture.request.batch_id.clone(),
        batch_sequence: fixture.request.batch_sequence,
        events: Vec::new(),
        extensions: Extensions::new(),
    };
    empty.validate().unwrap();
    fixture.request.batch_hash = empty.identity().unwrap();
    if let PacketInputContext::Stage { cut } = &mut fixture.context {
        cut.batch_hash = fixture.request.batch_hash.clone();
        fixture.inventory = bytes(Vec::<CommittedDeliveryV1>::new());
        cut.delivery_inventory = canonical::content_ref(
            &fixture.inventory,
            "application/vnd.crucible.input-inventory+json",
        )
        .unwrap();
    }
    fixture.stage.body = object(&fixture.request);
    fixture.stage.extensions = Extensions::from([(
        PACKET_INPUT_FEATURE.into(),
        serde_json::to_value(&fixture.context).unwrap(),
    )]);
    let start = fixture.native.inventory().unwrap().reached;
    let limit = fixture.context.cut().cutoff;
    assert!(
        fixture
            .native
            .run(id("uncommitted-empty"), start, limit)
            .is_err()
    );
    let stage_receipt = fixture.stage();
    assert!(
        fixture
            .native
            .run(id("staged-empty"), start, limit)
            .is_err()
    );
    let (envelope, context) = fixture.commitment(stage_receipt);
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
    let initial = fixture.native.inventory().unwrap();
    assert_eq!(initial.stages.len(), 1);
    assert_eq!(initial.commits.len(), 1);
    let projected = project_grant(&initial, &id("closed-empty"), start, limit, true).unwrap();
    let actual = fixture
        .native
        .run(id("closed-empty"), start, limit)
        .unwrap()
        .clone();
    assert_eq!(actual, projected);
    assert!(fixture.traces().is_empty());
    assert!(actual.inventory.delivered_inputs.is_empty());
}

#[test]
fn empty_reactive_inventory_preserves_publication_bound_without_inventing_eof() {
    let fixture = Fixture::new(true);
    let mut inventory = fixture.native.inventory().unwrap();
    for (reached, expected) in [
        (
            position(7, 3, Phase::BoundaryControl),
            position(7, 3, Phase::Publication),
        ),
        (
            position(7, 3, Phase::Delivery),
            position(7, 4, Phase::Publication),
        ),
        (
            position(7, 3, Phase::Reaction),
            position(7, 4, Phase::Publication),
        ),
    ] {
        inventory.reached = reached;
        assert_eq!(
            output_bound(&inventory, true).unwrap(),
            crate::node_scheduling::NativeOutputBound::At(expected)
        );
        assert_eq!(
            output_bound(&inventory, false).unwrap(),
            crate::node_scheduling::NativeOutputBound::AfterInstant(U64::new(7))
        );
    }
    inventory.reached = position(7, 15, Phase::Reaction);
    assert!(output_bound(&inventory, true).is_err());
}

#[test]
fn v8_body_join_refuses_split_native_records_before_returning_a_stop_root() {
    let mut fixture = Fixture::with_timing(false, 3, 2, 0);
    fixture.commit();
    let start = fixture.native.inventory().unwrap().reached;
    let limit = position(8, 0, Phase::Reaction);
    let grant = fixture
        .native
        .run(id("original-body-join"), start, limit)
        .unwrap()
        .clone();
    assert_eq!(fixture.traces()[0]["action"], "delivery");
    let root = reference(&bytes(&grant));
    let result = ExactRunResult {
        grant_id: grant.operation,
        reached: grant.inventory.reached,
        stop_reason: StopReason::Ceiling,
        stop_receipt: root.clone(),
        observation_batch: root.clone(),
        pending_inventory: root.clone(),
        next_attention: Bound {
            kind: BoundKind::Unknown,
            position: None,
            evidence: None,
        },
    };
    assert_eq!(
        native_result_root(Some(&MethodResult::ExactRun(result.clone()))).unwrap(),
        Some(root)
    );
    for field in ["pending", "observation"] {
        let mut changed = result.clone();
        if field == "pending" {
            changed.pending_inventory = reference(b"foreign whole inventory");
        } else {
            changed.observation_batch = reference(b"foreign whole observation");
        }
        assert!(native_result_root(Some(&MethodResult::ExactRun(changed))).is_err());
    }
}

#[test]
fn v8_body_join_refuses_attention_as_full_exclusive_ceiling_completion() {
    let root = reference(b"complete native original source record");
    let mut result = ExactRunResult {
        grant_id: id("original-ceiling"),
        reached: position(9, 3, Phase::Reaction),
        stop_reason: StopReason::Attention,
        stop_receipt: root.clone(),
        observation_batch: root.clone(),
        pending_inventory: root.clone(),
        next_attention: Bound {
            kind: BoundKind::Unknown,
            position: None,
            evidence: None,
        },
    };
    assert!(native_result_root(Some(&MethodResult::ExactRun(result.clone()))).is_err());
    result.stop_reason = StopReason::Ceiling;
    assert_eq!(
        native_result_root(Some(&MethodResult::ExactRun(result))).unwrap(),
        Some(root)
    );
}
