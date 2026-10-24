//! Regresses omitted histories and contradictory settled-success data.
//!
//! These are data-predicate controls. Their fixtures construct no live scope,
//! source admission, process, archive ticket or fresh runtime authority.

#![allow(clippy::unwrap_used)]

use super::*;
use crucible_node_transport::{
    envelope::{MessageKind, Nullable},
    reference_packet::{
        PacketInventory,
        control::{PacketNative5UnderlyingRecord, PacketNativeRecord},
    },
};
use std::collections::BTreeMap;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn position() -> Position {
    Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl)
}

fn reference() -> ContentRef {
    canonical::content_ref(b"retained original bytes", "application/json").unwrap()
}

fn activation() -> SavedRuntimeActivation {
    SavedRuntimeActivation {
        generation: U64::new(1),
        activation_id: id("activation"),
        world_binding_hash: canonical::json_hash("cnp.world-binding.v1", &"world").unwrap(),
        owners: Vec::new(),
        boundary: position(),
    }
}

fn common() -> ArchivedSemanticCustody {
    ArchivedSemanticCustody {
        schema: "source-owned.packet-semantic-custody/5".into(),
        arm_attempt: None,
        ready: None,
        prepared_owner: None,
        activate_response: None,
        observe_sequence: U64::new(0),
        activation_attempt: None,
        active: None,
        inputs: BTreeMap::new(),
        operations: BTreeMap::new(),
        watermark: U64::new(0),
        observation: None,
        reclaimed: None,
        retained_credit: 0,
        quarantined: false,
    }
}

#[test]
fn original_input_cannot_disappear_with_empty_common_population() {
    let mut common = common();
    let stage = id("stage");
    assert!(input::required_input_row(&common.inputs, &stage).is_err());
    common.inputs.insert(
        stage.clone(),
        ArchivedInput {
            original: ArchivedBatch {
                activation: activation(),
                node: id("node"),
                stage_operation: stage.clone(),
                batch: id("batch"),
                owners: Vec::new(),
                cutoff: position(),
                inventory: reference(),
                deliveries: Vec::new(),
                payloads: Vec::new(),
            },
            acknowledgement: None,
            watermark: U64::new(0),
            request: InputRequest {
                binding_hash: canonical::json_hash("cnp.owner-binding.v1", &"owner").unwrap(),
                owner_generation: U64::new(1),
                batch_id: id("batch"),
                batch_sequence: U64::new(1),
                input_epoch: id("epoch"),
                events: Vec::new(),
                batch_hash: canonical::json_hash("cnp.input-batch.v1", &"batch").unwrap(),
                extensions: Extensions::new(),
            },
            commitment: None,
            response: None,
        },
    );
    input::required_input_row(&common.inputs, &stage).unwrap();
    common.inputs.remove(&stage);
    assert!(input::required_input_row(&common.inputs, &stage).is_err());
}

#[test]
fn completed_observe_requires_latest_data_and_exact_population() {
    let mut common = common();
    projection::require_observation_population(&common, 0).unwrap();
    common.observe_sequence = U64::new(1);
    assert!(projection::require_observation_population(&common, 1).is_err());
    common.observation = Some((
        activation(),
        NativeSchedulingObservation {
            node: id("node"),
            owners: Vec::new(),
            reached: position(),
            closed_prefix: position(),
            bounds: Vec::new(),
            publications: Vec::new(),
            input_progress: None,
            external_inputs: Vec::new(),
            proof_ref: reference(),
        },
    ));
    projection::require_observation_population(&common, 1).unwrap();
    assert!(projection::require_observation_population(&common, 2).is_err());
    common.observation = None;
    assert!(projection::require_observation_population(&common, 1).is_err());
}

fn operation() -> ArchivedOperation {
    let operation = id("operation");
    let node = id("node");
    ArchivedOperation {
        operation: operation.clone(),
        route: NodeRoute {
            node: node.clone(),
            owners: Vec::new(),
        },
        request: OperationRequest::BoundarySettle {
            start: position(),
            limit: position(),
        },
        activation: activation(),
        inputs: None,
        begin: BeginRequest {
            kind: BeginKind::BoundarySettle,
            binding_hash: canonical::json_hash("cnp.owner-binding.v1", &"owner").unwrap(),
            owner_generation: U64::new(1),
            activation_id: Nullable(Some(id("activation"))),
            world_generation: U64::new(1),
            arguments: serde_json::Map::new(),
            extensions: Extensions::new(),
        },
        outcome: Some(OperationOutcome {
            operation,
            node,
            owners: Vec::new(),
            progress: ProgressEvidence::Exact {
                reached: position(),
                stop: crate::node_contract::StopReason::HorizonPark,
            },
            retained_outputs: Vec::new(),
            scheduling: None,
        }),
        failure: None,
        polls: U64::new(0),
        begin_acknowledged: true,
        cancellation: ("not-attempted".into(), None),
        acknowledged: false,
        retirement: None,
    }
}

#[test]
fn outcome_does_not_erase_later_failure_or_unresolved_retirement() {
    let mut operation = operation();
    projection::settled_operation(&operation).unwrap();
    operation.failure = Some(refused("retained later failure"));
    assert!(projection::settled_operation(&operation).is_err());
    assert!(operation.outcome.is_some());
    operation.failure = None;
    operation.retirement = Some(InputPayload {
        reference: reference(),
        bytes: Vec::new(),
    });
    assert!(projection::settled_operation(&operation).is_err());
    operation.acknowledged = true;
    projection::settled_operation(&operation).unwrap();
    operation.retirement = None;
    assert!(projection::settled_operation(&operation).is_err());
}

#[test]
fn underlying_native_record_must_retain_literal_nullable_grant() {
    let original = Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(id("session"))),
        incarnation_id: Nullable(Some(id("incarnation"))),
        node_id: Nullable(Some(id("node"))),
        execution_owner_id: Nullable(Some(id("owner"))),
        capture_owner_id: Nullable(None),
        request_id: Nullable(Some(id("observe"))),
        operation_id: Nullable(None),
        sequence: U64::new(9),
        method: Method::Observe,
        body: serde_json::Map::new(),
        extensions: Extensions::new(),
    };
    let record = PacketNativeRecord {
        schema: "source-owned.packet-native/2".into(),
        native_pid: U64::new(42),
        original,
        inventory: PacketInventory {
            reached: position(),
            gate_closed: false,
            pending: Vec::new(),
            retained_outputs: Vec::new(),
            private_mutations: U64::new(0),
            packet_effects: U64::new(0),
        },
        grant: None,
    };
    let mut value = serde_json::to_value(&record).unwrap();
    let record = PacketNative5UnderlyingRecord::Producer(Box::new(record));
    projection::strict_native_record_data(&record, &value).unwrap();
    value.as_object_mut().unwrap().remove("grant");
    assert!(projection::strict_native_record_data(&record, &value).is_err());
}
