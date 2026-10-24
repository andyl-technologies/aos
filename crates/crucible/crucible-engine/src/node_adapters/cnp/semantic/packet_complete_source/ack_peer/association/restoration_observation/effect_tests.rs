//! Exercises the actual terminal DATA predicate without Source/native authority.

use super::*;
use crucible_node_format::{Extensions, ObservationBatch, U64, Visibility};
use crucible_node_transport::reference_packet::service::complete_restore::activation::*;
use crucible_node_transport::{
    bodies::{
        EffectCertainty, ErrorRecord, MethodResult, ObserveResult, OperationState, ResponseShape,
    },
    envelope::{Envelope, MessageKind, Method, Nullable},
};

fn request() -> PacketRestorationObservationRequest {
    let reference = canonical::content_ref(b"ordinary-test-data", "application/json").unwrap();
    let owner = Id::new("owner").unwrap();
    let world = canonical::hash("cnp.world-binding.v1", b"world").unwrap();
    PacketRestorationObservationRequest {
        schema: PACKET_RESTORATION_OBSERVE_FEATURE.into(),
        scope: PacketRestorationActivationScope {
            source_birth: reference.clone(),
            source_runtime: reference.clone(),
            scope_proof: reference.clone(),
            target: PacketRestorationActivationTarget {
                native_pid: 1.into(),
                session: Id::new("session").unwrap(),
                incarnation: Id::new("incarnation").unwrap(),
                node: Id::new("node").unwrap(),
                owner,
                owner_generation: 1.into(),
                binding_hash: canonical::hash("cnp.owner-binding.v1", b"binding").unwrap(),
                world,
                activation: Id::new("activation").unwrap(),
                generation: 1.into(),
                prepared_token: Id::new("prepared").unwrap(),
                gate: Id::new("gate").unwrap(),
                admission: Id::new("admission").unwrap(),
                transaction: Id::new("transaction").unwrap(),
            },
            restoration: PacketRestorationActivationOriginals {
                captured_owner_state: reference.clone(),
                captured_control: reference.clone(),
                captured_journal: reference.clone(),
                mapping: reference.clone(),
                commit_request: reference.clone(),
                commit_response: reference.clone(),
                context_digest: Bytes::new(vec![9; 32]),
            },
        },
        world_original: reference.clone(),
        world_terminal: reference,
        maximum_items: 1.into(),
        native_allocation: PacketRestorationActivationAllocationRow {
            retained_requested_bytes: 1.into(),
            maximum_simultaneous_transient_bytes: 2.into(),
            declared_counter_scratch_bytes: 3.into(),
        },
    }
}

fn pair() -> (PacketRestorationObservationRequest, Envelope, ResponseBody) {
    let request = request();
    let target = &request.scope.target;
    let id = Id::new("cnp-restoration-observe-activation").unwrap();
    let original = Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(target.session.clone())),
        incarnation_id: Nullable(Some(target.incarnation.clone())),
        node_id: Nullable(Some(target.node.clone())),
        execution_owner_id: Nullable(Some(target.owner.clone())),
        capture_owner_id: Nullable(None),
        request_id: Nullable(Some(id.clone())),
        operation_id: Nullable(None),
        sequence: U64::new(7),
        method: Method::Observe,
        body: Default::default(),
        extensions: Default::default(),
    };
    let batch = ObservationBatch {
        schema_version: 1,
        execution_owner_id: target.owner.clone(),
        owner_binding_hash: target.binding_hash.clone(),
        world_binding_hash: target.world.clone(),
        activation_id: target.activation.clone(),
        world_generation: target.generation,
        owner_generation: target.owner_generation,
        operation_id: id,
        grant_id: None,
        first_sequence: 0.into(),
        last_sequence: 0.into(),
        events: Vec::new(),
        visibility: Visibility::Staged,
        measurement_ref: canonical::content_ref(b"real-result-slot", "application/json").unwrap(),
        extensions: Extensions::new(),
    };
    let result = ObserveResult {
        observations: vec![batch],
        next_sequence: 1.into(),
        complete: true,
        inventory_hash: canonical::hash("cnp.packet-inventory.v5", b"inventory").unwrap(),
    };
    let response = ResponseBody {
        shape: ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result: serde_json::to_value(&result)
                .unwrap()
                .as_object()
                .unwrap()
                .clone(),
            extensions: Extensions::new(),
        },
        result: Some(MethodResult::Observe(result)),
    };
    (request, original, response)
}

#[test]
fn actual_observation_terminal_returns_only_the_borrowed_single_measurement() {
    let (request, original, response) = pair();
    let actual = authenticate_terminal(&response, &request, &original).unwrap();
    let Some(MethodResult::Observe(result)) = response.result.as_ref() else {
        panic!("fixture Observe absent")
    };
    assert!(std::ptr::eq(
        actual,
        &result.observations[0].measurement_ref
    ));

    let mut foreign = original.clone();
    foreign.request_id = Nullable(Some(Id::new("other-request").unwrap()));
    assert!(authenticate_terminal(&response, &request, &foreign).is_err());
    let mut changed = request.clone();
    changed.scope.target.owner = Id::new("other-owner").unwrap();
    assert!(authenticate_terminal(&response, &changed, &original).is_err());
}

#[test]
fn actual_observation_terminal_refuses_partial_error_extra_batch_and_grant() {
    let (request, original, response) = pair();
    for mutation in 0..7 {
        let mut changed = response.clone();
        match mutation {
            0 => {
                changed.shape = ResponseShape::Error {
                    operation_state: OperationState::Unknown,
                    error: ErrorRecord {
                        code: "RESOURCE_EXHAUSTED".into(),
                        message: "retained refusal".into(),
                        effect: EffectCertainty::Unknown,
                        retryable: false,
                        details: Default::default(),
                    },
                    extensions: Extensions::new(),
                }
            }
            1 => {
                changed.shape = ResponseShape::Accepted {
                    operation_state: OperationState::Running,
                    result: Default::default(),
                    extensions: Extensions::new(),
                }
            }
            2 => changed.result = None,
            _ => {
                let Some(MethodResult::Observe(result)) = changed.result.as_mut() else {
                    panic!("fixture Observe absent")
                };
                match mutation {
                    3 => result.observations.push(result.observations[0].clone()),
                    4 => result.observations[0].grant_id = Some(Id::new("invented-grant").unwrap()),
                    5 => result.complete = false,
                    _ => result.observations[0]
                        .extensions
                        .insert("unknown".into(), serde_json::Value::Bool(true))
                        .map(|_| ())
                        .unwrap_or(()),
                }
            }
        }
        assert!(authenticate_terminal(&changed, &request, &original).is_err());
    }
}

#[test]
fn actual_observation_terminal_binds_the_complete_verified_inventory_hash() {
    let (request, original, response) = pair();
    let Some(MethodResult::Observe(result)) = response.result.as_ref() else {
        panic!("fixture Observe absent");
    };
    let expected = result.inventory_hash.clone();
    authenticate_terminal_inventory_data(&response, &expected).unwrap();

    let mut changed = response.clone();
    let Some(MethodResult::Observe(result)) = changed.result.as_mut() else {
        panic!("fixture Observe absent");
    };
    result.inventory_hash =
        canonical::hash("cnp.packet-inventory.v5", b"different complete inventory").unwrap();

    let replacement = serde_json::to_value(&*result)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    let ResponseShape::Completed { result, .. } = &mut changed.shape else {
        panic!("fixture completed shape absent");
    };
    *result = replacement;

    // All earlier batch/target/sequence checks still accept this DATA; the
    // new complete-inventory correspondence is the causal refusal boundary.
    assert!(authenticate_terminal(&changed, &request, &original).is_ok());
    assert!(authenticate_terminal_inventory_data(&changed, &expected).is_err());
    assert!(authenticate_terminal_inventory_data(&response, &expected).is_ok());
}
