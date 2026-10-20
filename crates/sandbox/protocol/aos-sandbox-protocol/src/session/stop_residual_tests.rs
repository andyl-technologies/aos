//! Tests only canonical residual DATA and exact Runtime response binding.
//!
//! These fixtures mint no native cleanup proof or authenticated outcome.

use super::*;
use aos_sandbox_api::aos::sandbox::local::v1::{
    ApplyRuntimeRequest, AssignmentFence, RequestHeader, RuntimeAction,
};
use crate::storage_capture_session::stop_cleanup::{
    CaptureQuiescentIncompleteFieldsDataV4, CaptureQuiescentIncompleteReceiptDataV4,
};

fn fixture() -> (ApplyRuntimeRequest, RuntimeObservation) {
    let fence = AssignmentFence {
        sandbox_id: vec![1; 16].into(),
        incarnation_id: vec![2; 16].into(),
        assignment_epoch: 3,
        desired_generation: 4,
        assignment_digest: vec![5; 32].into(),
        ..Default::default()
    };
    let runtime = crate::semantics::host::runtime_handle_v1(&[2; 16], 3, &[5; 32]);
    let request = ApplyRuntimeRequest {
        header: Some(RequestHeader {
            request_id: vec![6; 16].into(),
            ..Default::default()
        }).into(),
        fence: Some(fence.clone()).into(),
        action: RuntimeAction::RUNTIME_ACTION_STOP.into(),
        ..Default::default()
    };
    let residual = CaptureQuiescentIncompleteReceiptDataV4::from_fields_v4(
        CaptureQuiescentIncompleteFieldsDataV4 {
            nonce: [1; 32],
            begin: [2; 32],
            source: aos_sandbox_model::ObjectDigest::from_bytes([3; 32]),
            attempt: [4; 16],
            durable_attempt: aos_sandbox_model::ObjectDigest::from_bytes([5; 32]),
            stop_request: [6; 16],
            runtime: aos_sandbox_model::ObjectDigest::from_bytes(runtime),
            stop_frame: aos_sandbox_model::ObjectDigest::from_bytes([7; 32]),
            stop_plan: aos_sandbox_model::ObjectDigest::from_bytes([8; 32]),
            stop_lease: aos_sandbox_model::ObjectDigest::from_bytes([9; 32]),
            physical_binding: aos_sandbox_model::ObjectDigest::from_bytes([10; 32]),
            native_cleanup: aos_sandbox_model::ObjectDigest::from_bytes([11; 32]),
            observed_wall_seconds: 12,
            observed_boottime_nanoseconds: 13,
            stop_cutoff_boottime_nanoseconds: 14,
        },
    ).unwrap();
    let response = RuntimeObservation {
        runtime_handle: runtime.to_vec().into(),
        fence: Some(fence).into(),
        state: RuntimeState::RUNTIME_STATE_ABSENT.into(),
        observation_sequence: 1,
        capture_stop_residual_v4: residual.encode_v4().to_vec().into(),
        ..Default::default()
    };
    (request, response)
}

#[test]
fn exact_stop_projects_the_same_whole_residual_and_ordinary_none_stays_unchanged() {
    let (request, mut response) = fixture();
    let residual = runtime_stop_residual_for_apply_v4(
        &response.encode_to_vec(), &request.encode_to_vec(),
    ).unwrap().unwrap();
    assert_eq!(residual.canonical_bytes_v4().as_slice(), response.capture_stop_residual_v4.as_slice());

    response.capture_stop_residual_v4 = Vec::new().into();
    let ordinary = response.encode_to_vec();
    assert!(runtime_stop_residual_for_apply_v4(&ordinary, &request.encode_to_vec()).unwrap().is_none());
    assert_eq!(RuntimeObservation::decode_from_slice(&ordinary).unwrap().encode_to_vec(), ordinary);
}

#[test]
fn residual_never_becomes_an_ordinary_launch_or_running_observation() {
    let (mut request, mut response) = fixture();
    request.action = RuntimeAction::RUNTIME_ACTION_LAUNCH.into();
    assert!(validate_runtime_effect_receipt_for_apply(&response.encode_to_vec(), &request.encode_to_vec()).is_err());

    request.action = RuntimeAction::RUNTIME_ACTION_STOP.into();
    response.state = RuntimeState::RUNTIME_STATE_READY.into();
    assert!(validate_runtime_effect_receipt_for_apply(&response.encode_to_vec(), &request.encode_to_vec()).is_err());
    response.state = RuntimeState::RUNTIME_STATE_ABSENT.into();
    response.leader_handle = vec![1; 32].into();
    assert!(validate_runtime_effect_receipt_for_apply(&response.encode_to_vec(), &request.encode_to_vec()).is_err());
}

#[test]
fn foreign_stop_and_unknown_residual_version_refuse_in_the_sole_engine() {
    let (mut request, mut response) = fixture();
    request.header = Some(RequestHeader { request_id: vec![7; 16].into(), ..Default::default() }).into();
    assert!(validate_runtime_effect_receipt_for_apply(&response.encode_to_vec(), &request.encode_to_vec()).is_err());

    request.header = Some(RequestHeader { request_id: vec![6; 16].into(), ..Default::default() }).into();
    let mut foreign = response.capture_stop_residual_v4.to_vec();
    foreign[9] = 5;
    response.capture_stop_residual_v4 = foreign.into();
    assert!(validate_runtime_effect_receipt_for_apply(&response.encode_to_vec(), &request.encode_to_vec()).is_err());
}
