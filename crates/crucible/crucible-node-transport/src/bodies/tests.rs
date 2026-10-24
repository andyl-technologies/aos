//! Exercises closed body schemas and original request/response identities.

use super::*;
use serde_json::json;

fn body(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}
fn reference() -> ContentRef {
    canonical::content_ref(b"fixture", "application/json").unwrap()
}
fn identity(domain: &str) -> HashRef {
    canonical::hash(domain, b"fixture").unwrap()
}

#[test]
fn all_nonhello_baseline_request_methods_have_closed_schemas() {
    let hash = identity("cnp.owner-binding.v1");
    let world = identity("cnp.world-binding.v1");
    let content = reference();
    let fixtures = [
        (Method::Discover, json!({"profile_ids":[],"extensions":{}})),
        (
            Method::Realize,
            json!({"realization_id":"realization","configuration":content,"requested_node_ids":["node"],"resource_limits":{"cpu_budget_ns":"0","memory_bytes":"0","writable_bytes":"0","processes":"0","descriptors":"0","pending_events":"0","content_bytes":"0","maximum_operations":"0","extensions":{}},"extensions":{}}),
        ),
        (
            Method::Admit,
            json!({"bindings":[],"world_binding_hash":world,"admission_receipt":content,"extensions":{}}),
        ),
        (
            Method::Activate,
            json!({"admission_id":"admission","activation_id":"activation","world_generation":"1","prepared_token":"prepared","world_binding_hash":world,"gate_id":"gate","extensions":{}}),
        ),
        (
            Method::Input,
            json!({"binding_hash":hash,"owner_generation":"1","batch_id":"batch","batch_sequence":"1","input_epoch":"epoch","events":[],"batch_hash":identity("cnp.input-batch.v1"),"extensions":{}}),
        ),
        (
            Method::Observe,
            json!({"binding_hash":hash,"owner_generation":"1","after_observation_sequence":"0","maximum_items":"5","extensions":{}}),
        ),
        (
            Method::Begin,
            json!({"kind":"pause","binding_hash":hash,"owner_generation":"1","activation_id":null,"world_generation":"0","arguments":{"participant_ids":["node"],"reason":"pause"},"extensions":{}}),
        ),
        (
            Method::Poll,
            json!({"after_observation_sequence":"0","extensions":{}}),
        ),
        (Method::Cancel, json!({"reason":"cancel","extensions":{}})),
        (
            Method::QuantumClose,
            json!({"grant_id":"grant","activation_id":"activation","world_generation":"1","owner_generation":"1","input_epoch":"epoch","quantum_index":"0","participant_ids":["node"],"cut":{"time_ps":"100","microstep":"0","phase":0},"policy_hash":hash,"observation_batch_hash":identity("cnp.observation-batch.v1"),"input_watermark":"1","deadline_disposition":"within_budget","extensions":{}}),
        ),
        (
            Method::WorldActivate,
            json!({"transaction_id":"transaction","activation_id":"activation","world_generation":"1","prepared_token":"prepared","world_binding_hash":world,"gate_id":"gate","activation_manifest":content,"extensions":{}}),
        ),
        (
            Method::Abort,
            json!({"transaction_id":"transaction","reason":"abort","extensions":{}}),
        ),
        (
            Method::Retire,
            json!({"request_ids":["request"],"operation_ids":[],"disposition":"abandoned_inert_transfer","custody_receipt":null,"extensions":{}}),
        ),
        (
            Method::BlobBegin,
            json!({"transfer_id":"transfer","content":content,"extensions":{}}),
        ),
        (
            Method::BlobChunk,
            json!({"transfer_id":"transfer","offset":"0","bytes":"AA","extensions":{}}),
        ),
        (
            Method::BlobFinish,
            json!({"transfer_id":"transfer","extensions":{}}),
        ),
        (
            Method::Release,
            json!({"realization_id":"realization","extensions":{}}),
        ),
    ];
    for (method, value) in fixtures {
        let valid = body(value);
        assert!(
            decode_request(method, &valid).is_ok(),
            "missing schema for {method:?}"
        );
        let mut extra = valid.clone();
        extra.insert("host_pointer".to_owned(), json!("123"));
        assert!(
            decode_request(method, &extra).is_err(),
            "unknown field accepted for {method:?}"
        );
        let mut missing = valid;
        missing.remove("extensions");
        assert!(
            decode_request(method, &missing).is_err(),
            "missing extensions accepted for {method:?}"
        );
    }
}

fn exact_request(kind: &str, start: Position, limit: Position) -> Map<String, Value> {
    body(
        json!({"kind":kind,"binding_hash":identity("cnp.owner-binding.v1"),"owner_generation":"1","activation_id":"activation","world_generation":"1","arguments":{"grant_id":"grant","participant_ids":["node"],"realization_id":"realization","activation_id":"activation","world_generation":"1","owner_generation":"1","input_epoch":"epoch","mode":"exact","ordering_profile":"superdense-v1","start":start,"limit":limit,"boundary_policy":"ordinary_stop","input_authorization":reference(),"input_watermark":"0"},"extensions":{}}),
    )
}

#[test]
fn grant_arguments_are_closed_and_bound_to_outer_live_authority() {
    let start = Position::new(U64::new(100), U64::new(0), Phase::BoundaryControl);
    let limit = Position::new(U64::new(200), U64::new(0), Phase::BoundaryControl);
    let mut valid = exact_request("exact_run", start, limit);
    assert!(decode_request(Method::Begin, &valid).is_ok());
    valid.get_mut("arguments").unwrap()["owner_generation"] = json!("2");
    assert!(decode_request(Method::Begin, &valid).is_err());
    valid = exact_request("exact_run", start, limit);
    valid.remove("activation_id");
    assert!(decode_request(Method::Begin, &valid).is_err());
    assert!(
        decode_request(
            Method::Begin,
            &exact_request("boundary_settle", start, limit)
        )
        .is_err()
    );
    let same_tick = Position {
        phase: Phase::Reaction,
        ..start
    };
    assert!(
        decode_request(
            Method::Begin,
            &exact_request("boundary_settle", start, same_tick)
        )
        .is_ok()
    );
}

#[test]
fn raw_success_result_debug_never_exposes_hello_credentials() {
    let response = ResponseShape::Completed {
        operation_state: OperationState::Completed,
        result: body(
            json!({"resume_token":"sensitive-launch-token","provider_nonce":"private-nonce"}),
        ),
        extensions: Extensions::new(),
    };
    let debug = format!("{response:?}");
    assert!(!debug.contains("sensitive-launch-token"));
    assert!(!debug.contains("private-nonce"));
}

#[test]
fn exact_physical_ceiling_excludes_settlement_but_permits_empty_parking() {
    let boundary = Position::new(U64::new(100), U64::new(0), Phase::BoundaryControl);
    assert!(
        decode_request(
            Method::Begin,
            &exact_request("exact_run", boundary, boundary)
        )
        .is_ok()
    );

    let settlement = Position {
        phase: Phase::Reaction,
        ..boundary
    };
    assert!(
        decode_request(
            Method::Begin,
            &exact_request("exact_run", boundary, settlement)
        )
        .is_err()
    );
    assert!(
        decode_request(
            Method::Begin,
            &exact_request("boundary_settle", boundary, settlement)
        )
        .is_ok()
    );
    assert!(
        decode_request(
            Method::Begin,
            &exact_request("exact_run", settlement, boundary)
        )
        .is_err()
    );
}

#[test]
fn optional_cursor_is_optional_but_never_implicit_null() {
    assert!(
        decode_request(
            Method::Discover,
            &body(json!({"profile_ids":[],"extensions":{}}))
        )
        .is_ok()
    );
    assert!(
        decode_request(
            Method::Discover,
            &body(json!({"profile_ids":[],"cursor":null,"extensions":{}}))
        )
        .is_err()
    );
}

#[test]
fn exact_response_cannot_claim_progress_beyond_original_grant() {
    let start = Position::new(U64::new(100), U64::new(0), Phase::BoundaryControl);
    let limit = Position::new(U64::new(200), U64::new(0), Phase::BoundaryControl);
    let request = decode_request(Method::Begin, &exact_request("exact_run", start, limit)).unwrap();
    let mut response = body(
        json!({"status":"completed","operation_state":"completed","result":{"grant_id":"grant","reached":limit,"stop_reason":"ceiling","stop_receipt":reference(),"observation_batch":reference(),"pending_inventory":reference(),"next_attention":{"kind":"unknown","position":null,"evidence":null}},"extensions":{}}),
    );
    assert!(decode_response(&request, &response).is_ok());
    response.get_mut("result").unwrap()["reached"]["time_ps"] = json!("201");
    assert!(decode_response(&request, &response).is_err());
}

#[test]
fn terminal_unknown_error_is_retained_without_claiming_completed_effects() {
    let request = decode_request(
        Method::Poll,
        &body(json!({"after_observation_sequence":"0","extensions":{}})),
    )
    .unwrap();
    let outcome = json!({"status":"error","operation_state":"unknown","error":{"code":"OUTCOME_UNKNOWN","message":"native custody is ambiguous","effect":"unknown","retryable":false,"details":{}},"extensions":{}});
    let response = body(
        json!({"status":"completed","operation_state":"completed","result":{"operation_id":"operation","operation_state":"unknown","outcome":outcome,"observations":[],"next_observation_sequence":"0"},"extensions":{}}),
    );
    assert!(decode_response(&request, &response).is_ok());
    let mut missing = response;
    missing
        .get_mut("result")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("outcome");
    assert!(decode_response(&request, &missing).is_err());
}

#[test]
fn unknown_error_codes_have_no_stronger_default_effect_certainty() {
    let error = ErrorRecord {
        code: "VENDOR_FAILURE".to_owned(),
        message: "details".to_owned(),
        effect: EffectCertainty::NotStarted,
        retryable: true,
        details: Map::new(),
    };
    assert_eq!(
        error.baseline_handling(),
        ("IMPLEMENTATION_FAILURE", EffectCertainty::Unknown)
    );
}

#[test]
fn notifications_cannot_act_as_request_methods_or_authoritative_results() {
    let notification = body(
        json!({"operation_state":"running","last_observation_sequence":"7","details":{},"extensions":{}}),
    );
    assert!(decode_notification(Method::ObservationReady, &notification).is_ok());
    assert!(decode_request(Method::ObservationReady, &notification).is_err());
    assert!(decode_notification(Method::Begin, &notification).is_err());
}
