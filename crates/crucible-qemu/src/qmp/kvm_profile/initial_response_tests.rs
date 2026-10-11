//! Wire and retained-first-callback model controls; no native effects are executed.

use super::*;
use serde_json::json;

fn request(operation: QmpKvmInitialResponseOperation) -> QmpKvmInitialResponseRequest {
    QmpKvmInitialResponseRequest {
        operation,
        record_index: 2,
        generation: 3,
        expected_invocation: 4,
    }
}

fn observation() -> serde_json::Value {
    json!({
        "schema-version":1,"record-index":2,"generation":3,"expected-invocation":4,
        "vcpu-index":0,"native-vcpu-id":0,"exit-sequence":5,"service-id":6,
        "submitted":true,"completed":true,"result-known":true,"callback-result":0,
        "uncertain-effects":false,"opaque-effects":false,"device-closure":false,
        "input-custody":false,"output-custody":false,"profile-qualified":false
    })
}

#[test]
fn original_initial_response_command_preserves_signed_source_namespace() {
    let request = request(QmpKvmInitialResponseOperation::Poll);
    let command = QmpCommand::KvmInitialResponse { request: &request };
    assert_eq!(command.kind(), QmpCommandKind::KvmInitialResponse);
    assert_eq!(
        command.request(),
        json!({"execute":"x-crucible-kvm-initial-response", "arguments":{
            "operation":"poll","record-index":2,"generation":3,"expected-invocation":4
        }})
    );
    assert!(parse_response(&request, &observation()).is_ok());
}

#[test]
fn original_initial_response_refuses_changed_scope_false_collection_and_closure() {
    let request = request(QmpKvmInitialResponseOperation::Poll);
    for (name, value) in [
        ("schema-version", json!(2)),
        ("record-index", json!(1)),
        ("generation", json!(4)),
        ("expected-invocation", json!(5)),
        ("vcpu-index", json!(4096)),
        ("submitted", json!(false)),
        ("completed", json!(false)),
        ("exit-sequence", json!(0)),
        ("service-id", json!(0)),
        ("device-closure", json!(true)),
        ("input-custody", json!(true)),
        ("output-custody", json!(true)),
        ("profile-qualified", json!(true)),
    ] {
        let mut changed = observation();
        changed[name] = value;
        assert!(
            parse_response(&request, &changed).is_err(),
            "changed {name} accepted"
        );
    }
    let mut changed = observation();
    changed["foreign-field"] = json!(1);
    assert!(parse_response(&request, &changed).is_err());
}

#[test]
fn original_callback_history_keeps_authentic_pending_and_negative_results() -> Result<(), QmpError>
{
    let request = request(QmpKvmInitialResponseOperation::Poll);
    let mut pending = observation();
    pending["completed"] = json!(false);
    pending["result-known"] = json!(false);
    assert!(parse_response(&request, &pending).is_ok());
    pending["callback-result"] = json!(-5);
    assert!(parse_response(&request, &pending).is_err());

    let mut negative = observation();
    negative["callback-result"] = json!(-5);
    negative["uncertain-effects"] = json!(true);
    let state = parse_response(&request, &negative)?;
    assert_eq!(state.observed().callback_result, -5);
    assert!(state.observed().uncertain_effects);
    Ok(())
}

#[test]
fn initial_request_bounds_refuse_before_any_transport() {
    for request in [
        QmpKvmInitialResponseRequest {
            record_index: 65_536,
            ..request(QmpKvmInitialResponseOperation::Submit)
        },
        QmpKvmInitialResponseRequest {
            generation: 0,
            ..request(QmpKvmInitialResponseOperation::Submit)
        },
        QmpKvmInitialResponseRequest {
            expected_invocation: 0,
            ..request(QmpKvmInitialResponseOperation::Submit)
        },
    ] {
        assert!(validate_request(&request).is_err());
    }
}
