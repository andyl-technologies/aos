//! Closed More callback wire controls with explicitly modeled source replies.

use super::*;
use serde_json::{Value, json};

fn request() -> QmpKvmMoreResponseRequest {
    QmpKvmMoreResponseRequest {
        operation: QmpKvmMoreResponseOperation::Submit,
        vcpu_index: 0,
        completion_id: 1,
        exit_sequence: 6,
    }
}

fn observed(completed: bool, collected: bool, result: i32) -> Value {
    json!({
        "schema-version":1,"vcpu-index":0,"kernel-vcpu-id":0,
        "completion-id":1,"exit-sequence":6,"service-id":7,"submitted":true,
        "completed":completed,"result-known":collected,"callback-result":result,
        "uncertain-effects":result < 0,"opaque-effects":false,
        "device-closure":false,"input-custody":false,"output-custody":false,
        "profile-qualified":false
    })
}

#[test]
fn original_more_command_preserves_exact_native_namespace_and_fragment() -> Result<(), QmpError> {
    let request = request();
    let command = QmpCommand::KvmMoreResponse { request: &request };
    assert_eq!(command.kind(), QmpCommandKind::KvmMoreResponse);
    assert_eq!(
        command.request(),
        json!({
            "execute":"x-crucible-kvm-response-service","arguments":{
                "operation":"submit","vcpu-index":0,"completion-id":1,"exit-sequence":6
            }
        })
    );
    for (completed, collected, result) in [(false, false, 0), (true, false, 0), (true, true, -5)] {
        let state = parse_response(&request, &observed(completed, collected, result))?;
        assert_eq!(state.observed().completed, completed);
        assert_eq!(state.observed().result_known, collected);
        assert_eq!(state.observed().callback_result, result);
    }
    Ok(())
}

#[test]
fn changed_more_scope_or_false_closure_refuses_without_native_admission() {
    let request = request();
    for (key, replacement) in [
        ("schema-version", json!(2)),
        ("vcpu-index", json!(1)),
        ("completion-id", json!(2)),
        ("exit-sequence", json!(7)),
        ("service-id", json!(0)),
        ("submitted", json!(false)),
        ("device-closure", json!(true)),
        ("input-custody", json!(true)),
        ("output-custody", json!(true)),
        ("profile-qualified", json!(true)),
        ("unknown-field", json!(1)),
    ] {
        let mut changed = observed(true, true, 0);
        changed[key] = replacement;
        assert!(
            parse_response(&request, &changed).is_err(),
            "changed {key} accepted"
        );
    }
    for (completed, collected, result) in [(false, true, 0), (false, false, 1)] {
        assert!(parse_response(&request, &observed(completed, collected, result)).is_err());
    }
    for invalid in [
        QmpKvmMoreResponseRequest {
            vcpu_index: 4096,
            ..request
        },
        QmpKvmMoreResponseRequest {
            completion_id: 0,
            ..request
        },
        QmpKvmMoreResponseRequest {
            exit_sequence: 0,
            ..request
        },
    ] {
        assert!(validate_request(&invalid).is_err());
    }
}
