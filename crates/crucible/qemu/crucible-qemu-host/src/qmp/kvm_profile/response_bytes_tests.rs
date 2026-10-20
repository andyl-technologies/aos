//! Canonical native-byte wire models, distinct from hardware qualification.

use super::*;
use serde_json::{Value, json};

fn request(operation: QmpKvmResponseBytesOperation) -> QmpKvmResponseBytesRequest {
    let complete = operation == QmpKvmResponseBytesOperation::Complete;
    QmpKvmResponseBytesRequest {
        operation,
        record_index: 2,
        generation: 3,
        expected_invocation: 4,
        operation_id: u64::from(complete),
        expected_sequence: if complete { 5 } else { 0 },
    }
}

fn native_query() -> Value {
    json!({
        "schema-version":1,"payload-kind":"native-query","components":7,
        "kernel-capability":41002,"native-abi-size":4264,"maximum-data-bytes":4096,
        "clock-edition":3,"clock-components":159,"qemu-build-id":"a".repeat(64),
        "qemu-source-hash":"b".repeat(64),"record-index":2,"vcpu-index":0,
        "native-vcpu-id":0,"generation":3,"invocation":4,"operation-id":0,
        "expected-sequence":0,"expected-revision":0,"pending-sequence":5,
        "consumed-sequence":4,"revision":6,"native-phase":1,"callback-result":0,
        "native-errno":0,"reason":6,"address":4096,"data-offset":0,
        "length":4,"count":0,"size":0,"direction":1,"data-length":4,
        "data-base64":"AAEC/w==","result-known":true,"uncertain-effects":false,
        "opaque-effects":false,"kernel-source-qualified":false,"device-closure":false,
        "input-custody":false,"output-custody":false,"profile-qualified":false
    })
}

fn native_done() -> Value {
    let mut value = native_query();
    for (key, replacement) in [
        ("payload-kind", json!("native-result")),
        ("operation-id", json!(1)),
        ("expected-sequence", json!(5)),
        ("expected-revision", json!(6)),
        ("consumed-sequence", json!(5)),
        ("revision", json!(7)),
        ("native-phase", json!(3)),
        ("reason", json!(0)),
        ("address", json!(0)),
        ("length", json!(0)),
        ("direction", json!(0)),
        ("data-length", json!(0)),
        ("data-base64", json!("")),
    ] {
        value[key] = replacement;
    }
    value
}

fn original_echo() -> Value {
    let mut value = native_query();
    for (key, replacement) in [
        ("payload-kind", json!("original-request")),
        ("operation-id", json!(1)),
        ("expected-sequence", json!(5)),
        ("expected-revision", json!(6)),
        ("invocation", json!(0)),
        ("pending-sequence", json!(0)),
        ("consumed-sequence", json!(0)),
        ("revision", json!(0)),
        ("native-phase", json!(4)),
        ("native-errno", json!(5)),
        ("direction", json!(0)),
        ("result-known", json!(false)),
        ("uncertain-effects", json!(true)),
    ] {
        value[key] = replacement;
    }
    value
}

#[test]
fn original_byte_command_and_binary_native_fragment_preserve_source_geometry()
-> Result<(), QmpError> {
    let request = request(QmpKvmResponseBytesOperation::Query);
    let command = QmpCommand::KvmResponseBytes { request: &request };
    assert_eq!(command.kind(), QmpCommandKind::KvmResponseBytes);
    assert_eq!(
        command.request(),
        json!({"execute":"x-crucible-kvm-response-bytes",
        "arguments":{"operation":"query","record-index":2,"generation":3,
        "expected-invocation":4,"operation-id":0,"expected-sequence":0}})
    );
    let state = parse_response(&request, &native_query())?;
    assert_eq!(state.bytes(), &[0, 1, 2, 255]);
    assert_eq!(
        state.observed().payload_kind,
        QmpKvmResponseBytesPayloadKind::NativeQuery
    );
    Ok(())
}

#[test]
fn canonical_echo_is_input_only_and_cannot_be_promoted_to_a_native_result() -> Result<(), QmpError>
{
    let request = request(QmpKvmResponseBytesOperation::Complete);
    let state = parse_response(&request, &original_echo())?;
    assert_eq!(state.bytes(), &[0, 1, 2, 255]);
    assert!(!state.observed().result_known);
    assert!(state.observed().uncertain_effects);
    for (key, replacement) in [
        ("result-known", json!(true)),
        ("uncertain-effects", json!(false)),
        ("native-errno", json!(0)),
        ("invocation", json!(4)),
        ("native-vcpu-id", json!(1)),
        ("pending-sequence", json!(5)),
        ("consumed-sequence", json!(4)),
        ("callback-result", json!(1)),
        ("revision", json!(7)),
        ("payload-kind", json!("native-result")),
        ("direction", json!(1)),
    ] {
        let mut value = original_echo();
        value[key] = replacement;
        assert!(
            parse_response(&request, &value).is_err(),
            "changed {key} accepted"
        );
    }
    assert!(
        parse_response(
            &super::tests::request(QmpKvmResponseBytesOperation::Query),
            &original_echo()
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn canonical_completion_keeps_done_more_and_negative_original_revision_arithmetic()
-> Result<(), QmpError> {
    let request = request(QmpKvmResponseBytesOperation::Complete);
    assert!(parse_response(&request, &native_done())?.bytes().is_empty());
    let mut more = native_query();
    for (key, value) in [
        ("payload-kind", json!("native-result")),
        ("operation-id", json!(1)),
        ("expected-sequence", json!(5)),
        ("expected-revision", json!(6)),
        ("pending-sequence", json!(6)),
        ("consumed-sequence", json!(5)),
        ("revision", json!(8)),
        ("native-phase", json!(2)),
    ] {
        more[key] = value;
    }
    assert_eq!(parse_response(&request, &more)?.bytes(), &[0, 1, 2, 255]);

    let mut negative = native_done();
    negative["native-phase"] = json!(4);
    negative["callback-result"] = json!(-5);
    negative["uncertain-effects"] = json!(true);
    negative["consumed-sequence"] = json!(4);
    assert!(
        parse_response(&request, &negative)?
            .observed()
            .uncertain_effects
    );
    for original in [native_done(), more, negative] {
        for key in [
            "pending-sequence",
            "consumed-sequence",
            "revision",
            "expected-revision",
        ] {
            let mut value = original.clone();
            value[key] = json!(99);
            assert!(
                parse_response(&request, &value).is_err(),
                "changed {key} accepted"
            );
        }
    }
    Ok(())
}

#[test]
fn canonical_compatibility_roster_and_false_closure_remain_closed() {
    let request = request(QmpKvmResponseBytesOperation::Query);
    for (key, replacement) in [
        ("schema-version", json!(2)),
        ("components", json!(8)),
        ("kernel-capability", json!(0)),
        ("native-abi-size", json!(4263)),
        ("maximum-data-bytes", json!(8192)),
        ("clock-edition", json!(1)),
        ("clock-components", json!(228)),
        ("qemu-build-id", json!("A".repeat(64))),
        ("qemu-source-hash", json!("b".repeat(63))),
        ("record-index", json!(3)),
        ("vcpu-index", json!(4096)),
        ("generation", json!(4)),
        ("invocation", json!(5)),
        ("operation-id", json!(1)),
        ("expected-sequence", json!(5)),
        ("expected-revision", json!(1)),
        ("native-errno", json!(5)),
        ("native-phase", json!(6)),
        ("result-known", json!(false)),
        ("kernel-source-qualified", json!(true)),
        ("device-closure", json!(true)),
        ("input-custody", json!(true)),
        ("output-custody", json!(true)),
        ("profile-qualified", json!(true)),
    ] {
        let mut value = native_query();
        value[key] = replacement;
        assert!(
            parse_response(&request, &value).is_err(),
            "changed {key} accepted"
        );
    }
    let mut foreign = native_query();
    foreign["extra"] = json!(1);
    assert!(parse_response(&request, &foreign).is_err());
}

#[test]
fn canonical_encoding_geometry_and_maximum_private_payload_are_checked() -> Result<(), QmpError> {
    for invalid in [
        "A", "AAA", "A===", "AA=A", "AB==", "AAB=", "AA==AAAA", "AA__", "AA\n=",
    ] {
        assert!(
            payload::decode(invalid).is_err(),
            "foreign encoding accepted: {invalid:?}"
        );
    }
    let request = request(QmpKvmResponseBytesOperation::Query);
    for (key, replacement) in [
        ("reason", json!(0)),
        ("data-offset", json!(1)),
        ("length", json!(9)),
        ("count", json!(1)),
        ("size", json!(1)),
        ("direction", json!(2)),
        ("data-length", json!(3)),
        ("data-base64", json!("AA==")),
        ("consumed-sequence", json!(5)),
    ] {
        let mut value = native_query();
        value[key] = replacement;
        assert!(
            parse_response(&request, &value).is_err(),
            "changed {key} accepted"
        );
    }
    let mut pio = native_query();
    for (key, value) in [
        ("reason", json!(2)),
        ("address", json!(65535)),
        ("length", json!(0)),
        ("count", json!(4096)),
        ("size", json!(1)),
        ("data-offset", json!(4096)),
        ("data-length", json!(4096)),
        ("data-base64", json!("AAAA".repeat(1365) + "AA==")),
    ] {
        pio[key] = value;
    }
    assert_eq!(parse_response(&request, &pio)?.bytes().len(), 4096);
    for (key, value) in [
        ("count", json!(4097)),
        ("size", json!(3)),
        ("address", json!(65536)),
        ("data-offset", json!(u64::MAX)),
        ("data-base64", json!("AAAA".repeat(1366))),
    ] {
        let mut changed = pio.clone();
        changed[key] = value;
        assert!(
            parse_response(&request, &changed).is_err(),
            "changed {key} accepted"
        );
    }
    Ok(())
}

#[test]
fn canonical_request_refuses_unbounded_or_mixed_original_operations() {
    let query = request(QmpKvmResponseBytesOperation::Query);
    let complete = request(QmpKvmResponseBytesOperation::Complete);
    for invalid in [
        QmpKvmResponseBytesRequest {
            record_index: 65_536,
            ..query
        },
        QmpKvmResponseBytesRequest {
            generation: 0,
            ..query
        },
        QmpKvmResponseBytesRequest {
            expected_invocation: 0,
            ..query
        },
        QmpKvmResponseBytesRequest {
            operation_id: 1,
            ..query
        },
        QmpKvmResponseBytesRequest {
            expected_sequence: 5,
            ..query
        },
        QmpKvmResponseBytesRequest {
            operation_id: 0,
            ..complete
        },
        QmpKvmResponseBytesRequest {
            expected_sequence: 0,
            ..complete
        },
        QmpKvmResponseBytesRequest {
            expected_sequence: u64::MAX,
            ..complete
        },
    ] {
        assert!(validate_request(&invalid).is_err());
    }
}
