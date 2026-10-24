//! Original-return wire and ACK ancestry controls; no live KVM execution.

use super::*;
use serde_json::json;
use std::{
    io::{self, Cursor, Read, Write},
    time::Duration,
};

fn request(operation: QmpKvmOriginalReturnOperation) -> QmpKvmOriginalReturnRequest {
    QmpKvmOriginalReturnRequest {
        operation,
        record_index: 0,
        generation: 2,
        expected_invocation: 4,
    }
}

fn identity() -> QmpKvmOriginalReturnIdentity {
    QmpKvmOriginalReturnIdentity {
        record_index: 0,
        generation: 2,
        expected_invocation: 4,
        vcpu_index: 0,
        native_vcpu_id: 0,
        issued: true,
        receipt_known: true,
        no_birth_known: false,
        ack_known: false,
    }
}

fn receipt() -> serde_json::Value {
    json!({"schema-version":1,"record-index":0,"generation":2,
        "expected-invocation":4,"invocation":4,"native-vcpu-id":0,
        "native-result":0,"generation-begin":2,"generation-end":2,
        "current-begin-ns":10,"current-end-ns":40,"pending-mask":3,
        "response-sequence":1,"response-consumed":0,"response-revision":2,
        "response-phase":1,"response-flags":0,"receipt-flags":7,
        "issued":true,"receipt-known":true,"no-birth-known":false,
        "ack-known":false,"query-errno":0,"ack-errno":0,
        "profile-qualified":false})
}

struct ScriptedStream {
    received: Cursor<Vec<u8>>,
    written: Vec<u8>,
}

impl ScriptedStream {
    fn new(replies: &[serde_json::Value]) -> Result<Self, serde_json::Error> {
        let mut bytes = Vec::new();
        for reply in replies {
            bytes.extend(serde_json::to_vec(reply)?);
            bytes.push(b'\n');
        }
        Ok(Self {
            received: Cursor::new(bytes),
            written: Vec::new(),
        })
    }
}

impl Read for ScriptedStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.received.read(bytes)
    }
}

impl Write for ScriptedStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl QmpTimeoutStream for ScriptedStream {
    fn set_qmp_read_timeout(&mut self, _: Duration) -> io::Result<()> {
        Ok(())
    }
    fn set_qmp_write_timeout(&mut self, _: Duration) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn query_preserves_exact_new_namespace_and_full_original_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let query = request(QmpKvmOriginalReturnOperation::Query);
    let command = QmpCommand::KvmOriginalReturn { request: &query };
    assert_eq!(command.kind(), QmpCommandKind::KvmOriginalReturn);
    assert_eq!(
        command.request(),
        json!({"execute":"x-crucible-kvm-original-return",
        "arguments":{"operation":"query","record-index":0,"generation":2,
        "expected-invocation":4}})
    );
    let state = parse_response(&query, &receipt())?;
    assert_eq!(state.observed().pending_mask, 3);
    assert_eq!(state.observed().response_consumed, 0);
    assert!(!state.observed().profile_qualified);
    Ok(())
}

#[test]
fn no_birth_retains_prior_invocation_and_ack_without_creating_a_new_return()
-> Result<(), Box<dyn std::error::Error>> {
    let mut value = receipt();
    value["invocation"] = json!(3);
    value["generation-begin"] = json!(1);
    value["generation-end"] = json!(1);
    value["native-result"] = json!(-11);
    value["receipt-known"] = json!(false);
    value["no-birth-known"] = json!(true);
    value["ack-known"] = json!(true);
    let state = parse_response(&request(QmpKvmOriginalReturnOperation::Query), &value)?;
    assert_eq!(state.observed().invocation, 3);
    assert_eq!(state.observed().expected_invocation, 4);
    assert_eq!(state.observed().generation_end, 1);
    assert!(QmpKvmOriginalAckTransaction::prepare(&identity(), &state).is_err());
    for (field, replacement) in [
        ("invocation", json!(4)),
        ("ack-known", json!(false)),
        ("receipt-known", json!(true)),
        ("native-result", json!(0)),
    ] {
        let mut changed = value.clone();
        changed[field] = replacement;
        assert!(
            parse_response(&request(QmpKvmOriginalReturnOperation::Query), &changed).is_err(),
            "{field}"
        );
    }
    Ok(())
}

#[test]
fn initial_no_birth_basis_zero_is_observable_but_never_ack_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let mut query = request(QmpKvmOriginalReturnOperation::Query);
    query.expected_invocation = 1;
    let mut value = receipt();
    value["expected-invocation"] = json!(1);
    value["invocation"] = json!(0);
    value["receipt-known"] = json!(false);
    value["no-birth-known"] = json!(true);
    value["ack-known"] = json!(true);
    value["native-result"] = json!(-11);
    value["receipt-flags"] = json!(0);
    assert!(parse_response(&query, &value).is_ok());
    Ok(())
}

#[test]
fn authentic_unknown_native_history_remains_observable_without_ack_permission()
-> Result<(), Box<dyn std::error::Error>> {
    let mut value = receipt();
    value["generation-end"] = json!(3);
    value["response-flags"] = json!(1);
    value["native-result"] = json!(-14);
    let state = parse_response(&request(QmpKvmOriginalReturnOperation::Query), &value)?;
    assert_eq!(state.observed().generation_end, 3);
    assert_eq!(state.observed().native_result, -14);
    assert_eq!(state.observed().response_flags, 1);
    assert!(QmpKvmOriginalAckTransaction::prepare(&identity(), &state).is_err());
    Ok(())
}

#[test]
fn original_return_refuses_changed_knowledge_shape_and_qualification() {
    for (field, replacement) in [
        ("schema-version", json!(2)),
        ("record-index", json!(1)),
        ("generation", json!(3)),
        ("expected-invocation", json!(5)),
        ("invocation", json!(3)),
        ("issued", json!(false)),
        ("receipt-flags", json!(32)),
        ("pending-mask", json!(16)),
        ("response-flags", json!(4)),
        ("response-phase", json!(6)),
        ("response-consumed", json!(2)),
        ("current-begin-ns", json!(50)),
        ("query-errno", json!(-14)),
        ("profile-qualified", json!(true)),
        ("private-native-pointer", json!(1)),
    ] {
        let mut value = receipt();
        value[field] = replacement;
        assert!(
            parse_response(&request(QmpKvmOriginalReturnOperation::Query), &value).is_err(),
            "{field}"
        );
    }
}

#[test]
fn ack_preparation_correlates_original_cpu_and_inventory_without_label_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let state = parse_response(&request(QmpKvmOriginalReturnOperation::Query), &receipt())?;
    assert!(QmpKvmOriginalAckTransaction::prepare(&identity(), &state).is_ok());
    for field in 0..4 {
        let mut changed = identity();
        match field {
            0 => changed.record_index = 1,
            1 => changed.generation = 3,
            2 => changed.expected_invocation = 5,
            _ => changed.native_vcpu_id = 1,
        }
        assert!(QmpKvmOriginalAckTransaction::prepare(&changed, &state).is_err());
    }
    Ok(())
}

#[test]
fn ack_refusal_then_query_recovery_does_not_repeat_ack_or_clear_history()
-> Result<(), Box<dyn std::error::Error>> {
    let initial = parse_response(&request(QmpKvmOriginalReturnOperation::Query), &receipt())?;
    let mut known = receipt();
    known["ack-known"] = json!(true);
    let mut client = QmpClient::connect(ScriptedStream::new(&[
        json!({"QMP":{"version":{},"capabilities":[]}}),
        json!({"return":{}}),
        json!({"error":{"class":"GenericError","desc":"original ACK unresolved"}}),
        json!({"return":known}),
    ])?)?;
    let mut original = QmpKvmOriginalAckTransaction::prepare(&identity(), &initial)?;
    assert!(original.dispatch_once(&mut client).is_err());
    let written = client.stream.get_ref().written.len();
    assert!(original.dispatch_once(&mut client).is_err());
    assert_eq!(client.stream.get_ref().written.len(), written);
    let recovered = original.reconcile(&mut client)?;
    assert!(recovered.observed().ack_known);
    assert!(original.uncertain_effects());
    assert_eq!(original.baseline().response_consumed, 0);
    assert_eq!(recovered.observed().pending_mask, 3);
    let commands = std::str::from_utf8(&client.stream.get_ref().written)?
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(commands.len(), 3);
    assert_eq!(commands[1]["arguments"]["operation"], "ack");
    assert_eq!(commands[2]["arguments"]["operation"], "query");
    Ok(())
}

#[test]
fn changed_original_receipt_is_retained_and_rejected_after_ack()
-> Result<(), Box<dyn std::error::Error>> {
    let initial = parse_response(&request(QmpKvmOriginalReturnOperation::Query), &receipt())?;
    let mut changed = receipt();
    changed["ack-known"] = json!(true);
    changed["response-consumed"] = json!(1);
    let mut client = QmpClient::connect(ScriptedStream::new(&[
        json!({"QMP":{"version":{},"capabilities":[]}}),
        json!({"return":{}}),
        json!({"return":changed}),
    ])?)?;
    let mut original = QmpKvmOriginalAckTransaction::prepare(&identity(), &initial)?;
    assert!(original.dispatch_once(&mut client).is_err());
    assert!(original.uncertain_effects());
    assert_eq!(original.baseline().response_consumed, 0);
    let retained = original
        .latest()
        .ok_or_else(|| io::Error::other("conflicting original reply discarded"))?;
    assert_eq!(retained.observed().response_consumed, 1);
    Ok(())
}

#[test]
fn missing_ack_reply_fences_stream_and_preserves_the_full_original()
-> Result<(), Box<dyn std::error::Error>> {
    let baseline = parse_response(&request(QmpKvmOriginalReturnOperation::Query), &receipt())?;
    let mut client = QmpClient::connect(ScriptedStream::new(&[
        json!({"QMP":{"version":{},"capabilities":[]}}),
        json!({"return":{}}),
    ])?)?;
    let mut original = QmpKvmOriginalAckTransaction::prepare(&identity(), &baseline)?;
    assert!(original.dispatch_once(&mut client).is_err());
    assert!(original.uncertain_effects());
    let written = client.stream.get_ref().written.len();
    assert_eq!(
        original.reconcile(&mut client),
        Err(QmpError::ConnectionPoisoned)
    );
    assert_eq!(client.stream.get_ref().written.len(), written);
    assert_eq!(original.baseline(), baseline.observed());
    assert!(original.latest().is_none());
    Ok(())
}

#[test]
fn known_ack_collects_return_without_consuming_pending_response_or_qualifying_node()
-> Result<(), Box<dyn std::error::Error>> {
    let baseline = parse_response(&request(QmpKvmOriginalReturnOperation::Query), &receipt())?;
    let mut known = receipt();
    known["ack-known"] = json!(true);
    let mut client = QmpClient::connect(ScriptedStream::new(&[
        json!({"QMP":{"version":{},"capabilities":[]}}),
        json!({"return":{}}),
        json!({"return":known}),
    ])?)?;
    let mut original = QmpKvmOriginalAckTransaction::prepare(&identity(), &baseline)?;
    let collected = original.dispatch_once(&mut client)?;
    assert!(collected.observed().ack_known);
    assert_eq!(collected.observed().pending_mask, 3);
    assert_eq!(collected.observed().response_consumed, 0);
    assert!(!collected.observed().profile_qualified);
    assert_eq!(original.baseline().pending_mask, 3);
    let written = client.stream.get_ref().written.len();
    assert!(original.dispatch_once(&mut client).is_err());
    assert_eq!(client.stream.get_ref().written.len(), written);
    Ok(())
}
