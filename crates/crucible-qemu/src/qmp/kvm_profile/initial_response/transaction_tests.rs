//! Original first-response journal controls with explicitly modeled QMP peers.

use std::{
    error::Error,
    io::{self, Cursor, Read, Write},
    time::Duration,
};

use serde_json::{Value, json};

use super::*;
use crate::qmp::{QmpKvmOriginalReturnOperation, QmpKvmOriginalReturnRequest};

struct Stream {
    responses: Cursor<Vec<u8>>,
    written: Vec<u8>,
}

impl Stream {
    fn new(responses: Vec<Value>) -> Result<Self, serde_json::Error> {
        let mut bytes = Vec::new();
        for value in responses {
            serde_json::to_writer(&mut bytes, &value)?;
            bytes.push(b'\n');
        }
        Ok(Self {
            responses: Cursor::new(bytes),
            written: Vec::new(),
        })
    }
}

impl Read for Stream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.responses.read(bytes)
    }
}

impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl QmpTimeoutStream for Stream {
    fn set_qmp_read_timeout(&mut self, _: Duration) -> io::Result<()> {
        Ok(())
    }

    fn set_qmp_write_timeout(&mut self, _: Duration) -> io::Result<()> {
        Ok(())
    }
}

fn identity() -> QmpKvmOriginalReturnIdentity {
    QmpKvmOriginalReturnIdentity {
        record_index: 2,
        generation: 3,
        expected_invocation: 4,
        vcpu_index: 0,
        native_vcpu_id: 0,
        issued: true,
        receipt_known: true,
        no_birth_known: false,
        ack_known: false,
    }
}

fn receipt() -> Value {
    json!({
        "schema-version":1,"record-index":2,"generation":3,"expected-invocation":4,
        "invocation":4,"native-vcpu-id":0,"native-result":0,
        "generation-begin":3,"generation-end":3,"current-begin-ns":0,"current-end-ns":20,
        "pending-mask":3,"response-sequence":5,"response-consumed":4,"response-revision":6,
        "response-phase":1,"response-flags":0,"receipt-flags":7,"issued":true,
        "receipt-known":true,"no-birth-known":false,"ack-known":false,
        "query-errno":0,"ack-errno":0,"profile-qualified":false
    })
}

fn observed(completed: bool, result: i32) -> Value {
    json!({
        "schema-version":1,"record-index":2,"generation":3,"expected-invocation":4,
        "vcpu-index":0,"native-vcpu-id":0,"exit-sequence":5,"service-id":6,
        "submitted":true,"completed":completed,"result-known":completed,
        "callback-result":result,"uncertain-effects":result < 0,"opaque-effects":false,
        "device-closure":false,"input-custody":false,"output-custody":false,
        "profile-qualified":false
    })
}

fn prepare(
    baseline: Value,
    responses: Vec<Value>,
) -> Result<(QmpClient<Stream>, QmpKvmInitialResponseTransaction), Box<dyn Error>> {
    let mut sequence = vec![
        json!({"QMP":{"version":{},"capabilities":[]}}),
        json!({"return":{}}),
        json!({"return":baseline}),
    ];
    sequence.extend(responses);
    let mut client = QmpClient::connect(Stream::new(sequence)?)?;
    let receipt = client.control_native_kvm_original_return(&QmpKvmOriginalReturnRequest {
        operation: QmpKvmOriginalReturnOperation::Query,
        record_index: 2,
        generation: 3,
        expected_invocation: 4,
    })?;
    let original = QmpKvmInitialResponseTransaction::prepare(&identity(), &receipt)?;
    Ok((client, original))
}

#[test]
fn pending_original_becomes_known_without_repeating_submission() -> Result<(), Box<dyn Error>> {
    let (mut client, mut original) = prepare(
        receipt(),
        vec![
            json!({"return":observed(false, 0)}),
            json!({"return":observed(true, 0)}),
        ],
    )?;
    let before = client.stream.get_ref().written.len();
    assert!(original.reconcile(&mut client).is_err());
    assert_eq!(client.stream.get_ref().written.len(), before);

    assert!(!original.dispatch_once(&mut client)?.observed().completed);
    let after_submission = client.stream.get_ref().written.len();
    assert!(original.dispatch_once(&mut client).is_err());
    assert_eq!(client.stream.get_ref().written.len(), after_submission);
    assert!(original.reconcile(&mut client)?.observed().result_known);
    assert!(!original.uncertain_effects());
    assert_eq!(original.baseline().response_sequence, 5);

    let sent = std::str::from_utf8(&client.stream.get_ref().written)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(sent.len(), 4);
    assert_eq!(sent[2]["arguments"]["operation"], "submit");
    assert_eq!(sent[3]["arguments"]["operation"], "poll");
    Ok(())
}

#[test]
fn original_native_failure_retains_taint_after_poll_collection() -> Result<(), Box<dyn Error>> {
    let (mut client, mut original) = prepare(
        receipt(),
        vec![
            json!({"error":{"class":"GenericError","desc":"unknown callback result"}}),
            json!({"return":observed(true, -5)}),
        ],
    )?;
    assert!(original.dispatch_once(&mut client).is_err());
    assert!(original.uncertain_effects());
    assert_eq!(
        original.reconcile(&mut client)?.observed().callback_result,
        -5
    );
    assert!(original.uncertain_effects());
    assert_eq!(original.original().expected_invocation, 4);
    assert_eq!(original.baseline().response_sequence, 5);
    Ok(())
}

#[test]
fn structurally_valid_foreign_owner_fences_channel_and_preserves_conflict()
-> Result<(), Box<dyn Error>> {
    let mut foreign = observed(true, 0);
    foreign["native-vcpu-id"] = json!(1);
    let (mut client, mut original) = prepare(
        receipt(),
        vec![
            json!({"return":foreign}),
            json!({"return":observed(true, 0)}),
        ],
    )?;
    assert!(original.dispatch_once(&mut client).is_err());
    assert!(original.uncertain_effects());
    assert_eq!(
        original
            .latest()
            .ok_or("missing retained conflict")?
            .observed()
            .native_vcpu_id,
        1
    );
    assert_eq!(original.baseline().native_vcpu_id, 0);
    let before = client.stream.get_ref().written.len();
    assert!(original.reconcile(&mut client).is_err());
    assert_eq!(client.stream.get_ref().written.len(), before);
    Ok(())
}

#[test]
fn changed_original_handler_result_cannot_replace_accepted_lifetime() -> Result<(), Box<dyn Error>>
{
    let (mut client, mut original) = prepare(
        receipt(),
        vec![
            json!({"return":observed(true, 0)}),
            json!({"return":observed(true, -5)}),
        ],
    )?;
    original.dispatch_once(&mut client)?;
    assert!(original.reconcile(&mut client).is_err());
    assert!(original.uncertain_effects());
    assert_eq!(
        original
            .accepted
            .ok_or("missing accepted original")?
            .observed()
            .callback_result,
        0
    );
    assert_eq!(
        original
            .latest()
            .ok_or("missing retained conflict")?
            .observed()
            .callback_result,
        -5
    );
    Ok(())
}

#[test]
fn non_pending_or_uncertain_receipt_refuses_before_any_callback() {
    for (field, value) in [
        ("response-phase", json!(2)),
        ("response-flags", json!(1)),
        ("pending-mask", json!(8)),
        ("response-consumed", json!(5)),
        ("native-result", json!(-5)),
        ("receipt-flags", json!(1)),
    ] {
        let mut baseline = receipt();
        baseline[field] = value;
        assert!(
            prepare(baseline, Vec::new()).is_err(),
            "changed {field} accepted"
        );
    }
}
