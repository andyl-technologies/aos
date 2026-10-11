//! Original native More custody with modeled QMP peers and real framing.

use serde_json::{Value, json};
use std::{
    error::Error,
    io::{self, Cursor, Read, Write},
    time::Duration,
};

use super::*;
use crate::qmp::{QmpKvmResponseBytesOperation, QmpKvmResponseBytesRequest};

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

fn native_more() -> Value {
    json!({
        "schema-version":1,"payload-kind":"native-result","components":7,
        "kernel-capability":41002,"native-abi-size":4264,"maximum-data-bytes":4096,
        "clock-edition":3,"clock-components":159,"qemu-build-id":"a".repeat(64),
        "qemu-source-hash":"b".repeat(64),"record-index":2,"vcpu-index":0,
        "native-vcpu-id":0,"generation":3,"invocation":4,"operation-id":1,
        "expected-sequence":5,"expected-revision":6,"pending-sequence":6,
        "consumed-sequence":5,"revision":8,"native-phase":2,"callback-result":0,
        "native-errno":0,"reason":6,"address":4096,"data-offset":0,
        "length":4,"count":0,"size":0,"direction":1,"data-length":4,
        "data-base64":"AAEC/w==","result-known":true,"uncertain-effects":false,
        "opaque-effects":false,"kernel-source-qualified":false,"device-closure":false,
        "input-custody":false,"output-custody":false,"profile-qualified":false
    })
}

fn callback(completed: bool, result: i32) -> Value {
    json!({
        "schema-version":1,"vcpu-index":0,"kernel-vcpu-id":0,
        "completion-id":1,"exit-sequence":6,"service-id":7,"submitted":true,
        "completed":completed,"result-known":completed,"callback-result":result,
        "uncertain-effects":result < 0,"opaque-effects":false,"device-closure":false,
        "input-custody":false,"output-custody":false,"profile-qualified":false
    })
}

fn birth(
    value: Value,
    operation: QmpKvmResponseBytesOperation,
    responses: Vec<Value>,
) -> Result<(QmpClient<Stream>, QmpKvmResponseBytesState), Box<dyn Error>> {
    let mut sequence = vec![
        json!({"QMP":{"version":{},"capabilities":[]}}),
        json!({"return":{}}),
        json!({"return":value}),
    ];
    sequence.extend(responses);
    let mut client = QmpClient::connect(Stream::new(sequence)?)?;
    let complete = operation == QmpKvmResponseBytesOperation::Complete;
    let state = client.control_native_kvm_response_bytes(&QmpKvmResponseBytesRequest {
        operation,
        record_index: 2,
        generation: 3,
        expected_invocation: 4,
        operation_id: u64::from(complete),
        expected_sequence: if complete { 5 } else { 0 },
    })?;
    Ok((client, state))
}

#[test]
fn original_more_birth_is_retained_across_one_submit_poll_and_host_cached_result()
-> Result<(), Box<dyn Error>> {
    let (mut client, state) = birth(
        native_more(),
        QmpKvmResponseBytesOperation::Complete,
        vec![
            json!({"return":callback(false, 0)}),
            json!({"return":callback(true, 0)}),
        ],
    )?;
    let mut original = QmpKvmMoreResponseTransaction::prepare(state)?;
    let before = client.stream.get_ref().written.len();
    assert!(original.reconcile(&mut client).is_err());
    assert_eq!(client.stream.get_ref().written.len(), before);
    assert!(!original.dispatch_once(&mut client)?.observed().completed);
    let submitted = client.stream.get_ref().written.len();
    assert!(original.dispatch_once(&mut client).is_err());
    assert_eq!(client.stream.get_ref().written.len(), submitted);
    let known = original.reconcile(&mut client)?;
    let collected = client.stream.get_ref().written.len();
    assert_eq!(original.reconcile(&mut client)?, known);
    assert_eq!(client.stream.get_ref().written.len(), collected);
    assert_eq!(original.birth().bytes(), &[0, 1, 2, 255]);
    assert_eq!(original.birth().observed().revision, 8);
    assert!(!original.uncertain_effects());
    let commands = std::str::from_utf8(&client.stream.get_ref().written)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(commands.len(), 4);
    assert_eq!(commands[2]["arguments"]["operation"], "submit");
    assert_eq!(commands[3]["arguments"]["operation"], "poll");
    Ok(())
}

#[test]
fn native_failure_reconciles_only_original_callback_and_retains_sticky_taint()
-> Result<(), Box<dyn Error>> {
    let (mut client, state) = birth(
        native_more(),
        QmpKvmResponseBytesOperation::Complete,
        vec![
            json!({"error":{"class":"GenericError","desc":"callback result unknown"}}),
            json!({"return":callback(true, 0)}),
        ],
    )?;
    let mut original = QmpKvmMoreResponseTransaction::prepare(state)?;
    assert!(original.dispatch_once(&mut client).is_err());
    assert!(original.uncertain_effects());
    assert!(original.reconcile(&mut client)?.observed().result_known);
    assert!(original.uncertain_effects());
    assert_eq!(original.birth().bytes(), &[0, 1, 2, 255]);
    Ok(())
}

#[test]
fn foreign_original_owner_fences_exchange_and_preserves_native_birth_and_conflict()
-> Result<(), Box<dyn Error>> {
    let mut foreign = callback(true, 0);
    foreign["kernel-vcpu-id"] = json!(1);
    let (mut client, state) = birth(
        native_more(),
        QmpKvmResponseBytesOperation::Complete,
        vec![
            json!({"return":foreign}),
            json!({"return":callback(true, 0)}),
        ],
    )?;
    let mut original = QmpKvmMoreResponseTransaction::prepare(state)?;
    assert!(original.dispatch_once(&mut client).is_err());
    assert_eq!(
        original
            .latest()
            .ok_or("missing retained conflict")?
            .observed()
            .kernel_vcpu_id,
        1
    );
    assert_eq!(original.birth().observed().native_vcpu_id, 0);
    assert!(original.uncertain_effects());
    let before = client.stream.get_ref().written.len();
    assert!(original.reconcile(&mut client).is_err());
    assert_eq!(client.stream.get_ref().written.len(), before);
    Ok(())
}

#[test]
fn changed_pending_service_cannot_overwrite_accepted_original_history() -> Result<(), Box<dyn Error>>
{
    let mut changed = callback(true, 0);
    changed["service-id"] = json!(8);
    let (mut client, state) = birth(
        native_more(),
        QmpKvmResponseBytesOperation::Complete,
        vec![
            json!({"return":callback(false, 0)}),
            json!({"return":changed}),
        ],
    )?;
    let mut original = QmpKvmMoreResponseTransaction::prepare(state)?;
    original.dispatch_once(&mut client)?;
    assert!(original.reconcile(&mut client).is_err());
    assert_eq!(
        original
            .accepted
            .ok_or("missing accepted original")?
            .observed()
            .service_id,
        7
    );
    assert_eq!(
        original
            .latest()
            .ok_or("missing retained conflict")?
            .observed()
            .service_id,
        8
    );
    assert!(original.uncertain_effects());
    Ok(())
}

#[test]
fn query_or_non_more_native_facts_cannot_authorize_a_paused_callback() -> Result<(), Box<dyn Error>>
{
    let mut query = native_more();
    for (key, value) in [
        ("payload-kind", json!("native-query")),
        ("operation-id", json!(0)),
        ("expected-sequence", json!(0)),
        ("expected-revision", json!(0)),
    ] {
        query[key] = value;
    }
    let (_, state) = birth(query, QmpKvmResponseBytesOperation::Query, Vec::new())?;
    assert!(QmpKvmMoreResponseTransaction::prepare(state).is_err());
    for (key, value) in [
        ("uncertain-effects", json!(true)),
        ("opaque-effects", json!(true)),
    ] {
        let mut changed = native_more();
        changed[key] = value;
        let (_, state) = birth(changed, QmpKvmResponseBytesOperation::Complete, Vec::new())?;
        assert!(QmpKvmMoreResponseTransaction::prepare(state).is_err());
    }

    let mut done = native_more();
    for (key, value) in [
        ("pending-sequence", json!(5)),
        ("revision", json!(7)),
        ("native-phase", json!(3)),
        ("reason", json!(0)),
        ("address", json!(0)),
        ("length", json!(0)),
        ("direction", json!(0)),
        ("data-length", json!(0)),
        ("data-base64", json!("")),
    ] {
        done[key] = value;
    }
    let (_, state) = birth(done, QmpKvmResponseBytesOperation::Complete, Vec::new())?;
    assert!(QmpKvmMoreResponseTransaction::prepare(state).is_err());

    let mut echo = native_more();
    for (key, value) in [
        ("payload-kind", json!("original-request")),
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
        echo[key] = value;
    }
    let (_, state) = birth(echo, QmpKvmResponseBytesOperation::Complete, Vec::new())?;
    assert!(QmpKvmMoreResponseTransaction::prepare(state).is_err());
    Ok(())
}

#[test]
fn negative_original_callback_is_retained_without_clearing_uncertainty()
-> Result<(), Box<dyn Error>> {
    let (mut client, state) = birth(
        native_more(),
        QmpKvmResponseBytesOperation::Complete,
        vec![json!({"return":callback(true, -5)})],
    )?;
    let mut original = QmpKvmMoreResponseTransaction::prepare(state)?;
    assert_eq!(
        original
            .dispatch_once(&mut client)?
            .observed()
            .callback_result,
        -5
    );
    let before = client.stream.get_ref().written.len();
    assert_eq!(
        original.reconcile(&mut client)?.observed().callback_result,
        -5
    );
    assert_eq!(client.stream.get_ref().written.len(), before);
    assert!(original.uncertain_effects());
    Ok(())
}
