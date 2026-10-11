//! Same-owner finite completion chains exercised by explicitly modeled peers.

use super::*;
use crate::qmp::QmpKvmResponseBytesPayloadKind;
use serde_json::{Value, json};
use std::{
    error::Error,
    io::{self, Cursor, Read, Write},
    sync::{Arc, Mutex},
    time::Duration,
};

type InitialFixture = (Journal<Stream>, KvmComponentToken, Arc<Mutex<Vec<u8>>>);

struct Stream {
    responses: Cursor<Vec<u8>>,
    written: Arc<Mutex<Vec<u8>>>,
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
            written: Arc::new(Mutex::new(Vec::new())),
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
        self.written
            .lock()
            .map_err(|error| io::Error::other(error.to_string()))?
            .extend_from_slice(bytes);
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

fn written_length(written: &Arc<Mutex<Vec<u8>>>) -> io::Result<usize> {
    Ok(written
        .lock()
        .map_err(|error| io::Error::other(error.to_string()))?
        .len())
}

fn written_bytes(written: &Arc<Mutex<Vec<u8>>>) -> io::Result<Vec<u8>> {
    Ok(written
        .lock()
        .map_err(|error| io::Error::other(error.to_string()))?
        .clone())
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

fn native_query(more: bool, read: bool) -> Value {
    let mut value = native_more();
    for (key, replacement) in [
        ("payload-kind", json!("native-query")),
        ("operation-id", json!(0)),
        ("expected-sequence", json!(0)),
        ("expected-revision", json!(0)),
    ] {
        value[key] = replacement;
    }
    if !more {
        for (key, replacement) in [
            ("native-phase", json!(1)),
            ("pending-sequence", json!(5)),
            ("consumed-sequence", json!(4)),
            ("revision", json!(6)),
        ] {
            value[key] = replacement;
        }
    }
    if read {
        value["direction"] = json!(0);
        value["data-length"] = json!(0);
        value["data-base64"] = json!("");
    }
    value
}

fn done(second: bool) -> Value {
    let mut value = native_more();
    for (key, replacement) in [
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
    if second {
        for (key, replacement) in [
            ("operation-id", json!(2)),
            ("expected-sequence", json!(6)),
            ("expected-revision", json!(8)),
            ("consumed-sequence", json!(6)),
            ("revision", json!(9)),
        ] {
            value[key] = replacement;
        }
    } else {
        for (key, replacement) in [("pending-sequence", json!(5)), ("revision", json!(7))] {
            value[key] = replacement;
        }
    }
    value
}

fn echo() -> Value {
    let mut value = native_more();
    for (key, replacement) in [
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
        value[key] = replacement;
    }
    value
}

fn callback(known: bool) -> Value {
    json!({"schema-version":1,"vcpu-index":0,"kernel-vcpu-id":0,
        "completion-id":1,"exit-sequence":6,"service-id":7,"submitted":true,
        "completed":known,"result-known":known,"callback-result":0,
        "uncertain-effects":false,"opaque-effects":false,"device-closure":false,
        "input-custody":false,"output-custody":false,"profile-qualified":false})
}

fn retained_initial(responses: Vec<Value>) -> Result<InitialFixture, Box<dyn Error>> {
    let page = json!({"schema-version":1,"generation":3,"first-record":2,
        "next-record":3,"retained-returns":3,"profile-qualified":false,
        "entries":[{"record-index":2,"generation":3,"expected-invocation":4,
        "vcpu-index":0,"native-vcpu-id":0,"issued":true,"receipt-known":true,
        "no-birth-known":false,"ack-known":false}]});
    let mut sequence = vec![
        json!({"QMP":{"version":{},"capabilities":[]}}),
        json!({"return":{}}),
        json!({"return":page}),
        json!({"return":receipt()}),
        json!({"return":observed(false, 0)}),
        json!({"return":observed(true, 0)}),
    ];
    sequence.extend(responses);
    let stream = Stream::new(sequence)?;
    let written = Arc::clone(&stream.written);
    let qmp = QmpClient::connect(stream)?;
    let mut journal = JournalReservation::reserve(8, 4)?.connect(qmp);
    let (initial, submitted) = journal.submit_initial(3, 2)?;
    submitted?;
    assert!(journal.reconcile_initial(&initial)?.observed().result_known);
    Ok((journal, initial, written))
}

#[test]
fn original_complete_more_complete_chain_preserves_all_parent_byte_and_callback_records()
-> Result<(), Box<dyn Error>> {
    let (mut journal, initial, written) = retained_initial(vec![
        json!({"return":native_query(false, false)}),
        json!({"return":native_more()}),
        json!({"return":callback(false)}),
        json!({"return":callback(true)}),
        json!({"return":native_query(true, false)}),
        json!({"return":done(true)}),
    ])?;
    let (first, result) = journal.submit_completion(&initial)?;
    assert_eq!(result?.native_phase, 2);
    assert_eq!(
        journal.completion_reply(&first, 0)?.bytes(),
        &[0, 1, 2, 255]
    );
    let original_credit = journal.retained_byte_credit;
    let before = written_length(&written)?;
    assert!(matches!(
        journal.submit_completion(&initial),
        Err(KvmComponentError::Transition(_))
    ));
    assert_eq!(written_length(&written)?, before);
    assert_eq!(journal.retained_byte_credit, original_credit);

    let (more, result) = journal.submit_more(&first)?;
    assert!(!result?.observed().result_known);
    let before = written_length(&written)?;
    assert!(matches!(
        journal.submit_more(&first),
        Err(KvmComponentError::Transition(_))
    ));
    assert_eq!(written_length(&written)?, before);
    assert!(journal.reconcile_more(&more)?.observed().result_known);
    let (second, result) = journal.submit_completion(&more)?;
    assert_eq!(result?.operation_id, 2);
    assert_eq!(
        journal
            .completion_reply(&second, 0)?
            .observed()
            .consumed_sequence,
        6
    );
    let before = written_length(&written)?;
    assert_eq!(journal.reconcile_completion(&first)?.native_phase, 2);
    assert!(journal.reconcile_more(&more)?.observed().result_known);
    assert_eq!(written_length(&written)?, before);
    assert_eq!(
        journal.completion_reply(&first, 0)?.bytes(),
        &[0, 1, 2, 255]
    );
    assert_eq!(journal.entries.len(), 4);
    assert!(journal.history(&initial)?.iter().all(|state| matches!(
        state,
        super::super::KvmComponentObservation::Initial {
            uncertain: false,
            ..
        }
    )));
    Ok(())
}

#[test]
fn unknown_original_input_echo_recovers_only_same_complete_and_keeps_sticky_taint()
-> Result<(), Box<dyn Error>> {
    let (mut journal, initial, written) = retained_initial(vec![
        json!({"return":native_query(false, true)}),
        json!({"return":echo()}),
        json!({"return":done(false)}),
    ])?;
    let (completion, result) = journal.submit_completion(&initial)?;
    let result = result?;
    assert_eq!(
        result.payload_kind,
        QmpKvmResponseBytesPayloadKind::OriginalRequest
    );
    assert!(!result.result_known);
    assert!(result.uncertain_effects);
    assert_eq!(
        journal.completion_reply(&completion, 0)?.bytes(),
        &[0, 1, 2, 255]
    );
    assert!(matches!(
        journal.submit_more(&completion),
        Err(KvmComponentError::Transition(_))
    ));
    let result = journal.reconcile_completion(&completion)?;
    assert!(result.result_known);
    assert!(result.uncertain_effects);
    assert_eq!(
        journal
            .completion_reply(&completion, 1)?
            .observed()
            .payload_kind,
        QmpKvmResponseBytesPayloadKind::NativeResult
    );
    assert_eq!(
        journal
            .completion_reply(&completion, 0)?
            .observed()
            .payload_kind,
        QmpKvmResponseBytesPayloadKind::OriginalRequest
    );
    let before = written_length(&written)?;
    assert!(matches!(
        journal.submit_more(&completion),
        Err(KvmComponentError::Transition(_))
    ));
    assert_eq!(written_length(&written)?, before);
    let sent_bytes = written_bytes(&written)?;
    let sent = std::str::from_utf8(&sent_bytes)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(sent[6], sent[7]);
    assert_eq!(sent[6]["arguments"]["operation"], "complete");
    Ok(())
}

#[test]
fn changed_original_owner_fences_exchange_before_another_completion() -> Result<(), Box<dyn Error>>
{
    let mut foreign = native_more();
    foreign["native-vcpu-id"] = json!(1);
    let (mut journal, initial, written) = retained_initial(vec![
        json!({"return":native_query(false, false)}),
        json!({"return":foreign}),
    ])?;
    let (completion, result) = journal.submit_completion(&initial)?;
    assert!(result.is_err());
    assert_eq!(
        journal
            .completion_reply(&completion, 0)?
            .observed()
            .native_vcpu_id,
        1
    );
    assert!(matches!(
        journal.submit_more(&completion),
        Err(KvmComponentError::Transition(_))
    ));
    let before = written_length(&written)?;
    assert!(journal.reconcile_completion(&completion).is_err());
    assert_eq!(written_length(&written)?, before);
    assert_eq!(
        journal.completion_reply(&completion, 0)?.bytes(),
        &[0, 1, 2, 255]
    );
    Ok(())
}

#[test]
fn finite_byte_credit_and_foreign_classes_refuse_before_native_query() -> Result<(), Box<dyn Error>>
{
    let (mut journal, initial, written) = retained_initial(Vec::new())?;
    let before = written_length(&written)?;
    let attempts = journal.entries[initial.index].attempts;
    assert!(matches!(
        journal.reconcile_completion(&initial),
        Err(KvmComponentError::ForeignToken)
    ));
    assert!(matches!(
        journal.submit_more(&initial),
        Err(KvmComponentError::ForeignToken)
    ));
    assert_eq!(journal.entries[initial.index].attempts, attempts);
    journal.retained_byte_credit = completion::MAXIMUM_RETAINED_BYTE_CREDIT;
    assert!(matches!(
        journal.submit_completion(&initial),
        Err(KvmComponentError::ResourceLimit)
    ));
    assert_eq!(written_length(&written)?, before);
    assert_eq!(journal.entries.len(), 1);
    Ok(())
}

#[test]
fn conflicting_input_echo_retains_each_original_octet_and_rejects_replacement()
-> Result<(), Box<dyn Error>> {
    let mut changed = echo();
    changed["data-base64"] = json!("BAUG/w==");
    let (mut journal, initial, written) = retained_initial(vec![
        json!({"return":native_query(false, true)}),
        json!({"return":echo()}),
        json!({"return":changed}),
    ])?;
    let (completion, result) = journal.submit_completion(&initial)?;
    result?;
    assert!(journal.reconcile_completion(&completion).is_err());
    assert_eq!(
        journal.completion_reply(&completion, 0)?.bytes(),
        &[0, 1, 2, 255]
    );
    assert_eq!(
        journal.completion_reply(&completion, 1)?.bytes(),
        &[4, 5, 6, 255]
    );
    let Original::Completion { transaction, .. } = &journal.entries[completion.index].original
    else {
        return Err("missing retained completion".into());
    };
    assert_eq!(
        transaction
            .accepted()
            .ok_or("missing accepted original")?
            .bytes(),
        &[0, 1, 2, 255]
    );
    assert!(transaction.uncertain_effects());
    assert_eq!(
        written_bytes(&written)?
            .iter()
            .filter(|byte| **byte == b'\n')
            .count(),
        8
    );
    Ok(())
}

#[test]
fn completion_identity_persists_across_original_run_rows_on_the_same_cpu()
-> Result<(), Box<dyn Error>> {
    let page = json!({"schema-version":1,"generation":4,"first-record":3,
        "next-record":4,"retained-returns":4,"profile-qualified":false,
        "entries":[{"record-index":3,"generation":4,"expected-invocation":5,
        "vcpu-index":0,"native-vcpu-id":0,"issued":true,"receipt-known":true,
        "no-birth-known":false,"ack-known":false}]});
    let mut next_receipt = receipt();
    for (key, value) in [
        ("record-index", json!(3)),
        ("generation", json!(4)),
        ("expected-invocation", json!(5)),
        ("invocation", json!(5)),
        ("generation-begin", json!(4)),
        ("generation-end", json!(4)),
        ("response-sequence", json!(6)),
        ("response-consumed", json!(5)),
        ("response-revision", json!(8)),
    ] {
        next_receipt[key] = value;
    }
    let mut next_callback = observed(true, 0);
    for (key, value) in [
        ("record-index", json!(3)),
        ("generation", json!(4)),
        ("expected-invocation", json!(5)),
        ("exit-sequence", json!(6)),
        ("service-id", json!(7)),
    ] {
        next_callback[key] = value;
    }
    let mut next_query = native_query(true, false);
    next_query["native-phase"] = json!(1);
    let mut next_done = done(true);
    for value in [&mut next_query, &mut next_done] {
        value["record-index"] = json!(3);
        value["generation"] = json!(4);
        value["invocation"] = json!(5);
    }
    let (mut journal, initial, written) = retained_initial(vec![
        json!({"return":native_query(false, false)}),
        json!({"return":done(false)}),
        json!({"return":page}),
        json!({"return":next_receipt}),
        json!({"return":next_callback}),
        json!({"return":next_query}),
        json!({"return":next_done}),
    ])?;
    let (first, result) = journal.submit_completion(&initial)?;
    assert_eq!(result?.operation_id, 1);
    let (next_initial, result) = journal.submit_initial(4, 3)?;
    assert!(result?.observed().result_known);
    let (second, result) = journal.submit_completion(&next_initial)?;
    assert_eq!(result?.operation_id, 2);
    assert_eq!(
        journal.completion_reply(&first, 0)?.observed().invocation,
        4
    );
    assert_eq!(
        journal.completion_reply(&second, 0)?.observed().invocation,
        5
    );
    let frames = written_bytes(&written)?;
    let sent = std::str::from_utf8(&frames)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        sent.last().ok_or("missing next completion")?["arguments"]["operation-id"],
        2
    );
    Ok(())
}

#[test]
fn original_native_error_reconciles_same_complete_without_losing_request_custody()
-> Result<(), Box<dyn Error>> {
    let (mut journal, initial, written) = retained_initial(vec![
        json!({"return":native_query(false, false)}),
        json!({"error":{"class":"GenericError","desc":"original native result unavailable"}}),
        json!({"return":done(false)}),
    ])?;
    let (completion, result) = journal.submit_completion(&initial)?;
    assert!(result.is_err());
    let Original::Completion { transaction, .. } = &journal.entries[completion.index].original
    else {
        return Err("missing original after failed native exchange".into());
    };
    assert!(transaction.uncertain_effects());
    assert_eq!(transaction.baseline().bytes(), &[0, 1, 2, 255]);
    assert!(transaction.replies().is_empty());
    let result = journal.reconcile_completion(&completion)?;
    assert!(result.result_known);
    assert!(result.uncertain_effects);
    let frames = written_bytes(&written)?;
    let sent = std::str::from_utf8(&frames)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(sent[6], sent[7]);
    assert_eq!(journal.entries.len(), 2);
    assert_eq!(journal.history(&completion)?.len(), 2);
    Ok(())
}

#[test]
fn negative_native_completion_is_retained_and_blocks_new_more_before_any_dispatch()
-> Result<(), Box<dyn Error>> {
    let mut negative = done(false);
    negative["native-phase"] = json!(4);
    negative["callback-result"] = json!(-5);
    negative["uncertain-effects"] = json!(true);
    negative["consumed-sequence"] = json!(4);
    let (mut journal, initial, written) = retained_initial(vec![
        json!({"return":native_query(false, false)}),
        json!({"return":negative}),
    ])?;
    let (completion, result) = journal.submit_completion(&initial)?;
    assert_eq!(result?.callback_result, -5);
    assert_eq!(
        journal
            .completion_reply(&completion, 0)?
            .observed()
            .native_phase,
        4
    );
    let before = written_length(&written)?;
    assert!(matches!(
        journal.submit_more(&completion),
        Err(KvmComponentError::Transition(_))
    ));
    assert_eq!(
        journal.reconcile_completion(&completion)?.callback_result,
        -5
    );
    assert_eq!(written_length(&written)?, before);
    Ok(())
}

fn next_window(
    operation: crate::qmp::QmpKvmOriginalWindowOperation,
) -> QmpKvmOriginalWindowRequest {
    QmpKvmOriginalWindowRequest {
        operation,
        generation: if operation == crate::qmp::QmpKvmOriginalWindowOperation::Begin {
            4
        } else {
            3
        },
        start_ns: if operation == crate::qmp::QmpKvmOriginalWindowOperation::Begin {
            20
        } else {
            0
        },
        end_ns: if operation == crate::qmp::QmpKvmOriginalWindowOperation::Begin {
            40
        } else {
            0
        },
        stop_budget_ns: if operation == crate::qmp::QmpKvmOriginalWindowOperation::Close {
            5_000_000
        } else {
            0
        },
    }
}

#[test]
fn lost_completion_blocks_fresh_window_and_callback_before_writes_or_credits()
-> Result<(), Box<dyn Error>> {
    let (mut journal, initial, written) = retained_initial(vec![
        json!({"return":native_query(false, false)}),
        json!({"error":{"class":"GenericError","desc":"original reply delivery failed"}}),
        json!({"return":done(false)}),
    ])?;
    let (completion, result) = journal.submit_completion(&initial)?;
    assert!(result.is_err());
    let before = written_length(&written)?;
    let retained = journal.entries.len();
    let credit = journal.retained_byte_credit;
    let attempts = journal.entries[completion.index].attempts;

    assert!(matches!(
        journal.submit_window(next_window(
            crate::qmp::QmpKvmOriginalWindowOperation::Begin
        )),
        Err(KvmComponentError::Transition(_))
    ));
    assert!(matches!(
        journal.submit_initial(4, 3),
        Err(KvmComponentError::Transition(_))
    ));
    assert_eq!(written_length(&written)?, before);
    assert_eq!(journal.entries.len(), retained);
    assert_eq!(journal.retained_byte_credit, credit);
    assert_eq!(journal.entries[completion.index].attempts, attempts);

    let recovered = journal.reconcile_completion(&completion)?;
    assert!(recovered.result_known && recovered.uncertain_effects);
    let after_recovery = written_length(&written)?;
    assert!(matches!(
        journal.submit_window(next_window(
            crate::qmp::QmpKvmOriginalWindowOperation::Begin
        )),
        Err(KvmComponentError::Transition(_))
    ));
    assert_eq!(written_length(&written)?, after_recovery);
    assert_eq!(journal.reconcile_completion(&completion)?, recovered);
    assert_eq!(written_length(&written)?, after_recovery);

    let bytes = written_bytes(&written)?;
    let messages = std::str::from_utf8(&bytes)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(messages[messages.len() - 2], messages[messages.len() - 1]);
    assert_eq!(
        messages[messages.len() - 1]["arguments"]["operation"],
        "complete"
    );
    Ok(())
}

#[test]
fn unfinished_more_blocks_new_run_until_original_callback_and_done_chain()
-> Result<(), Box<dyn Error>> {
    let (mut journal, initial, written) = retained_initial(vec![
        json!({"return":native_query(false, false)}),
        json!({"return":native_more()}),
        json!({"return":callback(false)}),
        json!({"return":callback(true)}),
        json!({"return":native_query(true, false)}),
        json!({"return":done(true)}),
    ])?;
    let (completion, result) = journal.submit_completion(&initial)?;
    assert_eq!(result?.native_phase, 2);
    let before_more = written_length(&written)?;
    assert!(matches!(
        journal.submit_window(next_window(
            crate::qmp::QmpKvmOriginalWindowOperation::Begin
        )),
        Err(KvmComponentError::Transition(_))
    ));
    assert_eq!(written_length(&written)?, before_more);

    let (more, result) = journal.submit_more(&completion)?;
    assert!(!result?.observed().result_known);
    let before_poll = written_length(&written)?;
    assert!(matches!(
        journal.submit_window(next_window(
            crate::qmp::QmpKvmOriginalWindowOperation::Begin
        )),
        Err(KvmComponentError::Transition(_))
    ));
    assert!(matches!(
        journal.submit_initial(4, 3),
        Err(KvmComponentError::Transition(_))
    ));
    assert_eq!(written_length(&written)?, before_poll);
    assert!(journal.reconcile_more(&more)?.observed().result_known);
    let after_poll = written_length(&written)?;
    assert!(matches!(
        journal.submit_window(next_window(
            crate::qmp::QmpKvmOriginalWindowOperation::Begin
        )),
        Err(KvmComponentError::Transition(_))
    ));
    assert_eq!(written_length(&written)?, after_poll);

    let (terminal, result) = journal.submit_completion(&more)?;
    assert_eq!(result?.native_phase, 3);
    let before_new_run = written_length(&written)?;
    // There is deliberately no modeled reply for the next window: observing its
    // attempted command proves admission, without inventing a native success.
    let (_, no_reply) = journal.submit_window(next_window(
        crate::qmp::QmpKvmOriginalWindowOperation::Begin,
    ))?;
    assert!(no_reply.is_err());
    assert!(written_length(&written)? > before_new_run);
    assert!(
        journal
            .completion_reply(&terminal, 0)?
            .observed()
            .result_known
    );
    assert_eq!(
        journal.completion_reply(&completion, 0)?.bytes(),
        &[0, 1, 2, 255]
    );
    Ok(())
}

#[test]
fn pending_initial_response_blocks_begin_but_allows_original_close_attempt()
-> Result<(), Box<dyn Error>> {
    let (mut journal, initial, written) = retained_initial(Vec::new())?;
    let before = written_length(&written)?;
    assert!(matches!(
        journal.submit_window(next_window(
            crate::qmp::QmpKvmOriginalWindowOperation::Begin
        )),
        Err(KvmComponentError::Transition(_))
    ));
    assert_eq!(written_length(&written)?, before);
    let (_, no_reply) = journal.submit_window(next_window(
        crate::qmp::QmpKvmOriginalWindowOperation::Close,
    ))?;
    assert!(no_reply.is_err());
    assert!(written_length(&written)? > before);
    assert!(journal.history(&initial)?.iter().all(|event| matches!(
        event,
        super::super::KvmComponentObservation::Initial {
            uncertain: false,
            ..
        }
    )));
    Ok(())
}

fn fresh_adoption_refuses_without_writes_or_credits(
    journal: &mut Journal<Stream>,
    written: &Arc<Mutex<Vec<u8>>>,
) -> Result<(), Box<dyn Error>> {
    let before = written_length(written)?;
    let entries = journal.entries.len();
    let credit = journal.retained_byte_credit;
    let attempts = journal
        .entries
        .iter()
        .map(|entry| entry.attempts)
        .collect::<Vec<_>>();

    assert!(matches!(
        journal.submit_initial(4, 3),
        Err(KvmComponentError::Transition(_))
    ));
    assert!(matches!(
        journal.submit_window(next_window(
            crate::qmp::QmpKvmOriginalWindowOperation::Begin
        )),
        Err(KvmComponentError::Transition(_))
    ));

    assert_eq!(written_length(written)?, before);
    assert_eq!(journal.entries.len(), entries);
    assert_eq!(journal.retained_byte_credit, credit);
    assert_eq!(
        journal
            .entries
            .iter()
            .map(|entry| entry.attempts)
            .collect::<Vec<_>>(),
        attempts
    );
    Ok(())
}

#[test]
fn known_more_birth_blocks_fresh_initial_adoption_before_query_or_credit()
-> Result<(), Box<dyn Error>> {
    let (mut journal, initial, written) = retained_initial(vec![
        json!({"return":native_query(false, false)}),
        json!({"return":native_more()}),
    ])?;
    let (completion, result) = journal.submit_completion(&initial)?;
    assert_eq!(result?.native_phase, 2);

    fresh_adoption_refuses_without_writes_or_credits(&mut journal, &written)?;

    let before = written_length(&written)?;
    assert_eq!(journal.reconcile_completion(&completion)?.native_phase, 2);
    assert_eq!(written_length(&written)?, before);
    assert_eq!(
        journal.completion_reply(&completion, 0)?.bytes(),
        &[0, 1, 2, 255]
    );
    Ok(())
}

#[test]
fn failed_canonical_response_query_keeps_original_callback_and_blocks_fresh_adoption()
-> Result<(), Box<dyn Error>> {
    let mut invalid = native_query(false, false);
    invalid["profile-qualified"] = json!(true);
    let (mut journal, initial, written) = retained_initial(vec![json!({"return":invalid})])?;
    let history = journal.history(&initial)?.len();

    assert!(journal.submit_completion(&initial).is_err());
    // Query failed before a completion was born; the genuine original callback
    // still needs its terminal chain. A failed observation cannot license adoption.
    assert_eq!(journal.entries.len(), 1);
    assert_eq!(journal.history(&initial)?.len(), history);
    fresh_adoption_refuses_without_writes_or_credits(&mut journal, &written)?;
    assert_eq!(journal.history(&initial)?.len(), history);
    Ok(())
}

#[test]
fn modeled_transport_reconnect_preserves_conflicted_original_and_zero_fresh_writes()
-> Result<(), Box<dyn Error>> {
    let mut foreign = done(false);
    foreign["operation-id"] = json!(77);
    let (mut journal, initial, original_written) = retained_initial(vec![
        json!({"return":native_query(false, false)}),
        json!({"return":foreign}),
    ])?;
    let (completion, result) = journal.submit_completion(&initial)?;
    assert!(result.is_err());
    fresh_adoption_refuses_without_writes_or_credits(&mut journal, &original_written)?;

    // This replaces only the modeled transport. Real owning reconnect separately
    // authenticates the same PID/startticks/executable before this exact field move.
    let replacement = Stream::new(vec![
        json!({"QMP":{"version":{},"capabilities":[]}}),
        json!({"return":{}}),
        json!({"return":done(false)}),
    ])?;
    let replacement_written = Arc::clone(&replacement.written);
    journal.qmp = QmpClient::connect(replacement)?;
    fresh_adoption_refuses_without_writes_or_credits(&mut journal, &replacement_written)?;

    let recovered = journal.reconcile_completion(&completion)?;
    assert!(recovered.result_known && recovered.uncertain_effects);
    fresh_adoption_refuses_without_writes_or_credits(&mut journal, &replacement_written)?;
    let Original::Completion { transaction, .. } = &journal.entries[completion.index].original
    else {
        return Err("original completion disappeared during reconnect".into());
    };
    // Done has no current fragment; its original admitted input remains private
    // in the same transaction rather than being relabeled as terminal output.
    assert_eq!(transaction.baseline().bytes(), &[0, 1, 2, 255]);
    assert!(journal.completion_reply(&completion, 0)?.bytes().is_empty());
    assert_eq!(journal.history(&completion)?.len(), 2);
    Ok(())
}
