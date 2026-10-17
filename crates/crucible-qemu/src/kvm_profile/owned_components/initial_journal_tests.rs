//! Finite first-handler journal controls with explicitly modeled wire peers.

use super::*;
use serde_json::{Value, json};
use std::{
    error::Error,
    io::{self, Cursor, Read, Write},
    time::Duration,
};

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

fn journal() -> Result<Journal<Stream>, Box<dyn Error>> {
    let page = json!({"schema-version":1,"generation":3,"first-record":2,
        "next-record":3,"retained-returns":3,"profile-qualified":false,
        "entries":[{"record-index":2,"generation":3,"expected-invocation":4,
        "vcpu-index":0,"native-vcpu-id":0,"issued":true,"receipt-known":true,
        "no-birth-known":false,"ack-known":false}]});
    let stream = Stream::new(vec![
        json!({"QMP":{"version":{},"capabilities":[]}}),
        json!({"return":{}}),
        json!({"return":page}),
        json!({"return":receipt()}),
        json!({"return":observed(false, 0)}),
        json!({"return":observed(true, 0)}),
    ])?;
    Ok(JournalReservation::reserve(2, 2)?.connect(QmpClient::connect(stream)?))
}

#[test]
fn initial_response_class_checks_do_not_consume_original_poll_credit() -> Result<(), Box<dyn Error>>
{
    let mut original = journal()?;
    let (token, submitted) = original.submit_initial(3, 2)?;
    assert!(!submitted?.observed().completed);
    assert_eq!(original.entries[0].attempts, 1);

    assert!(matches!(
        original.admit_attempt(&token, CommandClass::Window),
        Err(KvmComponentError::ForeignToken)
    ));
    assert!(matches!(
        original.admit_attempt(&token, CommandClass::Ack),
        Err(KvmComponentError::ForeignToken)
    ));
    assert_eq!(original.entries[0].attempts, 1);
    assert!(original.reconcile_initial(&token)?.observed().completed);
    assert_eq!(original.history(&token)?.len(), 2);
    assert!(matches!(
        original.reconcile_initial(&token),
        Err(KvmComponentError::ResourceLimit)
    ));
    assert_eq!(original.entries[0].attempts, 2);
    assert_eq!(original.history(&token)?.len(), 2);
    Ok(())
}

#[test]
fn initial_response_duplicate_does_not_replace_original_custody() -> Result<(), Box<dyn Error>> {
    let mut original = journal()?;
    let (token, submitted) = original.submit_initial(3, 2)?;
    submitted?;
    assert!(matches!(
        original.submit_initial(3, 2),
        Err(KvmComponentError::Transition(_))
    ));
    assert_eq!(original.entries.len(), 1);
    assert_eq!(original.history(&token)?.len(), 1);
    assert!(original.reconcile_initial(&token)?.observed().completed);
    let Original::Initial(retained) = &original.entries[0].original else {
        return Err("wrong original journal class".into());
    };
    assert_eq!(retained.baseline().response_sequence, 5);
    assert_eq!(retained.original().expected_invocation, 4);
    Ok(())
}
