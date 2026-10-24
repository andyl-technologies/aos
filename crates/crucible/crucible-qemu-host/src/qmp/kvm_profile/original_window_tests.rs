//! Wire/model controls for original windows; no native KVM execution occurs.

use super::*;
use serde_json::json;
use std::io::{self, Cursor, Read, Write};
use std::time::Duration;

struct ScriptedStream {
    received: Cursor<Vec<u8>>,
    written: Vec<u8>,
}

impl ScriptedStream {
    fn new(replies: &[serde_json::Value]) -> Result<Self, serde_json::Error> {
        let mut received = Vec::new();
        for reply in replies {
            received.extend_from_slice(&serde_json::to_vec(reply)?);
            received.push(b'\n');
        }
        Ok(Self {
            received: Cursor::new(received),
            written: Vec::new(),
        })
    }
}

impl Read for ScriptedStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.received.read(buffer)
    }
}

impl Write for ScriptedStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl QmpTimeoutStream for ScriptedStream {
    fn set_qmp_read_timeout(&mut self, _timeout: Duration) -> io::Result<()> {
        Ok(())
    }

    fn set_qmp_write_timeout(&mut self, _timeout: Duration) -> io::Result<()> {
        Ok(())
    }
}

fn query() -> QmpKvmOriginalWindowRequest {
    QmpKvmOriginalWindowRequest {
        operation: QmpKvmOriginalWindowOperation::Query,
        generation: 4,
        start_ns: 0,
        end_ns: 0,
        stop_budget_ns: 0,
    }
}

fn observation() -> serde_json::Value {
    json!({
        "schema-version":1,"clock-edition":3,"clock-components":159,
        "generation":4,"phase":3,"current-ns":100,
        "clock-active":false,"kernel-run-owners":0,"clock-closed":true,
        "original-cpus-stopped":true,"retained-returns":2,
        "input-custody-known":false,"device-custody-known":false,
        "publication-custody-known":false,"profile-qualified":false
    })
}

#[test]
fn original_window_command_preserves_exact_new_namespace_and_geometry() {
    let request = query();
    let command = QmpCommand::KvmOriginalWindow { request: &request };
    assert_eq!(command.kind(), QmpCommandKind::KvmOriginalWindow);
    assert_eq!(
        command.request(),
        json!({"execute":"x-crucible-kvm-original-window","arguments":{
            "operation":"query","generation":4,"start-ns":0,"end-ns":0,
            "stop-budget-ns":0
        }})
    );
    assert!(parse_original_window(&request, &observation()).is_ok());
}

#[test]
fn old_window_request_geometry_cannot_be_rounded_or_reinterpreted() {
    let mut request = query();
    request.start_ns = 1;
    assert!(validate_original_window_request(&request).is_err());
    request = query();
    request.operation = QmpKvmOriginalWindowOperation::Close;
    assert!(validate_original_window_request(&request).is_err());
    request.stop_budget_ns = MAXIMUM_STOP_BUDGET_NS;
    assert!(validate_original_window_request(&request).is_ok());
    request.stop_budget_ns += 1;
    assert!(validate_original_window_request(&request).is_err());

    request = query();
    request.operation = QmpKvmOriginalWindowOperation::Begin;
    request.start_ns = 2;
    request.end_ns = 3;
    assert!(validate_original_window_request(&request).is_ok());
    request.end_ns = request.start_ns;
    assert!(validate_original_window_request(&request).is_err());
    request.end_ns = u64::MAX;
    assert!(validate_original_window_request(&request).is_err());
    request.end_ns = 3;
    request.generation = 0;
    assert!(validate_original_window_request(&request).is_err());
}

#[test]
fn stopped_kernel_component_cannot_claim_input_device_or_publication_authority() {
    for field in [
        "input-custody-known",
        "device-custody-known",
        "publication-custody-known",
        "profile-qualified",
    ] {
        let mut value = observation();
        value[field] = json!(true);
        assert!(parse_original_window(&query(), &value).is_err(), "{field}");
    }
}

#[test]
fn window_response_refuses_forged_generation_census_or_stopped_facts() {
    for (field, replacement) in [
        ("schema-version", json!(2)),
        ("generation", json!(5)),
        ("phase", json!(5)),
        ("current-ns", json!(u64::MAX)),
        ("kernel-run-owners", json!(1)),
        ("clock-active", json!(true)),
        ("clock-closed", json!(false)),
        ("original-cpus-stopped", json!(false)),
        ("retained-returns", json!(65_537)),
        ("clock-components", json!(228)),
        ("invented-complete-stop", json!(true)),
    ] {
        let mut value = observation();
        value[field] = replacement;
        assert!(parse_original_window(&query(), &value).is_err(), "{field}");
    }
}

#[test]
fn actual_arm_coverage_and_unknown_native_state_remain_partial_observations() {
    let mut value = observation();
    value["clock-edition"] = json!(2);
    value["clock-components"] = json!(228);
    value["phase"] = json!(4);
    assert!(parse_original_window(&query(), &value).is_ok());
}

#[test]
fn begin_response_must_remain_inside_original_exact_coordinate_ceiling() {
    let request = QmpKvmOriginalWindowRequest {
        operation: QmpKvmOriginalWindowOperation::Begin,
        generation: 4,
        start_ns: 50,
        end_ns: 100,
        stop_budget_ns: 0,
    };
    let mut value = observation();
    value["phase"] = json!(1);
    value["clock-active"] = json!(true);
    value["clock-closed"] = json!(false);
    value["original-cpus-stopped"] = json!(false);
    assert!(parse_original_window(&request, &value).is_ok());
    value["current-ns"] = json!(101);
    assert!(parse_original_window(&request, &value).is_err());
    value["current-ns"] = json!(49);
    assert!(parse_original_window(&request, &value).is_err());
}

#[test]
fn original_mutation_failure_reconciles_by_query_without_repeating_begin()
-> Result<(), Box<dyn std::error::Error>> {
    let original = QmpKvmOriginalWindowRequest {
        operation: QmpKvmOriginalWindowOperation::Begin,
        generation: 4,
        start_ns: 50,
        end_ns: 100,
        stop_budget_ns: 0,
    };
    let stream = ScriptedStream::new(&[
        json!({"QMP":{"version":{},"capabilities":[]}}),
        json!({"return":{}}),
        json!({"error":{"class":"GenericError","desc":"outcome unresolved"}}),
        json!({"return":observation()}),
    ])?;
    let mut client = QmpClient::connect(stream)?;
    let mut transaction = QmpKvmOriginalWindowTransaction::prepare(original)?;
    assert!(transaction.reconcile(&mut client).is_err());
    assert!(transaction.dispatch_once(&mut client).is_err());
    assert!(transaction.uncertain_effects());
    assert_eq!(transaction.original(), &original);

    let written_before_repeat = client.stream.get_ref().written.len();
    assert!(transaction.dispatch_once(&mut client).is_err());
    assert_eq!(client.stream.get_ref().written.len(), written_before_repeat);
    let state = transaction.reconcile(&mut client)?;
    assert_eq!(state.observed().phase, 3);
    assert!(transaction.uncertain_effects());
    assert_eq!(transaction.original(), &original);
    assert_eq!(transaction.observation(), Some(&state));

    let requests = std::str::from_utf8(&client.stream.get_ref().written)?
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[1]["arguments"]["operation"], "begin");
    assert_eq!(requests[2]["arguments"]["operation"], "query");
    assert_eq!(requests[2]["arguments"]["generation"], 4);
    Ok(())
}

#[test]
fn invalid_original_request_is_refused_before_any_command_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let mut client = QmpClient::connect(ScriptedStream::new(&[
        json!({"QMP":{"version":{},"capabilities":[]}}),
        json!({"return":{}}),
    ])?)?;
    let before = client.stream.get_ref().written.len();
    let mut request = query();
    request.start_ns = 1;
    assert!(client.control_native_kvm_original_window(&request).is_err());
    assert_eq!(client.stream.get_ref().written.len(), before);
    assert!(QmpKvmOriginalWindowTransaction::prepare(request).is_err());
    assert!(QmpKvmOriginalWindowTransaction::prepare(query()).is_err());
    Ok(())
}

#[test]
fn missing_reply_keeps_original_mutation_in_uncertain_custody()
-> Result<(), Box<dyn std::error::Error>> {
    let original = QmpKvmOriginalWindowRequest {
        operation: QmpKvmOriginalWindowOperation::Begin,
        generation: 4,
        start_ns: 50,
        end_ns: 100,
        stop_budget_ns: 0,
    };
    let mut client = QmpClient::connect(ScriptedStream::new(&[
        json!({"QMP":{"version":{},"capabilities":[]}}),
        json!({"return":{}}),
    ])?)?;
    let mut transaction = QmpKvmOriginalWindowTransaction::prepare(original)?;
    assert!(transaction.dispatch_once(&mut client).is_err());
    assert!(transaction.uncertain_effects());
    assert!(transaction.observation().is_none());
    assert_eq!(transaction.original(), &original);

    let written = client.stream.get_ref().written.len();
    assert!(transaction.dispatch_once(&mut client).is_err());
    assert_eq!(client.stream.get_ref().written.len(), written);
    // A failed observation cannot replace the original request or clear taint.
    assert!(transaction.reconcile(&mut client).is_err());
    assert!(transaction.uncertain_effects());
    assert_eq!(transaction.original(), &original);
    Ok(())
}

// The delayed original reply has the same shape and generation as Query.
// After ambiguity it must never be consumed as a fresh observation.
#[test]
fn timed_out_original_exchange_fences_late_reply_before_query()
-> Result<(), Box<dyn std::error::Error>> {
    struct LateReplyStream {
        initial: Cursor<Vec<u8>>,
        late: Cursor<Vec<u8>>,
        timed_out: bool,
        written: Vec<u8>,
    }

    impl Read for LateReplyStream {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let count = self.initial.read(bytes)?;
            if count != 0 {
                return Ok(count);
            }
            if !self.timed_out {
                self.timed_out = true;
                return Err(io::ErrorKind::TimedOut.into());
            }
            self.late.read(bytes)
        }
    }

    impl Write for LateReplyStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl QmpTimeoutStream for LateReplyStream {
        fn set_qmp_read_timeout(&mut self, _: Duration) -> io::Result<()> {
            Ok(())
        }

        fn set_qmp_write_timeout(&mut self, _: Duration) -> io::Result<()> {
            Ok(())
        }
    }

    let initial = ScriptedStream::new(&[
        json!({"QMP":{"version":{},"capabilities":[]}}),
        json!({"return":{}}),
    ])?;
    let mut delayed_begin = observation();
    delayed_begin["phase"] = json!(1);
    delayed_begin["clock-active"] = json!(true);
    delayed_begin["clock-closed"] = json!(false);
    delayed_begin["original-cpus-stopped"] = json!(false);
    let late = ScriptedStream::new(&[json!({"return":delayed_begin})])?;
    let stream = LateReplyStream {
        initial: initial.received,
        late: late.received,
        timed_out: false,
        written: Vec::new(),
    };
    let mut client = QmpClient::connect(stream)?;
    let mut original = QmpKvmOriginalWindowTransaction::prepare(QmpKvmOriginalWindowRequest {
        operation: QmpKvmOriginalWindowOperation::Begin,
        generation: 4,
        start_ns: 50,
        end_ns: 100,
        stop_budget_ns: 0,
    })?;
    assert!(original.dispatch_once(&mut client).is_err());
    assert!(original.uncertain_effects());
    let written = client.stream.get_ref().written.len();
    assert_eq!(
        original.reconcile(&mut client),
        Err(QmpError::ConnectionPoisoned)
    );
    assert_eq!(client.stream.get_ref().written.len(), written);
    assert!(original.observation().is_none());
    assert!(original.uncertain_effects());
    Ok(())
}
