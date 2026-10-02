//! Controlled request brackets, unknown outcomes and recorder bounds.

use std::cell::RefCell;
use std::rc::Rc;

use super::*;

fn trace() -> (RequestTrace, Rc<RefCell<Vec<serde_json::Value>>>) {
    trace_selected(Scope::ManagedGcGuard, "actual-action-selector".into())
}

fn trace_selected(
    scope: Scope,
    subject: String,
) -> (RequestTrace, Rc<RefCell<Vec<serde_json::Value>>>) {
    let records = Rc::new(RefCell::new(Vec::new()));
    let output = records.clone();
    let sink = Rc::new(move |body: &str| {
        output
            .borrow_mut()
            .push(serde_json::from_str(body).unwrap());
        true
    });
    let selected = RequestTrace::new(
        Configuration {
            version: 1,
            capture_id: "a".repeat(32),
            prefix: "controlled/gc".into(),
        },
        "b".repeat(32),
        scope,
        "controlled/gc/object".into(),
        subject,
        sink,
    )
    .unwrap();
    (selected, records)
}

#[test]
fn actual_closed_bracket_contains_each_invocation_and_returned_metadata() {
    let (selected, records) = trace();
    selected
        .call(Method::Head)
        .unwrap()
        .finish(Outcome::Object {
            size: 42,
            etag: "\"actual-tag\"".into(),
            version: "actual-upload".into(),
        });
    selected
        .call(Method::Delete)
        .unwrap()
        .finish(Outcome::Resolved);
    selected.finish();
    drop(selected);
    let records = records.borrow();
    assert_eq!(records.len(), 6);
    assert_eq!(records[0]["event"]["kind"], "request_entry");
    assert_eq!(records[2]["event"]["outcome"]["version"], "actual-upload");
    assert_eq!(
        records[5]["event"],
        serde_json::json!({
            "kind":"request_terminal", "healthy":true, "invoked":2, "completed":2, "pending":0,
        })
    );
}

#[test]
fn empty_closed_request_is_distinct_from_absent_or_dropped_request() {
    let (selected, records) = trace();
    selected.finish();
    assert_eq!(records.borrow().len(), 2);
    assert_eq!(records.borrow()[1]["event"]["healthy"], true);
    let (dropped, unknown) = trace();
    drop(dropped);
    assert_eq!(unknown.borrow()[1]["event"]["healthy"], false);
}

#[test]
fn dropped_call_and_explicit_unknown_cannot_produce_healthy_terminal() {
    for drop_call in [true, false] {
        let (selected, records) = trace();
        let call = selected.call(Method::Delete).unwrap();
        if drop_call {
            drop(call)
        } else {
            call.finish(Outcome::Unknown)
        }
        selected.finish();
        assert_eq!(records.borrow()[2]["event"]["outcome"]["kind"], "unknown");
        assert_eq!(records.borrow()[3]["event"]["healthy"], false);
    }
}

#[test]
fn pending_call_at_terminal_and_overflow_remain_incomplete() {
    let (selected, records) = trace();
    let pending = selected.call(Method::Get).unwrap();
    selected.finish();
    assert_eq!(records.borrow()[2]["event"]["pending"], 1);
    assert_eq!(records.borrow()[2]["event"]["healthy"], false);
    drop(pending);
    let (selected, records) = trace();
    for _ in 0..MAX_CALLS {
        selected.call(Method::Head).unwrap().finish(Outcome::Absent);
    }
    assert!(selected.call(Method::Head).is_none());
    selected.finish();
    assert_eq!(records.borrow().last().unwrap()["event"]["healthy"], false);
}

#[test]
fn missing_scope_and_output_failure_never_manufacture_positive_coverage() {
    let configuration = Configuration {
        version: 1,
        capture_id: "a".repeat(32),
        prefix: "selected/gc".into(),
    };
    assert!(RequestTrace::new(
        configuration.clone(),
        "b".repeat(32),
        Scope::ManagedGcGuard,
        "other/object".into(),
        "action".into(),
        Rc::new(|_| true)
    )
    .is_none());
    let records = Rc::new(RefCell::new(Vec::new()));
    let output = records.clone();
    let sink = Rc::new(move |body: &str| {
        output
            .borrow_mut()
            .push(serde_json::from_str::<serde_json::Value>(body).unwrap());
        false
    });
    let selected = RequestTrace::new(
        configuration,
        "b".repeat(32),
        Scope::ManagedInventoryRange,
        "selected/gc/object".into(),
        "plan".into(),
        sink,
    )
    .unwrap();
    selected.call(Method::Get).unwrap().finish(Outcome::Object {
        size: 1,
        etag: "x".repeat(MAX_RECORD_BYTES),
        version: "actual-upload".into(),
    });
    selected.finish();
    assert_eq!(records.borrow().last().unwrap()["event"]["healthy"], false);
    assert!(records
        .borrow()
        .iter()
        .all(|row| serde_json::to_vec(row).unwrap().len() <= MAX_RECORD_BYTES));
}

#[test]
fn range_records_exact_arguments_without_object_bytes() {
    let (selected, records) = trace();
    selected
        .call_range(65_536, 8_192)
        .unwrap()
        .finish(Outcome::Object {
            size: 100_000,
            etag: "\"actual-tag\"".into(),
            version: "actual-upload".into(),
        });
    selected.finish();

    let records = records.borrow();
    assert_eq!(records[1]["event"]["method"], "get");
    assert_eq!(
        records[1]["event"]["range"],
        serde_json::json!([65_536, 8_192])
    );
    assert_eq!(records.last().unwrap()["event"]["healthy"], true);
}

#[test]
fn oversized_result_with_successful_sink_remains_incomplete() {
    let (selected, records) = trace();
    selected
        .call(Method::Head)
        .unwrap()
        .finish(Outcome::Object {
            size: 1,
            etag: "x".repeat(MAX_RECORD_BYTES),
            version: "actual-upload".into(),
        });
    selected.finish();

    let records = records.borrow();
    assert_eq!(records.len(), 3);
    assert_eq!(records.last().unwrap()["event"]["healthy"], false);
    assert!(records
        .iter()
        .all(|row| serde_json::to_vec(row).unwrap().len() <= MAX_RECORD_BYTES));
}

#[test]
fn call_after_terminal_leaves_visible_invalid_continuation() {
    let (selected, records) = trace();
    selected.finish();
    assert!(selected.call(Method::Delete).is_none());

    let records = records.borrow();
    assert_eq!(records[1]["event"]["kind"], "request_terminal");
    assert_eq!(records[2]["event"]["kind"], "call_invoke");
}

#[test]
fn terminal_cleanup_binds_both_full_commitments_and_dropped_route_stays_incomplete() {
    let subject = format!("{}{}", "c".repeat(64), "d".repeat(64));
    let (selected, records) = trace_selected(Scope::ManagedTerminalCleanup, subject.clone());
    selected.finish();
    assert_eq!(records.borrow()[0]["scope"], "managed_terminal_cleanup");
    assert_eq!(records.borrow()[0]["capture_id"], "a".repeat(32));
    assert_eq!(records.borrow()[0]["subject_id"], subject);
    assert_eq!(records.borrow()[1]["event"]["invoked"], 0);
    assert_eq!(records.borrow()[1]["event"]["healthy"], true);

    let (selected, records) = trace_selected(Scope::ManagedTerminalCleanup, subject);
    let pending = selected.call(Method::Delete).unwrap();
    drop(selected);
    // A pending SDK promise retains the span after its response owner is gone.
    assert_eq!(records.borrow().len(), 2);
    pending.finish(Outcome::Resolved);
    assert_eq!(records.borrow().last().unwrap()["event"]["healthy"], false);
}

#[test]
fn terminal_cleanup_rejects_partial_uppercase_or_oversized_subjects() {
    for subject in ["c".repeat(64), "C".repeat(128), "c".repeat(129)] {
        assert!(RequestTrace::new(
            Configuration {
                version: 1,
                capture_id: "a".repeat(32),
                prefix: "controlled/gc".into(),
            },
            "b".repeat(32),
            Scope::ManagedTerminalCleanup,
            "controlled/gc/object".into(),
            subject,
            Rc::new(|_| true),
        )
        .is_none());
    }
}
