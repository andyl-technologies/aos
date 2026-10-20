//! Controlled closed-observer regressions without provider or runtime qualification.

use std::cell::RefCell;

use super::*;

fn selection() -> String {
    serde_json::json!({"version":1,"capture_id":"a".repeat(32),
        "source_prefix":"qualification/source", "destination_prefixes":["qualification/target"]})
    .to_string()
}

fn new_trace(role: Role) -> (Rc<Trace>, Rc<RefCell<Vec<serde_json::Value>>>) {
    let rows = Rc::new(RefCell::new(Vec::new()));
    let sink = Rc::clone(&rows);
    let trace = Trace::selected(
        &selection(),
        "qualification/source",
        "qualification/target",
        "b".repeat(64),
        "c".repeat(64),
        role,
        Rc::new(move |body| {
            sink.borrow_mut().push(serde_json::from_str(body).unwrap());
            true
        }),
    )
    .unwrap();
    (trace, rows)
}

#[test]
fn selection_is_closed_exact_and_bounded_without_pool_mutation() {
    let before = serde_json::to_value(provider_capacity::observation()).unwrap();
    let sink = Rc::new(|_: &str| true);
    for raw in [selection().replace("qualification/source", "another/source"),
        selection().replace("qualification/target", "another/target"),
        selection().replace("\"version\":1", "\"version\":2"),
        serde_json::json!({"version":1,"capture_id":"a".repeat(32),"source_prefix":"qualification/source",
            "destination_prefixes":["qualification/target","qualification/target"]}).to_string(),
        serde_json::json!({"version":1,"capture_id":"a".repeat(32),"source_prefix":"qualification/source",
            "destination_prefixes":["qualification/target"],"approval":true}).to_string(),
        "x".repeat(MAX_CONFIGURATION_BYTES + 1)] {
        assert!(Trace::selected(&raw, "qualification/source", "qualification/target",
            "b".repeat(64), "c".repeat(64), Role::SourceGuard, sink.clone()).is_none());
    }
    assert_eq!(
        serde_json::to_value(provider_capacity::observation()).unwrap(),
        before
    );
}

#[test]
fn actual_source_progress_and_local_cleanup_are_distinct_from_settlement() {
    let (trace, rows) = new_trace(Role::SourceGuard);
    trace.admitted(1);
    trace.progress(65536, false);
    trace.progress(131072, false);
    trace.progress(131072, true);
    trace.cleanup("owner_drop", true, true, 2);
    let rows = rows.borrow();
    assert_eq!(rows.len(), 6);
    assert_eq!(rows[2]["event"]["bytes"], 65536);
    assert_eq!(rows[3]["event"]["eof"], true);
    assert_eq!(rows[4]["event"]["owned_capacity_released"], true);
    assert_eq!(rows[5]["event"]["outcome"], "eof");
    assert_eq!(rows[5]["event"]["healthy"], true);
    assert!(rows
        .iter()
        .all(|row| row["original_sha256"] == "b".repeat(64)));
    assert!(!serde_json::to_string(&*rows)
        .unwrap()
        .contains("qualification/source"));
}

#[test]
fn native_abort_and_drop_never_claim_remote_drain() {
    let (trace, rows) = new_trace(Role::DestinationExecutor);
    trace.cleanup("native_signal", true, false, 2);
    assert_eq!(
        rows.borrow().last().unwrap()["event"]["outcome"],
        "incoming_abort"
    );
    trace.finish("returned");
    assert_eq!(rows.borrow().len(), 3);
    drop(trace);

    let (trace, rows) = new_trace(Role::DestinationExecutor);
    drop(trace);
    assert_eq!(rows.borrow().last().unwrap()["event"]["outcome"], "unknown");
    assert!(!serde_json::to_string(&*rows.borrow())
        .unwrap()
        .contains("remote_drained"));
}

#[test]
fn overflow_and_failed_recording_do_not_produce_a_healthy_complete_bracket() {
    let (trace, rows) = new_trace(Role::DestinationExecutor);
    for _ in 0..MAX_RECORDS {
        trace.admitted(1);
    }
    trace.finish("returned");
    assert_eq!(rows.borrow().len(), MAX_RECORDS);
    assert_ne!(rows.borrow().last().unwrap()["event"]["kind"], "terminal");

    let trace = Trace::selected(
        &selection(),
        "qualification/source",
        "qualification/target",
        "b".repeat(64),
        "c".repeat(64),
        Role::SourceGuard,
        Rc::new(|_| false),
    )
    .unwrap();
    assert!(!trace.healthy.get());
}
