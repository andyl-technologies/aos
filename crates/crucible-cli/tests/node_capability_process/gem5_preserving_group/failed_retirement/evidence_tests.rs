//! Exercises terminal data grammar without a native or supervisor permission.
//!
//! Every body below is an authored test DTO. Passing these checks establishes
//! only reader refusal behavior; the ignored process fixture must obtain its
//! actual private ACK, same Child wait and complete original histories separately.

use super::*;
use crucible_core::node_contract::OwnerIdentity;

fn terminal_model() -> (BTreeMap<ContentRef, Vec<u8>>, Summary, NodeRoute) {
    let frame = b"\0\0\0\x13{\"kind\":\"shutdown\"}";
    let route = NodeRoute {
        node: Id::new("cpu").unwrap(),
        owners: vec![OwnerIdentity {
            owner: Id::new("owner/cpu").unwrap(),
            incarnation: Id::new("model-incarnation").unwrap(),
            generation: 1.into(),
        }],
    };
    let shutdown = serde_json::to_vec(&json!({
        "format":"crucible.gem5.retirement-shutdown-history", "version":1,
        "owner":"owner/cpu", "incarnation":"model-incarnation", "generation":"1",
        "request":frame, "written":frame.len(), "received":frame, "acknowledged":true
    }))
    .unwrap();
    let reaping = serde_json::to_vec(&json!({
        "schema":"crucible.gem5.native-reclamation.v1", "owner":"owner/cpu",
        "incarnation":"model-incarnation", "generation":"1", "pid":"17", "start_ticks":"19",
        "source_scope":{"model":"data-only"}, "exit_code":0, "exit_signal":null,
        "remaining_group_members":[],
        "graceful_shutdown":{"written_bytes":frame.len().to_string(),"received_bytes":frame,
            "acknowledged":true,"signal_fallback":false}
    }))
    .unwrap();
    let shutdown_ref = canonical::content_ref(&shutdown, "application/json").unwrap();
    let reaping_ref = canonical::content_ref(&reaping, "application/json").unwrap();
    let inert = canonical::content_ref(b"model-only", "application/octet-stream").unwrap();
    let summary = Summary {
        source_credit: inert.clone(),
        source_index: inert.clone(),
        metadata: inert,
        histories: Vec::new(),
        shutdown: shutdown_ref.clone(),
        reaping: reaping_ref.clone(),
    };
    (
        BTreeMap::from([(shutdown_ref, shutdown), (reaping_ref, reaping)]),
        summary,
        route,
    )
}

fn replace_reaping(
    histories: &mut BTreeMap<ContentRef, Vec<u8>>,
    summary: &mut Summary,
    changed: Value,
) {
    histories.remove(&summary.reaping);
    let bytes = serde_json::to_vec(&changed).unwrap();
    summary.reaping = canonical::content_ref(&bytes, "application/json").unwrap();
    histories.insert(summary.reaping.clone(), bytes);
}

#[test]
fn same_terminal_data_refuses_missing_nullable_or_foreign_owner() {
    let (mut histories, mut summary, route) = terminal_model();
    assert!(verify_terminal(&histories, &summary, &route).is_ok());

    let original: Value = serde_json::from_slice(histories.get(&summary.reaping).unwrap()).unwrap();
    let mut omitted = original.clone();
    omitted.as_object_mut().unwrap().remove("exit_signal");
    replace_reaping(&mut histories, &mut summary, omitted);
    assert!(verify_terminal(&histories, &summary, &route).is_err());

    let mut foreign = original;
    foreign["incarnation"] = json!("another-model-incarnation");
    replace_reaping(&mut histories, &mut summary, foreign);
    assert!(verify_terminal(&histories, &summary, &route).is_err());
}

#[test]
fn kernel_terminal_data_cannot_replace_shutdown_ack_or_media() {
    let (mut histories, mut summary, route) = terminal_model();
    let original: Value = serde_json::from_slice(histories.get(&summary.reaping).unwrap()).unwrap();

    let mut fallback = original;
    fallback["graceful_shutdown"]["signal_fallback"] = json!(true);
    replace_reaping(&mut histories, &mut summary, fallback);
    assert!(verify_terminal(&histories, &summary, &route).is_err());

    let (mut histories, mut summary, route) = terminal_model();
    let old = histories.remove(&summary.shutdown).unwrap();
    let mut no_ack: Value = serde_json::from_slice(&old).unwrap();
    no_ack["acknowledged"] = json!(false);
    let changed = serde_json::to_vec(&no_ack).unwrap();
    summary.shutdown = canonical::content_ref(&changed, "application/json").unwrap();
    histories.insert(summary.shutdown.clone(), changed);
    assert!(verify_terminal(&histories, &summary, &route).is_err());

    let (mut histories, mut summary, route) = terminal_model();
    let body = histories.remove(&summary.reaping).unwrap();
    let old_hash = summary.reaping.hash.clone();
    summary.reaping.media_type = "application/octet-stream".to_owned();
    assert_eq!(summary.reaping.hash, old_hash);
    histories.insert(summary.reaping.clone(), body);
    assert!(verify_terminal(&histories, &summary, &route).is_err());
}

#[test]
fn borrowed_complete_body_credit_refuses_duplicates_and_undercredit() {
    let first = canonical::content_ref(b"first", "application/octet-stream").unwrap();
    let second = canonical::content_ref(b"second", "application/octet-stream").unwrap();
    let exact = first.length.get() + second.length.get();

    assert!(bounded_geometry([&first, &second].into_iter(), exact).is_ok());
    assert!(bounded_geometry([&first, &second].into_iter(), exact - 1).is_err());
    assert!(bounded_geometry([&first, &first].into_iter(), exact).is_err());
}
