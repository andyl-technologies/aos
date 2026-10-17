//! Exercises complete archive accounting without native ownership or effects.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Inert exact accounting and closed-body controls deliberately fail assertions.
#![allow(clippy::unwrap_used)]

use super::*;

fn source_credit() -> ArchiveCredit {
    let root = canonical::content_ref(b"inert metadata root", "application/json").unwrap();
    let selected = canonical::content_ref(b"inert selected root", "application/json").unwrap();
    ArchiveCredit::new(&root, &selected, 4, [&root, &selected].into_iter()).unwrap()
}

#[test]
fn original_total_and_one_byte_short_refuse_complete_reservation() {
    let credit = source_credit();
    assert!(credit.require_aggregate(NATIVE_RECORD_BYTES).is_err());
    assert!(
        credit
            .require_aggregate(credit.total_record_bytes - 1)
            .is_err()
    );
    credit.require_aggregate(credit.total_record_bytes).unwrap();
    let body: serde_json::Value = serde_json::from_slice(credit.body()).unwrap();
    let immutable = body["immutable_bytes_without_credit"].as_u64().unwrap() as usize;
    let residual = credit.total_record_bytes
        - immutable
        - credit.body().len()
        - 8 * RECORD_BYTES
        - RECORD_BYTES
        - QUEUED_PAYLOAD_BYTES;
    assert_eq!(residual, NATIVE_RECORD_BYTES);
    assert_eq!(credit.limits().native.maximum_record_bytes, RECORD_BYTES);
}

#[test]
fn source_union_deduplicates_full_references_and_charges_exact_credit_body() {
    let root = canonical::content_ref(b"original root", "application/json").unwrap();
    let selected = canonical::content_ref(b"selected root", "application/json").unwrap();
    let once = ArchiveCredit::new(&root, &selected, 4, [&root, &selected].into_iter()).unwrap();
    let repeated = ArchiveCredit::new(
        &root,
        &selected,
        4,
        [&root, &selected, &root, &selected].into_iter(),
    )
    .unwrap();
    assert_eq!(once.reference(), repeated.reference());
    assert_eq!(once.body(), repeated.body());
    let body: serde_json::Value = serde_json::from_slice(once.body()).unwrap();
    assert_eq!(body["immutable_objects_without_credit"], 2);
    assert_eq!(
        once.total_record_bytes,
        body["total_record_bytes_without_credit_body"]
            .as_u64()
            .unwrap() as usize
            + once.body().len()
    );
}

#[test]
fn malformed_owner_scope_self_role_and_overflow_refuse() {
    let root = canonical::content_ref(b"root", "application/json").unwrap();
    let selected = canonical::content_ref(b"selected", "application/json").unwrap();
    assert!(ArchiveCredit::new(&root, &selected, 3, [&root].into_iter()).is_err());
    assert!(ArchiveCredit::new(&root, &root, 4, [&root].into_iter()).is_err());
    assert!(complete_bytes(usize::MAX, 8, 0).is_err());
    assert!(complete_bytes(0, usize::MAX, 0).is_err());
    assert!(complete_bytes(TOTAL_STATE_BYTES, 8, 0).is_err());
    let overhead = complete_bytes(0, 8, 0).unwrap();
    assert_eq!(
        complete_bytes(TOTAL_STATE_BYTES - overhead, 8, 0).unwrap(),
        TOTAL_STATE_BYTES
    );
    assert!(complete_bytes(TOTAL_STATE_BYTES - overhead + 1, 8, 0).is_err());
}

#[test]
fn missing_changed_or_foreign_credit_body_refuses() {
    let credit = source_credit();
    credit
        .authenticate(credit.reference(), Some(credit.body()))
        .unwrap();
    assert!(credit.authenticate(credit.reference(), None).is_err());
    let mut changed: serde_json::Value = serde_json::from_slice(credit.body()).unwrap();
    changed["native_record_residual_bytes"] = serde_json::json!(NATIVE_RECORD_BYTES + 1);
    let changed = canonical::canonical_json(&changed).unwrap();
    assert!(
        credit
            .authenticate(credit.reference(), Some(&changed))
            .is_err()
    );
    let rehashed = canonical::content_ref(&changed, "application/json").unwrap();
    assert!(credit.authenticate(&rehashed, Some(&changed)).is_err());
}

#[test]
fn actual_queued_payload_boundary_preserves_native_residual() {
    let credit = source_credit();
    assert_eq!(
        credit.native_record_ceiling(QUEUED_PAYLOAD_BYTES).unwrap(),
        NATIVE_RECORD_BYTES
    );
    assert!(
        credit
            .native_record_ceiling(QUEUED_PAYLOAD_BYTES + 1)
            .is_err()
    );
    assert!(credit.native_record_ceiling(usize::MAX).is_err());
}
