//! Borrowed-record parsing controls without archive or native authority.

// crucible-lint: allow panic-shortcut -- These parser tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::WriterHistory;

fn record(charge: u64, inode: u64, active: bool, copy_buffer: bool) -> Vec<u8> {
    let root = b"/tmp/owned-writer";
    let name = b"temp.dmtcp";
    let mut body = b"DCPBUD01".to_vec();
    for number in [
        42,
        1000,
        1,
        charge,
        u64::from(copy_buffer),
        root.len() as u64,
    ] {
        body.extend_from_slice(&number.to_be_bytes());
    }
    body.extend_from_slice(root);
    for number in [name.len() as u64, 0, 1, u64::from(active), charge, 7, inode] {
        body.extend_from_slice(&number.to_be_bytes());
    }
    body.extend_from_slice(name);
    body
}

#[test]
fn complete_fixture_body_is_borrowed_exactly() {
    let body = record(128, 19, false, false);
    let original = WriterHistory::parse(&body).unwrap();

    assert_eq!(original.body(), body.as_slice());
    assert_eq!(original.process(), 42);
}

#[test]
fn final_attempted_charge_preserves_smaller_original_prefix() {
    let before = record(0, 19, true, true);
    let after = record(128, 19, false, false);
    let before = WriterHistory::parse(&before).unwrap();
    let after = WriterHistory::parse(&after).unwrap();

    assert!(after.preserves(&before).is_ok());
}

#[test]
fn failed_write_debits_cannot_be_reduced_to_physical_length() {
    let before = record(128, 19, false, false);
    let after = record(1, 19, false, false);
    let before = WriterHistory::parse(&before).unwrap();
    let after = WriterHistory::parse(&after).unwrap();

    assert!(after.preserves(&before).is_err());
}

#[test]
fn original_adopted_inode_cannot_be_replaced() {
    let before = record(128, 19, false, false);
    let after = record(128, 20, false, false);
    let before = WriterHistory::parse(&before).unwrap();
    let after = WriterHistory::parse(&after).unwrap();

    assert!(after.preserves(&before).is_err());
}

#[test]
fn final_live_descriptor_or_copy_buffer_is_refused() {
    let before = record(128, 19, false, false);
    let before = WriterHistory::parse(&before).unwrap();
    for (active, copy_buffer) in [(true, false), (false, true)] {
        let after = record(128, 19, active, copy_buffer);
        let after = WriterHistory::parse(&after).unwrap();

        assert!(after.preserves(&before).is_err());
    }
}

#[test]
fn record_edition_and_full_byte_extent_are_checked() {
    let mut body = record(128, 19, false, false);
    body[0] = b'x';
    assert!(WriterHistory::parse(&body).is_err());

    body[0] = b'D';
    body.push(0);
    assert!(WriterHistory::parse(&body).is_err());
}

#[test]
fn record_charge_and_slot_limits_are_enforced() {
    let body = record(2 * 1024 * 1024 * 1024 + 1, 19, false, false);
    assert!(WriterHistory::parse(&body).is_err());

    let mut body = record(128, 19, false, false);
    body[24..32].copy_from_slice(&4097u64.to_be_bytes());
    assert!(WriterHistory::parse(&body).is_err());
}

#[test]
fn complete_row_sum_must_match_original_header_charge() {
    let mut body = record(128, 19, false, false);
    body[32..40].copy_from_slice(&1u64.to_be_bytes());

    assert!(WriterHistory::parse(&body).is_err());
}

#[test]
fn original_process_identity_cannot_be_rebound_by_parsing() {
    let before = record(128, 19, false, false);
    let mut after = before.clone();
    after[8..16].copy_from_slice(&43u64.to_be_bytes());
    let before = WriterHistory::parse(&before).unwrap();
    let after = WriterHistory::parse(&after).unwrap();

    assert!(after.preserves(&before).is_err());
}
