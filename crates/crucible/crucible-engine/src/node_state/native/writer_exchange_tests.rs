//! Inert byte-model controls; no native message or source authority is constructed.

// crucible-lint: allow panic-shortcut -- These parser tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{OriginalFinalExchange, validate_control_history};

fn number(body: &mut Vec<u8>, value: u64) {
    body.extend_from_slice(&value.to_be_bytes());
}

fn final_exchange() -> (Vec<u8>, Vec<u8>) {
    let history = b"original attempted debit body".to_vec();
    let mut body = b"DCPFIN01".to_vec();
    for value in [
        41,
        1,
        1,
        history.len() as u64,
        16 + history.len() as u64,
        16,
        0,
        16,
        1,
    ] {
        number(&mut body, value);
    }
    body.extend_from_slice(&[0x42; 32]);
    body.extend_from_slice(&history);
    (body, history)
}

#[test]
fn complete_exchange_borrows_exact_original_body() {
    let (body, history) = final_exchange();
    let original = OriginalFinalExchange::parse(&body, &history, 41).expect("inert complete frame");
    assert_eq!(original.body().as_ptr(), body.as_ptr());
}

#[test]
fn exchange_rejects_changed_scalar_or_original_body() {
    let (body, history) = final_exchange();
    for (field, value) in [
        (0usize, 42u64),
        (1, 0),
        (2, 0),
        (3, 0),
        (4, 0),
        (5, 0),
        (6, 5),
        (7, 4097),
        (8, 2),
    ] {
        let mut changed = body.clone();
        changed[8 + field * 8..16 + field * 8].copy_from_slice(&value.to_be_bytes());
        assert!(OriginalFinalExchange::parse(&changed, &history, 41).is_err());
    }
    let mut changed_history = history.clone();
    changed_history[0] ^= 1;
    assert!(OriginalFinalExchange::parse(&body, &changed_history, 41).is_err());
    for end in 0..body.len() {
        assert!(OriginalFinalExchange::parse(&body[..end], &history, 41).is_err());
    }
}

#[test]
fn control_retains_failed_partial_row_without_success_projection() {
    let mut body = b"DCPCTL01".to_vec();
    for value in [41, 1, 1, 0, 5, 2, 5, 0, 0] {
        number(&mut body, value);
    }
    body.extend_from_slice(b"known");
    assert!(validate_control_history(&body, 41).is_ok());
    body[32..40].copy_from_slice(&1u64.to_be_bytes());
    assert!(validate_control_history(&body, 41).is_err());
}

#[test]
fn control_rejects_foreign_process_count_ordinal_and_trailing_bytes() {
    let mut body = b"DCPCTL01".to_vec();
    number(&mut body, 41);
    number(&mut body, 0);
    assert!(validate_control_history(&body, 41).is_ok());
    assert!(validate_control_history(&body, 42).is_err());
    body.push(0);
    assert!(validate_control_history(&body, 41).is_err());
}
