//! Checks bounded original failure retention without constructing native authority.

// crucible-lint: allow panic-shortcut -- Data-only diagnostic tests panic on a violated first-failure or fixed-storage invariant.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fmt::Write;

use super::*;

#[test]
fn first_refusal_survives_later_errors_and_unwind() {
    let mut original = None;
    CleanupFailureRecord::retain_first(
        &mut original,
        CleanupFailureRecord::refused(&"first actual cleanup refusal"),
    );
    CleanupFailureRecord::retain_first(
        &mut original,
        CleanupFailureRecord::refused(&"later cleanup refusal"),
    );
    CleanupFailureRecord::retain_first(&mut original, CleanupFailureRecord::unwound());

    assert_eq!(
        original.as_ref().unwrap().status(),
        InstalledRootCleanupFailure::Refused {
            reason: "first actual cleanup refusal".into(),
        }
    );
}

#[test]
fn fixed_storage_keeps_utf8_prefix_across_formatter_chunks() {
    let mut reason = BoundedReason::new();
    reason
        .write_str(&"x".repeat(MAXIMUM_REASON_BYTES - 1))
        .unwrap();
    reason.write_str("é").unwrap();
    reason.write_str("a later formatter chunk").unwrap();

    assert_eq!(reason.as_str().len(), MAXIMUM_REASON_BYTES - 1);
    assert!(reason.as_str().bytes().all(|byte| byte == b'x'));
}

#[test]
fn formatting_unwind_becomes_a_retained_marker() {
    struct PanickingDisplay;

    impl std::fmt::Display for PanickingDisplay {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("original cleanup display unwound");
        }
    }

    let failure = CleanupFailureRecord::refused(&PanickingDisplay);
    let mut original = Some(failure);
    CleanupFailureRecord::retain_first(
        &mut original,
        CleanupFailureRecord::refused(&"later retry"),
    );

    assert_eq!(
        original.as_ref().unwrap().status(),
        InstalledRootCleanupFailure::Unwound {},
    );
}
