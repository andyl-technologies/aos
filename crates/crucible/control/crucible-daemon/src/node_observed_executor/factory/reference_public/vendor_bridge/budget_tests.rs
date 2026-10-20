//! Exercises the source-selected native operation/journal credit before birth.

use super::*;

#[test]
fn selected_windows_obey_both_native_original_reservations() {
    assert!(authenticate_window_credit(8, U64::new(8), U64::new(256)).is_ok());
    assert!(authenticate_window_credit(8, U64::new(256), U64::new(8)).is_ok());

    assert!(authenticate_window_credit(8, U64::new(7), U64::new(256)).is_err());
    assert!(authenticate_window_credit(8, U64::new(256), U64::new(7)).is_err());
    assert!(authenticate_window_credit(1, U64::new(0), U64::new(256)).is_err());
    assert!(authenticate_window_credit(1, U64::new(256), U64::new(0)).is_err());
}

#[test]
fn original_native_slack_does_not_widen_the_selected_profile() {
    let unlimited = U64::new(u64::MAX);
    assert!(authenticate_window_credit(256, unlimited, unlimited).is_ok());

    assert!(authenticate_window_credit(0, unlimited, unlimited).is_err());
    assert!(authenticate_window_credit(257, unlimited, unlimited).is_err());
    assert!(authenticate_window_credit(usize::MAX, unlimited, unlimited).is_err());
}
