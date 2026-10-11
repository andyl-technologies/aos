//! Checks narrowing against actual remaining native-record credit.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Pure credit controls deliberately assert exact limits and refusal.
#![allow(clippy::unwrap_used)]

use super::*;

fn limits(total: usize) -> NativeCaptureLimits {
    NativeCaptureLimits {
        maximum_objects: 20_000,
        maximum_record_bytes: 16 * 1024 * 1024,
        maximum_total_record_bytes: total,
        maximum_artifact_bytes: 2 * 1024 * 1024 * 1024,
        maximum_total_artifact_bytes: 8 * 1024 * 1024 * 1024,
    }
}

#[test]
fn portable_slack_does_not_expand_selected_native_residual() {
    let native = 64 * 1024 * 1024;
    let narrowed = narrow_native_records(limits(native + 17 * 1024 * 1024), Some(native)).unwrap();
    assert_eq!(narrowed.maximum_total_record_bytes, native);
    assert_eq!(narrowed.maximum_record_bytes, 16 * 1024 * 1024);
    assert_eq!(narrowed.maximum_objects, 20_000);
    assert_eq!(
        narrowed.maximum_total_artifact_bytes,
        8 * 1024 * 1024 * 1024
    );
}

#[test]
fn widening_zero_and_one_byte_below_source_requirement_refuse() {
    let native = 64 * 1024 * 1024;
    assert!(narrow_native_records(limits(native), Some(native + 1)).is_err());
    assert!(narrow_native_records(limits(native), Some(0)).is_err());
    assert!(narrow_native_records(limits(native - 1), Some(native)).is_err());
    let unchanged = narrow_native_records(limits(native), None).unwrap();
    assert_eq!(unchanged.maximum_total_record_bytes, native);
    assert_eq!(unchanged.maximum_record_bytes, 16 * 1024 * 1024);
}
