//! Exercises the prebirth complete-source/history credit and artifact verifier.
#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Pure source-credit fixtures panic on failed setup.
#![allow(clippy::unwrap_used)]

use super::*;
use std::io::Write;

#[test]
fn complete_credit_refuses_combined_exhaustion_before_retaining_source() {
    let overhead = geometry(std::iter::once(1), MAXIMUM_TOTAL_BYTES).unwrap() - 1;
    assert_eq!(
        geometry(std::iter::once(10), overhead + 10).unwrap(),
        overhead + 10
    );
    assert!(geometry(std::iter::once(10), overhead + 9).is_err());
    assert!(geometry(std::iter::empty(), MAXIMUM_TOTAL_BYTES).is_err());
    assert!(geometry(std::iter::once(u64::MAX), MAXIMUM_TOTAL_BYTES).is_err());
    assert!(
        geometry(
            std::iter::repeat_n(1, MAXIMUM_SOURCE_OBJECTS + 1),
            MAXIMUM_TOTAL_BYTES
        )
        .is_err()
    );
    assert!(geometry(std::iter::once(1), MAXIMUM_TOTAL_BYTES + 1).is_err());
}

#[test]
fn original_file_handle_authenticates_full_bytes_without_path_reopen() {
    let path =
        std::env::temp_dir().join(format!("retirement-source-credit-{}", std::process::id()));
    let original = b"original-source-body";
    let reference = canonical::content_ref(original, "application/octet-stream").unwrap();
    let mut writer = File::create(&path).unwrap();
    writer.write_all(original).unwrap();
    writer.sync_all().unwrap();
    let file = File::open(&path).unwrap();
    std::fs::remove_file(&path).unwrap();

    authenticate_file(&file, &reference).unwrap();
    // The source descriptor survives removal. Repeated reads have independent
    // positions and cannot turn an EOF cursor into successful authentication.
    authenticate_file(&file, &reference).unwrap();
    let mut wrong_length = reference.clone();
    wrong_length.length = (original.len() as u64 + 1).into();
    assert!(authenticate_file(&file, &wrong_length).is_err());
    let altered =
        canonical::content_ref(b"altered--source-body", "application/octet-stream").unwrap();
    assert_eq!(altered.length, reference.length);
    assert!(authenticate_file(&file, &altered).is_err());
}
