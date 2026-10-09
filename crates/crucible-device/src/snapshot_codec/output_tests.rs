//! Measured canonical-output admission and unchanged ordinary bytes.

use super::*;

#[test]
fn measured_output_hook_preserves_exact_canonical_bytes() {
    let value = vec![17_u64, 42, 8192];
    let mut expected = b"device-test\0".to_vec();
    ciborium::ser::into_writer(&value, &mut expected).unwrap();
    let mut requested = Vec::new();

    let actual = encode_prefixed_with_admission(
        &value,
        b"device-test\0",
        "test output",
        1024,
        1024,
        &mut |count| {
            requested.push(count);
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(actual, expected);
    assert_eq!(requested, [expected.len() as u64]);
}

#[test]
fn output_refusal_stops_after_measurement_before_reservation() {
    let mut requested = Vec::new();

    let result = encode_prefixed_with_admission(
        &vec![7_u64, 91],
        b"device-test\0",
        "test output",
        1024,
        1024,
        &mut |count| {
            requested.push(count);
            Err("saved original output refusal")
        },
    );

    assert!(matches!(result, Err(SnapshotEncodeError::Malformed)));
    assert_eq!(requested.len(), 1);
    assert!(requested[0] > b"device-test\0".len() as u64);
}

#[test]
fn compiled_output_ceiling_precedes_original_output_admission() {
    let mut calls = 0;

    let result = encode_prefixed_with_admission(
        &vec![7_u64, 91],
        b"device-test\0",
        "test output",
        1,
        1,
        &mut |_| {
            calls += 1;
            Ok(())
        },
    );

    assert!(matches!(result, Err(SnapshotEncodeError::Resource(_))));
    assert_eq!(calls, 0);
}
