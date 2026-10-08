//! Raw suffix accounting, borrow custody, and original failure-frontier tests.

#![allow(clippy::unwrap_used)]

use super::*;

fn bounds() -> NativeGeometryBounds {
    NativeGeometryBounds {
        maximum_journal_bytes: u64::MAX,
        maximum_record_bytes: usize::MAX,
        maximum_key_bytes: usize::MAX,
        maximum_records_per_transaction: usize::MAX,
        maximum_transaction_bytes: usize::MAX,
        maximum_transactions: usize::MAX,
        maximum_materialized_bytes: usize::MAX,
        maximum_materialized_records: usize::MAX,
    }
}

fn record(key: &[u8], value_bytes: Option<usize>) -> NativeRecordExtentRef<'_> {
    NativeRecordExtentRef {
        namespace_byte: 40,
        key,
        value_bytes,
    }
}

#[test]
fn exact_borrows_and_signed_prefixes_follow_put_delete_and_empty_put() {
    let key = b"ab".to_vec();
    let before = b"123".to_vec();
    let after = b"12345".to_vec();
    let empty = Vec::<u8>::new();
    let mut measurement = NativeSuffixMeasurement::new();

    measurement
        .observe_append(
            [1; 16],
            [NativeBeforeAfterRef {
                key: &key,
                before: Some(&before),
                after: Some(&after),
            }],
            &[record(&key, Some(after.len()))],
            false,
            bounds(),
        )
        .unwrap();
    let (stored_key, stored_value) = measurement.states.get_key_value(key.as_slice()).unwrap();
    assert_eq!(stored_key.as_ptr(), key.as_ptr());
    assert_eq!(stored_value.unwrap().as_ptr(), after.as_ptr());

    measurement
        .observe_append(
            [2; 16],
            [NativeBeforeAfterRef {
                key: &key,
                before: Some(&after),
                after: None,
            }],
            &[record(&key, None)],
            false,
            bounds(),
        )
        .unwrap();
    measurement
        .observe_append(
            [3; 16],
            [NativeBeforeAfterRef {
                key: &key,
                before: None,
                after: Some(&empty),
            }],
            &[record(&key, Some(0))],
            true,
            bounds(),
        )
        .unwrap();

    let measured = measurement.finish();
    assert_eq!(
        measured.geometry,
        NativeSuffixGeometry {
            transactions: 3,
            records: 3,
            // Each append is BEGIN(76) + RECORD(72+payload) + COMMIT(108).
            append_bytes: (256 + 14) + (256 + 9) + (256 + 9),
            maximum_transaction_records: 1,
            maximum_transaction_record_bytes: 14,
            maximum_retained_growth_bytes: 2,
            maximum_retained_growth_records: 0,
        },
    );
    assert_eq!(
        measured.prefixes,
        vec![
            NativeSuffixPrefix {
                owner_bytes: 2,
                owner_records: 0,
                final_append: false
            },
            NativeSuffixPrefix {
                owner_bytes: -5,
                owner_records: -1,
                final_append: false
            },
            NativeSuffixPrefix {
                owner_bytes: -3,
                owner_records: 0,
                final_append: true
            },
        ],
    );
    assert_eq!(measured.maximum_key_bytes, 2);
    assert_eq!(measured.maximum_record_payload_bytes, 14);
}

#[test]
fn inconsistent_before_precedes_identity_and_bounds_without_publishing_a_prefix() {
    let mut measurement = NativeSuffixMeasurement::new();
    let change = NativeBeforeAfterRef {
        key: b"k",
        before: None,
        after: Some(b"v"),
    };
    measurement
        .observe_append([1; 16], [change], &[record(b"k", Some(1))], false, bounds())
        .unwrap();
    let geometry = measurement.geometry;

    let error = measurement.observe_append(
        [0; 16],
        [change],
        &[record(b"", Some(usize::MAX))],
        true,
        bounds(),
    );

    assert!(matches!(
        error,
        Err(NativeSuffixError::InconsistentBeforeImage)
    ));
    assert_eq!(measurement.geometry, geometry);
    assert_eq!(measurement.prefixes.len(), 1);
    assert_eq!(
        measurement.states.get(b"k".as_slice()),
        Some(&Some(b"v".as_slice()))
    );
}

#[test]
fn transaction_refusal_retains_exact_prior_row_work_but_no_geometry() {
    let mut measurement = NativeSuffixMeasurement::new();

    let error = measurement.observe_append(
        [0; 16],
        [NativeBeforeAfterRef {
            key: b"k",
            before: Some(b"old"),
            after: Some(b"newer"),
        }],
        &[record(b"", Some(usize::MAX))],
        false,
        bounds(),
    );

    assert!(matches!(error, Err(NativeSuffixError::InvalidTransaction)));
    assert_eq!(measurement.original_bytes, 4);
    assert_eq!(measurement.current_bytes, 6);
    assert_eq!(measurement.original_records, 1);
    assert_eq!(measurement.current_records, 1);
    assert_eq!(
        measurement.states.get(b"k".as_slice()),
        Some(&Some(b"newer".as_slice()))
    );
    assert_eq!(measurement.geometry, NativeSuffixGeometry::default());
    assert!(measurement.prefixes.is_empty());
}

#[test]
fn configured_bounds_and_raw_namespace_duplicates_keep_their_order() {
    let cases = [
        (
            NativeGeometryBounds {
                maximum_records_per_transaction: 1,
                ..bounds()
            },
            "records per transaction",
        ),
        (
            NativeGeometryBounds {
                maximum_key_bytes: 0,
                ..bounds()
            },
            "record key bytes",
        ),
        (
            NativeGeometryBounds {
                maximum_record_bytes: 8,
                ..bounds()
            },
            "record payload bytes",
        ),
        (
            NativeGeometryBounds {
                maximum_transaction_bytes: 17,
                ..bounds()
            },
            "transaction bytes",
        ),
    ];

    for (limits, expected) in cases {
        let error = NativeSuffixMeasurement::new().observe_append(
            [1; 16],
            [],
            &[record(b"k", Some(1)), record(b"k", Some(1))],
            true,
            limits,
        );
        assert!(matches!(error, Err(NativeSuffixError::LimitExceeded(bound)) if bound == expected));
    }

    let repeated = [record(b"k", Some(1)), record(b"k", None)];
    assert!(matches!(
        NativeSuffixMeasurement::new().observe_append([1; 16], [], &repeated, true, bounds()),
        Err(NativeSuffixError::DuplicateRecordKey),
    ));

    let distinct = [
        repeated[0],
        NativeRecordExtentRef {
            namespace_byte: 46,
            ..repeated[1]
        },
    ];
    let mut measurement = NativeSuffixMeasurement::new();
    measurement
        .observe_append([1; 16], [], &distinct, true, bounds())
        .unwrap();
    assert_eq!(measurement.finish().geometry.records, 2);
}

#[test]
fn representation_key_width_precedes_payload_and_duplicate_checks() {
    let key = vec![1; u16::MAX as usize + 1];
    let repeated = [record(&key, Some(usize::MAX)), record(&key, None)];

    let error =
        NativeSuffixMeasurement::new().observe_append([1; 16], [], &repeated, true, bounds());

    assert!(matches!(
        error,
        Err(NativeSuffixError::Frame(FrameError::LimitExceeded(
            "record key bytes"
        )))
    ));
}

#[cfg(target_pointer_width = "64")]
#[test]
fn value_and_frame_widths_are_checked_without_allocating_value_bytes() {
    let too_wide = [record(b"k", Some(u32::MAX as usize + 1))];
    let error =
        NativeSuffixMeasurement::new().observe_append([1; 16], [], &too_wide, true, bounds());
    assert!(matches!(
        error,
        Err(NativeSuffixError::Frame(FrameError::LimitExceeded(
            "record value bytes"
        )))
    ));

    let too_wide_frame = [record(b"k", Some(u32::MAX as usize))];
    let mut measurement = NativeSuffixMeasurement::new();
    let error = measurement.observe_append([1; 16], [], &too_wide_frame, true, bounds());
    assert!(matches!(
        error,
        Err(NativeSuffixError::Frame(FrameError::LimitExceeded(
            "frame payload bytes"
        )))
    ));
    assert_eq!(measurement.maximum_key_bytes, 1);
    assert_eq!(
        measurement.maximum_record_payload_bytes,
        8 + u32::MAX as usize
    );
    assert_eq!(measurement.geometry, NativeSuffixGeometry::default());
    assert!(measurement.prefixes.is_empty());
}

#[test]
fn count_and_append_overflow_preserve_partial_coordinate_publication() {
    let mut count_overflow = NativeSuffixMeasurement::new();
    count_overflow.geometry.transactions = u32::MAX;
    let error = count_overflow.observe_append([1; 16], [], &[record(b"k", None)], true, bounds());
    assert!(matches!(
        error,
        Err(NativeSuffixError::LimitExceeded("native suffix records"))
    ));
    assert_eq!(count_overflow.geometry.records, 0);
    assert!(count_overflow.prefixes.is_empty());

    let mut records_overflow = NativeSuffixMeasurement::new();
    records_overflow.geometry.records = u32::MAX;
    let error = records_overflow.observe_append([1; 16], [], &[record(b"k", None)], true, bounds());
    assert!(matches!(
        error,
        Err(NativeSuffixError::LimitExceeded("native suffix records"))
    ));
    assert_eq!(records_overflow.geometry.transactions, 1);
    assert_eq!(records_overflow.geometry.append_bytes, 0);
    assert!(records_overflow.prefixes.is_empty());

    let mut bytes_overflow = NativeSuffixMeasurement::new();
    bytes_overflow.geometry.append_bytes = u64::MAX;
    let error = bytes_overflow.observe_append([1; 16], [], &[record(b"k", None)], true, bounds());
    assert!(matches!(error, Err(NativeSuffixError::JournalTooLarge)));
    assert_eq!(bytes_overflow.geometry.transactions, 1);
    assert_eq!(bytes_overflow.geometry.records, 1);
    assert_eq!(bytes_overflow.geometry.maximum_transaction_records, 0);
    assert!(bytes_overflow.prefixes.is_empty());
}

#[test]
fn width_only_floor_extents_match_actual_canonical_encoding() {
    let old_key = b"capacity-old";
    let new_key = b"capacity-new";
    let value = vec![0; 257];
    let records = [record(old_key, None), record(new_key, Some(value.len()))];
    let encoded = [
        crate::record::encode_record_fields(40, old_key, None).unwrap(),
        crate::record::encode_record_fields(40, new_key, Some(&value)).unwrap(),
    ];
    let mut measurement = NativeSuffixMeasurement::new();

    measurement
        .observe_append([1; 16], [], &records, false, bounds())
        .unwrap();

    let measured = measurement.finish();
    let payload_bytes = encoded
        .iter()
        .map(|payload| payload.len() as u64)
        .sum::<u64>();
    assert_eq!(
        measured.geometry.maximum_transaction_record_bytes,
        payload_bytes
    );
    assert_eq!(
        measured.geometry.append_bytes,
        76 + 2 * 72 + payload_bytes + 108
    );
    assert_eq!(measured.maximum_record_payload_bytes, encoded[1].len());
    assert_eq!(measured.geometry.maximum_retained_growth_bytes, 0);
    assert_eq!(measured.prefixes[0].owner_bytes, 0);
}
