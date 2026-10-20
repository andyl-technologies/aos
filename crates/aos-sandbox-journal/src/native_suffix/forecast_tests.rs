//! Byte-expanded and compact images share exact equality and failure frontiers.

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

fn expand(prefix: &[u8], bytes: usize) -> Vec<u8> {
    let mut expanded = vec![0; bytes];
    expanded[..prefix.len()].copy_from_slice(prefix);
    expanded
}

#[test]
fn compact_equality_is_exhaustively_identical_to_small_expanded_bytes() {
    let mut values = Vec::new();
    for bytes in 0..=5 {
        for prefix_bytes in 0..=bytes.min(3) {
            for pattern in 0..(1 << prefix_bytes) {
                let prefix = (0..prefix_bytes)
                    .map(|bit| ((pattern >> bit) & 1) as u8)
                    .collect::<Vec<_>>();
                values.push((prefix.clone(), bytes, expand(&prefix, bytes)));
            }
        }
    }

    for (left_prefix, left_width, left) in &values {
        let left_compact = NativeSuffixValueRef::zero_padded(left_prefix, *left_width).unwrap();
        for (right_prefix, right_width, right) in &values {
            let right_compact =
                NativeSuffixValueRef::zero_padded(right_prefix, *right_width).unwrap();
            let equal = left == right;
            assert_eq!(left_compact == right_compact, equal);
            assert_eq!(
                left_compact == NativeSuffixValueRef::from_bytes(right),
                equal
            );
            assert_eq!(
                NativeSuffixValueRef::from_bytes(left) == right_compact,
                equal
            );
        }
    }
    assert!(NativeSuffixValueRef::zero_padded(&[1, 2], 1).is_err());
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    error: Option<String>,
    geometry: NativeSuffixGeometry,
    prefixes: Vec<NativeSuffixPrefix>,
    original: (u64, u32),
    current: (u64, u32),
    widest: (usize, usize),
}

fn snapshot(
    measurement: NativeSuffixMeasurement<'_>,
    error: Option<NativeSuffixError>,
) -> Snapshot {
    Snapshot {
        error: error.map(|cause| format!("{cause:?}")),
        geometry: measurement.geometry,
        prefixes: measurement.prefixes,
        original: (measurement.original_bytes, measurement.original_records),
        current: (measurement.current_bytes, measurement.current_records),
        widest: (
            measurement.maximum_key_bytes,
            measurement.maximum_record_payload_bytes,
        ),
    }
}

fn measure_pair(
    first: &[u8],
    before: &[u8],
    next: &[u8],
    width: usize,
    compact: bool,
    mut bounds: NativeGeometryBounds,
    fault: usize,
) -> Snapshot {
    let expanded_first = expand(first, width);
    let expanded_before = expand(before, width);
    let expanded_next = expand(next, width);
    let mut measurement = NativeSuffixMeasurement::new();
    let record = NativeRecordExtentRef {
        namespace_byte: 40,
        key: b"key",
        value_bytes: Some(width),
    };
    let first_result = if compact {
        measurement.observe_value_append(
            [1; 16],
            [NativeBeforeAfterValueRef {
                key: b"key",
                before: None,
                after: Some(NativeSuffixValueRef::zero_padded(first, width).unwrap()),
            }],
            &[record],
            false,
            bounds,
        )
    } else {
        measurement.observe_append(
            [1; 16],
            [NativeBeforeAfterRef {
                key: b"key",
                before: None,
                after: Some(&expanded_first),
            }],
            &[record],
            false,
            bounds,
        )
    };
    if let Err(cause) = first_result {
        return snapshot(measurement, Some(cause));
    }

    let transaction = if fault == 1 { [0; 16] } else { [2; 16] };
    match fault {
        3 => bounds.maximum_key_bytes = 2,
        4 => bounds.maximum_record_bytes = 6 + 3 + width,
        5 => bounds.maximum_records_per_transaction = 0,
        6 => bounds.maximum_transaction_bytes = 6 + 3 + width,
        7 => measurement.geometry.transactions = u32::MAX,
        8 => measurement.geometry.records = u32::MAX,
        9 => measurement.geometry.append_bytes = u64::MAX,
        _ => {}
    }
    let records = if fault == 2 {
        vec![record, record]
    } else {
        vec![record]
    };
    let result = if compact {
        measurement.observe_value_append(
            transaction,
            [NativeBeforeAfterValueRef {
                key: b"key",
                before: Some(NativeSuffixValueRef::zero_padded(before, width).unwrap()),
                after: Some(NativeSuffixValueRef::zero_padded(next, width).unwrap()),
            }],
            &records,
            true,
            bounds,
        )
    } else {
        measurement.observe_append(
            transaction,
            [NativeBeforeAfterRef {
                key: b"key",
                before: Some(&expanded_before),
                after: Some(&expanded_next),
            }],
            &records,
            true,
            bounds,
        )
    };
    snapshot(measurement, result.err())
}

#[test]
fn expanded_and_compact_folds_preserve_geometry_and_partial_failure_publication() {
    for width in 1..=5 {
        for first in [0, 1] {
            for predecessor in [0, 1] {
                for next in [0, 1] {
                    for fault in 0..=9 {
                        let old = measure_pair(
                            &[first],
                            &[predecessor],
                            &[next],
                            width,
                            false,
                            bounds(),
                            fault,
                        );
                        let compact = measure_pair(
                            &[first],
                            &[predecessor],
                            &[next],
                            width,
                            true,
                            bounds(),
                            fault,
                        );
                        assert_eq!(
                            old, compact,
                            "width={width}, first={first}, predecessor={predecessor}, next={next}, fault={fault}"
                        );
                    }
                }
            }
        }
    }
}
