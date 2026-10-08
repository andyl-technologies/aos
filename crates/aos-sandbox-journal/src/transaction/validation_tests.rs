//! Bounded raw validation precedence, original-key borrows, and namespace DATA.

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

#[test]
fn identity_and_empty_count_precede_configured_count_without_extra_gates() {
    let limited = NativeGeometryBounds {
        maximum_records_per_transaction: 1,
        ..bounds()
    };

    assert!(matches!(
        NativeRecordValidation::begin([0; 16], 2, limited),
        Err(NativeRecordValidationError::InvalidTransaction),
    ));
    assert!(matches!(
        NativeRecordValidation::begin([1; 16], 0, limited),
        Err(NativeRecordValidationError::InvalidTransaction),
    ));
    assert!(matches!(
        NativeRecordValidation::begin([1; 16], 2, limited),
        Err(NativeRecordValidationError::LimitExceeded(
            "records per transaction"
        )),
    ));

    // Raw validation does not admit configuration or serialize a frame count.
    let unvalidated = NativeGeometryBounds {
        maximum_journal_bytes: 0,
        maximum_record_bytes: 0,
        maximum_key_bytes: 0,
        maximum_transaction_bytes: 0,
        maximum_transactions: 0,
        maximum_materialized_bytes: 0,
        maximum_materialized_records: 0,
        ..bounds()
    };
    assert!(NativeRecordValidation::begin([1; 16], 1, unvalidated).is_ok());
    #[cfg(target_pointer_width = "64")]
    assert!(NativeRecordValidation::begin([1; 16], u32::MAX as usize + 1, bounds()).is_ok());
}

#[test]
fn key_checks_precede_native_representation_and_payload_checks() {
    let mut empty = NativeRecordValidation::begin([1; 16], 1, bounds()).unwrap();
    let mut limited = NativeRecordValidation::begin(
        [1; 16],
        1,
        NativeGeometryBounds {
            maximum_key_bytes: 1,
            ..bounds()
        },
    )
    .unwrap();
    let oversized = vec![1; u16::MAX as usize + 1];
    let mut representation = NativeRecordValidation::begin([1; 16], 1, bounds()).unwrap();

    assert!(matches!(
        empty.observe_extent(b"", Some(usize::MAX)),
        Err(NativeRecordValidationError::LimitExceeded(
            "record key bytes"
        )),
    ));
    assert!(matches!(
        limited.observe_extent(&oversized, Some(usize::MAX)),
        Err(NativeRecordValidationError::LimitExceeded(
            "record key bytes"
        )),
    ));
    assert!(matches!(
        representation.observe_extent(&oversized, Some(usize::MAX)),
        Err(NativeRecordValidationError::Frame(
            FrameError::LimitExceeded("record key bytes")
        )),
    ));

    #[cfg(target_pointer_width = "64")]
    assert!(matches!(
        representation.observe_extent(b"k", Some(u32::MAX as usize + 1)),
        Err(NativeRecordValidationError::Frame(
            FrameError::LimitExceeded("record value bytes")
        )),
    ));
    #[cfg(target_pointer_width = "32")]
    assert!(matches!(
        representation.observe_extent(b"k", Some(u32::MAX as usize)),
        Err(NativeRecordValidationError::Frame(
            FrameError::JournalTooLarge
        )),
    ));
}

#[test]
fn payload_checks_precede_aggregate_overflow_and_retain_reached_totals() {
    let mut payload = NativeRecordValidation::begin(
        [1; 16],
        1,
        NativeGeometryBounds {
            maximum_record_bytes: 7,
            ..bounds()
        },
    )
    .unwrap();
    payload.transaction_bytes = usize::MAX;
    let mut overflow = NativeRecordValidation::begin([1; 16], 1, bounds()).unwrap();
    overflow.transaction_bytes = usize::MAX;
    let mut aggregate = NativeRecordValidation::begin(
        [1; 16],
        2,
        NativeGeometryBounds {
            maximum_transaction_bytes: 15,
            ..bounds()
        },
    )
    .unwrap();

    assert!(matches!(
        payload.observe_extent(b"k", None),
        Err(NativeRecordValidationError::LimitExceeded(
            "record payload bytes"
        )),
    ));
    assert_eq!(payload.transaction_bytes, usize::MAX);
    assert!(matches!(
        overflow.observe_extent(b"k", None),
        Err(NativeRecordValidationError::LimitExceeded(
            "transaction bytes"
        )),
    ));
    assert_eq!(overflow.transaction_bytes, usize::MAX);

    aggregate.observe_extent(b"a", Some(0)).unwrap();
    aggregate.register_key(0, b"a").unwrap();
    assert_eq!(aggregate.transaction_bytes, 8);
    assert!(matches!(
        aggregate.observe_extent(b"b", None),
        Err(NativeRecordValidationError::LimitExceeded(
            "transaction bytes"
        )),
    ));
    assert_eq!(aggregate.transaction_bytes, 16);
    assert_eq!(aggregate.keys.len(), 1);
}

#[test]
fn duplicate_index_borrows_original_keys_and_compares_namespace_and_bytes() {
    let mut original = b"key".to_vec();
    let equal_bytes = original.clone();

    {
        let mut validation = NativeRecordValidation::begin([1; 16], 4, bounds()).unwrap();
        for namespace in [0, 254, 255] {
            validation.observe_extent(&original, Some(0)).unwrap();
            validation.register_key(namespace, &original).unwrap();
            let (_, stored) = validation
                .keys
                .get(&(namespace, original.as_slice()))
                .unwrap();
            assert_eq!(stored.as_ptr(), original.as_ptr());
        }

        validation.observe_extent(&equal_bytes, None).unwrap();
        assert!(matches!(
            validation.register_key(254, &equal_bytes),
            Err(NativeRecordValidationError::DuplicateRecordKey),
        ));
        let (_, retained) = validation.keys.get(&(254, original.as_slice())).unwrap();
        assert_eq!(retained.as_ptr(), original.as_ptr());
    }

    // The validator owns only its index nodes; the actual key survives its scope.
    original[0] = b'K';
    assert_eq!(original, b"Key");
    assert_eq!(equal_bytes, b"key");
}

#[test]
fn later_record_extent_refusal_precedes_duplicate_registration() {
    let mut validation = NativeRecordValidation::begin(
        [1; 16],
        2,
        NativeGeometryBounds {
            maximum_record_bytes: 8,
            ..bounds()
        },
    )
    .unwrap();
    validation.observe_extent(b"k", None).unwrap();
    validation.register_key(1, b"k").unwrap();

    assert!(matches!(
        validation.observe_extent(b"k", Some(1)),
        Err(NativeRecordValidationError::LimitExceeded(
            "record payload bytes"
        )),
    ));
    assert_eq!(validation.keys.len(), 1);
    assert!(matches!(
        validation.register_key(1, b"k"),
        Err(NativeRecordValidationError::DuplicateRecordKey),
    ));
}
