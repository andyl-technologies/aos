//! Checks physical history, independent backing restrictions and legacy refusal.

use super::*;

fn bank(maximum_rows: usize) -> PacketRuntimeMetadataRecordBank {
    // Tests exercise physical storage only; this local owner grants no Source action.
    PacketRuntimeMetadataRecordBank {
        bank: MetadataRecordBank {
            rows: Vec::new(),
            maximum_rows,
            reservation: ReservationState::Unallocated,
        },
    }
}

fn row(
    kind: MetadataRecordKind,
    extent: usize,
    element_bytes: usize,
    alignment: usize,
) -> MetadataCapacityRecord {
    MetadataCapacityRecord {
        kind,
        extent,
        element_bytes,
        alignment,
    }
}

fn encoded(capacity: usize, maximum: usize, state: &str, rows: &str) -> Vec<u8> {
    format!(
        "{{\"capacity_rows\":{capacity},\"format\":\"{PACKET_RUNTIME_METADATA_RECORD_FORMAT}\",\"maximum_rows\":{maximum},\"reservation\":\"{state}\",\"rows\":{rows}}}"
    ).into_bytes()
}

#[test]
fn packet_bank_records_above_legacy_limit_without_widening_legacy_grammar() {
    let maximum = MAXIMUM_ROWS + 1;
    let mut bank = bank(maximum);
    bank.reserve_retained_data().unwrap();
    let record = row(MetadataRecordKind::Vector, 0, 8, 8);
    for _ in 0..maximum {
        bank.recording_bank_data().unwrap().append(record).unwrap();
    }
    let backing = bank.allocated_bytes();
    assert!(bank.recording_bank_data().unwrap().append(record).is_err());
    assert_eq!(bank.rows().len(), maximum);
    assert_eq!(bank.allocated_bytes(), backing);

    let bytes = serde_json::to_vec(&bank).unwrap();
    let history =
        ValidatedPacketRuntimeMetadataRecords::validate(&bytes, maximum, backing, 0).unwrap();
    assert_eq!(history.row_count(), maximum);
    assert_eq!(history.maximum_rows(), maximum);
    assert_eq!(history.capacity_rows(), maximum);
    assert!(history.rows().all(|item| item.unwrap() == record));
    assert!(
        ValidatedPacketRuntimeMetadataRecords::validate(&bytes, maximum, backing - 1, 0).is_err()
    );
    assert!(MetadataRecordBank::reserve(maximum).is_err());
    assert!(MetadataRecordBank::unallocated(maximum).is_err());
    assert!(ValidatedMetadataRecords::validate(&bytes, MAXIMUM_ROWS, 0).is_err());
    let legacy_rows = serde_json::to_vec(&bank.bank).unwrap();
    assert!(ValidatedMetadataRecords::validate(&legacy_rows, maximum, 0).is_err());
    assert!(ValidatedMetadataRecords::validate(&legacy_rows, MAXIMUM_ROWS, 0).is_err());
    assert!(
        ValidatedPacketRuntimeMetadataRecords::validate(&legacy_rows, maximum, backing, 0).is_err()
    );
    assert_eq!(
        size_of::<PacketRuntimeMetadataRecordBank>(),
        size_of::<MetadataRecordBank>()
    );
}

#[test]
fn four_field_rows_keep_traversal_order_and_independent_backing_credit() {
    let rows = [
        row(MetadataRecordKind::String, 7, 1, 1),
        row(MetadataRecordKind::Vector, 3, 8, 8),
        row(MetadataRecordKind::Tree, 2, 64, 16),
        row(MetadataRecordKind::Shared, 80, 1, 8),
        row(MetadataRecordKind::Boxed, 32, 1, 16),
    ];
    let mut bank = bank(rows.len());
    bank.reserve_retained_data().unwrap();
    for row in rows {
        bank.recording_bank_data().unwrap().append(row).unwrap();
    }
    let bytes = serde_json::to_vec(&bank).unwrap();
    let backing = bank.allocated_bytes();
    let history =
        ValidatedPacketRuntimeMetadataRecords::validate(&bytes, rows.len(), backing, 31).unwrap();
    assert_eq!(
        history.reservation_state_data(),
        PacketRuntimeMetadataReservationData::Ready
    );
    assert_eq!(history.observed_backing_capacity_bytes_data(), 31);
    assert_eq!(history.rows().collect::<Result<Vec<_>, _>>().unwrap(), rows);
    assert!(
        ValidatedPacketRuntimeMetadataRecords::validate(&bytes, rows.len(), backing, 30).is_err()
    );
    assert!(
        ValidatedPacketRuntimeMetadataRecords::validate(&bytes, rows.len() + 1, backing, 31)
            .is_err()
    );
}

#[test]
fn unallocated_and_sticky_failed_attempts_remain_serializable() {
    let mut bank = bank(3);
    assert!(bank.recording_bank_data().is_err());
    let installed = serde_json::to_vec(&bank).unwrap();
    let history = ValidatedPacketRuntimeMetadataRecords::validate(&installed, 3, 0, 0).unwrap();
    assert_eq!(
        history.reservation_state_data(),
        PacketRuntimeMetadataReservationData::Unallocated
    );
    assert_eq!(history.row_count(), 0);
    assert_eq!(history.capacity_rows(), 0);

    assert!(
        bank.reserve_with_backing_data(record_bytes(3).unwrap() - 1)
            .is_err()
    );
    assert_eq!(
        bank.reservation_state_data(),
        PacketRuntimeMetadataReservationData::Failed
    );
    assert_eq!(bank.allocated_bytes(), 0);
    assert!(bank.reserve_retained_data().is_err());
    bank.bank.clear();
    assert!(bank.reserve_retained_data().is_err());
    assert!(bank.recording_bank_data().is_err());
    let failed = serde_json::to_vec(&bank).unwrap();
    let history = ValidatedPacketRuntimeMetadataRecords::validate(&failed, 3, 0, 0).unwrap();
    assert_eq!(
        history.reservation_state_data(),
        PacketRuntimeMetadataReservationData::Failed
    );
    assert_eq!(history.row_count(), 0);
}

#[test]
fn failed_overshoot_retains_actual_capacity_and_requires_its_own_credit() {
    let mut bank = bank(2);
    bank.bank.rows.try_reserve_exact(3).unwrap();
    bank.bank.reservation = ReservationState::Failed;
    let capacity = bank.capacity_rows();
    let backing = bank.allocated_bytes();
    assert!(capacity > bank.maximum_rows());
    assert!(bank.reserve_retained_data().is_err());
    assert!(bank.recording_bank_data().is_err());
    assert_eq!(bank.capacity_rows(), capacity);
    let bytes = serde_json::to_vec(&bank).unwrap();
    let history = ValidatedPacketRuntimeMetadataRecords::validate(&bytes, 2, backing, 0).unwrap();
    assert_eq!(history.capacity_rows(), capacity);
    assert_eq!(
        history.reservation_state_data(),
        PacketRuntimeMetadataReservationData::Failed
    );
    assert!(ValidatedPacketRuntimeMetadataRecords::validate(&bytes, 2, backing - 1, 0).is_err());
}

#[test]
fn impossible_allocation_history_and_excess_rows_are_refused() {
    let cases = [
        (1, "unallocated", "[]"),
        (0, "unallocated", "[[\"string\",0,1,1]]"),
        (1, "failed", "[]"),
        (2, "failed", "[]"),
        (3, "failed", "[[\"string\",0,1,1]]"),
        (0, "ready", "[]"),
        (1, "ready", "[]"),
        (3, "ready", "[]"),
        (
            2,
            "ready",
            "[[\"string\",0,1,1],[\"string\",0,1,1],[\"string\",0,1,1]]",
        ),
        (2, "completed", "[]"),
    ];
    for (capacity, state, rows) in cases {
        let bytes = encoded(capacity, 2, state, rows);
        assert!(
            ValidatedPacketRuntimeMetadataRecords::validate(&bytes, 2, usize::MAX, usize::MAX)
                .is_err(),
            "{state}, {capacity}, {rows}"
        );
    }
    assert!(record_bytes(0).is_err());
    assert!(record_bytes(usize::MAX).is_err());
    let overflow = encoded(usize::MAX, 2, "failed", "[]");
    assert!(ValidatedPacketRuntimeMetadataRecords::validate(&overflow, 2, usize::MAX, 0).is_err());
}

#[test]
fn malformed_headers_rows_truncation_and_trailing_input_are_refused() {
    let valid = encoded(2, 2, "ready", "[[\"vector\",3,8,8]]");
    let text = std::str::from_utf8(&valid).unwrap();
    let cases = [
        text.replace("/18", "/17"),
        text.replace("\"capacity_rows\":2", "\"capacity_rows\":02"),
        text.replace(
            "\"maximum_rows\":2",
            "\"maximum_rows\":2,\"maximum_rows\":2",
        ),
        text.replace("\"rows\":", "\"extra\":0,\"rows\":"),
        text.replace("[\"vector\",3,8,8]", "[\"vector\",3,8]"),
        text.replace("[\"vector\",3,8,8]", "[\"vector\",3,8,3]"),
        text.replace("[\"vector\",3,8,8]", "[\"string\",3,1,8]"),
        text.replace(
            "[\"vector\",3,8,8]",
            "[\"vector\",18446744073709551616,8,8]",
        ),
        text.replace(
            "[\"vector\",3,8,8]",
            &format!("[\"vector\",{},8,8]", usize::MAX),
        ),
        format!("{text} "),
        format!("{text}{{}}"),
    ];
    for bytes in cases {
        assert!(
            ValidatedPacketRuntimeMetadataRecords::validate(
                bytes.as_bytes(),
                2,
                usize::MAX,
                usize::MAX
            )
            .is_err(),
            "{bytes}"
        );
    }
    for end in 0..valid.len() {
        assert!(
            ValidatedPacketRuntimeMetadataRecords::validate(
                &valid[..end],
                2,
                usize::MAX,
                usize::MAX
            )
            .is_err(),
            "truncation {end}"
        );
    }
    assert!(ValidatedPacketRuntimeMetadataRecords::validate(&valid, 2, usize::MAX, 24).is_ok());
}

#[test]
fn public_capacity_data_appends_checked_rows_without_growing_or_erasing_prefixes() {
    let mut bank = bank(2);
    bank.reserve_retained_data().unwrap();
    let backing = bank.allocated_bytes();
    let first = row(MetadataRecordKind::String, 7, 1, 1);
    bank.append_capacity_record_data(first).unwrap();

    assert!(
        bank.append_capacity_record_data(row(MetadataRecordKind::String, 7, 1, 8))
            .is_err()
    );
    assert!(
        bank.append_capacity_record_data(row(MetadataRecordKind::Vector, usize::MAX, 2, 8))
            .is_err()
    );
    assert_eq!(bank.rows(), [first]);
    let empty_aligned_tree = row(MetadataRecordKind::Tree, 0, 0, 64);
    bank.append_capacity_record_data(empty_aligned_tree)
        .unwrap();
    assert!(bank.append_capacity_record_data(first).is_err());
    assert_eq!(bank.rows(), [first, empty_aligned_tree]);
    assert_eq!(bank.allocated_bytes(), backing);
    let encoded = serde_json::to_vec(&bank).unwrap();
    let decoded = ValidatedPacketRuntimeMetadataRecords::validate(&encoded, 2, backing, 7).unwrap();
    assert_eq!(
        decoded.rows().collect::<Result<Vec<_>, _>>().unwrap(),
        bank.rows()
    );
}

#[test]
fn appending_component_observer_keeps_earlier_and_refused_component_rows() {
    use crate::retained_metadata::MetadataObserver;

    let mut bank = bank(2);
    bank.reserve_retained_data().unwrap();
    let first = row(MetadataRecordKind::Boxed, 16, 1, 8);
    bank.append_capacity_record_data(first).unwrap();
    let mut value = String::with_capacity(17);
    value.push('x');
    let mut observer = MetadataObserver::appending(bank.recording_bank_data().unwrap());
    observer.observe(&value).unwrap();
    assert!(observer.observe(&String::new()).is_err());
    let _partial_facts = observer.finish();

    assert_eq!(
        bank.rows(),
        [
            first,
            row(MetadataRecordKind::String, value.capacity(), 1, 1)
        ]
    );
    let mut observer = MetadataObserver::appending(bank.recording_bank_data().unwrap());
    assert!(observer.observe(&value).is_err());
    let _partial_facts = observer.finish();
    assert_eq!(bank.rows().len(), 2);
}
