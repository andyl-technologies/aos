//! Checks retained Input terminal DTOs without validating native input custody.

use super::*;
use crate::retained_metadata::{
    RetainedCommonProtocolData,
    records::{MetadataCapacityRecord, MetadataRecordKind},
};

fn result() -> InputResult {
    let mut accepted_event_ids = Vec::with_capacity(7);
    for spare in [191, 193] {
        let mut id = String::with_capacity(spare);
        id.push_str("retained/duplicate-input");
        accepted_event_ids.push(Id::new(id).unwrap());
    }
    let mut custody_receipt = canonical::content_ref(b"custody DATA", "application/json").unwrap();
    custody_receipt.hash.digest.reserve(197);
    let mut inventory_hash = canonical::content_ref(b"inventory DATA", "application/json")
        .unwrap()
        .hash;
    inventory_hash.domain.reserve(199);
    InputResult {
        accepted_event_ids,
        input_watermark: U64::new(0),
        custody_receipt,
        inventory_hash,
    }
}

fn prefix() -> MetadataCapacityRecord {
    MetadataCapacityRecord {
        kind: MetadataRecordKind::String,
        extent: 211,
        element_bytes: 1,
        alignment: 1,
    }
}

#[test]
fn input_result_capacity_rejected_terminal_keeps_full_independent_fields() {
    let mut result = result();
    assert!(result.validate().is_err());
    let expected_strings = result
        .accepted_event_ids
        .iter()
        .map(Id::allocated_capacity)
        .sum::<usize>()
        + result.custody_receipt.hash.algorithm.capacity()
        + result.custody_receipt.hash.domain.capacity()
        + result.custody_receipt.hash.digest.capacity()
        + result.custody_receipt.media_type.capacity()
        + result.inventory_hash.algorithm.capacity()
        + result.inventory_hash.domain.capacity()
        + result.inventory_hash.digest.capacity();

    let facts = RetainedCaptureProtocolData::RestoredInputResult(&result)
        .observe_retained_metadata()
        .unwrap();

    assert_eq!(
        facts.vector_capacity_bytes,
        result.accepted_event_ids.capacity() * size_of::<Id>()
    );
    assert_eq!(facts.string_capacity_bytes, expected_strings);
    assert_eq!(
        facts,
        RetainedCommonProtocolData::InputResult(&result)
            .observe_retained_metadata()
            .unwrap()
    );
    result.input_watermark = U64::new(u64::MAX);
    assert_eq!(
        facts,
        RetainedCaptureProtocolData::RestoredInputResult(&result)
            .observe_retained_metadata()
            .unwrap()
    );
    assert!(result.validate().is_err());
}

#[test]
fn input_result_capacity_physical_repeated_views_preserve_prior_rows() {
    let result = result();
    let retained = RetainedCaptureProtocolData::RestoredInputResult(&result);
    let expected = retained.observe_retained_metadata().unwrap();
    let mut records = MetadataRecordBank::reserve(1 + 2 * expected.capacity_records).unwrap();
    records.append(prefix()).unwrap();
    let backing = records.allocated_bytes();

    for _ in 0..2 {
        let mut observer = MetadataObserver::appending(&mut records);
        retained.observe_into(&mut observer).unwrap();
        assert_eq!(observer.finish(), expected);
    }

    assert_eq!(records.rows()[0], prefix());
    assert_eq!(
        &records.rows()[1..1 + expected.capacity_records],
        &records.rows()[1 + expected.capacity_records..]
    );
    assert_eq!(records.allocated_bytes(), backing);
    assert!(RetainedCaptureProtocolData::capacity_counter_scratch_data() > 0);
}

#[test]
fn input_result_capacity_short_bank_keeps_actual_id_vector_before_refusal() {
    let result = result();
    let retained = RetainedCaptureProtocolData::RestoredInputResult(&result);
    let pointer = result.accepted_event_ids.as_ptr();
    let mut records = MetadataRecordBank::reserve(2).unwrap();
    records.append(prefix()).unwrap();
    let mut observer = MetadataObserver::appending(&mut records);

    assert!(retained.observe_into(&mut observer).is_err());

    let _partial = observer.finish();
    assert_eq!(records.rows().len(), 2);
    assert_eq!(records.rows()[0], prefix());
    assert_eq!(records.rows()[1].kind, MetadataRecordKind::Vector);
    assert_eq!(
        records.rows()[1].extent,
        result.accepted_event_ids.capacity()
    );
    assert_eq!(records.rows()[1].element_bytes, size_of::<Id>());
    assert_eq!(result.accepted_event_ids.as_ptr(), pointer);
    assert!(result.validate().is_err());
}
