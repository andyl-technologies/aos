//! Checks independent Capture decoder banks without promoting their eligibility.

use super::*;
use crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17ReadLimits;
use crate::retained_metadata::{
    RetainedCaptureProtocolData,
    records::{MetadataCapacityRecord, MetadataRecordBank, MetadataRecordKind},
};

fn partial() -> RestoredSettledNative17DecodeAttempt {
    let mut attempt = RestoredSettledNative17DecodeAttempt::new();
    let mut reference = canonical::content_ref(b"retained DATA", "application/json").unwrap();
    reference.hash.digest.reserve(223);
    attempt.references[0] = Some(reference.clone());
    attempt.references[4] = Some(reference);
    attempt.references[0]
        .as_mut()
        .unwrap()
        .hash
        .digest
        .reserve(223);
    for (index, raw) in attempt.raw.iter_mut().enumerate() {
        raw.reserve(227 + index);
        raw.extend_from_slice(b"invalid retained DATA");
    }
    attempt.before_encoded.reserve(233);
    attempt.before_encoded.extend_from_slice(b"before DATA");
    attempt.immutable.reserve(7);
    for spare in [239, 241] {
        let mut bytes = Vec::with_capacity(spare);
        bytes.extend_from_slice(b"independent immutable DATA");
        attempt
            .immutable
            .push((attempt.references[0].as_ref().unwrap().clone(), bytes));
    }
    attempt.aliases.reserve(11);
    let limits = NativeCurrentGraph17ReadLimits {
        maximum_requested: size_of::<
            Option<
                crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17DecodeAttempt,
            >,
        >() + 4096,
        maximum_target_requested: size_of::<
            Option<
                crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17DecodeAttempt,
            >,
        >() + 4096,
        maximum_nodes: 64,
        maximum_depth: 64,
    };
    assert!(
        attempt
            .before_native_graph
            .read_into_data(b"{}", limits)
            .is_err()
    );
    assert!(
        attempt
            .native_graph
            .read_into_data(b"[false]", limits)
            .is_err()
    );
    attempt.stage = DecodeStage::Failed;
    attempt
}

#[test]
fn capture_native_capacity_decoder_keeps_both_real_caches_and_independent_banks() {
    let attempt = partial();
    let pointer = attempt.before_encoded.as_ptr();
    let before = attempt
        .before_native_graph
        .retained_requested_storage_data(usize::MAX)
        .unwrap();
    let current = attempt
        .native_graph
        .retained_requested_storage_data(usize::MAX)
        .unwrap();
    assert!(
        before
            > size_of::<
                crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17DecodeAttempt,
            >()
    );
    assert!(
        current
            > size_of::<
                crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17DecodeAttempt,
            >()
    );
    let expected = attempt.retained_requested_storage_data(usize::MAX).unwrap();

    let facts = RetainedCaptureProtocolData::RestoredNative17Decode(&attempt)
        .observe_retained_metadata()
        .unwrap();

    assert_eq!(
        requested_metadata_backing_storage_data(&facts).unwrap(),
        expected
    );
    assert!(facts.vector_capacity_bytes >= before + current + attempt.before_encoded.capacity());
    assert_eq!(attempt.before_encoded.as_ptr(), pointer);
    assert!(attempt.stage == DecodeStage::Failed);
    assert!(!attempt.is_validated_data());
    assert!(
        attempt
            .before_native_graph
            .as_ref()
            .unwrap()
            .validate_data()
            .is_err()
    );
    assert!(
        attempt
            .native_graph
            .as_ref()
            .unwrap()
            .validate_data()
            .is_err()
    );
}

#[test]
fn capture_native_capacity_decoder_repeated_rows_preserve_actual_backing() {
    let attempt = partial();
    let retained = RetainedCaptureProtocolData::RestoredNative17Decode(&attempt);
    let facts = retained.observe_retained_metadata().unwrap();
    let prefix = MetadataCapacityRecord {
        kind: MetadataRecordKind::String,
        extent: 251,
        element_bytes: 1,
        alignment: 1,
    };
    let mut records = MetadataRecordBank::reserve(1 + 2 * facts.capacity_records).unwrap();
    records.append(prefix).unwrap();
    let backing = records.allocated_bytes();

    for _ in 0..2 {
        let mut observer = MetadataObserver::appending(&mut records);
        attempt.observe_capacity_data(&mut observer).unwrap();
        assert_eq!(observer.finish(), facts);
    }

    assert_eq!(records.rows()[0], prefix);
    assert_eq!(
        &records.rows()[1..1 + facts.capacity_records],
        &records.rows()[1 + facts.capacity_records..]
    );
    assert_eq!(records.allocated_bytes(), backing);
    assert!(!attempt.is_validated_data());
    assert!(RestoredSettledNative17DecodeAttempt::capacity_counter_scratch_data() > 0);
}

#[test]
fn capture_native_capacity_short_decoder_bank_keeps_full_reference_prefix() {
    let attempt = partial();
    let reference = attempt.references[0].as_ref().unwrap();
    let prefix = MetadataCapacityRecord {
        kind: MetadataRecordKind::String,
        extent: 257,
        element_bytes: 1,
        alignment: 1,
    };
    let mut records = MetadataRecordBank::reserve(2).unwrap();
    records.append(prefix).unwrap();
    let backing = records.allocated_bytes();
    let pointer = reference.hash.algorithm.as_ptr();
    let mut observer = MetadataObserver::appending(&mut records);

    assert!(attempt.observe_capacity_data(&mut observer).is_err());
    let _partial = observer.finish();

    assert_eq!(records.rows().len(), 2);
    assert_eq!(records.rows()[0], prefix);
    assert_eq!(records.rows()[1].kind, MetadataRecordKind::String);
    assert_eq!(
        records.rows()[1].extent,
        reference.hash.algorithm.capacity()
    );
    assert_eq!(records.allocated_bytes(), backing);
    assert_eq!(reference.hash.algorithm.as_ptr(), pointer);
    assert!(!attempt.is_validated_data());
}
