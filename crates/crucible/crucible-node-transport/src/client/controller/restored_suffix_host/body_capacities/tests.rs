//! Checks complete suffix-body DATA without creating a Controller or assignment.

use super::*;
use crate::envelope::Nullable;
use crate::retained_metadata::{
    RetainedCaptureProtocolData,
    records::{MetadataCapacityRecord, MetadataRecordBank, MetadataRecordKind},
};
use crucible_node_format::canonical;

fn extensions(capacity: usize) -> Extensions {
    let mut text = String::with_capacity(capacity);
    text.push_str("rejected extension DATA");
    Extensions::from_iter([("capacity/data".into(), serde_json::Value::String(text))])
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
fn producer_body_capacity_all_eight_families_keep_backing_while_suffix_eligibility_refuses() {
    let reference = canonical::content_ref(b"body DATA", "application/json").unwrap();
    let begin = BeginRequest {
        kind: BeginKind::Capture,
        binding_hash: reference.hash.clone(),
        owner_generation: U64::new(0),
        activation_id: Nullable(None),
        world_generation: U64::new(0),
        arguments: serde_json::Map::new(),
        extensions: extensions(151),
    };
    let input = InputRequest {
        binding_hash: reference.hash.clone(),
        owner_generation: U64::new(0),
        batch_id: Id::new("capacity/batch-data").unwrap(),
        batch_sequence: U64::new(0),
        input_epoch: Id::new("capacity/epoch-data").unwrap(),
        events: Vec::with_capacity(3),
        batch_hash: reference.hash.clone(),
        extensions: extensions(157),
    };
    let poll = PollRequest {
        after_observation_sequence: U64::new(9),
        extensions: extensions(163),
    };
    let retire = RetireRequest {
        request_ids: Vec::with_capacity(5),
        operation_ids: Vec::with_capacity(7),
        disposition: RetirementDisposition::AbandonedInertTransfer,
        custody_receipt: Nullable(None),
        extensions: extensions(167),
    };
    let observe = ObserveRequest {
        binding_hash: reference.hash.clone(),
        owner_generation: U64::new(0),
        after_observation_sequence: U64::new(9),
        maximum_items: U64::new(0),
        extensions: extensions(173),
    };
    let blob_begin = BlobBeginRequest {
        transfer_id: Id::new("capacity/blob-begin").unwrap(),
        content: reference,
        extensions: extensions(179),
    };
    let blob_chunk = BlobChunkRequest {
        transfer_id: Id::new("capacity/blob-chunk").unwrap(),
        offset: U64::new(0),
        bytes: Bytes::new(Vec::with_capacity(257)),
        extensions: extensions(181),
    };
    let blob_finish = BlobFinishRequest {
        transfer_id: Id::new("capacity/blob-finish").unwrap(),
        extensions: extensions(191),
    };
    for body in [
        OriginalRestoredSuffixBody::Begin(&begin),
        OriginalRestoredSuffixBody::Input(&input),
        OriginalRestoredSuffixBody::Poll(&poll),
        OriginalRestoredSuffixBody::Retire(&retire),
        OriginalRestoredSuffixBody::Observe(&observe),
        OriginalRestoredSuffixBody::BlobBegin(&blob_begin),
        OriginalRestoredSuffixBody::BlobChunk(&blob_chunk),
        OriginalRestoredSuffixBody::BlobFinish(&blob_finish),
    ] {
        assert!(body.method_data().is_err());
        let facts = RetainedCaptureProtocolData::RestoredSuffixBody(body)
            .observe_retained_metadata()
            .unwrap();
        assert!(facts.string_capacity_bytes >= 151);
        assert!(facts.capacity_records > 0);
    }
    let input_facts =
        RetainedCaptureProtocolData::RestoredSuffixBody(OriginalRestoredSuffixBody::Input(&input))
            .observe_retained_metadata()
            .unwrap();
    assert_eq!(
        input_facts.vector_capacity_bytes,
        input.events.capacity() * size_of::<crucible_node_format::Event>()
    );
    let retire_facts = RetainedCaptureProtocolData::RestoredSuffixBody(
        OriginalRestoredSuffixBody::Retire(&retire),
    )
    .observe_retained_metadata()
    .unwrap();
    assert_eq!(
        retire_facts.vector_capacity_bytes,
        (retire.request_ids.capacity() + retire.operation_ids.capacity()) * size_of::<Id>()
    );
    let chunk_facts = RetainedCaptureProtocolData::RestoredSuffixBody(
        OriginalRestoredSuffixBody::BlobChunk(&blob_chunk),
    )
    .observe_retained_metadata()
    .unwrap();
    assert_eq!(
        chunk_facts.vector_capacity_bytes,
        blob_chunk.bytes.allocation_capacity()
    );
    assert!(blob_chunk.bytes.as_slice().is_empty());
}

#[test]
fn producer_body_capacity_physical_upload_rows_keep_spares_repetition_and_prefix() {
    let chunk = BlobChunkRequest {
        transfer_id: Id::new("capacity/upload-data").unwrap(),
        offset: U64::new(0),
        bytes: Bytes::new(Vec::with_capacity(263)),
        extensions: extensions(197),
    };
    let body = OriginalRestoredSuffixBody::BlobChunk(&chunk);
    let expected = RetainedCaptureProtocolData::RestoredSuffixBody(
        OriginalRestoredSuffixBody::BlobChunk(&chunk),
    )
    .observe_retained_metadata()
    .unwrap();
    let mut records = MetadataRecordBank::reserve(1 + 2 * expected.capacity_records).unwrap();
    records.append(prefix()).unwrap();
    let backing = records.allocated_bytes();

    for _ in 0..2 {
        let mut observer = MetadataObserver::appending(&mut records);
        body.observe_capacity_data(&mut observer).unwrap();
        assert_eq!(observer.finish(), expected);
    }

    assert_eq!(records.rows()[0], prefix());
    assert_eq!(
        &records.rows()[1..1 + expected.capacity_records],
        &records.rows()[1 + expected.capacity_records..]
    );
    assert_eq!(records.allocated_bytes(), backing);
    assert_eq!(
        expected.vector_capacity_bytes,
        chunk.bytes.allocation_capacity()
    );
    assert!(OriginalRestoredSuffixBody::capacity_counter_scratch_data() > 0);
}

#[test]
fn producer_body_capacity_short_upload_bank_keeps_initialized_transfer_id() {
    let chunk = BlobChunkRequest {
        transfer_id: Id::new("capacity/upload-data").unwrap(),
        offset: U64::new(0),
        bytes: Bytes::new(Vec::with_capacity(263)),
        extensions: extensions(197),
    };
    let body = OriginalRestoredSuffixBody::BlobChunk(&chunk);
    let mut records = MetadataRecordBank::reserve(2).unwrap();
    records.append(prefix()).unwrap();
    let mut observer = MetadataObserver::appending(&mut records);

    assert!(body.observe_capacity_data(&mut observer).is_err());

    let _partial = observer.finish();
    assert_eq!(records.rows()[0], prefix());
    assert_eq!(
        records.rows()[1].extent,
        chunk.transfer_id.allocated_capacity()
    );
    assert_eq!(records.rows().len(), 2);
    assert!(body.method_data().is_err());
    assert_eq!(chunk.bytes.allocation_capacity(), 263);
}
