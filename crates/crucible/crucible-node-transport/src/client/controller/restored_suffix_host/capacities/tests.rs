//! Checks independent suffix and observation DATA without issuing a live attempt.
//!
//! These deliberately incomplete private slots have no Controller association,
//! assigned cut, native receipt or publication authority.

use super::*;
use crate::retained_metadata::{
    RetainedCaptureProtocolData,
    records::{MetadataCapacityRecord, MetadataRecordBank, MetadataRecordKind},
};

fn attempt() -> OriginalRestoredSuffixHostAttempt {
    let mut roots = Vec::with_capacity(5);
    roots.push(canonical::content_ref(b"retained root DATA", "application/json").unwrap());
    let mut text = String::with_capacity(173);
    text.push_str("raw response remains independent");
    let mut raw = serde_json::Map::new();
    raw.insert("raw".into(), serde_json::Value::String(text));
    OriginalRestoredSuffixHostAttempt {
        request_id: Id::new("capacity/suffix").unwrap(),
        operation_id: Some(Id::new("capacity/operation").unwrap()),
        method: Method::Observe,
        controller: std::ptr::null(),
        process: std::process::id(),
        thread: std::thread::current().id(),
        cut: None,
        completed_frontier: None,
        original: Some(crate::envelope::tests::request()),
        response: Some(crate::envelope::tests::request()),
        decoded: Some(Box::new(ResponseBody {
            shape: ResponseShape::Error {
                operation_state: OperationState::Unknown,
                error: ErrorRecord {
                    code: "OUTCOME_UNKNOWN".into(),
                    message: String::with_capacity(181),
                    effect: EffectCertainty::Unknown,
                    retryable: false,
                    details: raw,
                },
                extensions: Extensions::new(),
            },
            result: Some(MethodResult::Observe(ObserveResult {
                observations: Vec::with_capacity(7),
                next_sequence: U64::new(0),
                complete: false,
                inventory_hash: canonical::content_ref(b"typed DATA", "application/json")
                    .unwrap()
                    .hash,
            })),
        })),
        roots,
        stage: Stage::Publishing,
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
fn suffix_capacity_data_keeps_uncompleted_raw_typed_and_root_spares() {
    let mut attempt = attempt();
    let expected = attempt.retained_metadata_data().unwrap();
    let before = RetainedCaptureProtocolData::RestoredSuffixAttempt(&attempt)
        .observe_retained_metadata()
        .unwrap();
    assert_eq!(before, expected);
    assert_eq!(before.boxed_value_bytes, size_of::<ResponseBody>());
    assert!(
        before.vector_capacity_bytes
            >= attempt.roots.capacity() * size_of::<ContentRef>()
                + 7 * size_of::<crucible_node_format::ObservationBatch>()
    );
    assert!(before.string_capacity_bytes >= 173 + 181);
    assert!(attempt.completed_pair_data().is_err());

    attempt.stage = Stage::Preparing;
    assert_eq!(
        RetainedCaptureProtocolData::RestoredSuffixAttempt(&attempt)
            .observe_retained_metadata()
            .unwrap(),
        before
    );
    assert!(attempt.controller.is_null());
    assert!(attempt.cut.is_none());
    assert!(attempt.completed_pair_data().is_err());
    assert!(OriginalRestoredSuffixHostAttempt::capacity_counter_scratch_data() > 0);
}

#[test]
fn suffix_capacity_data_keeps_repeated_physical_rows_and_short_prefixes() {
    let attempt = attempt();
    let expected = attempt.retained_metadata_data().unwrap();
    let mut records = MetadataRecordBank::reserve(1 + 2 * expected.capacity_records).unwrap();
    records.append(prefix()).unwrap();
    let backing = records.allocated_bytes();
    for _ in 0..2 {
        let mut observer = MetadataObserver::appending(&mut records);
        attempt.observe_capacity_data(&mut observer).unwrap();
        assert_eq!(observer.finish(), expected);
    }
    assert_eq!(records.rows()[0], prefix());
    assert_eq!(
        &records.rows()[1..1 + expected.capacity_records],
        &records.rows()[1 + expected.capacity_records..]
    );
    assert_eq!(records.allocated_bytes(), backing);

    let mut short = MetadataRecordBank::reserve(2).unwrap();
    short.append(prefix()).unwrap();
    let mut observer = MetadataObserver::appending(&mut short);
    assert!(attempt.observe_capacity_data(&mut observer).is_err());
    let _partial = observer.finish();
    assert_eq!(short.rows()[0], prefix());
    assert_eq!(short.rows().len(), 2);
    assert_eq!(short.rows()[1].kind, MetadataRecordKind::String);
    assert_eq!(
        short.rows()[1].extent,
        attempt.request_id.allocated_capacity()
    );
    assert!(attempt.completed_pair_data().is_err());
}

#[test]
fn suffix_capacity_data_foreign_creator_precedes_any_row() {
    for process in [true, false] {
        let mut attempt = attempt();
        if process {
            attempt.process = attempt.process.wrapping_add(1);
        } else {
            attempt.thread = std::thread::spawn(|| std::thread::current().id())
                .join()
                .unwrap();
        }
        let mut records = MetadataRecordBank::reserve(4).unwrap();
        records.append(prefix()).unwrap();
        let mut observer = MetadataObserver::appending(&mut records);

        assert!(attempt.observe_capacity_data(&mut observer).is_err());

        assert_eq!(observer.finish().capacity_records, 0);
        assert_eq!(records.rows(), &[prefix()]);
        assert!(
            RetainedCaptureProtocolData::RestoredSuffixAttempt(&attempt)
                .check_original_creator()
                .is_err()
        );
    }
}

#[test]
fn suffix_capacity_data_closed_observation_body_preserves_independent_extension_backing() {
    use crate::reference_packet::service::complete_restore::restoration_observe::RetainedRestorationObservationData;
    let mut binding_hash = canonical::content_ref(b"binding DATA", "application/json")
        .unwrap()
        .hash;
    binding_hash.digest.reserve(193);
    let mut extension = String::with_capacity(197);
    extension.push_str("failed optional observation data");
    let mut extensions = Extensions::new();
    extensions.insert("capacity/data".into(), serde_json::Value::String(extension));
    let body = ObserveRequest {
        binding_hash,
        owner_generation: U64::new(0),
        after_observation_sequence: U64::new(7),
        maximum_items: U64::new(0),
        extensions,
    };
    let before = RetainedRestorationObservationData::Body(&body)
        .original_retained_metadata_facts()
        .unwrap();
    let actual = RetainedCaptureProtocolData::RestorationObservation(
        RetainedRestorationObservationData::Body(&body),
    )
    .observe_retained_metadata()
    .unwrap();

    assert_eq!(actual, before);
    assert!(actual.string_capacity_bytes >= 197 + body.binding_hash.digest.capacity());
    assert_eq!(body.maximum_items, U64::new(0));
    assert_eq!(body.after_observation_sequence, U64::new(7));
}
