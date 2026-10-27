//! Checks independent portable DTO backing without any live signed authority.

use super::*;
use crate::retained_metadata::{
    RetainedCaptureProtocolData,
    records::{MetadataCapacityRecord, MetadataRecordBank, MetadataRecordKind},
};

fn prefix() -> MetadataCapacityRecord {
    MetadataCapacityRecord {
        kind: MetadataRecordKind::String,
        extent: 211,
        element_bytes: 1,
        alignment: 1,
    }
}

#[test]
fn observation17_capacity_dto_roster_preserves_independent_context_artifact_and_post_checkpoint() {
    let (mut request, _) = super::super::tests::fixture().unwrap();
    request.schema.reserve(173);
    let context = PacketRestoredInputReactive17Context {
        schema: String::with_capacity(179),
        request: request.clone(),
        assigned_request: Bytes::new(Vec::with_capacity(181)),
    };
    let proof = PacketRestorationActivationProof {
        schema: String::with_capacity(191),
        algorithm: String::with_capacity(193),
        context_digest: Bytes::new(Vec::with_capacity(197)),
        mac: Bytes::new(Vec::with_capacity(199)),
    };
    let artifact = PacketRestoredInputReactive17Artifact {
        request: request.clone(),
        proof,
    };
    let checkpoint = PacketRestoredInputReactive17PostCheckpointData {
        schema: String::with_capacity(211),
        current_record: request.current_record.clone(),
        current_model: request.current_model.clone(),
    };
    for value in [
        PacketRestoredInputReactive17RetainedData::Request(&request),
        PacketRestoredInputReactive17RetainedData::Context(&context),
        PacketRestoredInputReactive17RetainedData::Artifact(&artifact),
        PacketRestoredInputReactive17RetainedData::PostCheckpoint(&checkpoint),
    ] {
        let expected = value.original_retained_metadata_data().unwrap();
        let actual = RetainedCaptureProtocolData::RestoredInputReactive17(value)
            .observe_retained_metadata()
            .unwrap();
        assert_eq!(actual, expected);
        assert!(actual.capacity_records > 0);
    }
    let context_facts = PacketRestoredInputReactive17RetainedData::Context(&context)
        .original_retained_metadata_data()
        .unwrap();
    assert!(context_facts.vector_capacity_bytes >= 181);
    assert!(context_facts.string_capacity_bytes >= 179);
    let artifact_facts = PacketRestoredInputReactive17RetainedData::Artifact(&artifact)
        .original_retained_metadata_data()
        .unwrap();
    assert!(artifact_facts.vector_capacity_bytes >= 197 + 199);
    assert!(artifact_facts.string_capacity_bytes >= 191 + 193);
    assert!(context.schema.is_empty());
    assert!(artifact.proof.mac.as_slice().is_empty());
    assert!(checkpoint.validate_data().is_err());
}

#[test]
fn observation17_capacity_dto_physical_appends_keep_repeated_views_and_prior_prefix() {
    let (request, _) = super::super::tests::fixture().unwrap();
    let value = PacketRestoredInputReactive17RetainedData::Request(&request);
    let expected = value.original_retained_metadata_data().unwrap();
    let mut records = MetadataRecordBank::reserve(1 + 2 * expected.capacity_records).unwrap();
    records.append(prefix()).unwrap();
    let backing = records.allocated_bytes();

    for _ in 0..2 {
        let mut observer = MetadataObserver::appending(&mut records);
        value.observe_capacity_data(&mut observer).unwrap();
        assert_eq!(observer.finish(), expected);
    }

    assert_eq!(records.rows()[0], prefix());
    assert_eq!(
        &records.rows()[1..1 + expected.capacity_records],
        &records.rows()[1 + expected.capacity_records..]
    );
    assert_eq!(records.allocated_bytes(), backing);
    assert!(PacketRestoredInputReactive17RetainedData::capacity_counter_scratch_data() > 0);
}

#[test]
fn observation17_capacity_dto_short_bank_keeps_actual_schema_prefix() {
    let (request, _) = super::super::tests::fixture().unwrap();
    let value = PacketRestoredInputReactive17RetainedData::Request(&request);
    let mut records = MetadataRecordBank::reserve(2).unwrap();
    records.append(prefix()).unwrap();
    let mut observer = MetadataObserver::appending(&mut records);

    assert!(value.observe_capacity_data(&mut observer).is_err());

    let _partial = observer.finish();
    assert_eq!(records.rows()[0], prefix());
    assert_eq!(records.rows().len(), 2);
    assert_eq!(records.rows()[1].kind, MetadataRecordKind::String);
    assert_eq!(records.rows()[1].extent, request.schema.capacity());
}
