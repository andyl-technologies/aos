//! Checks independent typed Producer DATA without any grant or SDK assignment.

use super::*;
use crate::retained_metadata::{
    RetainedCaptureProtocolData,
    records::{MetadataCapacityRecord, MetadataRecordBank, MetadataRecordKind},
};
use crucible_node_format::{Extensions, Phase, canonical};

fn arguments() -> ExactRunArguments {
    let mut ordering_profile = String::with_capacity(197);
    ordering_profile.push_str("rejected profile DATA");
    ExactRunArguments {
        grant_id: Id::new("capacity/grant-data").unwrap(),
        participant_ids: Vec::with_capacity(7),
        realization_id: Id::new("capacity/realization-data").unwrap(),
        activation_id: Id::new("capacity/activation-data").unwrap(),
        world_generation: U64::new(0),
        owner_generation: U64::new(0),
        input_epoch: Id::new("capacity/epoch-data").unwrap(),
        mode: OperatingMode::Quantized,
        ordering_profile,
        start: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
        limit: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
        boundary_policy: BoundaryPolicy::OrdinaryStop,
        input_authorization: canonical::content_ref(b"authorization DATA", "application/json")
            .unwrap(),
        input_watermark: U64::new(0),
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
fn producer_typed_capacity_roster_keeps_rejected_argument_and_method_body_spares() {
    let arguments = arguments();
    let mut text = String::with_capacity(181);
    text.push_str("independent raw arguments DATA");
    let begin = BeginRequest {
        kind: BeginKind::Capture,
        binding_hash: arguments.input_authorization.hash.clone(),
        owner_generation: U64::new(0),
        activation_id: Nullable(None),
        world_generation: U64::new(0),
        arguments: serde_json::Map::from_iter([("raw".into(), serde_json::Value::String(text))]),
        extensions: Extensions::new(),
    };
    let poll = PollRequest {
        after_observation_sequence: U64::new(9),
        extensions: Extensions::new(),
    };
    let retire = RetireRequest {
        request_ids: Vec::with_capacity(3),
        operation_ids: Vec::with_capacity(5),
        disposition: RetirementDisposition::AbandonedInertTransfer,
        custody_receipt: Nullable(None),
        extensions: Extensions::new(),
    };
    let observe = ObserveRequest {
        binding_hash: arguments.input_authorization.hash.clone(),
        owner_generation: U64::new(0),
        after_observation_sequence: U64::new(9),
        maximum_items: U64::new(0),
        extensions: Extensions::new(),
    };
    for value in [
        PacketRestoredProducerTypedOwnerData::Arguments(&arguments),
        PacketRestoredProducerTypedOwnerData::Begin(&begin),
        PacketRestoredProducerTypedOwnerData::Poll(&poll),
        PacketRestoredProducerTypedOwnerData::Retire(&retire),
        PacketRestoredProducerTypedOwnerData::Observe(&observe),
    ] {
        let expected = value.retained_metadata_data().unwrap();
        let actual = RetainedCaptureProtocolData::RestoredProducerTyped(value)
            .observe_retained_metadata()
            .unwrap();
        assert_eq!(actual, expected);
    }
    let facts = PacketRestoredProducerTypedOwnerData::Arguments(&arguments)
        .retained_metadata_data()
        .unwrap();
    assert!(facts.string_capacity_bytes >= arguments.ordering_profile.capacity());
    assert_eq!(
        facts.vector_capacity_bytes,
        arguments.participant_ids.capacity() * size_of::<Id>()
    );
    let begin_facts = PacketRestoredProducerTypedOwnerData::Begin(&begin)
        .retained_metadata_data()
        .unwrap();
    assert!(begin_facts.string_capacity_bytes >= 181);
    let retire_facts = PacketRestoredProducerTypedOwnerData::Retire(&retire)
        .retained_metadata_data()
        .unwrap();
    assert_eq!(
        retire_facts.vector_capacity_bytes,
        (retire.request_ids.capacity() + retire.operation_ids.capacity()) * size_of::<Id>()
    );
}

#[test]
fn producer_typed_capacity_physical_appends_keep_independent_repeated_rows_and_short_prefix() {
    let arguments = arguments();
    let value = PacketRestoredProducerTypedOwnerData::Arguments(&arguments);
    let expected = value.retained_metadata_data().unwrap();
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

    let mut short = MetadataRecordBank::reserve(2).unwrap();
    short.append(prefix()).unwrap();
    let mut observer = MetadataObserver::appending(&mut short);
    assert!(value.observe_capacity_data(&mut observer).is_err());
    let _partial = observer.finish();
    assert_eq!(short.rows()[0], prefix());
    assert_eq!(
        short.rows()[1].extent,
        arguments.grant_id.allocated_capacity()
    );
    assert_eq!(short.rows().len(), 2);
}

#[test]
fn producer_typed_capacity_fixed_values_change_no_backing_or_argument_eligibility() {
    use crucible_node_format::Validate;
    let mut arguments = arguments();
    let before = RetainedCaptureProtocolData::RestoredProducerTyped(
        PacketRestoredProducerTypedOwnerData::Arguments(&arguments),
    )
    .observe_retained_metadata()
    .unwrap();
    assert!(arguments.validate().is_err());
    arguments.world_generation = U64::new(7);
    arguments.owner_generation = U64::new(11);
    arguments.mode = OperatingMode::Exact;
    arguments.input_watermark = U64::new(13);

    let after = RetainedCaptureProtocolData::RestoredProducerTyped(
        PacketRestoredProducerTypedOwnerData::Arguments(&arguments),
    )
    .observe_retained_metadata()
    .unwrap();

    assert_eq!(after, before);
    assert!(arguments.validate().is_err());
    assert_eq!(arguments.participant_ids.capacity(), 7);
    assert!(PacketRestoredProducerTypedOwnerData::capacity_counter_scratch_data() > 0);
}
