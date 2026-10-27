//! Checks native requested-storage data against the actual model capture codec.

// crucible-lint: allow panic-shortcut -- real model codec and finite data assertions deliberately panic.
#![expect(
    clippy::unwrap_used,
    reason = "actual model codec data assertions intentionally panic"
)]

use super::*;
use crate::reference_packet::continuation_models::{
    PACKET_MODEL_SNAPSHOT_BYTES, decode_packet_model_snapshot,
};
use crate::reference_packet::{PacketEvent, PacketProgram};
use crate::retained_metadata::MetadataObserver;
use crucible_node_format::{Bytes, Id, Phase, Position, U64, canonical};
use std::os::unix::net::UnixDatagram;

#[test]
fn reserved_producer_encoding_matches_canonical_bytes_and_refuses_changed_extent() {
    let value = serde_json::json!({
        "escaped":"original\\\"\n", "unicode":"\u{e000}\u{10000}",
        "bytes":[0, 127, 255], "nested":{"complete":true}
    });
    let mut metadata = MetadataObserver::new();
    metadata.observe(&value).unwrap();
    let mut admitted =
        actual_serialization_storage_data(&value, metadata.finish(), 1024 * 1024).unwrap();
    let expected = canonical::canonical_json(&value).unwrap();

    let actual = encode_original_precharged_serialization(&value, &admitted).unwrap();

    assert_eq!(actual, expected);
    assert_eq!(actual.capacity(), admitted.maximum_encoded_bytes);
    admitted.maximum_encoded_bytes = expected.len() - 1;
    assert!(encode_original_precharged_serialization(&value, &admitted).is_err());
}

#[test]
fn original_canonical_writer_keeps_partial_bank_without_reserving_again() {
    use std::io::Write;
    let mut bytes = Vec::with_capacity(17);
    let original = bytes.as_ptr();
    {
        let mut writer = OriginalCanonicalBankWriter {
            bytes: &mut bytes,
            maximum: 2,
        };
        writer.write_all(b"ab").unwrap();
        assert!(writer.write_all(b"c").is_err());
    }

    assert_eq!(bytes, b"ab");
    assert_eq!(bytes.as_ptr(), original);
    assert_eq!(bytes.capacity(), 17);
}

fn actual_stopped_model() -> (PacketProgram, UnixDatagram) {
    let (writer, receiver) = UnixDatagram::pair().unwrap();
    let mut payload = Vec::with_capacity(113);
    payload.extend_from_slice(&[0, 127, 255, 17, 9]);
    let at = Position::new(U64::new(1), U64::new(0), Phase::Reaction);
    let mut events = Vec::with_capacity(17);
    events.push(PacketEvent {
        id: Id::new("actual-escaped-payload").unwrap(),
        evaluation: at,
        completion: Position::new(U64::new(1), U64::new(1), Phase::Publication),
        payload: Some(Bytes::new(payload)),
    });
    let mut model = PacketProgram::new(events, writer).unwrap();
    // This opens the model's local data gate; it grants no Source or Core right
    // and runs no callback or socket publication.
    model.open_gate().unwrap();
    (model, receiver)
}

#[test]
fn actual_model_capture_codec_fits_named_native_terms_with_spare_backing() {
    let (model, _receiver) = actual_stopped_model();
    let quote = model
        .quote_original_live_capture_encoding(PACKET_MODEL_SNAPSHOT_BYTES)
        .unwrap();
    let cursor = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
    let snapshot = model
        .capture_state(cursor, PACKET_MODEL_SNAPSHOT_BYTES)
        .unwrap();
    let decoded = decode_packet_model_snapshot(
        snapshot.bytes(),
        snapshot.reference(),
        PACKET_MODEL_SNAPSHOT_BYTES,
    )
    .unwrap();
    let parsed = canonical::parse_json(snapshot.bytes(), PACKET_MODEL_SNAPSHOT_BYTES).unwrap();
    let mut observer = MetadataObserver::new();
    observer.observe(&parsed).unwrap();
    let actual_parsed = observer.finish();

    assert!(snapshot.bytes().len() <= quote.maximum_encoded_bytes);
    assert!(
        actual_parsed.vector_capacity_bytes + actual_parsed.string_capacity_bytes
            <= quote.parsed_value_requested_bytes
    );
    assert!(quote.canonical_output_requested_bytes >= snapshot.bytes().len());
    assert_eq!(decoded.record.capacities.events, 17);
    assert_eq!(model.inventory().reached, cursor);
    assert_eq!(model.inventory().packet_effects, U64::new(0));
}

#[test]
fn actual_native_model_quote_accepts_exact_total_and_refuses_one_short() {
    let (model, _receiver) = actual_stopped_model();
    let inventory = model.inventory();
    let quote = model
        .quote_original_live_capture_encoding(PACKET_MODEL_SNAPSHOT_BYTES)
        .unwrap();
    let exact = quote.requested_bytes;

    assert_eq!(
        model
            .quote_original_live_capture_encoding(exact)
            .unwrap()
            .requested_bytes,
        exact
    );
    assert!(
        model
            .quote_original_live_capture_encoding(exact - 1)
            .is_err()
    );
    assert_eq!(model.inventory(), inventory);
}

#[test]
fn closed_event_layout_dominates_actual_serde_dom_parser_and_utf16_key_phases() {
    let values = [
        serde_json::json!({}),
        serde_json::json!({"unicode\"\n":"\u{10000}\u{e000}", "nested":[{}, [], "", 0, 1.0, null]}),
        serde_json::json!({"canonical":[[vec![255u8; 127], 257]], "records":[["native_policy", 81, 1, 1]]}),
    ];
    for value in values {
        let actual =
            actual_serialization_storage_data(&value, Default::default(), usize::MAX).unwrap();
        let bound = closed_event_serialization_storage_data(
            actual.maximum_encoded_bytes,
            actual.serialized_value_nodes,
            actual.serialized_capacity_records,
            actual.serializer_temporary_requested_bytes,
            usize::MAX,
        )
        .unwrap();

        assert!(actual.dom_and_canonical_scratch_bytes <= bound.dom_and_canonical_scratch_bytes);
        assert!(actual.retained_value_backing_bytes <= bound.retained_value_backing_bytes);
        let combined = sum_serialization_storage_data(&[&actual, &bound], usize::MAX).unwrap();
        assert_eq!(
            combined.retained_value_backing_bytes,
            actual.retained_value_backing_bytes + bound.retained_value_backing_bytes
        );
        assert!(actual.projected_parser_requested_bytes <= bound.projected_parser_requested_bytes);
        assert!(actual.canonical_output_requested_bytes <= bound.canonical_output_requested_bytes);
        assert!(actual.requested_total().unwrap() <= bound.requested_total().unwrap());
        assert!(
            closed_event_serialization_storage_data(
                actual.maximum_encoded_bytes,
                actual.serialized_value_nodes,
                actual.serialized_capacity_records,
                actual.serializer_temporary_requested_bytes,
                bound.requested_total().unwrap() - 1,
            )
            .is_err()
        );
    }
    assert!(closed_event_serialization_storage_data(1, 0, 0, 0, usize::MAX).is_err());
    assert!(closed_event_serialization_storage_data(usize::MAX, 1, 1, 0, usize::MAX).is_err());
}

#[test]
fn precharged_existing_bank_checks_logical_events_before_materialization() {
    let value = serde_json::json!({"objects": ["snapshot", "control"], "bytes": [0, 1, 255]});
    let admitted =
        actual_serialization_storage_data(&value, Default::default(), 16 * 1024 * 1024).unwrap();
    let mut bank = Vec::with_capacity(admitted.maximum_encoded_bytes);
    let before = (bank.as_ptr(), bank.capacity());
    encode_original_precharged_serialization_into(&value, &admitted, &mut bank).unwrap();
    assert_eq!(
        bank,
        crucible_node_format::canonical::canonical_json(&value).unwrap()
    );
    assert_eq!(before, (bank.as_ptr(), bank.capacity()));

    bank.clear();
    let mut one_short =
        actual_serialization_storage_data(&value, Default::default(), 16 * 1024 * 1024).unwrap();
    one_short.serialized_capacity_records -= 1;
    assert!(encode_original_precharged_serialization_into(&value, &one_short, &mut bank,).is_err());
    assert!(bank.is_empty());
    assert_eq!(before, (bank.as_ptr(), bank.capacity()));

    let mut backing_one_short =
        actual_serialization_storage_data(&value, Default::default(), 16 * 1024 * 1024).unwrap();
    backing_one_short.retained_value_backing_bytes -= 1;
    assert!(
        encode_original_precharged_serialization_into(&value, &backing_one_short, &mut bank)
            .is_err()
    );
    assert!(bank.is_empty());
    assert_eq!(before, (bank.as_ptr(), bank.capacity()));
}
