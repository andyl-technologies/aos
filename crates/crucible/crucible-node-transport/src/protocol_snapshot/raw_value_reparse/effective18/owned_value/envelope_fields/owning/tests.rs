//! Exercises actual field constructors and body-first refusal with real receipts.

use super::*;
use crate::envelope::Envelope;
use crate::protocol_snapshot::raw_value_reparse::historical_serde::decode_envelope;
use crate::transport::FrameReader;
use serde_json::json;
use std::io::Cursor;

fn envelope() -> Value {
    json!({"protocol":"CNP/1","message":"response","session_id":null,"incarnation_id":null,"node_id":null,"execution_owner_id":null,"capture_owner_id":null,"request_id":null,"operation_id":null,"sequence":"1","method":"begin","body":{},"extensions":{}})
}

fn sequence(value: &Value) -> Value {
    Value::Array(
        [
            "protocol",
            "message",
            "session_id",
            "incarnation_id",
            "node_id",
            "execution_owner_id",
            "capture_owner_id",
            "request_id",
            "operation_id",
            "sequence",
            "method",
            "body",
            "extensions",
        ]
        .into_iter()
        .map(|key| value[key].clone())
        .collect(),
    )
}

fn input(value: &Value) -> NativeImport18RawSelectionData {
    let bytes = serde_json::to_vec(value).unwrap();
    let mut wire = Vec::new();
    wire.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    wire.extend_from_slice(&bytes);
    let mut received = FrameReader::new(Cursor::new(wire), bytes.len())
        .unwrap()
        .read_retained()
        .unwrap();
    let mut raw = None;
    NativeImport18ImmutableRawCustodyData::take_into_data(&mut received, &mut raw).unwrap();
    let raw = raw.as_mut().unwrap();
    raw.quote_into_data(usize::MAX).unwrap();
    raw.freeze_data().unwrap();
    let row = raw
        .completed_bank_data()
        .unwrap()
        .root_selection_row_data(usize::MAX)
        .unwrap();
    let mut selected = None;
    NativeImport18RawSelectionData::read_into_data(&row, &mut selected).unwrap();
    selected.unwrap()
}

fn take(value: &Value) -> NativeImport18OwningEnvelopeAttemptData {
    let mut selected = Some(input(value));
    let mut output = None;
    NativeImport18OwningEnvelopeAttemptData::take_into_data(&mut selected, &mut output).unwrap();
    assert!(selected.is_none());
    output.unwrap()
}

fn quoted(value: &Value) -> NativeImport18OwningEnvelopeAttemptData {
    let mut owner = take(value);
    owner.quote_into_data(usize::MAX).unwrap();
    owner
}

fn fields(value: &Value) -> NativeImport18OwningEnvelopeAttemptData {
    let mut owner = quoted(value);
    owner.run_data().unwrap();
    owner
}

fn shallow(value: NativeImport18FirstFlatViewData<'_>, remaining: usize) -> Value {
    assert!(
        remaining > 0,
        "comparison never reconstructs a deep user Value"
    );
    match value.kind_data().unwrap() {
        NativeImport18FirstFlatKindData::Null => Value::Null,
        NativeImport18FirstFlatKindData::Bool(value) => Value::Bool(value),
        NativeImport18FirstFlatKindData::Number(value) => Value::Number(value.clone()),
        NativeImport18FirstFlatKindData::String(value) => Value::String(value.into()),
        NativeImport18FirstFlatKindData::Array(values) => {
            Value::Array(values.map(|value| shallow(value, remaining - 1)).collect())
        }
        NativeImport18FirstFlatKindData::Object(values) => Value::Object(
            values
                .map(|(key, value)| (key.into(), shallow(value, remaining - 1)))
                .collect(),
        ),
    }
}

fn assert_censused(
    owner: &NativeImport18OwningEnvelopeAttemptData,
    result: &Result<(), ProviderError>,
) {
    let bytes = super::super::super::storage::add(
        owner.retained_requested_storage_data(usize::MAX).unwrap(),
        error_retained_requested_data(result).unwrap(),
    )
    .unwrap();
    assert_eq!(
        owner.census_data(),
        NativeImport18OwningEnvelopeCensusData::Observed {
            requested_bytes: bytes,
            within_row: owner.row.as_ref().map(|row| bytes <= row.retained)
        }
    );
}

#[test]
fn actual_shallow_map_and_sequence_fields_match_locked_envelope_deserialize() {
    let ordinary = envelope();
    let mut markers = envelope();
    markers["body"] = json!({RAW_VALUE_KEY:"null", "nested":{RAW_VALUE_KEY:"[0,true]"}});
    markers["extensions"] = json!({RAW_VALUE_KEY:"null"});
    let mut id = envelope();
    id["session_id"] = json!({RAW_VALUE_KEY:"\"session/one\""});
    let mut wrong = envelope();
    wrong["protocol"] = json!(7);
    let mut unknown = envelope();
    unknown["zz"] = json!(true);
    for value in [
        ordinary.clone(),
        sequence(&ordinary),
        markers.clone(),
        sequence(&markers),
        id,
        wrong,
        unknown,
    ] {
        let mut owner = quoted(&value);
        let raw = owner.retained_frame_data().unwrap();
        let expected: Result<Envelope, _> = decode_envelope(raw.value.clone());
        let result = owner.run_data();
        assert_eq!(result.is_ok(), expected.is_ok());
        assert_censused(&owner, &result);
        if let Ok(expected) = expected {
            assert_eq!(
                owner.data.header.protocol.as_deref(),
                Some(expected.protocol.as_str())
            );
            assert_eq!(owner.data.header.message, Some(expected.message));
            assert_eq!(owner.data.header.sequence, Some(expected.sequence));
            assert_eq!(owner.data.header.method, Some(expected.method));
            for (index, expected_id) in [
                expected.session_id.0.as_ref(),
                expected.incarnation_id.0.as_ref(),
                expected.node_id.0.as_ref(),
                expected.execution_owner_id.0.as_ref(),
                expected.capture_owner_id.0.as_ref(),
                expected.request_id.0.as_ref(),
                expected.operation_id.0.as_ref(),
            ]
            .into_iter()
            .enumerate()
            {
                let actual_id = owner.data.header.nullable[index].as_ref().unwrap().as_ref();
                assert_eq!(actual_id, expected_id);
            }
            for (member, (key, value)) in expected.body.iter().enumerate() {
                let first = owner
                    .cut_first_data(EnvelopeField18Data::Body, member)
                    .unwrap();
                assert_eq!(shallow(first.completed_data().unwrap(), 8), *value);
                let cut = owner
                    .data
                    .cuts
                    .iter()
                    .find(|cut| cut.field == EnvelopeField18Data::Body && cut.member == member)
                    .unwrap();
                assert_eq!(cut.key.as_deref(), Some(key.as_str()));
            }
            for (member, (key, value)) in expected.extensions.iter().enumerate() {
                let first = owner
                    .cut_first_data(EnvelopeField18Data::Extensions, member)
                    .unwrap();
                assert_eq!(shallow(first.completed_data().unwrap(), 8), *value);
                let cut = owner
                    .data
                    .cuts
                    .iter()
                    .find(|cut| {
                        cut.field == EnvelopeField18Data::Extensions && cut.member == member
                    })
                    .unwrap();
                assert_eq!(cut.key.as_deref(), Some(key.as_str()));
            }
        }
    }
}

#[test]
fn structural_raw_key_is_not_an_invented_root_value_pass() {
    let mut value = envelope();
    value["body"] = json!({RAW_VALUE_KEY:"null"});
    value["extensions"] = json!({RAW_VALUE_KEY:"null"});
    let owner = fields(&value);
    for field in [EnvelopeField18Data::Body, EnvelopeField18Data::Extensions] {
        assert!(matches!(
            owner
                .cut_first_data(field, 0)
                .unwrap()
                .completed_data()
                .unwrap()
                .kind_data()
                .unwrap(),
            NativeImport18FirstFlatKindData::String("null")
        ));
    }
}

#[test]
fn actual_deep_body_is_retained_flat_and_canonical_refuses_before_any_later_cut() {
    let deep = format!("{}0{}", "[".repeat(80), "]".repeat(80));
    let mut value = envelope();
    value["body"] = json!({"deep":{RAW_VALUE_KEY:deep}});
    let mut owner = fields(&value);
    let first = owner.cut_first_data(EnvelopeField18Data::Body, 0).unwrap();
    let reparsing = matches!(first.state_data().mode, Some(RawMode::Reparse));
    if reparsing {
        assert!(first.maximum_intermediate_depth_data() >= 80);
    }
    owner.quote_body_canonical_into_data(usize::MAX).unwrap();
    let result = owner.check_body_canonical_data();
    assert_eq!(result.is_err(), reparsing);
    assert_censused(&owner, &result);
    if reparsing {
        assert!(owner.completed_canonical_bytes_data().is_err());
    }
    assert_eq!(
        owner
            .data
            .cuts
            .iter()
            .filter(|cut| cut.field == EnvelopeField18Data::Body)
            .count(),
        1
    );
    let snapshot = owner.census_data();
    assert!(owner.check_body_canonical_data().is_err());
    assert_eq!(owner.census_data(), snapshot);
}

#[test]
fn arbitrary_deep_extensions_do_not_trigger_an_invented_whole_envelope_canonical_ban() {
    let deep = format!("{}0{}", "[".repeat(80), "]".repeat(80));
    let mut value = envelope();
    value["extensions"] = json!({"deep":{RAW_VALUE_KEY:deep}});
    let mut owner = fields(&value);
    let first = owner
        .cut_first_data(EnvelopeField18Data::Extensions, 0)
        .unwrap();
    if matches!(first.state_data().mode, Some(RawMode::Reparse)) {
        assert!(first.maximum_intermediate_depth_data() >= 80);
    }
    owner.quote_body_canonical_into_data(usize::MAX).unwrap();
    owner.check_body_canonical_data().unwrap();
    assert_eq!(owner.completed_canonical_bytes_data().unwrap(), 2);
    assert_censused(&owner, &Ok(()));
}

#[test]
fn actual_map_and_sequence_error_prefixes_keep_the_locked_field_order() {
    let mut value = envelope();
    value["body"] = json!({"first":{RAW_VALUE_KEY:"invalid json"}});
    value["session_id"] = json!("bad id");
    let mut map = quoted(&value);
    let result = map.run_data();
    assert!(result.is_err());
    assert_censused(&map, &result);
    assert!(matches!(
        map.data.cuts.first().unwrap().field,
        EnvelopeField18Data::Body
    ));
    let mut seq = quoted(&sequence(&value));
    let result = seq.run_data();
    assert!(result.is_err());
    assert_censused(&seq, &result);
    assert_eq!(seq.data.cuts.len(), 1);
    assert!(matches!(
        seq.data.cuts[0].field,
        EnvelopeField18Data::SessionId
    ));
    assert!(seq.quote_body_canonical_into_data(usize::MAX).is_err());
}

#[test]
fn real_no_cut_failure_and_valid_fields_stop_each_one_short_row_before_reserve() {
    for value in [Value::Null, envelope()] {
        let mut exact = quoted(&value);
        let result = exact.run_data();
        assert_eq!(result.is_ok(), value.is_object());
        assert_censused(&exact, &result);
        for axis in 0..3 {
            let mut short = quoted(&value);
            let row = short.row.as_mut().unwrap();
            match axis {
                0 => row.retained -= 1,
                1 => row.transient -= 1,
                _ => row.scratch -= 1,
            }
            let result = short.run_data();
            assert!(result.is_err());
            assert_eq!(short.data.cuts.capacity(), 0);
            assert!(short.data.header.protocol.is_none());
            assert_censused(&short, &result);
        }
    }
}

#[test]
fn actual_structural_quote_exact_total_runs_and_one_short_keeps_the_input() {
    let value = envelope();
    let measured = quoted(&value);
    let (r, t, s) = measured.requested_storage_data().unwrap();
    let total = r.checked_add(t).unwrap().checked_add(s).unwrap();
    let mut exact = take(&value);
    exact.quote_into_data(total).unwrap();
    exact.run_data().unwrap();
    assert_censused(&exact, &Ok(()));
    let mut short = take(&value);
    let result = short.quote_into_data(total - 1);
    assert!(result.is_err());
    assert!(short.row.is_none());
    assert!(short.data.cuts.is_empty());
    assert_censused(&short, &result);
}

#[test]
fn actual_canonical_row_and_each_one_short_axis_preserve_completed_first_fields() {
    let mut value = envelope();
    value["body"] = json!({"x":[0,true]});
    let mut exact = fields(&value);
    exact.quote_body_canonical_into_data(usize::MAX).unwrap();
    exact.check_body_canonical_data().unwrap();
    let expected = crucible_node_format::canonical::canonical_json(&value["body"])
        .unwrap()
        .len();
    assert_eq!(exact.completed_canonical_bytes_data().unwrap(), expected);
    for axis in 0..3 {
        let mut short = fields(&value);
        short.quote_body_canonical_into_data(usize::MAX).unwrap();
        let row = short.canonical.as_mut().unwrap();
        match axis {
            0 => row.retained -= 1,
            1 => row.transient -= 1,
            _ => row.scratch -= 1,
        }
        let result = short.check_body_canonical_data();
        assert!(result.is_err());
        assert!(short.canonical_bytes.is_none());
        assert!(!short.data.cuts.is_empty());
        assert_censused(&short, &result);
    }
}

#[test]
fn actual_foreign_members_nonroot_take_and_reused_slots_cannot_rebind_input() {
    let a = input(&envelope());
    let b = input(&envelope());
    let foreign = &b.retained_frame_data().unwrap().value["body"];
    assert!(a.member_row_data(foreign, usize::MAX).is_err());
    let own = &a.retained_frame_data().unwrap().value["body"];
    let row = a.member_row_data(own, usize::MAX).unwrap();
    let mut child = None;
    NativeImport18RawSelectionData::read_into_data(&row, &mut child).unwrap();
    let mut failed = None;
    assert!(
        NativeImport18OwningEnvelopeAttemptData::take_into_data(&mut child, &mut failed).is_err()
    );
    assert!(child.is_none());
    let mut next = Some(b);
    assert!(
        NativeImport18OwningEnvelopeAttemptData::take_into_data(&mut next, &mut failed).is_err()
    );
    assert!(next.is_some());
    assert!(failed.as_ref().unwrap().retained_frame_data().is_ok());
}
