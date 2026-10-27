//! Exercises physical pairing, lossless bits and untrusted bank refusals.

use super::*;
use crate::client::compact_json::{self, Cursor};
use crate::envelope::{Envelope, MessageKind, Method, Nullable};
use crucible_node_format::{Extensions, Id, U64};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn envelope() -> Envelope {
    Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(Id::new("session-physical18").unwrap())),
        incarnation_id: Nullable(Some(Id::new("incarnation-physical18").unwrap())),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        request_id: Nullable(Some(Id::new("request-physical18").unwrap())),
        operation_id: Nullable(None),
        sequence: U64::new(u64::MAX),
        method: Method::Discover,
        body: serde_json::from_value(json!({"nested": [null, true, false, {"雪": "\n"}]})).unwrap(),
        extensions: Extensions::new(),
    }
}

fn wrap(bytes: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&(TAG, BorrowedCompactBytes::new(bytes))).unwrap()
}

fn decode(input: &[u8]) -> Result<HistoricalCompactEnvelope18, ProviderError> {
    HistoricalCompactEnvelope18::decode(input, input.len(), 1_000_000)
}

fn replace_field(bytes: &[u8], name: &str, replacement: &[u8]) -> Vec<u8> {
    let mut fields = Cursor { rest: &bytes[17..] };
    for _ in 0..13 {
        let key = fields.string().unwrap();
        let start = bytes.len() - fields.rest.len();
        fields.value().unwrap();
        let end = bytes.len() - fields.rest.len();
        if key == name {
            let mut result = bytes[..start].to_vec();
            result.extend_from_slice(replacement);
            result.extend_from_slice(&bytes[end..]);
            let extent = u64::try_from(result.len() - 17).unwrap();
            result[9..17].copy_from_slice(&extent.to_le_bytes());
            return result;
        }
    }
    panic!("missing field {name}")
}

fn raw_value(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    compact_json::encode(value, &mut bytes).unwrap();
    bytes
}

#[test]
fn physical_pair_preserves_exact_numbers_markers_unicode_and_bank_capacity() -> TestResult {
    let mut original = envelope();
    let mut numbers = vec![
        json!(u64::MAX),
        json!(i64::MIN),
        json!(9_007_199_254_740_993_u64),
    ];
    for value in [
        -0.0,
        0.0,
        1.0,
        f64::from_bits(1),
        f64::MIN_POSITIVE,
        f64::MAX,
    ] {
        numbers.push(json!(value));
    }
    original
        .body
        .insert("numbers".into(), Value::Array(numbers));
    original.body.insert(
        "markers".into(),
        json!({"$serde_json::private::RawValue": "DATA", "\u{e000}": 1, "𐀀": 2}),
    );
    let bank = CompactJson::from_envelope(&original, 1_000_000)?;
    let physical = serde_json::to_vec(&bank.physical18_data()?)?;

    let history = decode(&physical)?;

    assert_eq!(history.bank.bytes, bank.bytes);
    assert_eq!(history.retained_bank_bytes(), bank.retained_bytes());
    assert_eq!(history.bank.bytes.len(), history.bank.bytes.capacity());
    assert_eq!(history.materialize_data()?, original);
    assert_eq!(serde_json::to_vec(&history.physical_data())?, physical);
    let encoded_maximum =
        HistoricalCompactEnvelope18::maximum_encoded_bytes_data(bank.retained_bytes(), usize::MAX)?;
    assert_eq!(physical.len(), encoded_maximum);
    assert!(
        HistoricalCompactEnvelope18::maximum_encoded_bytes_data(
            bank.retained_bytes(),
            encoded_maximum - 1
        )
        .is_err()
    );
    assert!(
        HistoricalCompactEnvelope18::maximum_encoded_bytes_data(usize::MAX, usize::MAX).is_err()
    );

    assert_eq!(
        serde_json::to_vec(&history.as_serializable())?,
        serde_json::to_vec(&original)?
    );
    Ok(())
}

#[test]
fn every_truncation_and_changed_outer_framing_is_refused() -> TestResult {
    let bank = CompactJson::from_envelope(&envelope(), 1_000_000)?;
    for end in 0..bank.bytes.len() {
        assert!(
            decode(&wrap(&bank.bytes[..end])).is_err(),
            "raw prefix {end}"
        );
    }
    let physical = wrap(&bank.bytes);
    for end in 0..physical.len() {
        assert!(decode(&physical[..end]).is_err(), "encoded prefix {end}");
    }
    for input in [
        replace_bytes(
            &physical,
            TAG.as_bytes(),
            b"source-private.compact-envelope/17",
        ),
        [physical.as_slice(), b"null"].concat(),
        [physical[..physical.len() - 1].as_ref(), b",null]"].concat(),
        [bank.bytes.as_slice(), &[0]].concat(),
    ] {
        assert!(decode(&input).is_err());
    }
    assert!(
        HistoricalCompactEnvelope18::decode(&physical, physical.len() - 1, bank.bytes.len())
            .is_err()
    );
    assert!(
        HistoricalCompactEnvelope18::decode(&physical, physical.len(), bank.bytes.len() - 1)
            .is_err()
    );
    assert!(
        HistoricalCompactEnvelope18::decode(&physical, physical.len(), bank.bytes.len()).is_ok()
    );
    Ok(())
}

#[test]
fn malformed_scalars_fields_counts_and_duplicate_keys_never_become_history() -> TestResult {
    let bank = CompactJson::from_envelope(&envelope(), 1_000_000)?;
    let mut invalid_banks = Vec::new();
    for field in ["message", "method", "session_id", "sequence"] {
        invalid_banks.push(replace_field(&bank.bytes, field, &raw_value(&json!("?"))));
    }
    invalid_banks.push(replace_field(
        &bank.bytes,
        "sequence",
        &raw_value(&json!("00")),
    ));
    invalid_banks.push(replace_field(
        &bank.bytes,
        "sequence",
        &raw_value(&json!("18446744073709551616")),
    ));
    invalid_banks.push(replace_field(&bank.bytes, "body", &raw_value(&json!([]))));
    for count in [0_u64, 12, 14, u64::MAX] {
        let mut changed = bank.bytes.clone();
        changed[1..9].copy_from_slice(&count.to_le_bytes());
        invalid_banks.push(changed);
    }
    let mut changed = bank.bytes.clone();
    changed[17] = 255;
    invalid_banks.push(changed);
    let mut changed = bank.bytes.clone();
    changed.push(0);
    invalid_banks.push(changed);

    for (first, second) in [("same", "same"), ("z", "a")] {
        let mut body = Vec::new();
        compact_json::encode_container(compact_json::OBJECT, 2, &mut body, |output| {
            for key in [first, second] {
                compact_json::encode_string(key, output)?;
                output.push(compact_json::NULL);
            }
            Ok(())
        })?;
        invalid_banks.push(replace_field(&bank.bytes, "body", &body));
    }
    for (tag, bits) in [
        (compact_json::SIGNED, 0),
        (compact_json::SIGNED, 1),
        (compact_json::FLOAT, f64::NAN.to_bits()),
        (compact_json::FLOAT, f64::INFINITY.to_bits()),
        (compact_json::FLOAT, f64::NEG_INFINITY.to_bits()),
    ] {
        let mut body = raw_value(&json!({"number": 0}));
        let position = body.len() - 9;
        body[position] = tag;
        body[position + 1..].copy_from_slice(&bits.to_le_bytes());
        invalid_banks.push(replace_field(&bank.bytes, "body", &body));
    }
    let mut body = raw_value(&json!({"text": "x"}));
    *body.last_mut().unwrap() = 255;
    invalid_banks.push(replace_field(&bank.bytes, "body", &body));

    for (index, bytes) in invalid_banks.into_iter().enumerate() {
        assert!(decode(&wrap(&bytes)).is_err(), "mutation {index}");
        assert!(
            CompactJson { bytes }.physical18_data().is_err(),
            "writer mutation {index}"
        );
    }
    Ok(())
}

#[test]
fn depth_array_limits_and_complete_decode_rows_are_independent() -> TestResult {
    let bank = CompactJson::from_envelope(&envelope(), 1_000_000)?;
    for (arrays, accepted) in [(62, true), (63, false), (100, false)] {
        let mut nested = Value::Null;
        for _ in 0..arrays {
            nested = Value::Array(vec![nested]);
        }
        let body = raw_value(&json!({"deep": nested}));
        let physical = wrap(&replace_field(&bank.bytes, "body", &body));
        assert_eq!(decode(&physical).is_ok(), accepted, "arrays {arrays}");
    }
    for count in [
        crucible_node_format::MAX_ARRAY_ELEMENTS,
        crucible_node_format::MAX_ARRAY_ELEMENTS + 1,
    ] {
        let body = raw_value(&json!({"array": vec![Value::Null; count]}));
        let physical = wrap(&replace_field(&bank.bytes, "body", &body));
        assert_eq!(
            decode(&physical).is_ok(),
            count == crucible_node_format::MAX_ARRAY_ELEMENTS
        );
    }

    let row = HistoricalCompactEnvelope18::decoding_storage_data(bank.bytes.len(), usize::MAX)?;
    let peak = row.into_iter().sum();
    assert_eq!(
        row[0],
        bank.bytes.len() + size_of::<HistoricalCompactEnvelope18>()
    );
    assert_eq!(row[1], 0);
    assert_eq!(
        row[2],
        HistoricalCompactEnvelope18::decoding_counter_scratch_data()
    );
    assert_eq!(
        HistoricalCompactEnvelope18::decoding_storage_data(bank.bytes.len(), peak)?,
        row
    );
    assert!(
        HistoricalCompactEnvelope18::decoding_storage_data(bank.bytes.len(), peak - 1).is_err()
    );
    assert!(HistoricalCompactEnvelope18::decoding_storage_data(usize::MAX, usize::MAX).is_err());
    Ok(())
}

fn replace_bytes(input: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    let offset = input
        .windows(needle.len())
        .position(|bytes| bytes == needle)
        .unwrap();
    [
        &input[..offset],
        replacement,
        &input[offset + needle.len()..],
    ]
    .concat()
}
