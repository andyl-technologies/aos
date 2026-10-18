//! Exercises literal identity, shallow portability and retained failed attempts.

use super::*;
use crucible_node_contract::canonical::{canonical_json, parse_json};

fn literal_identity(left: &Value, right: &Value) {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => {
            assert_eq!(left.is_u64(), right.is_u64());
            assert_eq!(left.is_i64(), right.is_i64());
            assert_eq!(left.is_f64(), right.is_f64());
            if left.is_f64() {
                assert_eq!(
                    left.as_f64().unwrap().to_bits(),
                    right.as_f64().unwrap().to_bits()
                );
            } else {
                assert_eq!(left, right);
            }
        }
        (Value::Array(left), Value::Array(right)) => {
            assert_eq!(left.len(), right.len());
            for (left, right) in left.iter().zip(right) {
                literal_identity(left, right);
            }
        }
        (Value::Object(left), Value::Object(right)) => {
            assert_eq!(left.len(), right.len());
            for ((left_key, left), (right_key, right)) in left.iter().zip(right) {
                assert_eq!(left_key, right_key);
                literal_identity(left, right);
            }
        }
        _ => assert_eq!(left, right),
    }
}

fn through_wire(
    value: &Value,
    population: usize,
) -> (LiteralValue18TokenAttempt, LiteralValue18DecodeAttempt) {
    // The actual fixture population independently funds the disposable prewalk.
    let prewalk = traversal_prewalk_data(population, usize::MAX).unwrap();
    assert!(prewalk.requested_storage_data().2 > 0);
    let quote = quote_encode_data(value, population, usize::MAX).unwrap();
    let mut tokens = LiteralValue18TokenAttempt::new();
    encode_into_data(value, quote, &mut tokens, usize::MAX).unwrap();
    assert!(
        tokens.retained_requested_storage_data(usize::MAX).unwrap()
            <= quote.requested_storage_data().0
    );

    let wire = serde_json::to_value(tokens.data().unwrap()).unwrap();
    let bytes = canonical_json(&wire).unwrap();
    let raw = parse_json(&bytes, bytes.len()).unwrap();
    let read_quote = quote_read_data(&raw, usize::MAX).unwrap();
    let mut read = LiteralValue18TokenAttempt::new();
    read_into_data(&raw, read_quote, &mut read, usize::MAX).unwrap();
    assert_eq!(tokens.data().unwrap(), read.data().unwrap());
    assert!(
        read.retained_requested_storage_data(usize::MAX).unwrap()
            <= read_quote.requested_storage_data().0
    );

    let decode = quote_decode_data(read.data().unwrap(), usize::MAX).unwrap();
    let mut restored = LiteralValue18DecodeAttempt::new();
    decode_into_data(read.data().unwrap(), decode, &mut restored, usize::MAX).unwrap();
    assert!(
        restored
            .retained_requested_storage_data(population, usize::MAX)
            .unwrap()
            <= decode.requested_storage_data().0
    );
    literal_identity(value, restored.value().unwrap());
    (tokens, restored)
}

#[test]
fn deep_literal_raw_value_key_survives_ordinary_shallow_wire() {
    let mut value =
        serde_json::json!({"$serde_json::private::RawValue":"[1.0,-0.0,{\"literal\":true}]"});
    for _ in 0..80 {
        value = Value::Array(vec![value]);
    }
    assert!(canonical_json(&value).is_err());

    let (tokens, restored) = through_wire(&value, 82);
    assert!(tokens.data().unwrap().token_count().unwrap() > 160);
    let mut leaf = restored.value().unwrap();
    for _ in 0..80 {
        leaf = &leaf.as_array().unwrap()[0];
    }
    assert_eq!(
        leaf["$serde_json::private::RawValue"],
        Value::String("[1.0,-0.0,{\"literal\":true}]".to_owned())
    );
    assert!(canonical_json(restored.value().unwrap()).is_err());
}

#[test]
fn numeric_kinds_full_integers_and_negative_zero_survive_jcs() {
    let value = Value::Array(vec![
        Value::from(u64::MAX),
        Value::from(i64::MIN),
        Value::from(-1i64),
        Value::Number(serde_json::Number::from_f64(1.0).unwrap()),
        Value::Number(serde_json::Number::from_f64(-0.0).unwrap()),
        Value::Number(serde_json::Number::from_f64(f64::MIN_POSITIVE).unwrap()),
    ]);
    let (_, restored) = through_wire(&value, 7);
    let values = restored.value().unwrap().as_array().unwrap();
    assert_eq!(values[0].as_u64(), Some(u64::MAX));
    assert!(matches!(&values[3], Value::Number(number) if number.is_f64()));
    assert_eq!(values[4].as_f64().unwrap().to_bits(), (-0.0f64).to_bits());
}

#[test]
fn large_value_population_uses_portable_sized_chunks() {
    let count = MAX_ARRAY_ELEMENTS + 3;
    let value = Value::Array((0..count).map(|_| Value::Null).collect());
    assert!(canonical_json(&value).is_err());
    let (tokens, restored) = through_wire(&value, count + 1);
    assert_eq!(tokens.data().unwrap().chunks.len(), 2);
    assert_eq!(tokens.data().unwrap().chunks[0].len(), MAX_ARRAY_ELEMENTS);
    assert_eq!(restored.value().unwrap().as_array().unwrap().len(), count);
}

#[test]
fn exact_constructor_rows_and_one_short_refuse_without_retry() {
    let value = serde_json::json!({"key":["literal",false,null]});
    let quote = quote_encode_data(&value, 5, usize::MAX).unwrap();
    let (r, t, s) = quote.requested_storage_data();
    let exact = r.checked_add(t).unwrap().checked_add(s).unwrap();
    assert_eq!(quote_encode_data(&value, 5, exact).unwrap(), quote);
    assert!(quote_encode_data(&value, 5, exact - 1).is_err());
    assert!(quote_encode_data(&value, 4, usize::MAX).is_err());

    let mut tokens = LiteralValue18TokenAttempt::new();
    assert!(encode_into_data(&value, quote, &mut tokens, exact - 1).is_err());
    assert_eq!(tokens.state_data(), (true, true, false));
    assert_eq!(
        encode_into_data(&value, quote, &mut tokens, exact),
        Err(RuntimeError::DuplicateOperation)
    );
    assert!(tokens.data().is_err());
    assert!(
        tokens.retained_requested_storage_data(usize::MAX).unwrap()
            >= size_of::<LiteralValue18TokenAttempt>()
    );
}

#[test]
fn malformed_token_documents_preserve_constructed_banks_and_failure() {
    let cases = [
        serde_json::json!([{"type":"arrayStart"},{"type":"objectEnd"}]),
        serde_json::json!([{"type":"objectStart"},{"type":"key","value":"same"},{"type":"null"},{"type":"key","value":"same"},{"type":"null"},{"type":"objectEnd"}]),
        serde_json::json!([{"type":"objectStart"},{"type":"key","value":"unused"},{"type":"objectEnd"}]),
        serde_json::json!([{"type":"null"},{"type":"null"}]),
    ];
    for chunk in cases {
        let raw = serde_json::json!({"schema":SCHEMA,"chunks":[chunk]});
        let quote = quote_read_data(&raw, usize::MAX).unwrap();
        let mut attempt = LiteralValue18TokenAttempt::new();
        assert!(read_into_data(&raw, quote, &mut attempt, usize::MAX).is_err());
        assert_eq!(attempt.state_data(), (true, true, false));
        assert!(attempt.data().is_err());
        assert!(!attempt.data.chunks.is_empty());
        let retained = attempt.retained_requested_storage_data(usize::MAX).unwrap();
        assert!(retained > size_of::<LiteralValue18TokenAttempt>());
        assert_eq!(
            attempt.retained_requested_storage_data(retained).unwrap(),
            retained
        );
        assert!(
            attempt
                .retained_requested_storage_data(retained - 1)
                .is_err()
        );
        assert_eq!(
            read_into_data(&raw, quote, &mut attempt, usize::MAX),
            Err(RuntimeError::DuplicateOperation)
        );
    }
}

#[test]
fn closed_reader_refuses_unknown_null_and_invalid_numeric_fields() {
    let cases = [
        serde_json::json!({"type":"null","value":null}),
        serde_json::json!({"type":"string","value":null}),
        serde_json::json!({"type":"unknown"}),
        serde_json::json!({"type":"unsigned","value":"01"}),
        serde_json::json!({"type":"unsigned","value":"18446744073709551616"}),
        serde_json::json!({"type":"signed","value":"0"}),
        serde_json::json!({"type":"floatBits","value":U64::new(f64::INFINITY.to_bits())}),
        serde_json::json!({"type":"floatBits","value":U64::new(f64::NAN.to_bits())}),
    ];
    for token in cases {
        let raw = serde_json::json!({"schema":SCHEMA,"chunks":[[token]]});
        assert!(quote_read_data(&raw, usize::MAX).is_err());
    }
    assert!(
        quote_read_data(
            &serde_json::json!({"schema":SCHEMA,"chunks":[[{"type":"null"}]],"extra":false}),
            usize::MAX
        )
        .is_err()
    );
    assert!(
        quote_read_data(
            &serde_json::json!({"schema":SCHEMA,"chunks":[[{"type":"null"}],[{"type":"null"}]]}),
            usize::MAX
        )
        .is_err()
    );
}

#[test]
fn decoding_short_row_keeps_actual_once_failure_and_original_tokens() {
    let value = serde_json::json!(["owned",{"key":true}]);
    let encode = quote_encode_data(&value, 4, usize::MAX).unwrap();
    let mut tokens = LiteralValue18TokenAttempt::new();
    encode_into_data(&value, encode, &mut tokens, usize::MAX).unwrap();
    let quote = quote_decode_data(tokens.data().unwrap(), usize::MAX).unwrap();
    let (r, t, s) = quote.requested_storage_data();
    let exact = r.checked_add(t).unwrap().checked_add(s).unwrap();
    assert_eq!(
        quote_decode_data(tokens.data().unwrap(), exact).unwrap(),
        quote
    );
    assert!(quote_decode_data(tokens.data().unwrap(), exact - 1).is_err());

    let original = serde_json::to_value(tokens.data().unwrap()).unwrap();
    let mut output = LiteralValue18DecodeAttempt::new();
    assert!(decode_into_data(tokens.data().unwrap(), quote, &mut output, exact - 1).is_err());
    assert_eq!(output.state_data(), (true, true, false));
    assert!(output.value().is_err());
    assert_eq!(
        decode_into_data(tokens.data().unwrap(), quote, &mut output, exact),
        Err(RuntimeError::DuplicateOperation)
    );
    assert_eq!(
        serde_json::to_value(tokens.data().unwrap()).unwrap(),
        original
    );
}

#[test]
fn token_reader_row_is_exact_and_bank_transfer_refuses_before_move() {
    let raw =
        serde_json::json!({"schema":SCHEMA,"chunks":[[{"type":"string","value":"retained"}]]});
    let quote = quote_read_data(&raw, usize::MAX).unwrap();
    let (r, t, s) = quote.requested_storage_data();
    let exact = r.checked_add(t).unwrap().checked_add(s).unwrap();
    assert_eq!(quote_read_data(&raw, exact).unwrap(), quote);
    assert!(quote_read_data(&raw, exact - 1).is_err());

    let mut first = LiteralValue18TokenAttempt::new();
    read_into_data(&raw, quote, &mut first, exact).unwrap();
    let original_bank = first.data().unwrap().chunks[0].as_ptr();
    let original_capacity = first.data().unwrap().chunks[0].capacity();
    let mut occupied = LiteralValue18TokenAttempt::new();
    read_into_data(&raw, quote, &mut occupied, exact).unwrap();
    let mut output = None;
    occupied.take_data_into(&mut output).unwrap();
    assert_eq!(
        first.take_data_into(&mut output),
        Err(RuntimeError::DuplicateOperation)
    );
    assert_eq!(first.data().unwrap().chunks[0].as_ptr(), original_bank);

    let mut moved = None;
    first.take_data_into(&mut moved).unwrap();
    let moved = moved.unwrap();
    assert_eq!(moved.chunks[0].as_ptr(), original_bank);
    assert_eq!(moved.chunks[0].capacity(), original_capacity);
    assert_eq!(first.state_data(), (true, false, false));
    assert!(first.data().is_err());
    assert_eq!(
        read_into_data(&raw, quote, &mut first, exact),
        Err(RuntimeError::DuplicateOperation)
    );
}

#[test]
fn exact_retained_census_does_not_reuse_its_r_bound_for_transient_workspace() {
    // A source census may provide the whole actual owner population while this
    // one slot contains only null. The separately funded workspace is T.
    let owner = Value::Array((0..4096).map(|_| Value::Null).collect());
    let population = owner.as_array().unwrap().len() + 1;
    let quote = quote_encode_data(&Value::Null, population, usize::MAX).unwrap();
    let mut tokens = LiteralValue18TokenAttempt::new();
    encode_into_data(&Value::Null, quote, &mut tokens, usize::MAX).unwrap();
    let decode = quote_decode_data(tokens.data().unwrap(), usize::MAX).unwrap();
    let mut output = LiteralValue18DecodeAttempt::new();
    decode_into_data(tokens.data().unwrap(), decode, &mut output, usize::MAX).unwrap();
    let prewalk = retained_decode_prewalk_data(population, usize::MAX).unwrap();
    let exact = output
        .retained_requested_storage_data(population, usize::MAX)
        .unwrap();
    assert!(prewalk.requested_storage_data().1 > exact);
    assert_eq!(
        output
            .retained_requested_storage_data(population, exact)
            .unwrap(),
        exact
    );
    assert!(
        output
            .retained_requested_storage_data(population, exact - 1)
            .is_err()
    );
}
