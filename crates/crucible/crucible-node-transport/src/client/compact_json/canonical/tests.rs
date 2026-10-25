//! Compares the borrowed wire encoder with the defining whole-value JCS oracle.

use super::*;
use crate::envelope::{MessageKind, Method, Nullable};
use crucible_node_format::{Id, U64};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn compare(envelope: &Envelope) -> TestResult {
    let expected = canonical::canonical_json(&serde_json::to_value(envelope)?)?;
    let output = encode_envelope(envelope, expected.len())?;

    assert_eq!(output, expected);
    assert_eq!(output.capacity(), expected.len());
    assert!(encode_envelope(envelope, expected.len() - 1).is_err());
    Ok(())
}

#[test]
fn complete_root_fields_messages_and_unicode_match_defining_jcs() -> TestResult {
    let mut envelope = crate::envelope::tests::request();
    let controls: String = (0u8..=127).map(char::from).collect();
    envelope.body = serde_json::from_value(json!({
        "\u{e000}": {"\u{10000}": [null, false, true, {}, [], controls]},
        "\u{10000}": {"\u{e000}": "雪🙂\u{2028}\u{2029}"},
        "$serde_json::private::RawValue": "ordinary DATA",
        "$serde_json::private::Number": {"nested": "1e+42"}
    }))?;
    envelope.extensions = serde_json::from_value(json!({
        "\u{e000}": [{"\u{10000}": "extension"}],
        "\u{10000}": {"\u{e000}": 1.0}
    }))?;

    for populated in [false, true] {
        let id = populated.then(|| Id::new("i".repeat(128))).transpose()?;
        envelope.session_id = Nullable(id.clone());
        envelope.incarnation_id = Nullable(id.clone());
        envelope.node_id = Nullable(id.clone());
        envelope.execution_owner_id = Nullable(id.clone());
        envelope.capture_owner_id = Nullable(id.clone());
        envelope.request_id = Nullable(id.clone());
        envelope.operation_id = Nullable(id);
        for message in [
            MessageKind::Request,
            MessageKind::Response,
            MessageKind::Event,
        ] {
            envelope.message = message;
            for method in [
                Method::Poll,
                Method::NativeImport18Bootstrap,
                Method::BlobChunk,
            ] {
                envelope.method = method;
                for sequence in [0, 9, 10, 99, 100, u64::MAX] {
                    envelope.sequence = U64::new(sequence);
                    compare(&envelope)?;
                }
            }
        }
    }
    Ok(())
}

#[test]
fn numeric_lexical_forms_use_defining_jcs_without_changing_originals() -> TestResult {
    let mut envelope = crate::envelope::tests::request();
    let mut numbers = vec![
        json!(i64::MIN),
        json!(u64::MAX),
        json!(9_007_199_254_740_993_u64),
    ];
    for number in [
        -0.0,
        0.0,
        1.0,
        -1.0,
        1e-7,
        1e-6,
        1e20,
        1e21,
        f64::MIN_POSITIVE,
        f64::from_bits(1),
        f64::MAX,
    ] {
        numbers.push(json!(number));
    }
    envelope
        .body
        .insert("numbers".into(), Value::Array(numbers));
    let original = serde_json::to_vec(&envelope)?;

    compare(&envelope)?;

    assert_eq!(serde_json::to_vec(&envelope)?, original);
    Ok(())
}

#[test]
fn actual_enclosing_depth_and_array_limits_are_checked_before_output() -> TestResult {
    let mut envelope = crate::envelope::tests::request();
    let mut nested = Value::Null;
    for _ in 0..62 {
        nested = json!([nested]);
    }
    envelope.body.insert("nested".into(), nested.clone());
    compare(&envelope)?;

    envelope.body.insert("nested".into(), json!([nested]));
    assert!(encode_envelope(&envelope, 4096).is_err());
    assert!(canonical::canonical_json(&serde_json::to_value(&envelope)?).is_err());

    envelope
        .body
        .insert("nested".into(), Value::Array(vec![Value::Null; 65_536]));
    compare(&envelope)?;
    envelope
        .body
        .get_mut("nested")
        .unwrap()
        .as_array_mut()
        .unwrap()
        .push(Value::Null);
    assert!(encode_envelope(&envelope, 1_048_576).is_err());
    Ok(())
}

#[test]
fn bounded_output_never_grows_or_discards_a_refused_prefix() -> TestResult {
    let mut output = Output::new(3)?;
    output.write_all(b"ab")?;
    assert!(output.write_all(b"cd").is_err());

    assert!(output.refused);
    assert_eq!(output.bytes, b"ab");
    assert_eq!(output.bytes.capacity(), 3);
    assert!(encode_envelope(&crate::envelope::tests::request(), usize::MAX).is_err());
    Ok(())
}
