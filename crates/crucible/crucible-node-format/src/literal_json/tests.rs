//! Verifies literal wire data, independent ownership and bounded borrowed arrays.

use super::*;
use serde::Deserialize;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Deserialize)]
struct Fields {
    #[serde(deserialize_with = "deserialize_object")]
    object: Map<String, Value>,
    #[serde(deserialize_with = "deserialize_extensions")]
    extensions: Extensions,
    #[serde(deserialize_with = "deserialize_optional_object")]
    optional: Option<Map<String, Value>>,
}

#[test]
fn private_marker_objects_remain_literal_under_owned_and_borrowed_decoding() -> TestResult {
    for original in [
        json!({"$serde_json::private::RawValue": "ordinary DATA"}),
        json!({"$serde_json::private::RawValue": "{\"nested\":true}"}),
        json!({"$serde_json::private::Number": "123"}),
        json!({"nested": [{"$serde_json::private::RawValue": "null"}]}),
        json!({"deep_text": "[".repeat(1024)}),
    ] {
        let expected = serde_json::to_vec(&original)?;

        let borrowed = deserialize_value(&original)?;
        let owned = deserialize_value(original)?;

        assert_eq!(serde_json::to_vec(&borrowed)?, expected);
        assert_eq!(serde_json::to_vec(&owned)?, expected);
    }
    Ok(())
}

#[test]
fn borrowed_arrays_use_actual_lengths_and_results_do_not_borrow_source_backing() -> TestResult {
    for length in [0, 1, 3, 17, 32_768] {
        let original = Value::Array(vec![json!(["data", 7]); length]);

        let decoded = deserialize_value(&original)?;

        assert_eq!(decoded, original);
        let Value::Array(values) = &decoded else {
            return Err("array fixture changed".into());
        };
        assert_eq!(values.capacity(), length);
        for value in values {
            let Value::Array(values) = value else {
                return Err("nested array fixture changed".into());
            };
            assert_eq!(values.capacity(), values.len());
        }
    }

    let mut text = String::with_capacity(65_536);
    text.push_str("retained");
    let original = Value::String(text);
    let decoded = deserialize_value(&original)?;
    drop(original);

    let Value::String(text) = decoded else {
        return Err("string fixture changed".into());
    };
    assert_eq!(text, "retained");
    assert_eq!(text.capacity(), text.len());
    assert!(deserialization_counter_scratch_data() > 0);
    Ok(())
}

#[test]
fn objects_keep_required_null_and_duplicate_key_rules() -> TestResult {
    let mut input = json!({"object": {}, "extensions": {}, "optional": null});
    let fields = Fields::deserialize(&input)?;
    assert!(fields.object.is_empty());
    assert!(fields.extensions.is_empty());
    assert!(fields.optional.is_none());

    input["optional"] = json!({"$serde_json::private::RawValue": "null"});
    let fields = Fields::deserialize(&input)?;
    assert_eq!(
        fields
            .optional
            .as_ref()
            .map(|value| value.get("$serde_json::private::RawValue")),
        Some(Some(&json!("null")))
    );

    for field in ["object", "extensions", "optional"] {
        let mut missing = input.clone();
        missing
            .as_object_mut()
            .ok_or("object absent")?
            .remove(field);
        assert!(Fields::deserialize(&missing).is_err());

        let mut invalid = input.clone();
        invalid[field] = json!([]);
        assert!(Fields::deserialize(&invalid).is_err());
    }
    for source in [r#"{"x":1,"x":2}"#, r#"{"nested":{"x":1,"x":2}}"#] {
        let mut decoder = serde_json::Deserializer::from_str(source);
        assert!(deserialize_object(&mut decoder).is_err());
    }
    Ok(())
}

#[test]
fn numeric_variants_and_unicode_string_values_keep_their_serialized_bits() -> TestResult {
    let original = json!({
        "numbers": [-0.0, 1.0, 1e-7, 1e20, u64::MAX, i64::MIN],
        "\u{10000}": "雪\n\"\\",
        "\u{e000}": "e\u{301}"
    });

    let decoded = deserialize_value(&original)?;

    assert_eq!(decoded, original);
    assert_eq!(
        serde_json::to_vec(&decoded)?,
        serde_json::to_vec(&original)?
    );
    Ok(())
}

#[test]
fn portable_schema_fields_preserve_literal_extension_data() -> TestResult {
    let payload = json!({"$serde_json::private::RawValue": "ordinary DATA"});
    let input = json!({
        "id": "artifact/0", "role": "executable",
        "content": {
            "hash": {"algorithm": "blake3-256", "domain": "cnp.blob.v1",
                "digest": "00".repeat(32)},
            "length": "0", "media_type": "application/octet-stream"
        },
        "extensions": {"payload": payload}
    });

    let decoded: crate::ArtifactIdentity = serde_json::from_value(input.clone())?;

    assert_eq!(serde_json::to_value(decoded)?, input);
    Ok(())
}
