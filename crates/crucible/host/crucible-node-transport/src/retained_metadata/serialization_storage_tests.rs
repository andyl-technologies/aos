//! Exercises actual canonical encodings and finite data-counter boundaries.

use super::*;
use serde::Serialize;
use crate::retained_metadata::MetadataObserver;
use crucible_node_format::{Bytes, U64, canonical};

const MAXIMUM: usize = 64 * 1024 * 1024;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn actual_serialize_quote_covers_utf16_escaping_numbers_and_nested_arrays() -> TestResult {
    let value = serde_json::json!({
        "\u{10000}": [1.0, -1.25e-12, "\\\"\n\u{0}", [true, false, null]],
        "\u{e000}": {"child": "actual independent string"}
    });
    let mut observer = MetadataObserver::new();
    observer.observe(&value)?;
    let quote = actual_serialization_storage_data(&value, observer.finish(), MAXIMUM)?;
    let encoded = canonical::canonical_json(&value)?;

    assert!(encoded.len() <= quote.maximum_encoded_bytes);
    assert!(quote.projected_parser_requested_bytes > 0);
    assert!(quote.dom_and_canonical_scratch_bytes > 0);
    assert!(quote.canonical_output_requested_bytes >= encoded.len());
    assert!(canonical::parse_json(&encoded, encoded.len()).is_ok());
    Ok(())
}

#[test]
fn actual_bytes_formatter_and_exact_total_limit_are_independently_charged() -> TestResult {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(4099)?;
    bytes.extend_from_slice(&[0, 255, 1, 254]);
    let bytes = Bytes::new(bytes);
    let mut observer = MetadataObserver::new();
    observer.observe(&bytes)?;
    let facts = observer.finish();
    let value = (&bytes, U64::new(u64::MAX));
    let quote = actual_serialization_storage_data(&value, facts, MAXIMUM)?;
    let total = quote.requested_total()?;

    assert!(quote.serializer_temporary_requested_bytes >= 4 * 4099_usize.div_ceil(3) + 20);
    assert!(serde_json::to_vec(&value)?.len() <= quote.maximum_encoded_bytes);
    assert_eq!(
        actual_serialization_storage_data(&value, facts, total)?.requested_total()?,
        total
    );
    assert!(actual_serialization_storage_data(&value, facts, total - 1).is_err());
    Ok(())
}

#[test]
fn fixed_projection_covers_the_corresponding_real_closed_object() -> TestResult {
    #[derive(Serialize)]
    struct Actual<'a> {
        schema: &'a str,
        length: U64,
        nested: &'a serde_json::Value,
    }
    let nested = serde_json::json!({"field": ["x", "y", "z"]});
    let actual = Actual {
        schema: "closed/12",
        length: U64::new(u64::MAX),
        nested: &nested,
    };
    let mut projection = OriginalSerializationStorageProjection::new(MAXIMUM)?;
    projection.add_object()?;
    projection.add_field("schema")?;
    projection.add_string(actual.schema)?;
    projection.add_field("length")?;
    projection.add_value(&actual.length)?;
    projection.add_field("nested")?;
    projection.add_value(&nested)?;
    let quote = projection.finish(MAXIMUM)?;
    let encoded = canonical::canonical_json(&serde_json::to_value(&actual)?)?;

    assert!(encoded.len() <= quote.maximum_encoded_bytes);
    assert!(quote.requested_total()? <= MAXIMUM);
    let mut excessive = OriginalSerializationStorageProjection::new(1024)?;
    assert!(excessive.add_string_extent(usize::MAX).is_err());
    Ok(())
}

#[test]
fn unsupported_custom_bytes_and_display_codecs_cannot_enroll_storage() {
    struct RawBytes;
    impl Serialize for RawBytes {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(b"unknown custom bytes")
        }
    }
    struct DisplayValue;
    impl Serialize for DisplayValue {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.collect_str(&"unknown custom formatter")
        }
    }

    assert!(actual_serialization_storage_data(&RawBytes, Default::default(), MAXIMUM).is_err());
    assert!(actual_serialization_storage_data(&DisplayValue, Default::default(), MAXIMUM).is_err());
}

#[test]
fn future_key_extent_covers_real_maximum_id_and_escaped_key_layouts() -> TestResult {
    for key in ["x".repeat(128), "\n\"\\\u{0}".repeat(8)] {
        let actual = std::collections::BTreeMap::from([(key.clone(), false)]);
        let mut fields = MetadataObserver::new();
        fields.observe(&actual)?;
        let actual = actual_serialization_storage_data(&actual, fields.finish(), MAXIMUM)?;
        let mut future = OriginalSerializationStorageProjection::new(MAXIMUM)?;
        future.add_object()?;
        future.add_field_extent(key.len())?;
        future.add_value(&false)?;
        let future = future.finish(MAXIMUM)?;
        assert!(future.maximum_encoded_bytes >= actual.maximum_encoded_bytes);
        assert!(future.projected_parser_requested_bytes >= actual.projected_parser_requested_bytes);
        assert!(future.dom_and_canonical_scratch_bytes >= actual.dom_and_canonical_scratch_bytes);
    }
    let mut future = OriginalSerializationStorageProjection::new(MAXIMUM)?;
    assert!(future.add_field_extent(usize::MAX).is_err());
    Ok(())
}

#[test]
fn closed_array_projection_matches_actual_tuple_slots_and_sequence_counts() -> TestResult {
    let strings = ["actual", "\n\u{0}", "independent owned field"];
    let mut future = OriginalSerializationStorageProjection::new(MAXIMUM)?;
    future.add_array_extent(strings.len())?;
    for value in strings {
        future.add_string(value)?;
    }
    let future = future.finish(MAXIMUM)?;
    let actual = actual_serialization_storage_data(&strings, Default::default(), MAXIMUM)?;
    assert_eq!(future.sequence_elements, actual.sequence_elements);
    assert_eq!(future.sequence_containers, actual.sequence_containers);
    assert_eq!(future.maximum_encoded_bytes, actual.maximum_encoded_bytes);
    assert_eq!(
        future.projected_parser_requested_bytes,
        actual.projected_parser_requested_bytes
    );
    assert_eq!(
        future.dom_and_canonical_scratch_bytes,
        actual.dom_and_canonical_scratch_bytes
    );

    let mut huge = OriginalSerializationStorageProjection::new(MAXIMUM)?;
    assert!(huge.add_array_extent(usize::MAX).is_err());
    Ok(())
}
