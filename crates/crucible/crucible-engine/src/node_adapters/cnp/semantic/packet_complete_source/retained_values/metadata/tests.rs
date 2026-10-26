//! Checks private JSON geometry against the independent original byte walk.

use super::*;
use crate::node_adapters::cnp::PacketCompleteSemanticSource;
use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::{
    sum_with_error, value_storage_with_error,
};
use crate::node_contract::NodeRuntime;

fn text(capacity: usize, value: &str) -> String {
    let mut text = String::with_capacity(capacity);
    text.push_str(value);
    text
}

fn retained_value() -> Value {
    let mut children = Vec::with_capacity(19);
    children.push(Value::String(text(173, "retained")));
    children.push(Value::Null);
    children.push(Value::Bool(true));
    children.push(Value::from(73));
    children.push(Value::Object(Default::default()));
    let mut object = serde_json::Map::new();
    object.insert(text(211, "original-key"), Value::Array(children));
    Value::Object(object)
}

#[test]
fn private_json_geometry_keeps_actual_spare_backing_at_exact_and_short_credit() {
    let value = retained_value();
    let object = value.as_object().unwrap();
    let (key, child) = object.iter().next().unwrap();
    let children = child.as_array().unwrap();
    let string = children[0].as_str().unwrap();
    let key_pointer = key.as_ptr();
    let string_pointer = string.as_ptr();
    let expected = legacy_value_storage(&value, 0, usize::MAX).unwrap();

    let facts = value_capacity_data_with_error::<RuntimeError>(&value, 0, None).unwrap();

    assert_eq!(facts.tree_containers, 2);
    assert_eq!(facts.tree_entries, 1);
    assert_eq!(
        facts.maximum_tree_key_value_bytes,
        size_of::<(String, Value)>()
    );
    assert_eq!(
        facts.maximum_tree_entry_alignment,
        align_of::<(String, Value)>()
    );
    assert_eq!(facts.vector_banks, 1);
    assert_eq!(
        facts.vector_capacity_bytes,
        children.capacity() * size_of::<Value>()
    );
    assert_eq!(facts.string_banks, 2);
    assert_eq!(
        facts.string_capacity_bytes,
        key.capacity()
            + match &children[0] {
                Value::String(text) => text.capacity(),
                _ => unreachable!(),
            }
    );
    assert_eq!(facts.capacity_records, 5);
    assert_eq!(facts.observed_nodes, 0);
    assert_eq!(
        value_storage_with_error::<RuntimeError>(&value, 0, expected),
        Ok(expected)
    );
    assert!(value_storage_with_error::<RuntimeError>(&value, 0, expected - 1).is_err());
    assert_eq!(
        super::super::value_storage(&value, 0, expected).unwrap(),
        expected
    );
    assert!(super::super::value_storage(&value, 0, expected - 1).is_err());
    assert_eq!(key.as_ptr(), key_pointer);
    assert_eq!(string.as_ptr(), string_pointer);
}

#[test]
fn empty_private_object_keeps_its_own_compiled_layout() {
    let value = Value::Object(Default::default());

    let facts = value_capacity_data_with_error::<RuntimeError>(&value, 0, None).unwrap();
    let expected = NodeRuntime::capture_protocol_tree_storage(
        1,
        0,
        size_of::<(String, Value)>(),
        align_of::<(String, Value)>(),
        usize::MAX,
    )
    .unwrap();

    assert_eq!(facts.tree_containers, 1);
    assert_eq!(facts.tree_entries, 0);
    assert_eq!(facts.capacity_records, 1);
    assert_eq!(
        facts.maximum_tree_key_value_bytes,
        size_of::<(String, Value)>()
    );
    assert_eq!(
        value_storage_with_error::<RuntimeError>(&value, 0, expected),
        Ok(expected)
    );
    assert!(expected > 0);
    assert!(value_storage_with_error::<RuntimeError>(&value, 0, expected - 1).is_err());
}

#[test]
fn selected_row_refusal_preserves_earlier_private_json_rows() {
    let mut values = Vec::with_capacity(11);
    values.push(Value::String(text(173, "first")));
    values.push(Value::String(text(211, "refused")));
    let value = Value::Array(values);
    let mut census = OriginalOwnerCapacityMetadataData::new(2, None);

    assert_eq!(
        record_value_capacity_data_with_error::<RuntimeError>(&value, 0, &mut census),
        Err(RuntimeError::ResourceLimit)
    );
    let prefix = census.finish();

    assert_eq!(prefix.capacity_records, 2);
    assert_eq!(prefix.vector_banks, 1);
    assert_eq!(prefix.string_banks, 1);
    let values = value.as_array().unwrap();
    assert_eq!(
        prefix.vector_capacity_bytes,
        values.capacity() * size_of::<Value>()
    );
    assert_eq!(
        prefix.string_capacity_bytes,
        match &values[0] {
            Value::String(text) => text.capacity(),
            _ => unreachable!(),
        }
    );
    assert_eq!(values[1].as_str(), Some("refused"));
}

fn nested(depth: usize) -> Value {
    (0..depth).fold(Value::Null, |value, _| Value::Array(vec![value]))
}

#[test]
fn private_json_keeps_its_original_depth_fence_and_refused_prefix() {
    let accepted = nested(MAXIMUM_DEPTH);
    let refused = nested(MAXIMUM_DEPTH + 1);
    let original = legacy_value_storage(&accepted, 0, usize::MAX).unwrap();
    assert!(legacy_value_storage(&refused, 0, usize::MAX).is_err());
    assert_eq!(
        value_storage_with_error::<RuntimeError>(&accepted, 0, original),
        Ok(original)
    );
    assert!(value_storage_with_error::<RuntimeError>(&refused, 0, usize::MAX).is_err());
    let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);

    assert!(
        record_value_capacity_data_with_error::<RuntimeError>(&refused, 0, &mut census).is_err()
    );
    let prefix = census.finish();

    assert_eq!(prefix.vector_banks, MAXIMUM_DEPTH + 1);
    assert_eq!(prefix.capacity_records, MAXIMUM_DEPTH + 1);
    assert_eq!(prefix.observed_nodes, 0);
    assert!(
        value_capacity_data_with_error::<RuntimeError>(&Value::Null, MAXIMUM_DEPTH + 1, None)
            .is_err()
    );
}

#[test]
fn independent_private_json_views_keep_every_backing_row() {
    let value = retained_value();
    let original = value_capacity_data_with_error::<RuntimeError>(&value, 0, None).unwrap();
    let expected = legacy_value_storage(&value, 0, usize::MAX).unwrap() * 2;
    let mut census = OriginalOwnerCapacityMetadataData::new(original.capacity_records * 2, None);

    record_value_capacity_data_with_error::<RuntimeError>(&value, 0, &mut census).unwrap();
    record_value_capacity_data_with_error::<RuntimeError>(&value, 0, &mut census).unwrap();
    let actual = census.finish();

    assert_eq!(actual.capacity_records, original.capacity_records * 2);
    assert_eq!(actual.tree_containers, original.tree_containers * 2);
    assert_eq!(
        actual.string_capacity_bytes,
        original.string_capacity_bytes * 2
    );
    assert_eq!(
        actual.vector_capacity_bytes,
        original.vector_capacity_bytes * 2
    );
    assert_eq!(
        PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
            &actual, expected
        ),
        Ok(expected)
    );
}

// This independent original byte walk is retained only as a regression oracle.
fn legacy_value_storage(
    value: &Value,
    depth: usize,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    if depth > 64 {
        return Err(RuntimeError::refused(
            "retained private JSON depth unsupported",
        ));
    }
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(0),
        Value::String(value) => sum_with_error::<RuntimeError, _>([value.capacity()], maximum),
        Value::Array(values) => {
            let slots = values
                .capacity()
                .checked_mul(size_of::<Value>())
                .ok_or_else(|| RuntimeError::refused("retained private JSON array overflow"))?;
            let mut bytes = sum_with_error::<RuntimeError, _>([slots], maximum)?;
            for value in values {
                bytes = sum_with_error::<RuntimeError, _>(
                    [bytes, legacy_value_storage(value, depth + 1, maximum)?],
                    maximum,
                )?;
            }
            Ok(bytes)
        }
        Value::Object(values) => {
            let mut bytes = NodeRuntime::capture_protocol_tree_storage(
                1,
                values.len(),
                size_of::<String>() + size_of::<Value>(),
                align_of::<String>().max(align_of::<Value>()),
                maximum,
            )
            .map_err(RuntimeError::runtime)?;
            for (key, value) in values {
                bytes = sum_with_error::<RuntimeError, _>(
                    [
                        bytes,
                        key.capacity(),
                        legacy_value_storage(value, depth + 1, maximum)?,
                    ],
                    maximum,
                )?;
            }
            Ok(bytes)
        }
    }
}
