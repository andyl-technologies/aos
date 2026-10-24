//! Checks fresh clone bounds against actual capacities and pinned tree layouts.

use super::*;
use crate::retained_metadata::{
    MetadataObserver,
    records::{MetadataRecordBank, MetadataRecordKind},
    requested_storage::tree_storage_data,
};
use crucible_node_format::canonical;
use serde_json::{Map, Value};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn verify(values: &[Value]) -> TestResult {
    let canonical_bytes = values.iter().try_fold(0usize, |sum, value| {
        canonical::canonical_json(value).map(|bytes| sum + bytes.len())
    })?;
    let quote = original_json_value_clone_storage_forest_data(canonical_bytes, values.len())?;
    let mut backing = values.len() * size_of::<Value>();

    for original in values {
        let cloned = original.clone();
        assert_eq!(&cloned, original);

        let mut records = MetadataRecordBank::reserve(131_072)?;
        let mut observer = MetadataObserver::recording(&mut records);
        observer.observe(&cloned)?;
        observer.finish();

        for record in records.rows() {
            backing += match record.kind {
                MetadataRecordKind::String | MetadataRecordKind::Vector => {
                    record.extent * record.element_bytes
                }
                MetadataRecordKind::Tree => {
                    // Unlike arbitrary retained maps, a fresh empty clone has
                    // no root. A nonempty clone has at most one node/member.
                    tree_storage_data(0, record.extent, record.element_bytes, record.alignment)?
                }
                MetadataRecordKind::Shared | MetadataRecordKind::Boxed => {
                    return Err("unexpected backing in a JSON Value clone".into());
                }
            };
        }
    }

    assert!(backing <= quote, "backing={backing}, quote={quote}");
    let construction = original_json_value_storage_forest_data(canonical_bytes, values.len())?;
    assert!(quote < construction.value_dom_requested_bytes);
    Ok(())
}

#[test]
fn fresh_clones_cover_dense_arrays_split_trees_and_separate_roots() -> TestResult {
    let mut split = Map::new();
    for index in 0..256 {
        split.insert(format!("key-{index}"), serde_json::json!([index, "value"]));
    }
    let mut churned = split.clone();
    churned.retain(|key, _| key == "key-255");

    verify(&[
        Value::Object(split),
        Value::Object(churned),
        Value::Array(vec![Value::from(0); 512]),
        Value::Array(vec![Value::Object(Map::new()); 128]),
        serde_json::json!({"quoted": "\u{0}\n\"\\𝄞", "number": 1e-7}),
    ])?;
    verify(&vec![Value::from(0); 512])
}

#[test]
fn clone_backing_excludes_parent_spare_capacity_without_releasing_it() -> TestResult {
    let mut text = String::with_capacity(1024 * 1024);
    text.push_str("live");
    let mut array = Vec::with_capacity(4096);
    array.push(Value::String(text));
    let original = Value::Array(array);
    let parent_array = original.as_array().ok_or("array absent")?;
    let parent_text = parent_array[0].as_str().ok_or("text absent")?;
    let parent_capacity = parent_array.capacity();
    let Value::String(text) = &parent_array[0] else {
        return Err("string absent".into());
    };
    let text_capacity = text.capacity();
    let encoded = canonical::canonical_json(&original)?;

    verify(std::slice::from_ref(&original))?;
    let cloned = original.clone();
    let cloned_array = cloned.as_array().ok_or("cloned array absent")?;
    assert_eq!(cloned_array.capacity(), cloned_array.len());
    let Value::String(cloned_text) = &cloned_array[0] else {
        return Err("cloned string absent".into());
    };
    assert_eq!(cloned_text.capacity(), parent_text.len());

    assert_eq!(parent_array.capacity(), parent_capacity);
    assert_eq!(text.capacity(), text_capacity);
    assert_eq!(canonical::canonical_json(&original)?, encoded);
    let quote = original_json_value_clone_storage_forest_data(encoded.len(), 1)?;
    assert!(quote < text_capacity);
    Ok(())
}

#[test]
fn cloned_empty_maps_discard_only_their_own_old_tree_shape() -> TestResult {
    let mut map = Map::new();
    for index in 0..256 {
        map.insert(format!("key-{index}"), Value::from(index));
    }
    map.retain(|_, _| false);
    let original = Value::Object(map);
    verify(std::slice::from_ref(&original))?;
    assert_eq!(original, serde_json::json!({}));
    Ok(())
}

#[test]
fn empty_and_overflowing_clone_forests_refuse_before_allocating() -> TestResult {
    for (bytes, documents) in [(0, 1), (1, 0), (usize::MAX, 1), (usize::MAX / 32, 1)] {
        assert!(original_json_value_clone_storage_forest_data(bytes, documents).is_err());
    }
    assert_eq!(
        original_json_value_clone_storage_forest_data(3, usize::MAX)?,
        original_json_value_clone_storage_forest_data(3, 3)?,
    );
    Ok(())
}

fn lexical_storage_units(value: &Value) -> (usize, usize, usize) {
    match value {
        Value::Array(values) => values.iter().fold((values.len(), 0, 0), |sum, value| {
            let child = lexical_storage_units(value);
            (sum.0 + child.0, sum.1 + child.1, sum.2 + child.2)
        }),
        Value::Object(values) => values
            .iter()
            .fold((0, values.len(), 0), |sum, (key, value)| {
                let child = lexical_storage_units(value);
                (
                    sum.0 + child.0,
                    sum.1 + child.1,
                    sum.2 + key.len() + child.2,
                )
            }),
        Value::String(value) => (0, 0, value.len()),
        Value::Null | Value::Bool(_) | Value::Number(_) => (0, 0, 0),
    }
}

#[test]
fn joint_canonical_budget_covers_nested_maps_arrays_and_decoded_strings() -> TestResult {
    let mut values = vec![
        Value::Null,
        Value::Bool(false),
        Value::from(0),
        Value::from(1e-7),
        Value::String("\0\n\"\\𝄞".repeat(16)),
        Value::Array(vec![Value::from(0); 512]),
    ];
    let mut nested = Value::from(0);
    for _ in 0..16 {
        nested = serde_json::json!({"": [nested, 0], "\n𝄞": "\0\"\\"});
        values.push(nested.clone());
    }

    for value in &values {
        let (array_elements, object_members, string_bytes) = lexical_storage_units(value);
        let minimum = 1 + 2 * array_elements + 5 * object_members + string_bytes;
        assert!(canonical::canonical_json(value)?.len() >= minimum);
    }

    // The two minimal recursive grammars attain the structural bound. This
    // checks their shared byte accounting independently of the quote formula.
    for value in [serde_json::json!([0, 0]), serde_json::json!({"": {"": 0}})] {
        let (array_elements, object_members, string_bytes) = lexical_storage_units(&value);
        assert_eq!(
            canonical::canonical_json(&value)?.len(),
            1 + 2 * array_elements + 5 * object_members + string_bytes,
        );
    }
    verify(&values)
}
