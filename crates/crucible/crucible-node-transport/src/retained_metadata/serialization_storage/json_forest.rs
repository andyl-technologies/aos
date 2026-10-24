//! Checks aggregate JSON journal bounds against actual independent root owners.

use super::*;
use crate::retained_metadata::{
    MetadataObserver, requested_storage::requested_metadata_backing_storage_data,
};
use crucible_node_format::canonical;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn logical_values(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Array(values) => 1 + values.iter().map(logical_values).sum::<usize>(),
        serde_json::Value::Object(values) => {
            1 + values.len() + values.values().map(logical_values).sum::<usize>()
        }
        _ => 1,
    }
}

fn verify(inputs: &[&[u8]]) -> TestResult {
    let bytes = inputs.iter().map(|input| input.len()).sum();
    let forest = original_json_value_storage_forest_data(bytes, inputs.len())?;
    let mut observed_backing = 0;
    let mut values = 0;
    let mut members = 0;
    let mut encoded_bytes = 0;
    let mut independent_dom = 0;
    let mut independent_work = 0;
    let mut independent_output = 0;

    for input in inputs {
        let value = canonical::parse_json(input, input.len())?;
        let mut observer = MetadataObserver::new();
        observer.observe(&value)?;
        let facts = observer.finish();
        observed_backing += requested_metadata_backing_storage_data(&facts)?
            + std::mem::size_of::<serde_json::Value>();
        values += logical_values(&value);
        members += facts.tree_entries;
        encoded_bytes += canonical::canonical_json(&value)?.len();

        let single = original_json_value_storage_extent_data(input.len())?;
        independent_dom += single.value_dom_requested_bytes;
        independent_work += single.canonical_work_requested_bytes;
        independent_output += single.canonical_output_requested_bytes;
    }

    assert!(observed_backing <= forest.value_dom_requested_bytes);
    assert!(values <= forest.maximum_value_nodes);
    assert!(members <= forest.maximum_object_members);
    assert!(encoded_bytes <= forest.maximum_canonical_encoded_bytes);
    assert!(independent_dom <= forest.value_dom_requested_bytes);
    assert!(independent_work <= forest.canonical_work_requested_bytes);
    assert!(independent_output <= forest.canonical_output_requested_bytes);
    Ok(())
}

#[test]
fn separate_scalar_roots_keep_their_own_lexical_rounding_and_workspace() -> TestResult {
    let inputs = vec![b"0".as_slice(); 512];
    let single = original_json_value_storage_extent_data(inputs.len())?;
    assert!(single.maximum_value_nodes < inputs.len());

    verify(&inputs)
}

#[test]
fn mixed_journal_roots_cover_real_backing_and_independent_canonical_growth() -> TestResult {
    verify(&[
        b"{}",
        b"[]",
        b"[0,0,0,0,0,0,0,0]",
        br#"{"":0,"a":[],"b":{},"c":["",0],"d":1.0}"#,
        br#"{"quoted":"\u0000\n\"\\\uD834\uDD1E","number":1e+308}"#,
        b"[[[[[[[[]]]]]]]]",
        b"1e-7",
        b"-0.0",
    ])
}

#[test]
fn one_document_preserves_the_single_root_quote_and_shared_bytes_are_not_multiplied() -> TestResult
{
    let bytes = 65_536;
    let single = original_json_value_storage_extent_data(bytes)?;
    let one = original_json_value_storage_forest_data(bytes, 1)?;
    assert_eq!(one.maximum_value_nodes, single.maximum_value_nodes);
    assert_eq!(one.maximum_object_members, single.maximum_object_members);
    assert_eq!(
        one.value_dom_requested_bytes,
        single.value_dom_requested_bytes
    );
    assert_eq!(
        one.canonical_work_requested_bytes,
        single.canonical_work_requested_bytes
    );
    assert_eq!(
        one.canonical_output_requested_bytes,
        single.canonical_output_requested_bytes
    );
    assert!(one.declared_counter_scratch_bytes > single.declared_counter_scratch_bytes);

    let many = original_json_value_storage_forest_data(bytes, 128)?;
    assert!(many.value_dom_requested_bytes < 128 * single.value_dom_requested_bytes);
    assert_eq!(many.maximum_decoded_string_bytes, bytes);
    assert_eq!(
        original_json_value_storage_forest_data(3, usize::MAX)?,
        original_json_value_storage_forest_data(3, 3)?
    );
    Ok(())
}

#[test]
fn empty_and_overflowing_forests_refuse_without_constructing_documents() {
    for (bytes, documents) in [(0, 1), (1, 0), (usize::MAX, 1), (usize::MAX, usize::MAX)] {
        assert!(original_json_value_storage_forest_data(bytes, documents).is_err());
    }
}
