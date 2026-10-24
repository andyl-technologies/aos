//! Retains the original Transport paths for the shared pure serialization quote.
//!
//! Metadata ownership and independent observer tests remain in this crate.

#[cfg(test)]
use crate::retained_metadata::RetainedProtocolMetadataFacts;
use crucible_source_birth_data::profile::serialization_storage as shared;
pub use shared::{
    OriginalJsonValueStorageExtentData, original_json_value_storage_extent_counter_scratch_data,
    original_json_value_storage_extent_data,
    original_json_value_storage_forest_counter_scratch_data,
    original_json_value_storage_forest_data,
};
pub(crate) use shared::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection,
    actual_serialization_storage_data, original_json_value_storage_population_data,
    original_serialization_counter_scratch_data,
    original_serialization_formatter_temporary_storage_data,
    original_serialization_frame_counter_scratch_data,
    original_serialization_tree_node_counter_scratch_data,
    original_serialization_tree_node_requested_bytes_data,
};
#[cfg(test)]
use std::mem::size_of;

#[cfg(test)]
#[path = "serialization_storage/json_extent.rs"]
mod json_extent;

#[cfg(test)]
#[path = "serialization_storage/json_forest.rs"]
mod json_forest;

#[cfg(test)]
#[path = "serialization_storage_tests.rs"]
mod tests;

#[cfg(test)]
mod logical_event_tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn split_retained_value_backing_covers_real_objects_and_has_no_canonical_bank_alias()
    -> TestResult {
        for value in [
            serde_json::json!({}),
            serde_json::json!([{}, {"nested": ["value", 1]}, []]),
        ] {
            let mut observer = crate::retained_metadata::MetadataObserver::new();
            observer.observe(&value)?;
            let facts = observer.finish();
            let observed =
                crate::retained_metadata::requested_metadata_backing_storage_data(&facts)?;
            let row = actual_serialization_storage_data(&value, facts, usize::MAX)?;
            assert!(row.retained_value_backing_bytes >= observed + size_of::<serde_json::Value>());
            assert!(row.canonical_output_requested_bytes >= 256);
            // Backing and work are independent terms. A retained clone cannot
            // spend the already separately retained canonical Vec as its heap.
            let clone = value.clone();
            let mut clone_observer = crate::retained_metadata::MetadataObserver::new();
            clone_observer.observe(&clone)?;
            assert!(
                row.retained_value_backing_bytes
                    >= crate::retained_metadata::requested_metadata_backing_storage_data(
                        &clone_observer.finish()
                    )?
            );
        }
        Ok(())
    }

    #[test]
    fn actual_serializer_and_closed_projection_count_same_keys_values_and_backings() -> TestResult {
        let value = serde_json::json!({"a":["x",true,null],"b":{}});
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        observer.observe(&value)?;
        let actual = actual_serialization_storage_data(&value, observer.finish(), usize::MAX)?;
        let mut projected = OriginalSerializationStorageProjection::new(usize::MAX)?;
        projected.add_object()?;
        projected.add_field("a")?;
        projected.add_array_extent(3)?;
        projected.add_string("x")?;
        projected.add_value(&true)?;
        projected.add_value(&Option::<bool>::None)?;
        projected.add_field("b")?;
        projected.add_object()?;
        let projected = projected.finish(usize::MAX)?;
        assert_eq!(actual.serialized_value_nodes, 8);
        assert_eq!(actual.serialized_capacity_records, 6);
        assert_eq!(
            projected.serialized_value_nodes,
            actual.serialized_value_nodes
        );
        assert_eq!(
            projected.serialized_capacity_records,
            actual.serialized_capacity_records
        );
        Ok(())
    }

    #[test]
    fn scalar_and_string_events_remain_distinct_from_typed_wrapper_observation() -> TestResult {
        let numeric = actual_serialization_storage_data(
            &7u16,
            RetainedProtocolMetadataFacts::default(),
            usize::MAX,
        )?;
        assert_eq!(
            (
                numeric.serialized_value_nodes,
                numeric.serialized_capacity_records
            ),
            (1, 0)
        );
        let text = actual_serialization_storage_data(
            &"seven",
            RetainedProtocolMetadataFacts::default(),
            usize::MAX,
        )?;
        assert_eq!(
            (
                text.serialized_value_nodes,
                text.serialized_capacity_records
            ),
            (1, 1)
        );
        Ok(())
    }
}
