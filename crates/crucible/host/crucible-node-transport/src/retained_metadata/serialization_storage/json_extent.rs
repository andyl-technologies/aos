//! Preserves the independent actual-Transport JSON extent oracles.

use super::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained_metadata::{
        MetadataObserver, requested_storage::requested_metadata_backing_storage_data,
    };
    use crucible_node_format::canonical;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn logical_values(value: &serde_json::Value) -> usize {
        match value {
            serde_json::Value::Array(values) => {
                1 + values.iter().map(logical_values).sum::<usize>()
            }
            serde_json::Value::Object(values) => {
                1 + values.len() + values.values().map(logical_values).sum::<usize>()
            }
            _ => 1,
        }
    }

    fn verify(bytes: &[u8]) -> TestResult {
        let value = canonical::parse_json(bytes, bytes.len())?;
        let mut observer = MetadataObserver::new();
        observer.observe(&value)?;
        let facts = observer.finish();
        let bound = original_json_value_storage_extent_data(bytes.len())?;
        let backing = requested_metadata_backing_storage_data(&facts)?;
        let encoded = canonical::canonical_json(&value)?;

        assert!(backing <= bound.value_dom_requested_bytes);
        assert!(encoded.len() <= bound.maximum_canonical_encoded_bytes);
        assert!(logical_values(&value) <= bound.maximum_value_nodes);
        assert!(facts.tree_entries <= bound.maximum_object_members);
        assert!(facts.string_capacity_bytes <= bound.value_dom_requested_bytes);
        Ok(())
    }

    #[test]
    fn real_dense_arrays_maps_escapes_numbers_and_empty_containers_fit() -> TestResult {
        for input in [
            b"0".as_slice(),
            b"[]",
            b"{}",
            b"[0,0,0,0,0,0,0,0]",
            br#"{"":0,"a":[],"b":{},"c":["",0],"d":1.0}"#,
            br#"{"quoted":"\u0000\n\"\\\uD834\uDD1E","number":1e+308}"#,
            br#"[[[[[[[[]]]]]]]]"#,
        ] {
            verify(input)?;
        }
        Ok(())
    }

    #[test]
    fn zero_and_checked_overflow_refuse_without_allocating_a_shape() {
        assert!(original_json_value_storage_extent_data(0).is_err());
        assert!(original_json_value_storage_extent_data(usize::MAX).is_err());
        assert!(original_json_value_storage_extent_data(usize::MAX / 32).is_err());
    }
}
