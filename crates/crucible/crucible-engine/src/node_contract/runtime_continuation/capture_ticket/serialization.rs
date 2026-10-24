//! Adapts the shared serializer geometry to the original runtime's closed DTO size.

use super::RuntimeError;
#[cfg(test)]
use super::value_layout;
use serde::Serialize;
#[cfg(test)]
use serde::ser::{self, SerializeSeq};

pub(super) use crucible_source_birth_data::serialization::{
    borrowed_constructor_geometry, counter_scratch_data, original_constructor_value_allocations,
    value_allocations,
};

pub(super) fn future_decode_allocations(
    value: &impl Serialize,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    crucible_source_birth_data::serialization::future_decode_allocations(
        value,
        maximum,
        crate::node_contract::NodeRuntime::capture_closed_inline_storage(),
    )
}

pub(super) fn original_constructor_and_decode_geometry(
    value: &impl Serialize,
    maximum_decode_slot: usize,
    maximum: usize,
) -> Result<(usize, usize), RuntimeError> {
    crucible_source_birth_data::serialization::original_constructor_and_decode_geometry(
        value,
        maximum_decode_slot,
        maximum,
        crate::node_contract::NodeRuntime::capture_closed_inline_storage(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    // Failed checked serialization is the assertion signal in these controls.
    #[allow(clippy::unwrap_used)]
    #[test]
    fn huge_sequence_hint_refuses_without_value_allocation() {
        struct HugeHint;
        impl Serialize for HugeHint {
            fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_seq(Some(usize::MAX))?.end()
            }
        }
        assert_eq!(
            value_allocations(&HugeHint, 4096),
            Err(RuntimeError::ResourceLimit)
        );
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn core_container_credit_covers_actual_retained_value_storage() {
        use super::super::owned::OwnedStorage;
        let input = vec![vec!["alpha", "beta"], vec!["gamma"]];
        let admitted = value_allocations(&input, 65536).unwrap();
        let value = serde_json::to_value(&input).unwrap();
        assert!(admitted >= value.owned_storage().unwrap());
        assert_eq!(
            value_allocations(&input, admitted - 1),
            Err(RuntimeError::ResourceLimit)
        );
    }
}

#[cfg(test)]
mod original_constructor_controls {
    use super::super::owned::OwnedStorage;
    use super::*;
    #[test]
    fn selected_constructor_quotes_real_dom_canonical_and_collect_banks() {
        let values: std::collections::BTreeMap<String, bool> = (0..512)
            .map(|n| (format!("field-{n:04}"), n % 2 == 0))
            .collect();
        let requested = original_constructor_value_allocations(&values, usize::MAX).unwrap();
        let value = serde_json::to_value(&values).unwrap();
        let canonical = crucible_node_format::canonical::canonical_json(&value).unwrap();
        let objects = value.as_object().unwrap();
        let ordered: Vec<_> = objects
            .iter()
            .map(|(key, value)| {
                (
                    key.encode_utf16().collect::<Vec<_>>(),
                    (key.as_str(), value),
                )
            })
            .collect();
        let actual = value
            .owned_storage()
            .unwrap()
            .checked_add(canonical.capacity())
            .unwrap()
            .checked_add(ordered.capacity() * std::mem::size_of_val(&ordered[0]))
            .unwrap();
        assert!(requested >= actual);
        assert_eq!(
            original_constructor_value_allocations(&values, requested).unwrap(),
            requested
        );
        assert!(original_constructor_value_allocations(&values, requested - 1).is_err());
    }

    #[test]
    fn selected_scalar_output_is_counted_without_changing_ordinary_counter() {
        assert_eq!(value_allocations(&true, usize::MAX).unwrap(), 0);
        let value = serde_json::to_value(true).unwrap();
        let output = crucible_node_format::canonical::canonical_json(&value).unwrap();
        assert!(
            original_constructor_value_allocations(&true, usize::MAX).unwrap() >= output.capacity()
        );
    }
}

#[cfg(test)]
mod selected_decode_geometry_tests {
    use super::*;

    #[test]
    fn empty_selected_objects_keep_independent_dom_and_typed_roots() {
        let value = serde_json::json!({});
        let ordinary_before = value_allocations(&value, usize::MAX).unwrap();
        let (small, encoded) =
            original_constructor_and_decode_geometry(&value, 1, usize::MAX).unwrap();
        let (larger, same_encoded) =
            original_constructor_and_decode_geometry(&value, 33, usize::MAX).unwrap();
        let roots = std::mem::size_of::<serde_json::Map<String, serde_json::Value>>()
            + value_layout::value_slot_bytes()
            + 1;

        assert!(small >= ordinary_before + roots);
        assert_eq!(larger - small, 32);
        assert_eq!(encoded, same_encoded);
        assert_eq!(
            original_constructor_and_decode_geometry(&value, 1, small).unwrap(),
            (small, encoded)
        );
        assert!(original_constructor_and_decode_geometry(&value, 1, small - 1).is_err());
        assert!(original_constructor_and_decode_geometry(&value, 0, usize::MAX).is_err());
        assert_eq!(
            value_allocations(&value, usize::MAX).unwrap(),
            ordinary_before
        );
    }
}

#[cfg(test)]
mod selected_map_root_controls {
    use super::*;
    use crate::node_contract::runtime_owned_counter::OwnedStorage;

    #[test]
    fn selected_empty_and_nested_objects_cover_actual_retained_value_roots() {
        let empty = serde_json::json!({});
        let nested = serde_json::json!({"map": {}, "array": [{}, {"inner": {}}]});

        for value in [empty, nested] {
            let actual = value.owned_storage().unwrap();
            let (requested, encoded) = original_constructor_and_decode_geometry(
                &value,
                std::mem::size_of::<serde_json::Value>(),
                usize::MAX,
            )
            .unwrap();
            let bytes = crucible_node_format::canonical::canonical_json(&value).unwrap();

            assert!(actual >= value_layout::map_node_bytes());
            assert!(requested >= actual + value_layout::value_slot_bytes());
            assert!(encoded >= bytes.len());
            assert_eq!(
                original_constructor_and_decode_geometry(
                    &value,
                    std::mem::size_of::<serde_json::Value>(),
                    requested,
                )
                .unwrap(),
                (requested, encoded)
            );
            assert!(
                original_constructor_and_decode_geometry(
                    &value,
                    std::mem::size_of::<serde_json::Value>(),
                    requested - 1,
                )
                .is_err()
            );
        }
    }
}

#[cfg(test)]
mod borrowed_constructor_geometry_tests {
    use super::*;

    #[test]
    fn borrowed_geometry_preserves_constructor_cost_and_bounds_actual_encoding() {
        for value in [
            serde_json::json!({}),
            serde_json::json!({"nested": ["quote\"\n", {"unicode": "δ"}], "count": 13}),
        ] {
            let original = original_constructor_value_allocations(&value, usize::MAX).unwrap();
            let (requested, encoded) = borrowed_constructor_geometry(&value, usize::MAX).unwrap();
            let actual = crucible_node_format::canonical::canonical_json(&value).unwrap();

            assert_eq!(requested, original);
            assert!(encoded >= actual.len());
            assert_eq!(
                borrowed_constructor_geometry(&value, requested).unwrap(),
                (requested, encoded)
            );
            assert!(borrowed_constructor_geometry(&value, requested - 1).is_err());
            assert_eq!(
                original_constructor_value_allocations(&value, usize::MAX).unwrap(),
                original
            );
        }
    }
}
