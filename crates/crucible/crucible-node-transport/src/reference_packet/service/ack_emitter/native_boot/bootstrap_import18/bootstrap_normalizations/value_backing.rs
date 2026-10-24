//! Bounds the retained Value actually constructed by the closed serializers.
//!
//! The generic storage report also prices a growable strict parser. This path
//! invokes serde_json::to_value instead: strings are copied directly and arrays
//! use their exact hints or geometric growth. Parser banks are not allocated.

use super::*;
use crate::retained_metadata::serialization_storage::original_serialization_tree_node_requested_bytes_data;

/// Bounds the complete currently retained DOM, independently of canonical work.
///
/// For a JSON tree, values = 1 + array elements + object members. The visitor's
/// node count also includes each string key, so members = (nodes - 1 - elements)
/// / 2. The ordinary census prices one node per member plus possible empty
/// roots. Capacity records minus array containers count all keys, string values
/// and object roots, conservatively including extra roots for string values.
/// Encoded JSON bounds the total copied UTF-8 string bytes.
/// An array's retained capacity is bounded by twice its element count plus its
/// four-slot growth minimum. The four closed native views supply accurate
/// sequence hints; their retained Value children do too.
///
/// # Errors
/// Refuses inconsistent tree populations, layout refusal or checked overflow.
pub(super) fn requested_data(shape: &Shape) -> Result<usize, ProviderError> {
    let keyed = shape
        .serialized_value_nodes
        .checked_sub(1)
        .and_then(|nodes| nodes.checked_sub(shape.sequence_elements))
        .ok_or_else(exhausted)?;
    if keyed % 2 != 0 {
        return Err(exhausted());
    }
    let members = keyed / 2;
    let tree = original_serialization_tree_node_requested_bytes_data::<String, Value>()?;
    let roots_and_entries = shape
        .serialized_capacity_records
        .checked_sub(shape.sequence_containers)
        .ok_or_else(exhausted)?;
    if roots_and_entries < members {
        return Err(exhausted());
    }
    let maps = roots_and_entries.checked_mul(tree).ok_or_else(exhausted)?;
    let arrays = shape
        .sequence_elements
        .checked_mul(2)
        .and_then(|slots| {
            shape
                .sequence_containers
                .checked_mul(4)
                .and_then(|minimum| slots.checked_add(minimum))
        })
        .and_then(|slots| slots.checked_mul(size_of::<Value>()))
        .ok_or_else(exhausted)?;
    [
        size_of::<Value>(),
        shape.maximum_encoded_bytes,
        maps,
        arrays,
    ]
    .into_iter()
    .try_fold(0usize, |sum, field| {
        sum.checked_add(field).ok_or_else(exhausted)
    })
}

/// Names concrete recursive Value serializer controls within the closed depth.
///
/// # Errors
/// Refuses checked accumulation overflow.
pub(super) fn serializer_counter_scratch_data() -> Result<usize, ProviderError> {
    type Serializer = serde_json::value::Serializer;
    let compound = [
        size_of::<<Serializer as serde::Serializer>::SerializeSeq>(),
        size_of::<<Serializer as serde::Serializer>::SerializeTuple>(),
        size_of::<<Serializer as serde::Serializer>::SerializeTupleStruct>(),
        size_of::<<Serializer as serde::Serializer>::SerializeTupleVariant>(),
        size_of::<<Serializer as serde::Serializer>::SerializeMap>(),
        size_of::<<Serializer as serde::Serializer>::SerializeStruct>(),
        size_of::<<Serializer as serde::Serializer>::SerializeStructVariant>(),
    ]
    .into_iter()
    .max()
    .ok_or_else(exhausted)?;
    let frame = [
        compound,
        size_of::<Result<Value, serde_json::Error>>(),
        size_of::<&Value>(),
        size_of::<&str>(),
        size_of::<Result<(), serde_json::Error>>(),
    ]
    .into_iter()
    .try_fold(0usize, |sum, field| {
        sum.checked_add(field).ok_or_else(exhausted)
    })?;
    // The shape visitor admits at most 64 containers and one terminal scalar.
    frame
        .checked_mul(65)
        .and_then(|frames| frames.checked_add(size_of::<[usize; 7]>() + size_of::<[usize; 5]>()))
        .ok_or_else(exhausted)
}
