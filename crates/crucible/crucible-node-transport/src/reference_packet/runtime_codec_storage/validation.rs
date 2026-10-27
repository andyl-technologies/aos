//! Prices the concrete Native18 validation serializers after payload decoding.
//!
//! Restore, Prepare and Commit validation each serialize a typed request into a
//! Value and canonicalize it. Binding authentication repeats the Prepare pass
//! before hashing its bytes. These passes finish sequentially; their one funded
//! window is independent of the still-live decoded payload and schema factory.

use super::*;
use crate::reference_packet::service::{
    PacketNative5SerializedCreditFailureStorage, PacketNative5SourceLaunch,
    original_import18_serialized_credit_failure_counter_scratch_data,
};
use crate::retained_metadata::serialization_storage::{
    OriginalJsonValueStorageExtentData, original_json_value_storage_extent_counter_scratch_data,
    original_json_value_storage_extent_data,
};
use crucible_node_format::{ContractError, canonical};
use serde::Serializer;
use serde_json::Value;

/// Bounds one actual validation window without constructing a request or DOM.
///
/// # Errors
/// Refuses unsupported pinned geometry or checked requested-storage overflow.
pub(super) fn storage_data(frame: usize) -> Result<usize, ProviderError> {
    let extent = original_json_value_storage_extent_data(serialized_extent_data(frame)?)?;
    let (credit_failure, _) =
        PacketNative5SourceLaunch::original_import18_serialized_credit_failure_construction_data(
            usize::MAX,
        )?;
    add(extent.canonical_pass_requested_bytes()?, credit_failure)
}

/// Allows the actual field syntax introduced by positional record decoding.
///
/// The closed graph has no arbitrary typed Serialize implementation or growing
/// typed collection. Its strings, literal maps and normalized Bytes come from
/// the bounded input. Records can accept positional sequences and later emit
/// named fields: the recursive field/type/variant roster pays that additional
/// syntax independently, including every element of fixed arrays. Map-only
/// records already include their names in the input, so this remains additive.
///
/// # Errors
/// Refuses checked addition overflow.
pub(super) fn serialized_extent_data(frame: usize) -> Result<usize, ProviderError> {
    add(frame, fields::NAME_BYTES)
}

/// Names actual serializer compounds, canonical controls and hash views.
pub(super) fn counter_scratch_data() -> usize {
    type ValueSerializer = serde_json::value::Serializer;

    // These public associated types are the pinned to_value serializer's real
    // private container states. Every container activation has its own view;
    // the complete heap DOM and its scalar/base64 formatter work are covered
    // separately by the lexical extent. The strict input admits 64 containers
    // and the canonical writer can enter its next refusing activation.
    let frame = size_of::<ValueSerializer>()
        + size_of::<<ValueSerializer as Serializer>::SerializeSeq>()
        + size_of::<<ValueSerializer as Serializer>::SerializeTuple>()
        + size_of::<<ValueSerializer as Serializer>::SerializeTupleStruct>()
        + size_of::<<ValueSerializer as Serializer>::SerializeTupleVariant>()
        + size_of::<<ValueSerializer as Serializer>::SerializeMap>()
        + size_of::<<ValueSerializer as Serializer>::SerializeStruct>()
        + size_of::<<ValueSerializer as Serializer>::SerializeStructVariant>()
        + size_of::<&Value>()
        + size_of::<serde_json::map::Iter<'static>>()
        + size_of::<std::slice::Iter<'static, Value>>()
        + size_of::<Result<Value, serde_json::Error>>()
        + size_of::<Result<(), serde_json::Error>>();

    65 * frame
        + canonical::canonical_json_counter_scratch_bytes_data()
        + crate::connection::original_serialized_credit_counter_scratch_data()
        + original_import18_serialized_credit_failure_counter_scratch_data()
        + original_json_value_storage_extent_counter_scratch_data()
        + size_of::<OriginalJsonValueStorageExtentData>()
        + size_of::<Result<OriginalJsonValueStorageExtentData, ProviderError>>()
        + size_of::<Value>()
        + size_of::<Vec<u8>>()
        + size_of::<String>()
        + size_of::<Result<Vec<u8>, ContractError>>()
        + size_of::<Result<Vec<u8>, ProviderError>>()
        + size_of::<Result<(usize, usize), ProviderError>>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<&[u8; 32]>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<[usize; 2]>()
        + 4 * size_of::<usize>()
}
