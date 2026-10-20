//! Names downstream traversal controls after actual RawValue expansion.
//!
//! Reset-parser controls do not fund a later owned adapter, Value clone or Value
//! serializer. Each raw occurrence establishes its own reachable depth from the
//! original64 containers plus scalar leaf and the sum of actual reset layers.
//! These are declared layout controls, never physical process-stack permission.

use super::*;
use crate::protocol_snapshot::{
    raw_value_reparse::JsonValueReparseConstructionData, serde_decode_layout,
};
use std::mem::size_of;

/// Names the real layout-calculation and caller-owned quote controls.
pub(super) fn counter_scratch_data() -> usize {
    MetadataObserver::native_import18_json_profile_counter_scratch_data()
        + size_of::<&JsonValueReparseConstructionData>()
        + size_of::<usize>() * 8
        + size_of::<[usize; 6]>()
        + size_of::<[usize; 7]>()
        + size_of::<&[usize]>()
        + size_of::<&usize>()
        + size_of::<Option<usize>>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<Result<usize, ProviderError>>()
}

/// Prices the actual expanded typed/clone/serialization traversal frames.
pub(super) fn expanded_scratch_data(
    extra: &JsonValueReparseConstructionData,
) -> Result<usize, ProviderError> {
    let depth = extra
        .maximum_parser_layers_data()
        .checked_mul(128)
        .and_then(|layers| layers.checked_add(65))
        .ok_or_else(credit)?;
    let recursive = sum(&[
        serde_decode_layout::owned_value_frame_counter_scratch_data(),
        serde_decode_layout::content_frame_counter_scratch_data(),
        clone_frame_data(),
        value_equality_frame_data(),
        value_reencoding_frame_data(),
        json_serialization_frame_data(),
        MetadataObserver::native_import18_json_metadata_frame_counter_scratch_data(),
    ])?;
    let traversals = depth.checked_mul(recursive).ok_or_else(credit)?;

    // Canonical JCS itself rejects the65th container. Its exact65-frame fixed
    // supplier remains sufficient even when a preceding clone/to_value pass
    // traversed a deeper expanded tree before reaching that refusal.
    sum(&[
        counter_scratch_data(),
        traversals,
        serde_decode_layout::text_counter_scratch_data(),
        canonical::canonical_json_counter_scratch_bytes_data(),
        canonical::json_parse_counter_scratch_bytes_data(),
        wrapper_partial_controls_data(),
    ])
}

fn clone_frame_data() -> usize {
    size_of::<Value>()
        + size_of::<Option<Value>>()
        + size_of::<Vec<Value>>()
        + size_of::<serde_json::Map<String, Value>>()
        + size_of::<String>()
        + size_of::<(String, Value)>()
        + size_of::<Option<(String, Value)>>()
        + size_of::<std::slice::Iter<'static, Value>>()
        + size_of::<serde_json::map::Iter<'static>>()
        + size_of::<std::collections::btree_map::Iter<'static, String, Value>>()
        + size_of::<Option<&Value>>()
        + size_of::<&Value>()
        + size_of::<usize>()
}

// The pinned serde_json1.0.150 Value derives PartialEq. Its Vec branch uses
// Rust1.98.1's index-based slice equality; the selected Map uses BTreeMap::eq
// and its zipped borrowed entries. These are separate from clone/serde frames
// and establish requested layout only, never physical process-stack safety.
fn value_equality_frame_data() -> usize {
    type Entry = (&'static String, &'static Value);
    type Iter = std::collections::btree_map::Iter<'static, String, Value>;

    2 * size_of::<&Value>()
        + 2 * size_of::<std::mem::Discriminant<Value>>()
        + 2 * size_of::<Option<&Value>>()
        + 2 * size_of::<&bool>()
        + 2 * size_of::<&serde_json::Number>()
        + 2 * size_of::<&String>()
        + 2 * size_of::<&Vec<Value>>()
        + 2 * size_of::<&serde_json::Map<String, Value>>()
        + 2 * size_of::<&[Value]>()
        + 2 * size_of::<*const Value>()
        + 2 * size_of::<usize>()
        + 2 * size_of::<Option<&Value>>()
        + size_of::<std::iter::Zip<Iter, Iter>>()
        + 2 * size_of::<Entry>()
        + 2 * size_of::<Option<Entry>>()
        + size_of::<Option<(Entry, Entry)>>()
        + 2 * size_of::<&str>()
        + 2 * size_of::<&[u8]>()
        + 2 * size_of::<usize>()
        + 2 * size_of::<f64>()
        + 2 * size_of::<u64>()
        + 2 * size_of::<i64>()
        + size_of::<bool>()
}

fn envelope_equality_controls_data() -> usize {
    type Fields = (
        &'static String,
        &'static MessageKind,
        &'static Nullable<Id>,
        &'static Nullable<Id>,
        &'static Nullable<Id>,
        &'static Nullable<Id>,
        &'static Nullable<Id>,
        &'static Nullable<Id>,
        &'static Nullable<Id>,
        &'static U64,
        &'static Method,
        &'static serde_json::Map<String, Value>,
        &'static Extensions,
    );

    size_of::<(&Envelope, &Envelope)>()
        + size_of::<(Fields, Fields)>()
        + 2 * size_of::<&Option<Id>>()
        + 2 * size_of::<&Id>()
        + 2 * size_of::<Option<&Id>>()
        + size_of::<bool>()
}

fn value_reencoding_frame_data() -> usize {
    use serde::Serializer;
    type S = serde_json::value::Serializer;

    size_of::<S>()
        + size_of::<<S as Serializer>::SerializeSeq>()
        + size_of::<<S as Serializer>::SerializeMap>()
        + size_of::<<S as Serializer>::SerializeStruct>()
        + size_of::<<S as Serializer>::SerializeTuple>()
        + size_of::<<S as Serializer>::SerializeTupleVariant>()
        + size_of::<<S as Serializer>::SerializeStructVariant>()
        + size_of::<Value>()
        + size_of::<Result<Value, serde_json::Error>>()
        + size_of::<std::slice::Iter<'static, Value>>()
        + size_of::<serde_json::map::Iter<'static>>()
        + size_of::<Option<&Value>>()
        + 2 * size_of::<&Value>()
}

fn json_serialization_frame_data() -> usize {
    use serde::Serializer;
    type Writer = serde_json::Serializer<&'static mut Vec<u8>>;
    type S = &'static mut Writer;

    size_of::<Writer>()
        + size_of::<<S as Serializer>::SerializeSeq>()
        + size_of::<<S as Serializer>::SerializeMap>()
        + size_of::<<S as Serializer>::SerializeStruct>()
        + size_of::<<S as Serializer>::SerializeTuple>()
        + size_of::<<S as Serializer>::SerializeTupleVariant>()
        + size_of::<<S as Serializer>::SerializeStructVariant>()
        + size_of::<Result<(), serde_json::Error>>()
        + size_of::<std::slice::Iter<'static, Value>>()
        + size_of::<serde_json::map::Iter<'static>>()
        + size_of::<Option<&Value>>()
        + 2 * size_of::<&Value>()
}

fn wrapper_partial_controls_data() -> usize {
    // The Envelope visitor has13 exact required fields. ResponseShape's tagged
    // buffer and recursive Value descendants use the depth-priced Content
    // controls above; these are its independent outer return/visitor slots.
    type EnvelopeFields = (
        Option<String>,
        Option<MessageKind>,
        Option<Nullable<Id>>,
        Option<Nullable<Id>>,
        Option<Nullable<Id>>,
        Option<Nullable<Id>>,
        Option<Nullable<Id>>,
        Option<Nullable<Id>>,
        Option<Nullable<Id>>,
        Option<U64>,
        Option<Method>,
        Option<serde_json::Map<String, Value>>,
        Option<Extensions>,
    );

    size_of::<EnvelopeFields>()
        + envelope_equality_controls_data()
        + size_of::<Option<Envelope>>()
        + size_of::<Result<Envelope, serde_json::Error>>()
        + size_of::<RequestBody>()
        + size_of::<ResponseBody>()
        + size_of::<Result<ResponseBody, ProviderError>>()
        + size_of::<ResponseShape>()
        + size_of::<PacketNativeImport17PrepareReceipt>()
        + size_of::<Result<PacketNativeImport17PrepareReceipt, serde_json::Error>>()
        + size_of::<PacketNativeImport17CommitReceipt>()
        + size_of::<Result<PacketNativeImport17CommitReceipt, serde_json::Error>>()
        + size_of::<crate::connection::ReceivedFrame>()
        + size_of::<Result<crate::connection::ReceivedFrame, ProviderError>>()
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |total, value| {
        total.checked_add(*value).ok_or_else(credit)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_snapshot::raw_value_reparse::quote_value_data;

    #[test]
    fn actual_reserved_raw_layer_prices_later_owned_and_clone_frames() {
        let ordinary = serde_json::json!({"payload": "[null]"});
        let reserved = serde_json::json!({"$serde_json::private::RawValue": "[null]"});
        let ordinary = quote_value_data(&ordinary, usize::MAX).unwrap();
        let reserved = quote_value_data(&reserved, usize::MAX).unwrap();

        assert_eq!(ordinary.maximum_parser_layers_data(), 0);
        assert!(reserved.maximum_parser_layers_data() > 0);
        assert!(
            expanded_scratch_data(&reserved).unwrap() > expanded_scratch_data(&ordinary).unwrap()
        );
    }
}
