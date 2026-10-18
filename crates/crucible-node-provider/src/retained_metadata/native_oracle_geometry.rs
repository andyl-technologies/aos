//! Names concrete nested layouts for original native Oracle body construction.
//!
//! These are allocation DATA, independent of the live receipt validator. The
//! caller counts actual retained JSON occurrences before parsing and separately
//! funds semantic validators, schema factories, keys and Source currentness.

use std::mem::size_of;

use crucible_node_contract::{
    ArtifactIdentity, Bytes, ContentRef, Event, FacetSelection, HashRef, Id, NodeBinding,
    ObservationBatch, Position, SchemaRef, U64,
};
use serde_json::Value;

use super::RetainedProtocolMetadataFacts;
use super::serialization_storage::{
    actual_serialization_storage_data, original_serialization_counter_scratch_data,
    original_serialization_tree_node_counter_scratch_data,
    original_serialization_tree_node_requested_bytes_data,
};
use crate::ProviderError;
use crate::input_commit::CommittedDeliveryV1;
use crate::reference_packet::connected::{
    PacketConnectedPublication, PacketDeliveredInput, PacketPendingPublication, PacketReaction,
};
use crate::reference_packet::{PacketEvent, PacketPublication};

// The pinned internally tagged request/result profiles buffer these actual
// sequence and map elements. An upgrade must recheck this concrete roster.
type SerdeContent = serde::__private228::de::Content<'static>;

/// Reports exact largest nested array/tree requests in the closed body family.
///
/// Opaque root headers never substitute for this roster. Native producer and
/// reactive records, Stage/Commit records, baseline decode_request/response and
/// their dynamic Value fields retain these concrete nested container elements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalNativeOracleTypedLayoutsData {
    /// Bounds a concrete nested array element, excluding its child backing.
    pub maximum_array_element_bytes: usize,
    /// Retains the greatest alignment of those actual elements.
    pub maximum_array_element_alignment: usize,
    /// Bounds actual pinned tree-node requests, including validation uniqueness.
    pub maximum_tree_node_bytes: usize,
}

/// Computes the closed actual nested layout roster without constructing a DTO.
///
/// Strings and Bytes use u8 backing. Native2/4 records retain PacketEvent,
/// PacketPublication and the four reactive row types. Stage also retains
/// CommittedDeliveryV1, Position and Bytes vectors. Baseline bodies add the
/// binding, schema and observation vectors; arbitrary extensions retain Value.
///
/// # Errors
/// Refuses overflow or an unsupported pinned tree-node layout.
pub fn original_native_oracle_typed_layouts_data()
-> Result<OriginalNativeOracleTypedLayoutsData, ProviderError> {
    let elements = [
        std::alloc::Layout::new::<u8>(),
        std::alloc::Layout::new::<Value>(),
        std::alloc::Layout::new::<Id>(),
        std::alloc::Layout::new::<NodeBinding>(),
        std::alloc::Layout::new::<HashRef>(),
        std::alloc::Layout::new::<ContentRef>(),
        std::alloc::Layout::new::<ObservationBatch>(),
        std::alloc::Layout::new::<Event>(),
        std::alloc::Layout::new::<FacetSelection>(),
        std::alloc::Layout::new::<ArtifactIdentity>(),
        std::alloc::Layout::new::<SchemaRef>(),
        std::alloc::Layout::new::<PacketEvent>(),
        std::alloc::Layout::new::<PacketPublication>(),
        std::alloc::Layout::new::<PacketReaction>(),
        std::alloc::Layout::new::<PacketDeliveredInput>(),
        std::alloc::Layout::new::<PacketPendingPublication>(),
        std::alloc::Layout::new::<PacketConnectedPublication>(),
        std::alloc::Layout::new::<SerdeContent>(),
        std::alloc::Layout::new::<(SerdeContent, SerdeContent)>(),
        std::alloc::Layout::new::<CommittedDeliveryV1>(),
        std::alloc::Layout::new::<Position>(),
        std::alloc::Layout::new::<Bytes>(),
        std::alloc::Layout::new::<String>(),
        std::alloc::Layout::new::<crucible_node_contract::NodeManifest>(),
        std::alloc::Layout::new::<crucible_node_contract::NodeDescriptor>(),
        std::alloc::Layout::new::<crucible_node_contract::OwnerRef>(),
        std::alloc::Layout::new::<crucible_node_contract::OwnerBinding>(),
        std::alloc::Layout::new::<crucible_node_contract::PortDescriptor>(),
        std::alloc::Layout::new::<crucible_node_contract::LaneDescriptor>(),
        std::alloc::Layout::new::<crucible_node_contract::NodeBindingRef>(),
        std::alloc::Layout::new::<crucible_node_contract::ConnectionDescriptor>(),
        std::alloc::Layout::new::<crate::handshake::ResumedOperation>(),
    ];
    let mut maximum_array_element_bytes = 0;
    let mut maximum_array_element_alignment = 1;
    for element in elements {
        maximum_array_element_bytes = maximum_array_element_bytes.max(element.size());
        maximum_array_element_alignment = maximum_array_element_alignment.max(element.align());
    }
    let value_tree = original_serialization_tree_node_requested_bytes_data::<String, Value>()?;
    let sequence_tree = original_serialization_tree_node_requested_bytes_data::<(&Id, U64), ()>()?;
    Ok(OriginalNativeOracleTypedLayoutsData {
        maximum_array_element_bytes,
        maximum_array_element_alignment,
        maximum_tree_node_bytes: value_tree.max(sequence_tree),
    })
}

/// Bounds an independently decoded cached Value body without allocating it.
///
/// Only serde_json::Value is accepted, so this actual visit cannot invoke a
/// custom Bytes/U64 serializer. Its logical events bound concrete closed DTO
/// array/tree requests while its parser pool retains actual string extents.
/// This row includes Value clone/rebuild and typed container phases; it grants
/// no decoding or native meaning and excludes schema/semantic validators.
///
/// # Errors
/// Refuses excessive nesting, arithmetic overflow or the supplied storage bound.
pub fn original_native_oracle_value_decode_storage_data(
    value: &Value,
    maximum: usize,
) -> Result<usize, ProviderError> {
    value_decode(value, maximum)
}

/// Bounds a cached baseline body map through the same Value-only visitor.
///
/// # Errors
/// Refuses excessive nesting, checked arithmetic or the supplied storage bound.
pub fn original_native_oracle_body_decode_storage_data(
    body: &serde_json::Map<String, Value>,
    maximum: usize,
) -> Result<usize, ProviderError> {
    value_decode(body, maximum)
}

fn value_decode(value: &impl serde::Serialize, maximum: usize) -> Result<usize, ProviderError> {
    let row = actual_serialization_storage_data(
        value,
        RetainedProtocolMetadataFacts::default(),
        maximum,
    )?;
    let layouts = original_native_oracle_typed_layouts_data()?;
    let arrays = row
        .sequence_elements
        .checked_add(row.sequence_containers)
        .and_then(|n| n.checked_mul(4))
        .and_then(|n| n.checked_mul(layouts.maximum_array_element_bytes))
        .ok_or_else(exhausted)?;
    // Each visited node/key may conservatively be an independent typed object
    // entry. The factor2 covers root/split requests, not a raw-byte multiplier.
    let trees = row
        .serialized_value_nodes
        .checked_mul(2)
        .and_then(|n| n.checked_mul(layouts.maximum_tree_node_bytes))
        .ok_or_else(exhausted)?;
    [
        row.projected_parser_requested_bytes,
        row.retained_value_backing_bytes,
        arrays,
        trees,
    ]
    .into_iter()
    .try_fold(0usize, |sum, term| {
        sum.checked_add(term)
            .filter(|sum| *sum <= maximum)
            .ok_or_else(exhausted)
    })
}

/// Names concrete layout, Value visitor and scalar/result control frames.
pub fn original_native_oracle_geometry_counter_scratch_data() -> usize {
    crate::protocol_snapshot::owned11::typed::Fields::counter_scratch_data()
        + crate::protocol_snapshot::raw_value_reparse::raw_scanner_counter_scratch_data()
        + crate::protocol_snapshot::raw_value_reparse::value_scanner_counter_scratch_data()
        + size_of::<crate::protocol_snapshot::raw_value_reparse::JsonValueReparseConstructionData>()
        + size_of::<
            Result<
                crate::protocol_snapshot::raw_value_reparse::JsonValueReparseConstructionData,
                ProviderError,
            >,
        >()
        + original_serialization_counter_scratch_data()
        + original_serialization_tree_node_counter_scratch_data()
        + size_of::<OriginalNativeOracleTypedLayoutsData>()
        + size_of::<Result<OriginalNativeOracleTypedLayoutsData, ProviderError>>()
        + size_of::<[std::alloc::Layout; 32]>()
        + size_of::<std::array::IntoIter<std::alloc::Layout, 32>>()
        + super::serialization_storage::original_json_value_storage_extent_counter_scratch_data()
        + size_of::<&crate::protocol_snapshot::raw_value_reparse::JsonValueReparseConstructionData>(
        )
        + size_of::<super::serialization_storage::OriginalJsonValueStorageExtentData>()
        + size_of::<
            Result<super::serialization_storage::OriginalJsonValueStorageExtentData, ProviderError>,
        >()
        + size_of::<(usize, usize, usize)>()
        + size_of::<Result<(usize, usize, usize), ProviderError>>()
        + size_of::<Option<usize>>()
        + size_of::<&OriginalNativeOracleTypedLayoutsData>()
        + 9 * size_of::<usize>()
        + size_of::<[usize; 4]>()
        + size_of::<std::array::IntoIter<usize, 4>>()
        + size_of::<&Value>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<[&str; 2]>()
        + size_of::<std::array::IntoIter<&str, 2>>()
        + size_of::<Option<&[u8]>>()
        + size_of::<Result<Option<&[u8]>, ProviderError>>()
        + size_of::<Result<&str, ProviderError>>()
        + size_of::<Result<bool, ProviderError>>()
        + 5 * size_of::<usize>()
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("original native Oracle body geometry")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_stage_elements_and_alignments_are_real_roster_members() {
        let layouts = original_native_oracle_typed_layouts_data().unwrap();
        assert!(layouts.maximum_array_element_bytes >= size_of::<CommittedDeliveryV1>());
        assert!(
            layouts.maximum_array_element_alignment >= std::mem::align_of::<CommittedDeliveryV1>()
        );
        assert!(layouts.maximum_array_element_bytes >= size_of::<PacketConnectedPublication>());
    }

    #[test]
    fn actual_value_decode_quote_is_bounded_before_construction() {
        let value = serde_json::json!({"nested": [{"empty": []}], "payload": "AQID"});
        let exact = original_native_oracle_value_decode_storage_data(&value, usize::MAX).unwrap();
        assert!(exact > 0);
        assert!(original_native_oracle_value_decode_storage_data(&value, exact).is_ok());
        assert!(original_native_oracle_value_decode_storage_data(&value, exact - 1).is_err());
    }
}

/// Compares all cached reference fields without hashing or decoding a DTO.
pub fn original_native_oracle_value_reference_matches_data(
    value: &Value,
    expected: &ContentRef,
) -> bool {
    crate::reference_packet::service::capture_allocation::
        original_capture_allocation_reference_matches_data(value, expected)
}

/// Borrows the native_record full reference from one actual response-selected receipt.
///
/// Only the two actual complete receipt shapes are inspected. No referenced
/// object is fetched, verified or accepted as a native record by this loan.
///
/// # Errors
/// Refuses malformed canonical framing, duplicate fields or an absent reference.
pub fn original_native_oracle_underlying_reference_data(
    receipt: &[u8],
) -> Result<&[u8], ProviderError> {
    if let Some(reference) = raw_field(receipt, "native_record")? {
        return Ok(reference);
    }
    let native = raw_field(receipt, "native")?.ok_or_else(exhausted)?;
    raw_field(native, "native_record")?.ok_or_else(exhausted)
}

/// Compares the complete raw reference to a retained dictionary reference.
///
/// # Errors
/// Refuses malformed canonical framing or unsupported escaped scalar spelling.
pub fn original_native_oracle_raw_reference_matches_data(
    raw: &[u8],
    expected: &ContentRef,
) -> Result<bool, ProviderError> {
    use crate::protocol_snapshot::owned11::typed::{plain_string, unsigned};
    if raw_field_count(raw)? != 3 {
        return Ok(false);
    }
    let hash = raw_field(raw, "hash")?.ok_or_else(exhausted)?;
    if raw_field_count(hash)? != 3 {
        return Ok(false);
    }
    let algorithm = raw_field(hash, "algorithm")?.ok_or_else(exhausted)?;
    let domain = raw_field(hash, "domain")?.ok_or_else(exhausted)?;
    let digest = raw_field(hash, "digest")?.ok_or_else(exhausted)?;
    let length = raw_field(raw, "length")?.ok_or_else(exhausted)?;
    let media = raw_field(raw, "media_type")?.ok_or_else(exhausted)?;
    Ok(plain_string(algorithm)? == expected.hash.algorithm
        && plain_string(domain)? == expected.hash.domain
        && plain_string(digest)? == expected.hash.digest
        && unsigned(plain_string(length)?.as_bytes())? == expected.length.get()
        && plain_string(media)? == expected.media_type)
}

/// Refuses a reactive input journal before the initial-only witness constructor.
///
/// Producer pending events remain untouched. This is only a quote eligibility
/// cut; the real initial consumer independently checks all modeled inventory.
///
/// # Errors
/// Refuses malformed canonical framing or any retained reactive input reference.
pub fn original_native_oracle_initial_inputs_data(record: &[u8]) -> Result<(), ProviderError> {
    let inventory = raw_field(record, "inventory")?.ok_or_else(exhausted)?;
    for field in ["stages", "commits"] {
        if raw_field(inventory, field)?.is_some_and(|raw| raw != b"[]") {
            return Err(exhausted());
        }
    }
    Ok(())
}

fn raw_field<'a>(raw: &'a [u8], name: &str) -> Result<Option<&'a [u8]>, ProviderError> {
    use crate::protocol_snapshot::owned11::typed::{Fields, plain_string};
    let mut fields = Fields::object(raw)?;
    let mut selected = None;
    while let Some((key, value)) = fields.pair()? {
        if plain_string(key)? == name && selected.replace(value).is_some() {
            return Err(exhausted());
        }
    }
    fields.finish()?;
    Ok(selected)
}

#[cfg(test)]
mod raw_candidate_controls {
    use super::*;

    #[test]
    fn raw_reference_compares_full_identity_and_lends_same_original_span() {
        let reference = crucible_node_contract::canonical::content_ref(
            b"actual-original-native",
            "application/json",
        )
        .unwrap();
        let raw = crucible_node_contract::canonical::canonical_json(
            &serde_json::to_value(&reference).unwrap(),
        )
        .unwrap();
        assert!(original_native_oracle_raw_reference_matches_data(&raw, &reference).unwrap());
        let mut other = reference.clone();
        other.length = U64::new(reference.length.get() + 1);
        assert!(!original_native_oracle_raw_reference_matches_data(&raw, &other).unwrap());
        other = reference.clone();
        other.media_type = "application/octet-stream".to_owned();
        assert!(!original_native_oracle_raw_reference_matches_data(&raw, &other).unwrap());

        let receipt = format!(
            "{{\"native_record\":{}}}",
            std::str::from_utf8(&raw).unwrap()
        );
        let span = original_native_oracle_underlying_reference_data(receipt.as_bytes()).unwrap();
        assert_eq!(span, raw);
        assert!(std::ptr::eq(
            span.as_ptr(),
            receipt.as_bytes()[b"{\"native_record\":".len()..].as_ptr()
        ));
        assert!(original_native_oracle_underlying_reference_data(b"{\"native_record\":").is_err());
    }

    #[test]
    fn initial_input_cut_preserves_producer_pending_and_rejects_retained_stages() {
        let producer = br#"{"inventory":{"pending":[{"payload":"AQID"}]}}"#;
        assert!(original_native_oracle_initial_inputs_data(producer).is_ok());
        let reactive = br#"{"inventory":{"commits":[],"stages":[]}}"#;
        assert!(original_native_oracle_initial_inputs_data(reactive).is_ok());
        let active = br#"{"inventory":{"commits":[],"stages":[{}]}}"#;
        assert!(original_native_oracle_initial_inputs_data(active).is_err());
    }
}

fn raw_field_count(raw: &[u8]) -> Result<usize, ProviderError> {
    let mut fields = crate::protocol_snapshot::owned11::typed::Fields::object(raw)?;
    let mut count = 0usize;
    while fields.pair()?.is_some() {
        count = count.checked_add(1).ok_or_else(exhausted)?;
    }
    fields.finish()?;
    Ok(count)
}

/// Applies actual native typed/JCS layouts to additional reserved-key expansions.
///
/// The companion supplies EXTRA Value/parser/error ownership and logical event
/// extents. This adds the separate target DTO banks and later canonical pass;
/// baseline syntax and original owning roots remain independent caller rows.
///
/// # Errors
/// Refuses checked allocation/event arithmetic or the supplied whole-row bound.
pub fn original_native_oracle_expanded_decode_storage_data(
    extra: &crate::protocol_snapshot::raw_value_reparse::JsonValueReparseConstructionData,
    maximum: usize,
) -> Result<(usize, usize, usize), ProviderError> {
    let (retained, transient, scratch) = extra.requested_storage_data();
    let (nodes, members, text) = extra.expanded_json_extents_data();
    let layouts = original_native_oracle_typed_layouts_data()?;
    // Every expanded node can be an independent array or element. Four initial
    // slots bound the pinned minimum for non-byte elements; summed doubling
    // requests fit eight slots per possible container/element, including a
    // minimum request for an empty or one-element container. Byte-bank growth
    // is priced separately below.
    let arrays = nodes
        .checked_mul(8)
        .and_then(|n| n.checked_mul(layouts.maximum_array_element_bytes))
        .ok_or_else(exhausted)?;
    let trees = members
        .checked_mul(2)
        .and_then(|n| n.checked_mul(layouts.maximum_tree_node_bytes))
        .ok_or_else(exhausted)?;
    // Pinned RawVec byte banks request max(2 * old_capacity, required, 8).
    // Summed growth is bounded by 4 * text + 16 * independent banks, as in
    // raw_value_reparse::geometry::byte_bank_growth_data. Expanded nodes include
    // potential text/key owners, so two such envelopes give 8 * text + 32 * nodes:
    // an owned String (moved or cloned from Value) and a separate decoded Bytes
    // bank. Bytes::deserialize keeps its encoded String live while decoding.
    // The companion's initial reset-parser/Value owners are separate rows.
    let strings = text
        .checked_mul(8)
        .and_then(|n| nodes.checked_mul(32).and_then(|banks| n.checked_add(banks)))
        .ok_or_else(exhausted)?;
    let typed = arrays
        .checked_add(trees)
        .and_then(|n| n.checked_add(strings))
        .ok_or_else(exhausted)?;
    let canonical = if nodes == 0 {
        0
    } else {
        // This follows JSON's six-byte escaping and at-most36-byte scalar plus
        // delimiter grammar per actual expanded node, rather than a raw cap.
        let encoded = text
            .checked_mul(6)
            .and_then(|n| nodes.checked_mul(36).and_then(|nodes| n.checked_add(nodes)))
            .ok_or_else(exhausted)?;
        let row = super::serialization_storage::original_json_value_storage_extent_data(encoded)?;
        row.canonical_work_requested_bytes
            .checked_add(row.canonical_output_requested_bytes)
            .ok_or_else(exhausted)?
    };
    let retained = retained.checked_add(typed).ok_or_else(exhausted)?;
    let transient = transient.checked_add(canonical).ok_or_else(exhausted)?;
    retained
        .checked_add(transient)
        .and_then(|n| n.checked_add(scratch))
        .filter(|n| *n <= maximum)
        .ok_or_else(exhausted)?;
    Ok((retained, transient, scratch))
}
