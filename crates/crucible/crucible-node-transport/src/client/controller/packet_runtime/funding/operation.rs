//! Prices independently live owners on the actual closed packet call path.
//!
//! The aggregate deliberately sums phase populations instead of discounting
//! mutually exclusive ones. Each factor names a real constructor or owner; none
//! derives allocation credit from source length, unused quota or equal values.

use super::{multiply, refused, sum};
use crate::{
    ProviderError,
    bodies::{PacketRuntimeRequest, RequestBody, ResponseBody},
    client::{ClientSession, CnpController, compact_json::CompactJson},
    connection::ReceivedFrame,
    envelope::Envelope,
    retained_metadata::serialization_storage::{
        OriginalJsonValueStorageExtentData,
        original_json_value_clone_storage_forest_counter_scratch_data,
        original_json_value_clone_storage_forest_data,
        original_json_value_storage_extent_counter_scratch_data,
        original_json_value_storage_extent_data,
    },
};
use crucible_node_format::{ContentRef, Extensions, Id, canonical};
use std::mem::size_of;

// The outer request, Connection's redecoded original, its received typed body,
// the final returned body and an additionally decoded Begin argument each own
// an independent population. Notification/Request/Response share only this
// one received-body branch; its defining baseline quote includes Poll's extra
// outcome validation. Summing all five does not borrow a phase-overlap refund.
const TYPED_CONSTRUCTORS: usize = 5;

pub(super) fn storage_data(frame: usize) -> Result<[usize; 2], ProviderError> {
    let extent = original_json_value_storage_extent_data(frame)?;
    let body = crate::reference_packet::runtime_body_storage::storage_data(frame, usize::MAX)?;
    let vectors = crate::bodies::typed_vector_storage_data(frame, usize::MAX)?;
    let lookup = canonical::STRICT_JSON_KEY_LOOKUP_STORAGE_DATA.ok_or_else(refused)?;

    // A failed exchange can retain its pending Envelope and an unexpected
    // Envelope beside an independently decoded boxed Notification. Conservatively
    // retain the complete baseline body family, including its construction work,
    // rather than assuming a successful typed fault decoder's spare capacities.
    let retained = sum(&[
        multiply(2, extent.value_dom_requested_bytes)?,
        body[0],
        size_of::<ReceivedFrame>(),
    ])?;

    // Request construction, incoming parsing, suffix-cache materialization and
    // send's strict validation have independent Value populations. Parser growth
    // bounds cover exact fresh construction too; correlation/incident copies
    // remain separately retained by the defining Connection row.
    let values = multiply(4, extent.value_dom_requested_bytes)?;
    let typed = multiply(TYPED_CONSTRUCTORS, sum(&[body[0], vectors[0], vectors[1]])?)?;

    // Reference discovery owns prior disjoint roots while cloning the next
    // candidate subtree, including an invalid last candidate. Their aggregate
    // source syntax remains bounded by the original reply's F. The root Vec has
    // its own actual4096 ceiling and geometric growth, independent of DTO Vecs.
    let references = sum(&[
        original_json_value_clone_storage_forest_data(frame, frame)?,
        multiply(2 * 4096, size_of::<ContentRef>())?,
        multiply(4, frame)?,
    ])?;

    // Four route/session IDs are cloned before complete sizing. Argument IDs
    // move from the caller and stay independently funded by its Source claim.
    // BlobChunk's closed encoder can create one F-sized base64 String during
    // sizing and another during Value construction; price both complete phases.
    // Incoming raw and outgoing exact wire banks remain independent of DOMs.
    let wire_and_constructor = sum(&[
        multiply(4, crucible_node_format::MAX_ID_BYTES)?,
        "CNP/1".len(),
        multiply(2, frame)?,
        multiply(2, frame)?,
        extent.canonical_work_requested_bytes,
        lookup[0],
        lookup[1],
    ])?;
    Ok([
        retained,
        sum(&[values, typed, references, wire_and_constructor])?,
    ])
}

pub(super) fn counter_scratch_data() -> usize {
    crate::reference_packet::runtime_body_storage::counter_scratch_data() * TYPED_CONSTRUCTORS
        + crate::bodies::runtime_typed_vector_counter_scratch_data()
        + CnpController::scoped_request_construction_counter_scratch_data()
        + ClientSession::packet_runtime_exchange_counter_scratch_data()
        + CompactJson::materialization_counter_scratch_data()
        + CompactJson::canonical_encoding_counter_scratch_data()
        + canonical::json_parse_counter_scratch_bytes_data()
        + canonical::canonical_json_counter_scratch_bytes_data()
        + canonical::STRICT_JSON_KEY_LOOKUP_STORAGE_DATA.map_or(0, |row| row[2])
        + original_json_value_clone_storage_forest_counter_scratch_data()
        + original_json_value_storage_extent_counter_scratch_data()
        + 65 * super::super::super::original_suffix_response_references_counter_scratch_data()
        + crate::bodies::packet_runtime_preflight_counter_scratch_data()
        + size_of::<OriginalJsonValueStorageExtentData>()
        + size_of::<Result<OriginalJsonValueStorageExtentData, ProviderError>>()
        + size_of::<PacketRuntimeRequest<'static>>()
        + size_of::<&Extensions>()
        + size_of::<&mut Vec<ContentRef>>()
        + size_of::<ContentRef>()
        + size_of::<Vec<ContentRef>>()
        + size_of::<RequestBody>()
        + size_of::<ResponseBody>()
        + 2 * size_of::<Envelope>()
        + size_of::<ReceivedFrame>()
        + size_of::<Id>()
        + size_of::<Option<Id>>()
        + size_of::<Result<ResponseBody, ProviderError>>()
        + size_of::<Result<Envelope, ProviderError>>()
        + size_of::<Result<Option<ReceivedFrame>, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<[usize; 7]>()
        + size_of::<[usize; 4]>()
        + 3 * size_of::<[usize; 2]>()
        + size_of::<Option<[usize; 3]>>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + 4 * size_of::<Result<usize, ProviderError>>()
        + 4 * size_of::<Option<usize>>()
        + 16 * size_of::<usize>()
}
