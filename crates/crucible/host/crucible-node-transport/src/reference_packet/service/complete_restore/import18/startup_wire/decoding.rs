//! Quotes the actual three bounded bootstrap DATA parsers before allocating.
//!
//! The defining path is strict Value parsing followed by the real owned DTO
//! decoder. RawValue resets, concrete typed fields, tagged buffers, Bytes codec
//! controls and failed serde messages remain separate terms. Inline Bootstrap18
//! ownership and its retained raw bodies are supplied by the physical caller.
//! No initial result, recipe, admission or native model follows from this DATA.

use super::decoder_partials::PrivateBodyTypedGeometryData;
use super::*;
use crate::protocol_snapshot::{raw_value_reparse, serde_decode_layout};
use crate::reference_packet::continuation_models::serde_partials;
use crate::reference_packet::service::native_startup::{
    raw_json_extent_counter_scratch_data, raw_json_extent_data,
};
use crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData;

/// Quotes separately retained backing and work for the three original raw banks.
///
/// Callers first admit the allocation-free counter below. These rows exclude
/// their raw banks, inline output slots, channel and all later validation or
/// native effects. Each row's R includes failed diagnostic ownership. The
/// complete Initial producer must add its actual simultaneous physical owners.
///
/// # Errors
/// Refuses unsupported compact framing, population/layout overflow or a complete
/// parser row above the independent restriction, before any parser runs.
pub(in crate::reference_packet) fn private_body_decode_backing_data(
    bodies: [&[u8]; 3],
    maximum: usize,
) -> Result<[[usize; 3]; 3], ProviderError> {
    let geometry = private_body_typed_geometry_data();
    let partials = private_body_typed_partials_data();
    let mut rows = [[0; 3]; 3];
    for index in 0..3 {
        rows[index] = body(bodies[index], geometry[index], partials[index], maximum)?;
    }
    Ok(rows)
}

fn body(
    bytes: &[u8],
    geometry: PrivateBodyTypedGeometryData,
    partials: usize,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let raw = raw_json_extent_data(bytes)?;
    let reset = raw_value_reparse::quote_raw_json_data(bytes, maximum)?;
    body_population(&raw, &reset, bytes.len(), geometry, partials, maximum)
}

pub(super) fn body_population(
    raw: &OriginalJsonValueStorageExtentData,
    reset: &raw_value_reparse::JsonValueReparseConstructionData,
    diagnostic_input: usize,
    geometry: PrivateBodyTypedGeometryData,
    partials: usize,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let (reset_retained, reset_transient, reset_scratch) = reset.requested_storage_data();
    let (extra_nodes, extra_members, extra_text) = reset.expanded_json_extents_data();
    let nodes = add(raw.maximum_value_nodes, extra_nodes)?;
    let members = add(raw.maximum_object_members, extra_members)?;
    let text = add(raw.maximum_decoded_string_bytes, extra_text)?;

    // A tagged buffer owns Content sequences/maps, while ordinary fields use
    // this actual DTO DAG's concrete elements and tree entry layouts. Every
    // node may be an independently grown container; no body-byte heap ratio is
    // substituted for these observed lexical populations.
    type Content = serde::__private228::de::Content<'static>;
    let slot = geometry
        .slot_bytes
        .max(size_of::<Content>())
        .max(size_of::<(Content, Content)>());
    let typed_node = crucible_source_birth_data::selected_decode::map_node(
        geometry
            .map_entry_bytes
            .max(size_of::<String>() + size_of::<Value>()),
        geometry
            .map_entry_alignment
            .max(std::mem::align_of::<Value>()),
    )?;
    let arrays = mul(mul(8, nodes)?, slot)?;
    let maps = mul(mul(2, members)?, typed_node)?;
    let strings = add(mul(8, text)?, mul(32, nodes)?)?;
    // RecipeFields is exhaustively fixed inline DATA. Its U64 visitor strings
    // live in the already funded input Value; no typed heap survives that pass.
    let typed = if geometry.has_heap_fields {
        sum(&[arrays, maps, strings])?
    } else {
        0
    };

    let diagnostic = diagnostic_storage_data(add(diagnostic_input, extra_text)?, geometry)?;
    let retained = sum(&[typed, reset_retained, diagnostic])?;
    let tagged = mul(typed, geometry.buffered_tag_levels)?;
    let transient = sum(&[
        raw.value_dom_requested_bytes,
        raw.canonical_work_requested_bytes,
        raw.canonical_output_requested_bytes,
        typed,
        tagged,
        reset_retained,
        reset_transient,
        diagnostic,
    ])?;

    let depth = add(65, mul(128, reset.maximum_parser_layers_data())?)?;
    let scratch = sum(&[
        raw.declared_counter_scratch_bytes,
        reset_scratch,
        partials,
        serde_decode_layout::text_counter_scratch_data(),
        mul(
            depth,
            serde_decode_layout::owned_value_frame_counter_scratch_data(),
        )?,
        mul(
            mul(depth, geometry.buffered_tag_levels)?,
            serde_decode_layout::content_frame_counter_scratch_data(),
        )?,
        canonical::json_parse_counter_scratch_bytes_data(),
        canonical::canonical_number_counter_scratch_bytes_data(),
        body_controls(),
    ])?;
    let row = [retained, transient, scratch];
    if sum(&row)? > maximum {
        return Err(exhausted());
    }
    Ok(row)
}

pub(super) fn diagnostic_storage_data(
    text: usize,
    geometry: PrivateBodyTypedGeometryData,
) -> Result<usize, ProviderError> {
    let display = sum(&[
        mul(6, text)?,
        geometry.diagnostic_names_bytes,
        serde_partials::diagnostic_format_text_bytes_data(),
        size_of::<[u8; 20]>(),
    ])?;
    sum(&[
        mul(8, display)?,
        size_of::<[u8; 8]>(), // pinned u8 String growth minimum
        serde_partials::diagnostic_error_impl_allocation_upper_bytes_data(),
    ])
}

/// Names this quote's actual fixed lexical, type-DAG and returned layout views.
pub(in crate::reference_packet) fn private_body_decode_counter_scratch_data() -> usize {
    raw_json_extent_counter_scratch_data()
        + raw_value_reparse::raw_scanner_counter_scratch_data()
        + crucible_source_birth_data::selected_decode::arithmetic_counter_scratch_data()
        + size_of::<[&[u8]; 3]>()
        + size_of::<[PrivateBodyTypedGeometryData; 3]>()
        + size_of::<[usize; 3]>()
        + size_of::<[[usize; 3]; 3]>() * 2
        + size_of::<Result<[[usize; 3]; 3], ProviderError>>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<usize>() * 2
        + body_controls()
}

fn body_controls() -> usize {
    size_of::<&[u8]>()
        + size_of::<&OriginalJsonValueStorageExtentData>()
        + size_of::<&raw_value_reparse::JsonValueReparseConstructionData>()
        + size_of::<PrivateBodyTypedGeometryData>()
        + size_of::<PrivateBodyTypedGeometryData>()
        + size_of::<OriginalJsonValueStorageExtentData>()
        + size_of::<Result<OriginalJsonValueStorageExtentData, ProviderError>>()
        + size_of::<raw_value_reparse::JsonValueReparseConstructionData>()
        + size_of::<Result<raw_value_reparse::JsonValueReparseConstructionData, ProviderError>>()
        + size_of::<[usize; 3]>() * 4
        + size_of::<[usize; 8]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<&[usize]>()
        + size_of::<std::alloc::Layout>()
        + size_of::<Result<std::alloc::Layout, std::alloc::LayoutError>>()
        + size_of::<usize>() * 20
        + size_of::<bool>()
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<[usize; 3], ProviderError>>()
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(exhausted)
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(exhausted)
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms
        .iter()
        .try_fold(0usize, |total, &term| add(total, term))
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native import18 private body decoding")
}

#[cfg(test)]
#[path = "decoding/tests.rs"]
mod tests;
