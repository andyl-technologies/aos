//! Prices ordinary baseline decoding on the closed packet runtime call path.
//!
//! The defining method and Begin rosters require concrete decoder companions.
//! Literal result maps coexist with typed results, and Poll validation decodes
//! one further response shape from its retained outcome. These owners receive
//! separate populations. Private extension codecs, typed Vec backing, input
//! identity, raw parsing, request construction and transport remain independent.

use crate::protocol_snapshot::serde_decode_layout;
use crate::reference_packet::continuation_models::serde_partials;
use crate::retained_metadata::serialization_storage::{
    original_json_value_clone_storage_forest_counter_scratch_data,
    original_json_value_clone_storage_forest_data,
};
use crate::{ProviderError, bodies};
use std::mem::size_of;

mod partials;
mod validation;

/// Quotes one independently decoded baseline body's backing and controls.
///
/// The caller authenticates the installed Controller, idle original ownership
/// and closed packet runtime before admitting this DATA row. Whole current
/// requests and replies have at most `frame` bytes. The quote covers malformed
/// prefixes, the live borrowed response decoder and its Poll outcome validator;
/// it does not cover generic legacy methods or bootstrap18 dispatch.
///
/// Every simultaneously live body construction needs its own row. Typed Vec
/// banks are separately priced by the defining closed vector graph, including
/// any additionally decoded Begin arguments. Neither this quote nor its counter
/// creates an SDK, Source action, allocation grant or ownership handoff.
///
/// # Errors
/// Refuses unsupported frame geometry, checked overflow or a whole component
/// above `maximum_bytes`. No decoder, serializer or schema callback is invoked.
pub(crate) fn storage_data(
    frame: usize,
    maximum_bytes: usize,
) -> Result<[usize; 2], ProviderError> {
    if frame == 0 || frame > 65_536 || size_of::<usize>() != 8 {
        return Err(refused());
    }

    // The live successful ResponseShape clones its result map; MethodResult
    // clones literal descendants again. Poll's outcome validation can clone a
    // third shape while both earlier owners remain live. No generic tagged
    // enum buffer is used by this ordinary response path.
    let literal_forest = original_json_value_clone_storage_forest_data(frame, frame)?;
    let literals = multiply(3, literal_forest)?;

    // Each typed String/Bytes population is independent of those literal maps.
    // Four input bytes cover borrowed strings and even base64's rejected
    // one-character prefix, whose live String and output reservation total four.
    // A Poll outcome Error has a second independently decoded typed population.
    let typed_strings_and_bytes = multiply(2, multiply(4, frame)?)?;
    let boxed_roots = size_of::<bodies::RequestBody>()
        + size_of::<bodies::ResponseBody>()
        + size_of::<bodies::NotificationBody>();

    let names = add(
        bodies::BODY_DIAGNOSTIC_NAMES_BYTES,
        serde_partials::diagnostic_format_text_bytes_data(),
    )?;
    let diagnostics = add(
        add(multiply(8, add(multiply(6, frame)?, names)?)?, 8)?,
        serde_partials::diagnostic_error_impl_allocation_upper_bytes_data(),
    )?;
    let transient = [
        literals,
        typed_strings_and_bytes,
        boxed_roots,
        diagnostics,
        validation::storage_data(frame)?,
    ]
    .into_iter()
    .try_fold(0usize, add)?;
    let counter = counter_scratch_data();
    if add(transient, counter)? > maximum_bytes {
        return Err(refused());
    }

    Ok([transient, counter])
}

/// Names the actual field partials, live response adapters and quote views.
///
/// These explicit requested layouts make no compiler-frame or physical stack
/// claim. The enclosing Source independently admits them before quote entry.
pub(crate) fn counter_scratch_data() -> usize {
    bodies::body_decoder_counter_scratch_data()
        + partials::record_wrapper_controls_data()
        + 2 * bodies::response_shape_decode_counter_scratch_data()
        + 2 * size_of::<bodies::ResponseShape>()
        + size_of::<bodies::RequestBody>()
        + size_of::<bodies::ResponseBody>()
        + size_of::<bodies::MethodResult>()
        + size_of::<Result<bodies::RequestBody, ProviderError>>()
        + size_of::<Result<bodies::ResponseBody, ProviderError>>()
        + size_of::<Option<bodies::MethodResult>>()
        + serde_decode_layout::owned_value_counter_scratch_data()
        + 65 * crucible_node_format::literal_json::deserialization_counter_scratch_data()
        + serde_partials::version_field_counter_scratch_data()
        + original_json_value_clone_storage_forest_counter_scratch_data()
        + validation::counter_scratch_data()
        + size_of::<[usize; 5]>()
        + size_of::<std::array::IntoIter<usize, 5>>()
        + size_of::<[usize; 2]>()
        + size_of::<Result<[usize; 2], ProviderError>>()
        + 4 * size_of::<Result<usize, ProviderError>>()
        + size_of::<Option<usize>>()
        + 12 * size_of::<usize>()
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(refused)
}

fn multiply(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(refused)
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("packet runtime baseline body backing")
}

#[cfg(test)]
mod tests;
