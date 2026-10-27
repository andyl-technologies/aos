//! Prices fixed payload decoding in the actual Controller Native5 codec chain.
//!
//! The method graph alone cannot cover this work: selected extension payloads
//! can decode before their message kind refuses. The closed field graph names
//! those actual payloads, including the nested Commit envelope and tagged input
//! context. Ordinary baseline request/result vectors, identity serialization,
//! connection owners and the enclosing Source remain independent terms.

use crate::ProviderError;
use crate::protocol_snapshot::serde_decode_layout;
use crate::reference_packet::continuation_models::serde_partials;
use crate::reference_packet::service::complete_restore::import18::{
    native_import18_contract_counter_scratch_data, native_import18_contract_storage_data,
};
use crate::retained_metadata::serialization_storage::{
    original_json_value_clone_storage_forest_counter_scratch_data,
    original_json_value_clone_storage_forest_data,
};
use std::mem::size_of;

mod fields;
mod validation;

const fn maximum(left: usize, right: usize) -> usize {
    if left > right { left } else { right }
}

/// Quotes independent payload backing and fixed decoder controls as DATA.
///
/// The caller must first authenticate the actual installed ControllerPacket
/// codec and admit the counter. Complete input encodings have at most `frame`
/// bytes and retain literal JSON semantics under the strict 64-container
/// transport. The quote covers rejected prefixes as well as valid artifacts.
/// It constructs no payload, Value, text bank or schema factory.
///
/// # Errors
/// Refuses a zero/unsupported frame, changed pinned decoder layouts, checked
/// overflow, or a complete transient-plus-counter row above `maximum_bytes`.
pub(crate) fn storage_data(
    frame: usize,
    maximum_bytes: usize,
) -> Result<[usize; 2], ProviderError> {
    if frame == 0 || frame > 65_536 || size_of::<usize>() != 8 {
        return Err(refused());
    }

    // All dynamic fields in this closed graph are strings, Bytes or literal
    // JSON maps. Borrowed strings request their live lengths. Base64's rejected
    // one-character prefix can request three output octets while its encoded
    // String remains live; four bytes per input byte also covers that prefix.
    // Each literal root is charged independently, including its inline header.
    let strings_and_bytes = multiply(4, frame)?;
    let literals = original_json_value_clone_storage_forest_data(frame, frame)?;
    let typed_payload = add(strings_and_bytes, literals)?;

    // Pinned Content buffers reserve at most the supplied population (capped
    // initially at 1 MiB), then grow to at most twice the live population or
    // four slots. Per container, brackets/key syntax pays that minimum; each
    // array element or object member pays its own disjoint input syntax. Four
    // maximum pair slots per encoded byte cover both array and map backing,
    // including the failed next element. Strings need another input extent.
    // Each simultaneously nested tagged decoder gets a separate whole forest.
    let content_slot = serde_decode_layout::content_slot_bytes_data();
    let content_pair = serde_decode_layout::content_pair_bytes_data();
    if content_pair != 2 * content_slot {
        return Err(refused());
    }
    let buffered_forest = buffered_forest_storage_data(frame, content_pair)?;
    let tagged = multiply(fields::TAG_LEVELS, buffered_forest)?;

    // A derive error may escape the complete unexpected string and format the
    // actual closed field/type/variant roster. Keep successive grown messages,
    // the previous error, its boxed text and ErrorImpl independently funded.
    let names = add(
        fields::NAME_BYTES,
        serde_partials::diagnostic_format_text_bytes_data(),
    )?;
    let diagnostic_text = add(multiply(6, frame)?, names)?;
    let diagnostics = add(
        add(multiply(8, diagnostic_text)?, 8)?,
        serde_partials::diagnostic_error_impl_allocation_upper_bytes_data(),
    )?;

    // Native18's live selection check constructs this one compiled contract
    // factory before checking the message alternative. Other selected schema
    // comparisons in this Controller chain borrow their installed policies.
    let (factory, _) = native_import18_contract_storage_data(usize::MAX)?;
    let validation = validation::storage_data(frame)?;
    let transient = [typed_payload, tagged, diagnostics, factory, validation]
        .into_iter()
        .try_fold(0usize, |total, value| add(total, value))?;
    let counter = counter_scratch_data();
    if add(transient, counter)? > maximum_bytes {
        return Err(refused());
    }

    Ok([transient, counter])
}

/// Names the defining field partials, adapters and quote controls before entry.
///
/// These requested control layouts establish no compiler-frame or physical
/// machine-stack bound and grant no Source allocation or ownership handoff.
pub(crate) fn counter_scratch_data() -> usize {
    fields::control_bytes()
        + serde_decode_layout::owned_value_counter_scratch_data()
        + 65 * (1 + fields::TAG_LEVELS) * serde_decode_layout::content_frame_counter_scratch_data()
        + native_import18_contract_counter_scratch_data()
        + validation::counter_scratch_data()
        + original_json_value_clone_storage_forest_counter_scratch_data()
        + size_of::<[usize; 5]>()
        + size_of::<std::array::IntoIter<usize, 5>>()
        + size_of::<[usize; 2]>()
        + 4 * size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<[usize; 2], ProviderError>>()
        + size_of::<Result<(usize, usize), ProviderError>>()
        + size_of::<Option<usize>>()
        + 16 * size_of::<usize>()
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(refused)
}

fn multiply(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(refused)
}

fn buffered_forest_storage_data(frame: usize, pair_bytes: usize) -> Result<usize, ProviderError> {
    add(multiply(multiply(4, pair_bytes)?, frame)?, frame)
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("packet runtime concrete codec backing")
}

#[cfg(test)]
mod tests;
