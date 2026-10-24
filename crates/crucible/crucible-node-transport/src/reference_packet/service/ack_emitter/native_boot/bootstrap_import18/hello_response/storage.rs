//! Prices actual result serialization, Completed ownership and response headers.
//!
//! The original result map moves into Completed; serializing that real response
//! creates its independent second DOM. The body then moves into the actual
//! Envelope. Fixed physical slots and separately counted empty roots preserve
//! every intermediate owner without cloning the original request body.

use super::{attempt::Attempt, projection, serialize_controls};
use crate::ProviderError;
use crate::bodies::ResponseShape;
use crate::envelope::Envelope;
use crate::reference_packet::continuation_models::serde_partials;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::retained_metadata::requested_storage::tree_storage_data;
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageData as Shape;
use crucible_node_format::{MAX_ID_BYTES, canonical};
use serde_json::Value;
use std::mem::{align_of, needs_drop, size_of};

type RetainedFields = [usize; 8];
type TransientFields = [usize; 8];

/// Projects every actual initial response constructor from the original launch.
///
/// # Errors
/// Refuses unsupported map/Number or clone layouts, a foreign initial
/// declaration, checked overflow or the independent full peak restriction.
pub(super) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    if canonical::STRICT_JSON_KEY_LOOKUP_STORAGE_DATA.is_none()
        || needs_drop::<serde_json::Number>()
    {
        return Err(refused());
    }
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    let result = projection::result_data(launch, maximum)?;
    let completed = projection::completed_data(launch, maximum)?;
    let selected = projection::selection_data(maximum)?;
    // The original Completed extensions remain empty beside its result map.
    // Response header construction also owns an empty body root before moving
    // the serialized body, and the real outer selection map keeps one entry.
    let roots = tree_storage_data(
        3,
        1,
        size_of::<String>() + size_of::<Value>(),
        align_of::<String>().max(align_of::<Value>()),
    )?;
    let retained_fields: RetainedFields = [
        result.retained_value_backing_bytes,
        completed.retained_value_backing_bytes,
        selected.retained_value_backing_bytes,
        roots,
        "CNP/1".len(),
        MAX_ID_BYTES,
        binding.authority.incarnation_id.as_str().len(),
        crate::handshake::EXTENSION_NEGOTIATION_V1.len(),
    ];
    let retained = total(&retained_fields)?;
    let clone = super::super::hello_registrar::header_clone_controls_data()?;
    let constructor = total(&[
        size_of::<Envelope>() * 2,
        size_of::<ResponseShape>() * 2,
        size_of::<Value>() * 3,
        size_of::<Option<Value>>() * 3,
        size_of::<Result<Value, serde_json::Error>>() * 2,
    ])?;
    // Serializer partial owners and their diagnostic/error paths run in turn.
    // Their requested DOM backing is covered by the whole retained envelope;
    // concrete allocating compound states and field paths remain independent.
    let serialization = serialize_controls::result_data()
        .max(serialize_controls::completed_data())
        .max(serialize_controls::selection_data());
    let diagnostic_text = add(
        mul(
            result
                .maximum_encoded_bytes
                .max(completed.maximum_encoded_bytes),
            6,
        )?,
        serde_partials::diagnostic_format_text_bytes_data(),
    )?;
    let transient_fields: TransientFields = [
        retained,
        constructor,
        clone[0],
        serialization,
        projection::challenge_formatter_data()?,
        add(mul(diagnostic_text, 8)?, 8)?,
        serde_partials::diagnostic_error_impl_allocation_upper_bytes_data(),
        size_of::<String>() + size_of::<serde_json::Error>(),
    ];
    let row = [
        retained,
        total(&transient_fields)?,
        add(counter_scratch_data(), clone[1])?,
    ];
    if maximum == 0 || total(&row)? > maximum {
        return Err(refused());
    }
    Ok(row)
}

/// Names real quote results, actual serializers, original outputs and census.
pub(super) fn counter_scratch_data() -> usize {
    projection::counter_scratch_data()
        + Attempt::counter_scratch_data()
        + serialize_controls::result_data()
            .max(serialize_controls::completed_data())
            .max(serialize_controls::selection_data())
        + size_of::<Shape>() * 3
        + size_of::<Result<Shape, ProviderError>>()
        + size_of::<RetainedFields>()
        + size_of::<TransientFields>()
        + size_of::<[usize; 5]>()
        + size_of::<[usize; 2]>()
        + size_of::<[usize; 3]>() * 2
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<Result<usize, ProviderError>>() * 5
        + size_of::<Option<usize>>() * 3
        + size_of::<usize>() * 7
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(refused)
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(refused)
}

fn total(fields: &[usize]) -> Result<usize, ProviderError> {
    fields
        .iter()
        .try_fold(0usize, |sum, field| add(sum, *field))
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("original import18 Hello response construction")
}
