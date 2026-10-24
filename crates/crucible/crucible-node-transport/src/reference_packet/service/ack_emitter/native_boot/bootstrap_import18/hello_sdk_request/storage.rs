//! Prices the real SDK request decoder over an already checked strict body.
//!
//! The initial profile has three String/Id vectors, two 32-byte Bytes fields,
//! one session Id, fixed Limits, no resume object and an empty extension map.
//! These bounds use the original literal extent, not a fabricated request or
//! a supplied field population. Ordinary derive partials follow actual types.

use crate::ProviderError;
use crate::handshake::{HelloRequest, ResumeSession};
use crate::reference_packet::continuation_models::serde_partials::{
    self, DecoderPartial, decoder_struct,
};
use crate::reference_packet::service::native_startup::data_equality;
use crate::retained_metadata::requested_storage::tree_storage_data;
use crucible_node_format::{Id, MAX_ARRAY_ELEMENTS};
use serde_json::Value;
use std::mem::{align_of, size_of};

type RetainedFields = [usize; 4];
type TransientFields = [usize; 7];

decoder_struct!(ResumeSession {
    session_id,
    incarnation_id,
    resume_token,
    unresolved_operation_ids,
});

decoder_struct!(HelloRequest {
    versions,
    session_id,
    controller_nonce,
    required_features,
    optional_features,
    limits,
    admission_token,
    resume_session,
    extensions,
});

/// Quotes actual borrowed-Value decoding and complete body correspondence.
///
/// The caller first authenticates the original initial-only request. This row
/// funds decoding, its temporary diagnostics and comparison; SDK connection
/// admission and request validation are subsequent independent operations.
///
/// # Errors
/// Refuses zero framing, unsupported map geometry, overflow or a complete row
/// above the independently selected original restriction.
pub(super) fn construction_data(
    frame_bytes: usize,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    if frame_bytes == 0 || maximum == 0 {
        return Err(refused());
    }
    // Every admitted element is a nonempty ASCII string: quotes and separators
    // need at least three literal bytes per element across the three arrays.
    // serde's cautious initial capacity and Vec doubling request less than four
    // times their final length cumulatively. String and Id have the same actual
    // slot width; retain both dependencies instead of assuming that equality.
    let elements = (frame_bytes / 3).min(mul(MAX_ARRAY_ELEMENTS, 3)?);
    let vectors = mul(mul(elements, 4)?, size_of::<String>().max(size_of::<Id>()))?;
    let empty_map = tree_storage_data(
        1,
        0,
        add(size_of::<String>(), size_of::<Value>())?,
        align_of::<String>().max(align_of::<Value>()),
    )?;
    // Decoded text cannot exceed its original JSON literal. Each canonical
    // 43-byte base64 spelling reaches a real 33-byte decode estimate for its
    // 32-byte output. The encoded Strings are temporary, not retained fields.
    let retained_fields: RetainedFields = [vectors, frame_bytes, 2 * 33, empty_map];
    let retained = total(&retained_fields)?;

    let diagnostic_text = total(&[
        mul(frame_bytes, 6)?,
        HelloRequest::DIAGNOSTIC_NAMES_BYTES,
        serde_partials::diagnostic_format_text_bytes_data(),
        size_of::<[u8; 20]>(),
    ])?;
    let diagnostic = add(mul(diagnostic_text, 8)?, 8)?;
    let transient_fields: TransientFields = [
        retained, // actual decoder allocations and geometric Vec overlap
        diagnostic,
        serde_partials::diagnostic_error_impl_allocation_upper_bytes_data(),
        size_of::<HelloRequest>() * 2,
        size_of::<Result<HelloRequest, serde_json::Error>>(),
        2 * 43, // actual encoded Strings in the two Bytes decoders
        5 * 20, // fixed Limits decimal formatters in exact correspondence
    ];
    let row = [retained, total(&transient_fields)?, counter_scratch_data()];
    if total(&row)? > maximum {
        return Err(refused());
    }
    Ok(row)
}

/// Names the real derive partials, borrowed adapters and quote/comparison controls.
pub(super) fn counter_scratch_data() -> usize {
    HelloRequest::partial_counter_data()
        + data_equality::counter_scratch_data() * 4
        + size_of::<RetainedFields>()
        + size_of::<TransientFields>()
        + size_of::<[usize; 4]>()
        + size_of::<&Value>() * 4
        + size_of::<&HelloRequest>()
        + size_of::<serde_json::map::Iter<'static>>() * 4
        + size_of::<std::slice::Iter<'static, Value>>() * 4
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<serde::de::Unexpected<'static>>() * 2
        + size_of::<Result<(), serde_json::Error>>() * 4
        + size_of::<[usize; 3]>() * 2
        + size_of::<Option<usize>>() * 3
        + size_of::<Result<usize, ProviderError>>() * 4
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<usize>() * 12
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(refused)
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(refused)
}

fn total(fields: &[usize]) -> Result<usize, ProviderError> {
    fields.iter().try_fold(0, |sum, field| add(sum, *field))
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("original import18 SDK Hello request construction")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_sdk_request_row_rejects_overflow_and_a_one_byte_short_peak() {
        let row = construction_data(65_536, usize::MAX).unwrap();
        let peak = row.into_iter().sum();
        assert_eq!(construction_data(65_536, peak).unwrap(), row);
        assert!(construction_data(65_536, peak - 1).is_err());
        assert!(construction_data(0, peak).is_err());
        assert!(construction_data(usize::MAX, usize::MAX).is_err());
    }
}
