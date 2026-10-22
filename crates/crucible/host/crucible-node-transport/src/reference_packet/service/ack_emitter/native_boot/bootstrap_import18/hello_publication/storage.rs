//! Prices borrowed canonical response work, retained output and original I/O.
//!
//! The existing response DOM remains charged to its original owner. Projection
//! follows its complete future Envelope; canonical ordering and formatting work
//! is independent of the one bounded byte bank retained by this phase.

use super::*;
use crate::native_hello::{OriginalNativeHelloJournal, OriginalNativeHelloPublication};
use crate::reference_packet::continuation_models::serde_partials;
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageData as Shape;
use crucible_node_format::canonical;

/// Retains a pure complete row and bounded future response bank extent.
#[derive(Clone, Copy)]
pub(super) struct Quote {
    /// Prices retained, transient and scratch axes independently.
    pub(super) row: [usize; 3],
    /// Bounds the one retained canonical response bank.
    pub(super) maximum_body: usize,
}

type RetainedFields = [usize; 2];
type TransientFields = [usize; 5];

/// Projects complete construction from the original immutable launch fields.
///
/// # Errors
/// Refuses unsupported Number/map geometry, declarations, frame limits, checked
/// overflow or an independent complete-peak restriction.
pub(super) fn quote_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<Quote, ProviderError> {
    if std::mem::needs_drop::<serde_json::Number>()
        || canonical::STRICT_JSON_KEY_LOOKUP_STORAGE_DATA.is_none()
    {
        return Err(refused());
    }

    let shape = super::super::hello_response::response_frame_projection_data(launch, maximum)?;
    let frame = usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| refused())?;
    OriginalNativeHelloJournal::reservation_requested_storage_data(frame)?;

    // Reserve the actual frame ceiling when the future maximum is larger.
    // Encoding then refuses only actual overflow, preserving smaller legal IDs.
    let maximum_body = shape.maximum_encoded_bytes.min(frame);
    let retained_fields: RetainedFields = [
        maximum_body,
        canonical::CANONICAL_JSON_INVALID_REASON_BYTES_DATA,
    ];
    let publication =
        OriginalNativeHelloPublication::construction_data::<OriginalNativePublicBirthChannel>();
    let transient_fields: TransientFields = [
        shape.dom_and_canonical_scratch_bytes,
        shape.serializer_temporary_requested_bytes,
        serde_partials::diagnostic_error_impl_allocation_upper_bytes_data(),
        publication[1],
        size_of::<Attempt>()
            + size_of::<Option<Attempt>>()
            + size_of::<Vec<u8>>()
            + size_of::<Result<(), ProviderError>>() * 2,
    ];

    let row = [
        total(&retained_fields)?,
        total(&transient_fields)?,
        super::counter_scratch_data(),
    ];
    if maximum == 0 || total(&row)? > maximum {
        return Err(refused());
    }
    Ok(Quote { row, maximum_body })
}

/// Names actual quote, encoder, publication and retained failure controls.
pub(super) fn counter_scratch_data() -> usize {
    super::super::hello_response::response_frame_projection_counter_scratch_data()
        + crate::native_hello::canonical_hello_response_counter_scratch_data::<
            attempt::BodyWriter<'static>,
        >()
        + Attempt::counter_scratch_data::<OriginalNativePublicBirthChannel>()
        + OriginalNativePublicBirthChannel::write_counter_scratch_data()
        + size_of::<Quote>() * 2
        + size_of::<Option<Quote>>()
        + size_of::<Shape>()
        + size_of::<Result<Shape, ProviderError>>()
        + size_of::<RetainedFields>()
        + size_of::<TransientFields>()
        + size_of::<[usize; 3]>() * 2
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<usize>() * 5
        + size_of::<Option<usize>>() * 3
        + size_of::<Result<usize, ProviderError>>() * 3
}

fn total(fields: &[usize]) -> Result<usize, ProviderError> {
    fields.iter().try_fold(0usize, |sum, field| {
        sum.checked_add(*field).ok_or_else(refused)
    })
}
