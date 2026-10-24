//! Prices the actual closed assignment serializers and complete MAC context.
//!
//! Assignment validation clones the body into its typed decoder. Assignment
//! hashing then holds a complete Envelope DOM while bounded canonicalization
//! builds another DOM and its JCS bank. These distinct allocations are charged
//! before entry; the negotiated frame ceiling is only an independent restriction.

use super::*;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    PacketNativeImport18BootstrapAckProjectionData,
    native_import18_bootstrap_ack_counter_scratch_data,
    native_import18_bootstrap_ack_projection_data,
};
use crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData;

/// Quotes actual retained fields, clone/serializer banks and defining controls.
///
/// # Errors
/// Refuses closed population overflow, unsupported layouts or short restriction.
pub(super) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let shape = native_import18_bootstrap_ack_projection_data(maximum)?;
    let context = shape.serialization_requested_bytes_data()[0];
    let extent = super::super::bootstrap_value::closed_value_extent_data()?;
    let codec = super::super::bootstrap_codec::construction_data(launch, maximum)?;
    let backing = NATIVE_IMPORT18_BOOTSTRAP_ACK_CONTEXT
        .len()
        .checked_add(PACKET_COMPLETE_RESTORE_ALGORITHM.len())
        .and_then(|sum| sum.checked_add(9 * 32))
        .ok_or_else(exhausted)?;
    let retained = size_of::<Attempt>()
        .checked_add(backing)
        .ok_or_else(exhausted)?;
    // The complete closed envelope population bounds each body/envelope Value
    // clone. Three trees cover the body decode and both canonicalization DOMs;
    // counting them together also covers any dropped partial clone on refusal.
    let transient = [
        backing,
        extent
            .value_dom_requested_bytes
            .checked_mul(3)
            .ok_or_else(exhausted)?,
        extent.canonical_work_requested_bytes,
        extent.canonical_output_requested_bytes,
        codec[1],
        context[0],
        context[2],
        shape.bytes_formatter_temporary_data(),
        size_of::<Context>(),
        size_of::<Option<Context>>(),
        size_of::<Result<Context, ProviderError>>(),
        size_of::<Attempt>(),
        size_of::<Option<Attempt>>(),
        size_of::<Result<Attempt, ProviderError>>(),
    ]
    .into_iter()
    .try_fold(0usize, |sum, field| {
        sum.checked_add(field).ok_or_else(exhausted)
    })?;
    let scratch = [
        counter_scratch_data(),
        codec[2],
        extent.declared_counter_scratch_bytes,
        super::super::hello_evidence::pair_counter_scratch_data(),
    ]
    .into_iter()
    .try_fold(0usize, |sum, field| {
        sum.checked_add(field).ok_or_else(exhausted)
    })?;
    let row = [retained, transient, scratch];
    if row
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .is_none_or(|sum| sum > maximum)
    {
        return Err(exhausted());
    }
    Ok(row)
}

/// Names actual serializers, crypto, partial DTOs and borrowed census controls.
pub(super) fn counter_scratch_data() -> usize {
    native_import18_bootstrap_ack_counter_scratch_data()
        + size_of::<PacketNativeImport18BootstrapAckProjectionData>()
        + size_of::<Result<PacketNativeImport18BootstrapAckProjectionData, ProviderError>>()
        + size_of::<OriginalJsonValueStorageExtentData>()
        + size_of::<Result<OriginalJsonValueStorageExtentData, ProviderError>>()
        + size_of::<[[usize; 3]; 3]>()
        + size_of::<[usize; 3]>() * 4
        + size_of::<[usize; 14]>()
        + size_of::<std::array::IntoIter<usize, 14>>()
        + size_of::<[usize; 4]>()
        + size_of::<std::array::IntoIter<usize, 4>>()
        + size_of::<[&Bytes; 9]>()
        + size_of::<std::array::IntoIter<&'static Bytes, 9>>()
        + size_of::<&Context>() * 2
        + size_of::<&Bytes>()
        + size_of::<&[u8]>()
        + size_of::<&[u8; 32]>()
        + size_of::<Result<&[u8; 32], std::array::TryFromSliceError>>()
        + size_of::<crate::hello_frames::OriginalHelloFrameDigests>() * 2
        + size_of::<Result<crate::hello_frames::OriginalHelloFrameDigests, ProviderError>>()
        + size_of::<[u8; 32]>() * 2
        + size_of::<Result<[u8; 32], ProviderError>>() * 2
        + size_of::<usize>() * 6
        + size_of::<Option<usize>>() * 2
        + size_of::<Result<usize, ProviderError>>() * 3
        + size_of::<Result<(), ProviderError>>() * 4
}
