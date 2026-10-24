//! Prices the explicit outer14 invocation publisher before its private birth.
//!
//! The same existing closed report shapes remain independently charged. These
//! additional fixed views are not borrowed from an old row or runtime slack.
//! Actual Source admission and genuine original/target purpose remain separate.

use super::*;

/// Quotes the complete selected report shapes and invocation writer headers.
///
/// The caller admits the dedicated counter getter before entry. Both actual
/// immutable format rosters must contain the exact compiled outer14 definition.
/// A successful DATA quote neither issues a Source member nor selects purpose.
///
/// # Errors
/// Refuses an incomplete selected tuple, absent/duplicate/changed full outer14
/// schema, old shape-producer refusal, overflow or the unchanged absolute cap.
pub fn original_invocation_report_startup_storage_data(
    launch: &PacketNative5SourceLaunch,
    purpose: PacketNativeReportStartupPurpose,
) -> Result<PacketNativeReportStartupStorageData, ProviderError> {
    if launch.fresh_restore_allocation_selection != Some(
        super::super::super::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
        || launch.capture_allocation_selection != Some(
            super::super::super::capture_allocation::PacketNative5CaptureAllocationSelection::OriginalObserve12)
    { return Err(refused()); }
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    for formats in [
        &launch.selection.provider.implementation.formats,
        &binding.compatibility.implementation.formats,
    ] {
        let mut found = false;
        for schema in formats {
            if schema.id.as_str() == "source-owned.packet-native-continuation/14" {
                if found {
                    return Err(refused());
                }
                super::super::super::native_snapshot::authenticate_native_owned14_snapshot_schema_data(schema)?;
                found = true;
            }
        }
        if !found {
            return Err(refused());
        }
    }
    let mut data = original_report_startup_storage_data(launch, purpose)?;
    data.declared_counter_scratch_bytes = original_invocation_report_startup_counter_scratch_data();
    if sum(&[
        data.retained_growth_bytes,
        data.maximum_simultaneous_transient_bytes,
        data.declared_counter_scratch_bytes,
    ])? > MAXIMUM_COMPILED_PROJECTION_BYTES
    {
        return Err(exhausted());
    }
    Ok(data)
}

/// Names the old complete counter and all additional invocation writer views.
///
/// This is fixed requested-layout DATA, excluding original preowned banks,
/// recursive/compiler frames and allocator overhead. Overflow is unadmittable.
pub fn original_invocation_report_startup_counter_scratch_data() -> usize {
    [
        original_report_startup_counter_scratch_data(),
        crate::reference_packet::endpoint::original_invocation_capture_report_additional_scratch_data(),
        std::mem::size_of::<Result<PacketNativeReportStartupStorageData, ProviderError>>(),
        std::mem::size_of::<[&Vec<crucible_node_format::SchemaRef>; 2]>(),
        std::mem::size_of::<bool>(),
        super::super::original_invocation_report_startup_allocation_counter_scratch_data(),
    ]
    .into_iter()
    .try_fold(0usize, usize::checked_add)
    .unwrap_or(usize::MAX)
}
