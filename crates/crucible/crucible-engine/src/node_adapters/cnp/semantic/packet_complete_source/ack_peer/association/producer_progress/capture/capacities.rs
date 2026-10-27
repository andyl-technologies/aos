//! Supplies closed borrowed field controls for the original Capture census.
//!
//! These helpers observe actual retained DATA. JSON normalization, native key
//! syntax and historical labels neither authenticate Capture nor issue credit.

use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::{
    record_value_capacity_data_with_error, value_capacity_counter_scratch_data,
};
use crate::node_contract::{
    NativeStateKey, RuntimeError, restored_owner_history::OriginalOwnerCapacityMetadataData,
};
use crucible_node_transport::{
    client::RestoredSettledCaptureTypedOwnerData, retained_metadata::RetainedCaptureProtocolData,
};
use std::mem::size_of;

/// Infers the defining borrowed field tuple without constructing an owner.
///
/// The closure is a type witness and is never invoked. Exhaustive destructures
/// at call sites make an added owning field a compiler-visible roster change.
pub(super) fn fields_layout_data<T: 'static, R>(_: impl FnOnce(&'static T) -> R) -> usize {
    size_of::<R>()
}

/// Observes retained JSON backing through the defining bounded value walk.
///
/// # Errors
/// Refuses exhausted rows, unsupported values or checked geometry/depth overflow.
pub(super) fn record_value_data(
    value: &serde_json::Value,
    census: &mut OriginalOwnerCapacityMetadataData<'_>,
) -> Result<(), RuntimeError> {
    record_value_capacity_data_with_error::<RuntimeError>(value, 0, census)
}

/// Names the borrowed JSON controls and the defining value counter.
pub(super) fn value_counter_scratch_data() -> usize {
    size_of::<&serde_json::Value>()
        + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
        + size_of::<Result<(), RuntimeError>>()
        + value_capacity_counter_scratch_data()
}

/// Observes each retained native key field without validating its identity.
///
/// # Errors
/// Refuses exhausted rows or checked allocation geometry overflow.
pub(super) fn record_native_key_data(
    key: &NativeStateKey,
    census: &mut OriginalOwnerCapacityMetadataData<'_>,
) -> Result<(), RuntimeError> {
    let NativeStateKey {
        implementation,
        profile,
        schema,
    } = key;

    census.observe(implementation)?;
    census.observe(profile)?;
    census.observe(schema)
}

/// Names the borrowed native key fields and observer controls.
pub(super) fn native_key_counter_scratch_data() -> usize {
    fields_layout_data::<NativeStateKey, _>(|key| {
        let NativeStateKey {
            implementation,
            profile,
            schema,
        } = key;
        (implementation, profile, schema)
    }) + size_of::<&NativeStateKey>()
        + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
        + size_of::<Result<(), RuntimeError>>()
}

/// Observes one actual closed Capture DTO without signing or validating it.
///
/// # Errors
/// Refuses checked geometry/depth overflow, exhausted rows or unsupported backing.
pub(super) fn record_typed_capture_data(
    value: RestoredSettledCaptureTypedOwnerData<'_>,
    census: &mut OriginalOwnerCapacityMetadataData<'_>,
) -> Result<(), RuntimeError> {
    census.observe_capture_protocol_data(RetainedCaptureProtocolData::RestoredCaptureTyped(value))
}

/// Names the typed Capture view and its enclosing census controls.
pub(super) fn typed_capture_counter_scratch_data() -> usize {
    size_of::<RestoredSettledCaptureTypedOwnerData<'_>>()
        + size_of::<RetainedCaptureProtocolData<'_>>()
        + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
        + size_of::<Result<(), RuntimeError>>()
}
