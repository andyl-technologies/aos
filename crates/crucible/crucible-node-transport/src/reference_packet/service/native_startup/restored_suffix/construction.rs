//! Quotes only the new startup carrier owners beside the unchanged old baseline.
//!
//! Reservation rows are separately added in full by their real Core owner.
//! These carrier-growth terms cannot pay recurring ingress, a native proof,
//! callbacks or any future action. No Source, boot or Endpoint is constructed.

use super::super::{
    PacketNativeInvocationPurposeData, original_native_invocation_launch_identity_data,
};
use super::*;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
    original_json_value_storage_extent_data,
};
use std::mem::size_of;

/// Separates additional native, private and Source startup carrier ownership.
#[derive(Clone, Copy)]
pub struct PacketNativeSuffixConstructionStorageData {
    native_retained: usize,
    native_transient: usize,
    private_retained: usize,
    private_transient: usize,
    source_finalization: usize,
    wire_growth: usize,
    identity: PacketNativeSuffixLaunchIdentityData,
}

impl PacketNativeSuffixConstructionStorageData {
    /// Returns independent additional persistent native carrier/header owners.
    pub const fn native_retained_requested_bytes(&self) -> usize {
        self.native_retained
    }

    /// Returns the new native carrier's independent decode and conversion work.
    pub const fn native_transient_requested_bytes(&self) -> usize {
        self.native_transient
    }

    /// Returns the new private parser's persistent wrapper, raw and header owners.
    pub const fn private_retained_requested_bytes(&self) -> usize {
        self.private_retained
    }

    /// Returns its full additional raw parser and typed conversion work.
    pub const fn private_transient_requested_bytes(&self) -> usize {
        self.private_transient
    }

    /// Returns independent Source wrapper construction and encoding demand.
    pub const fn source_finalization_requested_bytes(&self) -> usize {
        self.source_finalization
    }

    /// Returns the additional retained Source wire-bank bound over launch6.
    pub const fn wire_growth_requested_bytes(&self) -> usize {
        self.wire_growth
    }

    /// Copies the exact streamed launch7 identity under the same retained inputs.
    pub const fn launch_identity_data(&self) -> PacketNativeSuffixLaunchIdentityData {
        self.identity
    }
}

/// Quotes actual new startup wrapper/header demand without creating a DOM.
///
/// The original invocation baseline remains independently mandatory. The
/// complete reservation itself is a separate retained Core resource row; this
/// function neither authenticates that admission nor proves future action fit.
/// The actual writer must retain its same canonical launch5 through failure.
///
/// # Errors
/// Refuses invalid rows/purpose, fixed frame excess, checked overflow or demand
/// above the actual installed resource ceiling.
pub fn original_native_suffix_construction_storage_data(
    purpose: &PacketNativeInvocationPurposeData,
    canonical_launch5: &[u8],
    reservation: &PacketRestoredSuffixReservationData,
    maximum: usize,
) -> Result<PacketNativeSuffixConstructionStorageData, ProviderError> {
    reservation.requested_bytes_data()?;
    let old = original_native_invocation_launch_identity_data(purpose, canonical_launch5)?;
    let identity =
        original_native_suffix_launch_identity_data(purpose, canonical_launch5, reservation)?;
    if identity.encoded_bytes > 1024 * 1024 {
        return Err(invalid());
    }
    let growth = identity
        .encoded_bytes
        .checked_sub(old.encoded_bytes)
        .ok_or_else(invalid)?;
    let mut projection = Projection::new(maximum)?;
    projection.add_object()?;
    projection.add_field("schema_version")?;
    projection.add_value(&7u16)?;
    projection.add_field("invocation")?;
    projection.add_value(purpose)?;
    projection.add_field("launch")?;
    // Existing complete launch5 ownership remains charged by the old baseline.
    // This null pays the new wrapper slot without replacing that nested owner.
    projection.add_value(&())?;
    projection.add_field("suffix_reservation")?;
    projection.add_value(&super::wire::CanonicalReservation(reservation))?;
    let wrapper = projection.finish(maximum)?;
    let parser = original_json_value_storage_extent_data(identity.encoded_bytes)?;
    let wrapper_work = wrapper.requested_total()?;
    let typed = size_of::<PacketNative7RestoredSuffixLaunch>();
    // Each existing native/private constructor retains a complete raw bank.
    // Preserve both old whole-bank terms and conservatively price the complete
    // new canonical bank, including its defining 4*n+256 growth envelope.
    let raw_bank = checked_sum(
        &[
            identity.encoded_bytes.checked_mul(4).ok_or_else(invalid)?,
            256,
        ],
        maximum,
    )?;
    let fixed = checked_sum(
        &[
            ORIGINAL_NATIVE_RESTORED_SUFFIX_PREAMBLE_BYTES,
            size_of::<PacketNativeSuffixPreambleData>(),
            size_of::<PacketRestoredSuffixReservationData>(),
            size_of::<OriginalRestoredSuffixBudget>(),
            crate::reference_packet::service::ack_emitter::original_restored_suffix_native_header_data(),
            crate::reference_packet::service::ack_emitter::original_restored_suffix_bootstrap_header_data(),
        ],
        maximum,
    )?;
    Ok(PacketNativeSuffixConstructionStorageData {
        native_retained: checked_sum(&[wrapper_work, raw_bank, typed, fixed], maximum)?,
        native_transient: checked_sum(
            &[
                wrapper_work,
                parser.canonical_pass_requested_bytes()?,
                typed,
            ],
            maximum,
        )?,
        private_retained: checked_sum(&[wrapper_work, raw_bank, typed, fixed], maximum)?,
        private_transient: checked_sum(
            &[
                wrapper_work,
                parser.canonical_pass_requested_bytes()?,
                typed,
            ],
            maximum,
        )?,
        source_finalization: checked_sum(&[wrapper_work, wrapper_work, raw_bank, fixed], maximum)?,
        wire_growth: checked_sum(
            &[growth, ORIGINAL_NATIVE_RESTORED_SUFFIX_PREAMBLE_BYTES],
            maximum,
        )?,
        identity,
    })
}

fn checked_sum(parts: &[usize], maximum: usize) -> Result<usize, ProviderError> {
    let mut total = 0usize;
    for part in parts {
        total = total
            .checked_add(*part)
            .filter(|value| *value <= maximum)
            .ok_or_else(invalid)?;
    }
    Ok(total)
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<PacketNativeSuffixConstructionStorageData>()
        + size_of::<Result<PacketNativeSuffixConstructionStorageData, ProviderError>>()
        + size_of::<Projection>()
        + size_of::<Result<Projection, ProviderError>>()
        + size_of::<OriginalSerializationStorageData>()
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
        + size_of::<crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData>()
        + size_of::<Result<crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData, ProviderError>>()
        + size_of::<super::super::PacketNativeInvocationLaunchIdentityData>()
        + size_of::<Result<super::super::PacketNativeInvocationLaunchIdentityData, ProviderError>>()
        + size_of::<&PacketNativeInvocationPurposeData>()
        + size_of::<&PacketRestoredSuffixReservationData>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<&usize>()
        + size_of::<[usize; 2]>()
        + size_of::<[usize; 3]>()
        + size_of::<[usize; 4]>()
        + size_of::<[usize; 6]>()
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, ProviderError>>()
        + crate::retained_metadata::serialization_storage::original_json_value_storage_extent_counter_scratch_data()
}

#[path = "construction/settled17.rs"]
mod settled17;
