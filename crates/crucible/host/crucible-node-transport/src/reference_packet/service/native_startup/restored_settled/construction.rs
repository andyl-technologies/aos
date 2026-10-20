//! Prices new wrapper8/prefix17 custody beside every unchanged suffix owner.
//!
//! Dynamic graph/output/action demand is independently supplied by the native17
//! producer. This helper prices only raw/DOM/parser/typed/wire construction and
//! never treats the portable carrier as a private boot or Capture grant.

use super::settled_data17::{CanonicalCarrier, CanonicalExistingRows, invalid};
use super::*;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
    original_json_value_storage_extent_data,
};
use std::mem::size_of;

/// Separates added native/private construction, Source finalization and wire.
#[derive(Clone, Copy)]
pub struct PacketNativeSettledConstructionStorageData {
    native_retained: usize,
    native_transient: usize,
    private_retained: usize,
    private_transient: usize,
    source_finalization: usize,
    wire_growth: usize,
    identity: PacketNativeSuffixLaunchIdentityData,
}

impl PacketNativeSettledConstructionStorageData {
    /// Returns independently retained native parser/raw/header demand.
    pub const fn native_retained_requested_bytes(&self) -> usize {
        self.native_retained
    }

    /// Returns independently requested native decode/canonical work.
    pub const fn native_transient_requested_bytes(&self) -> usize {
        self.native_transient
    }

    /// Returns independently retained private parser/raw/header demand.
    pub const fn private_retained_requested_bytes(&self) -> usize {
        self.private_retained
    }

    /// Returns independently requested private decode/canonical work.
    pub const fn private_transient_requested_bytes(&self) -> usize {
        self.private_transient
    }

    /// Returns actual Source wrapper/DOM/encoding construction demand.
    pub const fn source_finalization_requested_bytes(&self) -> usize {
        self.source_finalization
    }

    /// Returns new wire-bank extent beside the existing launch7/prefix16 bound.
    pub const fn wire_growth_requested_bytes(&self) -> usize {
        self.wire_growth
    }

    /// Copies the streamed complete wrapper8 identity, without boot authority.
    pub const fn launch_identity_data(&self) -> PacketNativeSuffixLaunchIdentityData {
        self.identity
    }
}

/// Quotes only the new carrier construction around the unchanged nested launch7.
///
/// Both original phase rows and the complete native17 storage row remain separate
/// mandatory additions. Full new raw banks are conservatively counted, while the
/// old complete launch and suffix owners remain charged by their actual rows.
///
/// # Errors
/// Refuses invalid carrier, changed writer geometry, fixed frame excess,
/// arithmetic overflow or demand above the actual unchanged installed ceiling.
pub fn original_native_settled_construction_storage_data(
    purpose: &PacketNativeInvocationPurposeData,
    raw5: &[u8],
    suffix: &PacketRestoredSuffixReservationData,
    existing_rows: &PacketRestoredSettledNativeExistingRowsData,
    capture: &PacketRestoredSettledNativeCarrierData,
    maximum: usize,
) -> Result<PacketNativeSettledConstructionStorageData, ProviderError> {
    capture.validate_data()?;
    let old = original_native_suffix_launch_identity_data(purpose, raw5, suffix)?;
    let identity = original_native_settled_launch_identity_data(
        purpose,
        raw5,
        suffix,
        existing_rows,
        capture,
    )?;
    if identity.encoded_bytes > 1024 * 1024 {
        return Err(invalid());
    }
    let growth = identity
        .encoded_bytes
        .checked_sub(old.encoded_bytes)
        .ok_or_else(invalid)?;

    let mut projection = Projection::new(maximum)?;
    projection.add_object()?;
    projection.add_field("capture_reservation")?;
    projection.add_value(&CanonicalCarrier(capture))?;
    projection.add_field("existing_rows")?;
    projection.add_value(&CanonicalExistingRows(existing_rows))?;
    projection.add_field("schema_version")?;
    projection.add_value(&8u16)?;
    projection.add_field("suffix")?;
    // Old suffix7 ownership remains wholly charged. Null pays only this slot.
    projection.add_value(&())?;
    let wrapper = projection.finish(maximum)?;
    let wrapper_work = wrapper.requested_total()?;

    let parser = original_json_value_storage_extent_data(identity.encoded_bytes)?;
    let raw_bank = sum(
        &[
            identity.encoded_bytes.checked_mul(4).ok_or_else(invalid)?,
            256,
        ],
        maximum,
    )?;
    let typed = size_of::<PacketNative8RestoredSettledLaunch>();
    let header =
        crate::reference_packet::service::ack_emitter::original_restored_settled_bootstrap_header_data();
    let read_scratch =
        crate::reference_packet::service::ack_emitter::original_restored_settled_bootstrap_counter_scratch_data();
    let fixed = sum(
        &[
            ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES,
            size_of::<PacketNativeSettledPreambleData>(),
            size_of::<PacketRestoredSettledNativeCarrierData>(),
            header,
            read_scratch,
            crate::reference_packet::service::ack_emitter::original_restored_settled_bootstrap_accept_header_data()
        ],
        maximum
    )?;

    let retained = sum(&[wrapper_work, raw_bank, typed, fixed], maximum)?;
    let transient = sum(
        &[
            wrapper_work,
            parser.canonical_pass_requested_bytes()?,
            typed,
            read_scratch,
        ],
        maximum,
    )?;

    Ok(PacketNativeSettledConstructionStorageData {
        native_retained: retained,
        native_transient: transient,
        private_retained: retained,
        private_transient: transient,
        source_finalization: sum(&[wrapper_work, wrapper_work, raw_bank, fixed], maximum)?,
        wire_growth: sum(
            &[growth, ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES],
            maximum,
        )?,
        identity,
    })
}

fn sum(parts: &[usize], maximum: usize) -> Result<usize, ProviderError> {
    parts.iter().try_fold(0usize, |total, part| {
        total
            .checked_add(*part)
            .filter(|n| *n <= maximum)
            .ok_or_else(invalid)
    })
}

pub(super) fn counter_scratch_data() -> usize {
    let terms = [
        size_of::<PacketNativeSettledConstructionStorageData>(),
        size_of::<Result<PacketNativeSettledConstructionStorageData, ProviderError>>(),
        size_of::<Projection>(),
        size_of::<Result<Projection, ProviderError>>(),
        size_of::<OriginalSerializationStorageData>(),
        size_of::<Result<OriginalSerializationStorageData, ProviderError>>(),
        size_of::<crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData>(),
        size_of::<Result<crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData, ProviderError>>(),
        size_of::<PacketNativeSuffixLaunchIdentityData>(),
        size_of::<Result<PacketNativeSuffixLaunchIdentityData, ProviderError>>(),
        size_of::<&PacketNativeInvocationPurposeData>(),
        size_of::<&PacketRestoredSuffixReservationData>(),
        size_of::<&PacketRestoredSettledNativeCarrierData>(),
        size_of::<&PacketRestoredSettledNativeExistingRowsData>(),
        size_of::<CanonicalExistingRows<'static>>(),
        size_of::<[usize; 7]>(),
        size_of::<[usize; 3]>(),
        size_of::<&[usize]>(),
        size_of::<std::slice::Iter<'static, usize>>(),
        size_of::<&usize>(),
        size_of::<[usize; 2]>(),
        size_of::<[usize; 4]>(),
        size_of::<[usize; 5]>(),
        size_of::<[usize; 6]>(),
        size_of::<Option<usize>>(),
        size_of::<Result<usize, ProviderError>>(),
        crate::retained_metadata::serialization_storage::original_json_value_storage_extent_counter_scratch_data(),
    ];
    std::mem::size_of_val(&terms)
        + size_of::<std::array::IntoIter<usize, 27>>()
        + terms.into_iter().sum::<usize>()
}

impl PacketNativeSettledConstructionStorageData {
    /// Borrows every actual construction axis and its complete launch identity.
    ///
    /// This serializer preserves inert fixed DATA without allocating backing or
    /// reconstructing current startup, allocation, debit or native permission.
    pub fn borrowed_settled17_history_data(&self) -> impl serde::Serialize + '_ {
        ConstructionHistory17(self)
    }

    /// Quotes the two concrete fixed borrowed history serializer headers.
    pub const fn settled17_history_counter_scratch_data() -> usize {
        size_of::<ConstructionHistory17<'static>>() + size_of::<LaunchIdentityHistory17<'static>>()
    }
}

struct ConstructionHistory17<'a>(&'a PacketNativeSettledConstructionStorageData);

impl serde::Serialize for ConstructionHistory17<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let PacketNativeSettledConstructionStorageData {
            native_retained,
            native_transient,
            private_retained,
            private_transient,
            source_finalization,
            wire_growth,
            identity,
        } = self.0;
        let mut fields =
            serializer.serialize_struct("PacketNativeSettledConstructionStorageData", 7)?;
        fields.serialize_field("native_retained", native_retained)?;
        fields.serialize_field("native_transient", native_transient)?;
        fields.serialize_field("private_retained", private_retained)?;
        fields.serialize_field("private_transient", private_transient)?;
        fields.serialize_field("source_finalization", source_finalization)?;
        fields.serialize_field("wire_growth", wire_growth)?;
        fields.serialize_field("identity", &LaunchIdentityHistory17(identity))?;
        fields.end()
    }
}

struct LaunchIdentityHistory17<'a>(&'a PacketNativeSuffixLaunchIdentityData);

impl serde::Serialize for LaunchIdentityHistory17<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let PacketNativeSuffixLaunchIdentityData {
            encoded_bytes,
            raw_digest,
        } = self.0;
        let mut fields = serializer.serialize_struct("PacketNativeSuffixLaunchIdentityData", 2)?;
        fields.serialize_field("encoded_bytes", encoded_bytes)?;
        fields.serialize_field("raw_digest", raw_digest)?;
        fields.end()
    }
}
