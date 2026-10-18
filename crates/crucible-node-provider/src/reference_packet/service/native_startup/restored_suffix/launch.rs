//! Retains the distinct suffix launch without widening version six.
//!
//! ```text
//! {schema_version:7,invocation:<purpose/1>,launch:<launch5>,suffix_reservation:{...}}
//! ```
//!
//! The existing Source15 binding, purpose/1 and nested launch5 remain unchanged.
//! Their successful decoding does not select this edition or install a budget.

use super::super::super::PacketNative5SourceLaunch;
use super::super::invocation::PacketNativeInvocationPurposeData;
use super::*;
use serde::{Serializer, ser::SerializeStruct};
use serde_json::Value;

/// Owns the new startup wrapper as DATA, independently of live construction.
pub struct PacketNative7RestoredSuffixLaunch {
    purpose: PacketNativeInvocationPurposeData,
    launch: PacketNative5SourceLaunch,
    suffix: PacketRestoredSuffixReservationData,
}

impl PacketNative7RestoredSuffixLaunch {
    /// Retains all decoded owners before validating their current correspondence.
    ///
    /// The caller must retain the raw frame and Value under independent ingress
    /// credit before invoking this decoder. Legacy launch6 cannot select it.
    ///
    /// # Errors
    /// Refuses another revision, unknown fields, occupied output, invalid rows
    /// or a purpose that does not authenticate the complete nested launch.
    pub fn decode_original_value_into(
        value: &Value,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(invalid());
        }
        let fields = value.as_object().ok_or_else(invalid)?;
        if fields.len() != 4
            || fields.get("schema_version").and_then(Value::as_u64) != Some(7)
            || !fields.contains_key("invocation")
            || !fields.contains_key("launch")
            || !fields.contains_key("suffix_reservation")
        {
            return Err(invalid());
        }
        let purpose =
            PacketNativeInvocationPurposeData::from_original_value_data(&fields["invocation"])?;
        let suffix =
            PacketRestoredSuffixReservationData::deserialize(&fields["suffix_reservation"])
                .map_err(crucible_node_contract::ContractError::from)?;
        let launch = PacketNative5SourceLaunch::deserialize(&fields["launch"])
            .map_err(crucible_node_contract::ContractError::from)?;
        *output = Some(Self {
            purpose,
            launch,
            suffix,
        });

        let retained = output.as_ref().ok_or_else(invalid)?;
        retained.suffix.requested_bytes_data()?;
        if retained.purpose.is_original_execution_data() {
            return Err(invalid());
        }
        retained.launch.validate()?;
        retained.purpose.authenticate_target_data(&retained.launch)
    }

    // A completed outer8 owner can move this exact child without a second
    // decode or Clone. This DATA decomposition issues no native permission.
    pub(in crate::reference_packet::service::native_startup) fn into_parts_data(
        self,
    ) -> (
        PacketNativeInvocationPurposeData,
        PacketNative5SourceLaunch,
        PacketRestoredSuffixReservationData,
    ) {
        (self.purpose, self.launch, self.suffix)
    }

    /// Borrows the complete unchanged nested launch.
    pub fn launch_data(&self) -> &PacketNative5SourceLaunch {
        &self.launch
    }

    /// Copies the unchanged invocation DATA, without issuing a live purpose.
    pub const fn invocation_data(&self) -> PacketNativeInvocationPurposeData {
        self.purpose
    }

    /// Copies the separate fixed reservation, without installing it.
    pub const fn suffix_reservation_data(&self) -> PacketRestoredSuffixReservationData {
        self.suffix
    }
}

/// Serializes genuine borrowed startup inputs into the distinct wrapper.
pub struct PacketNative7RestoredSuffixLaunchView<'a> {
    /// Borrows the actual complete typed launch.
    pub launch: &'a PacketNative5SourceLaunch,
    /// Borrows the actual member's original invocation provenance.
    pub invocation: &'a PacketNativeInvocationPurposeData,
    /// Borrows the independent already admitted suffix reservation.
    pub suffix_reservation: &'a PacketRestoredSuffixReservationData,
}

impl Serialize for PacketNative7RestoredSuffixLaunchView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("NativeRestoredSuffixLaunch", 4)?;
        fields.serialize_field("schema_version", &7u16)?;
        fields.serialize_field("invocation", self.invocation)?;
        fields.serialize_field("launch", self.launch)?;
        fields.serialize_field("suffix_reservation", self.suffix_reservation)?;
        fields.end()
    }
}
