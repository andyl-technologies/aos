//! Defines separately reserved startup data for restored baseline actions.
//!
//! This edition is an upfront allocation carrier. It does not change ordinary
//! Input, Begin, Poll, Retire or Observe bodies, and it does not issue an action
//! from a decoded budget. The inherited bootstrap must authenticate the same
//! Source, selected contracts and native birth before installing the reservation.
//! The live dispatcher additionally needs its actual first-observation witness.
//!
//! ```text
//! {maximum_originals:"...", ingress:{R,T,S}, actions:{R,T,S}}
//! ```

use super::PacketNativeStartupAllocationRow;
use crate::ProviderError;
use crucible_node_format::U64;
use serde::{Deserialize, Serialize};

#[path = "restored_suffix/budget.rs"]
mod budget;
#[path = "restored_suffix/construction.rs"]
mod construction;
#[path = "restored_suffix/contract.rs"]
mod contract;
#[path = "restored_suffix/selection.rs"]
mod selection;
#[path = "restored_suffix/wire.rs"]
mod wire;

#[path = "restored_suffix/launch.rs"]
mod launch;
#[path = "restored_suffix/preamble.rs"]
mod preamble;
#[cfg(test)]
#[path = "restored_suffix/tests.rs"]
mod tests;

pub(crate) use budget::OriginalRestoredSuffixBudget;

pub use contract::{
    authenticate_restoration_suffix_schema_data, restoration_suffix_contract_data,
    restoration_suffix_schema, restoration_suffix_schema_counter_scratch_data,
};
pub use selection::authenticate_restoration_suffix_selection_data;

pub use construction::{
    PacketNativeSuffixConstructionStorageData, original_native_suffix_construction_storage_data,
};

pub use wire::{
    PacketNativeSuffixLaunchIdentityData, original_native_suffix_launch_identity_data,
    write_original_native_suffix_launch_data,
};

pub use launch::{PacketNative7RestoredSuffixLaunch, PacketNative7RestoredSuffixLaunchView};
pub use preamble::{
    ORIGINAL_NATIVE_RESTORED_SUFFIX_PREAMBLE_BYTES, PacketNativeSuffixPreambleData,
    authenticate_original_native_suffix_preamble_data, decode_original_native_suffix_preamble_data,
    encode_original_native_suffix_preamble_data,
};

/// Names the independently negotiated allocation and restored-action family.
pub const PACKET_RESTORATION_SUFFIX_FEATURE: &str = "source-owned.packet-restoration-suffix/1";

/// Carries finite independent ingress and action windows without issuing rights.
///
/// Both retained terms remain independently charged for the whole lifetime of
/// the native owner. An unknown or failed attempt never refunds its debit.
/// Each actual action must fit every remaining retained/phase/scratch axis
/// before its allocation or callback. A count or matching total is no grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestoredSuffixReservationData {
    /// Bounds fresh baseline originals independently of the first Observe slot.
    pub maximum_originals: U64,
    /// Prepays raw, typed and failure owners before the next original is known.
    pub ingress: PacketNativeStartupAllocationRow,
    /// Prepays subsequent current-model, proof and callback construction.
    pub actions: PacketNativeStartupAllocationRow,
}

impl PacketRestoredSuffixReservationData {
    /// Checks fixed extents and the sum of both independent phase windows.
    ///
    /// # Errors
    /// Refuses an empty or excessive count, incomplete rows or checked overflow.
    pub fn requested_bytes_data(&self) -> Result<u64, ProviderError> {
        if self.maximum_originals.get() == 0 || self.maximum_originals.get() > 256 {
            return Err(invalid());
        }
        // Both windows are charged independently. No inferred phase overlap
        // discounts a prior failed parse, current proof or unresolved callback.
        self.ingress
            .requested_peak_data()?
            .checked_add(self.actions.requested_peak_data()?)
            .ok_or_else(invalid)
    }

    /// Compares every actual reservation field with its admitted counterpart.
    ///
    /// # Errors
    /// Refuses invalid rows, a changed finite count or any widened axis.
    pub fn authenticate_actual_data(&self, actual: &Self) -> Result<(), ProviderError> {
        self.requested_bytes_data()?;
        actual.requested_bytes_data()?;
        if self.maximum_originals != actual.maximum_originals {
            return Err(invalid());
        }
        self.ingress.authenticate_actual_data(&actual.ingress)?;
        self.actions.authenticate_actual_data(&actual.actions)
    }
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("restored suffix startup reservation differs")
}

/// Names startup carrier, comparison and independent fixed-ledger layouts.
///
/// This fixed demand is separate from raw/parser/typed dynamic ownership and
/// all future current-model, reply, transfer and action-specific construction.
pub fn original_native_suffix_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<PacketRestoredSuffixReservationData>()
        + size_of::<&PacketRestoredSuffixReservationData>() * 2
        + size_of::<Result<PacketRestoredSuffixReservationData, ProviderError>>()
        + size_of::<PacketNativeSuffixPreambleData>()
        + size_of::<Result<PacketNativeSuffixPreambleData, ProviderError>>()
        + size_of::<[u8; ORIGINAL_NATIVE_RESTORED_SUFFIX_PREAMBLE_BYTES]>() * 2
        + size_of::<Result<[u8; ORIGINAL_NATIVE_RESTORED_SUFFIX_PREAMBLE_BYTES], ProviderError>>()
        + size_of::<[u8; 336]>() * 2
        + size_of::<Result<[u8; 336], ProviderError>>()
        + size_of::<super::PacketNativeInvocationPreambleData>()
        + size_of::<Result<super::PacketNativeInvocationPreambleData, ProviderError>>()
        + size_of::<PacketNative7RestoredSuffixLaunch>()
        + size_of::<Option<PacketNative7RestoredSuffixLaunch>>()
        + size_of::<PacketNative7RestoredSuffixLaunchView<'static>>()
        + size_of::<OriginalRestoredSuffixBudget>()
        + size_of::<Result<OriginalRestoredSuffixBudget, ProviderError>>()
        + size_of::<PacketNativeStartupAllocationRow>() * 3
        + size_of::<Result<PacketNativeStartupAllocationRow, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<u64, ProviderError>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<[u8; 32]>() * 2
        + size_of::<[u8; 8]>()
        + size_of::<[U64; 3]>()
        + size_of::<std::array::IntoIter<U64, 3>>()
        + size_of::<std::slice::ChunksExactMut<'static, u8>>()
        + size_of::<
            std::iter::Zip<std::slice::ChunksExactMut<'static, u8>, std::array::IntoIter<U64, 3>>,
        >()
        + size_of::<(&'static mut [u8], U64)>()
        + size_of::<std::ops::Range<usize>>() * 2
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<&[u8; 32]>()
        + size_of::<Result<&'static [u8; 32], std::array::TryFromSliceError>>()
        + size_of::<Result<[u8; 8], std::array::TryFromSliceError>>()
        + size_of::<Result<&'static [u8; 32], ProviderError>>()
        + size_of::<Result<[u8; 8], ProviderError>>()
        + size_of::<std::slice::Iter<'static, u8>>() * 2
        + size_of::<std::iter::Zip<std::slice::Iter<'static, u8>, std::slice::Iter<'static, u8>>>()
        + size_of::<u8>()
        + size_of::<(&'static u8, &'static u8)>()
        + size_of::<&u8>() * 2
        + size_of::<&serde_json::Value>()
        + size_of::<Option<&serde_json::Map<String, serde_json::Value>>>()
        + size_of::<Result<&'static serde_json::Map<String, serde_json::Value>, ProviderError>>()
        + size_of::<Option<u64>>()
        + size_of::<super::PacketNativeInvocationPurposeData>()
        + size_of::<Result<super::PacketNativeInvocationPurposeData, ProviderError>>()
        + size_of::<Result<PacketRestoredSuffixReservationData, serde_json::Error>>()
        + size_of::<
            Result<PacketRestoredSuffixReservationData, crucible_node_format::ContractError>,
        >()
        + size_of::<
            Result<super::super::PacketNative5SourceLaunch, crucible_node_format::ContractError>,
        >()
        + size_of::<Result<super::super::PacketNative5SourceLaunch, serde_json::Error>>()
        + size_of::<Option<&PacketNative7RestoredSuffixLaunch>>()
        + size_of::<Result<&'static PacketNative7RestoredSuffixLaunch, ProviderError>>()
        + size_of::<&mut Option<PacketNative7RestoredSuffixLaunch>>()
        + crate::reference_packet::service::ack_emitter::original_restored_suffix_native_counter_scratch_data()
        + crate::reference_packet::service::ack_emitter::original_restored_suffix_bootstrap_counter_scratch_data()
        + original_native_restored_suffix_startup_counter_scratch_data()
        + construction::counter_scratch_data()
        + budget::counter_scratch_data()
        + selection::counter_scratch_data()
        + wire::counter_scratch_data()
}

#[path = "restored_suffix/reservation.rs"]
mod reservation;
pub use reservation::{
    PacketNativeRestoredSuffixStartupHistoricalData, PacketNativeRestoredSuffixStartupStorageData,
    original_native_restored_suffix_startup_counter_scratch_data,
    original_native_restored_suffix_startup_storage_data,
};

#[path = "restored_suffix/observe_custody.rs"]
mod observe_custody;
pub(crate) use observe_custody::{
    NativeRestoredSuffixObserveAttempt,
    original_restored_suffix_observe_custody_counter_scratch_data,
    original_restored_suffix_observe_ingress_row_data,
};

#[path = "restored_suffix/observation.rs"]
mod observation;
pub use observation::{
    PacketNativeRestoredSuffixObservationHistoricalData,
    PacketNativeRestoredSuffixObservationStorageData,
    original_native_restored_suffix_observation_counter_scratch_data,
    original_native_restored_suffix_observation_storage_data,
};

pub(crate) use observation::original_native_restored_suffix_observation_required_storage_data;

#[path = "restored_suffix/producer_lifecycle.rs"]
mod producer_lifecycle;
pub use producer_lifecycle::{
    PacketRestoredProducerArgumentsData, PacketRestoredProducerLifecycleHistoricalData,
    PacketRestoredProducerLifecycleInputs, PacketRestoredProducerLifecycleStorageData,
    PacketRestoredProducerPopulationData,
    original_restored_producer_lifecycle_counter_scratch_data,
    original_restored_producer_lifecycle_storage_data,
};

#[path = "restored_suffix/producer_ingress.rs"]
mod producer_ingress;
pub(crate) use producer_ingress::{
    NativeRestoredProducerAttempt, original_restored_producer_ingress_row_data,
};

pub(crate) use producer_lifecycle::{
    native_closed_producer_action_counter_scratch_data, native_closed_producer_action_row_data,
};
