//! Quotes a new ordinary Observe independently from the first signed action.
//!
//! The actual received startup member supplies immutable cached model geometry.
//! A caller separately authenticates its Source/Controller/World and admits every
//! returned axis before assignment. This DATA creates neither a native permit
//! nor reusable credit; native dispatch rechecks the same live initial model.

use super::*;
use crate::bodies::ObserveRequest;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::{
    restoration_observe, transfer::PacketCompleteRestoreOwnerValidationStorage,
};
use std::mem::size_of;

/// Carries a separately computed ordinary-Observe construction demand.
///
/// The native window remains owned by startup16. A native attempt must debit
/// its remaining axes before constructing proof or invoking publication. Host
/// and Source owners are independent additions to their current census.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PacketNativeRestoredSuffixObservationStorageData {
    startup: PacketNativeRestoredSuffixStartupStorageData,
    initial: restoration_observe::OriginalInstalledRestorationObservationConstructionData,
    native: PacketNativeStartupAllocationRow,
    maximum_restored: usize,
    maximum_underlying: usize,
    requested: usize,
    scratch: usize,
}

impl PacketNativeRestoredSuffixObservationStorageData {
    /// Copies the complete independently debited native demand.
    pub const fn native_allocation_data(&self) -> PacketNativeStartupAllocationRow {
        self.native
    }

    /// Returns new SDK assignment, raw/typed terminal, content and history backing.
    pub fn host_retained_requested_bytes_data(&self) -> usize {
        self.initial.host_retained_requested_bytes_data()
    }

    /// Returns complete simultaneous SDK construction and ACK work.
    pub fn host_maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.initial
            .host_maximum_simultaneous_transient_bytes_data()
    }

    /// Returns the SDK and defining quote's fixed counter demand.
    pub fn host_counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    /// Returns independently copied Source restored-record and native-model backing.
    pub fn source_evidence_retained_requested_bytes_data(&self) -> usize {
        self.initial.source_evidence_retained_requested_bytes_data()
    }

    /// Returns full Source proof decode and repeated validation work.
    pub fn source_evidence_maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.initial
            .source_evidence_maximum_simultaneous_transient_bytes_data()
    }

    /// Returns fixed Source evidence and quote views.
    pub fn source_evidence_counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    /// Bounds the complete restored12 object produced by a successful action.
    pub const fn maximum_restored_record_bytes_data(&self) -> usize {
        self.maximum_restored
    }

    /// Bounds underlying2/4 bytes accepted by the actual native record decoder.
    pub const fn maximum_underlying_record_bytes_data(&self) -> usize {
        self.maximum_underlying
    }

    /// Returns all independent native, host, evidence and defining quote demand.
    pub const fn requested_bytes_data(&self) -> usize {
        self.requested
    }

    /// Checks every fixed geometry and output field after a genuine fresh quote.
    ///
    /// # Errors
    /// Refuses any changed startup/model geometry or construction axis.
    pub fn authenticate_same_quote_data(&self, actual: &Self) -> Result<(), ProviderError> {
        if self != actual {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Re-evaluates current initial-model geometry without decoding an archive.
///
/// The actual member authenticates the same retained typed/raw launch owners
/// around this call. Full raw identity, cached geometry, original count, frame,
/// complete selected schemas and all startup snapshot axes are rechecked here.
/// Begin/Input/Retire are unavailable, so a native initial-Hold equality check
/// may still reject any progress; this row never predicts an advanced model.
///
/// # Errors
/// Refuses changed raw launch or opaque startup correspondence, unsupported
/// ordinary Observe body, overflow or the complete demand exceeding `maximum`.
pub fn original_native_restored_suffix_observation_storage_data(
    startup: &PacketNativeRestoredSuffixStartupStorageData,
    launch: &PacketNative5SourceLaunch,
    canonical_launch5: &[u8],
    observe: &ObserveRequest,
    maximum: usize,
) -> Result<PacketNativeRestoredSuffixObservationStorageData, ProviderError> {
    use crucible_node_format::Validate;
    observe.validate()?;
    if observe.after_observation_sequence.get() != 0
        || observe.maximum_items.get() != 1
        || !observe.extensions.is_empty()
    {
        return Err(invalid());
    }
    let model = startup.authenticate_observation_quote_inputs_data(launch, canonical_launch5)?;
    quote_cached_model_data(startup, launch, model, maximum)
}

pub(super) fn quote_cached_model_data(
    startup: &PacketNativeRestoredSuffixStartupStorageData,
    launch: &PacketNative5SourceLaunch,
    model: &PacketCompleteRestoreOwnerValidationStorage,
    maximum: usize,
) -> Result<PacketNativeRestoredSuffixObservationStorageData, ProviderError> {
    let (initial, native, maximum_restored) = native_cached_model_data(launch, model, maximum)?;
    let scratch = original_native_restored_suffix_observation_counter_scratch_data();
    let requested = sum(&[
        usize::try_from(native.requested_peak_data()?).map_err(|_| invalid())?,
        initial.host_retained_requested_bytes_data(),
        initial.host_maximum_simultaneous_transient_bytes_data(),
        scratch,
        initial.source_evidence_retained_requested_bytes_data(),
        initial.source_evidence_maximum_simultaneous_transient_bytes_data(),
        scratch,
    ])?;
    if requested > maximum {
        return Err(ProviderError::ResourceExhausted(
            "recurring Observe construction demand",
        ));
    }
    Ok(PacketNativeRestoredSuffixObservationStorageData {
        startup: *startup,
        initial,
        native,
        maximum_restored,
        maximum_underlying: 65_536,
        requested,
        scratch,
    })
}

type NativeObservationQuote = (
    restoration_observe::OriginalInstalledRestorationObservationConstructionData,
    PacketNativeStartupAllocationRow,
    usize,
);

pub(super) fn native_cached_model_data(
    launch: &PacketNative5SourceLaunch,
    model: &PacketCompleteRestoreOwnerValidationStorage,
    maximum: usize,
) -> Result<NativeObservationQuote, ProviderError> {
    // This is a fresh evaluation of complete prefix/ACK/cache/model/proof
    // formulas, not a loan from the first-Observe allocation or its receipt.
    let initial = restoration_observe::restoration_observe_cached_model_projection_data(
        launch, model, maximum,
    )?;
    let [_, terminal, proof, _, _] =
        restoration_observe::restoration_observe_repeated_projection_data(maximum)?;
    let old_native = initial.native_allocation_data();
    let scratch = original_native_restored_suffix_observation_counter_scratch_data();
    let native = PacketNativeStartupAllocationRow {
        retained_requested_bytes: quantity(sum(&[
            usize::try_from(old_native.retained_requested_bytes.get()).map_err(|_| invalid())?,
            terminal.requested_total()?,
            size_of::<PacketNativeRestoredSuffixObservationStorageData>(),
        ])?)?,
        maximum_simultaneous_transient_bytes: old_native.maximum_simultaneous_transient_bytes,
        declared_counter_scratch_bytes: quantity(sum(&[
            usize::try_from(old_native.declared_counter_scratch_bytes.get())
                .map_err(|_| invalid())?,
            scratch,
        ])?)?,
    };
    Ok((initial, native, proof.maximum_encoded_bytes))
}

/// Requotes a real native initial model under its own independent action axes.
///
/// # Errors
/// Refuses changed typed/raw/cached startup correspondence or unsupported body.
pub(crate) fn original_native_restored_suffix_observation_required_storage_data(
    startup: &PacketNativeRestoredSuffixStartupStorageData,
    launch: &PacketNative5SourceLaunch,
    canonical_launch5: &[u8],
    observe: &ObserveRequest,
    maximum: usize,
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    use crucible_node_format::Validate;
    observe.validate()?;
    if observe.after_observation_sequence.get() != 0
        || observe.maximum_items.get() != 1
        || !observe.extensions.is_empty()
    {
        return Err(invalid());
    }
    let model = startup.authenticate_observation_quote_inputs_data(launch, canonical_launch5)?;
    let (_, native, _) = native_cached_model_data(launch, model, maximum)?;
    if usize::try_from(native.requested_peak_data()?).map_err(|_| invalid())? > maximum {
        return Err(ProviderError::ResourceExhausted(
            "recurring Observe native demand",
        ));
    }
    Ok(native)
}

/// Names exact construction, old complete prefix and borrowed proof views.
pub fn original_native_restored_suffix_observation_counter_scratch_data() -> usize {
    use crate::retained_metadata::serialization_storage::OriginalSerializationStorageData;
    type WireProjection = [OriginalSerializationStorageData; 5];

    let quote_views = size_of::<PacketNativeRestoredSuffixObservationStorageData>()
        + size_of::<Result<PacketNativeRestoredSuffixObservationStorageData, ProviderError>>()
        + size_of::<&PacketNativeRestoredSuffixStartupStorageData>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&[u8]>()
        + size_of::<&ObserveRequest>()
        + size_of::<&PacketCompleteRestoreOwnerValidationStorage>()
        + size_of::<Result<&PacketCompleteRestoreOwnerValidationStorage, ProviderError>>()
        + size_of::<&PacketNativeRestoredSuffixObservationStorageData>() * 2;

    let projection_views = size_of::<WireProjection>()
        + size_of::<Result<WireProjection, ProviderError>>()
        + size_of::<NativeObservationQuote>()
        + size_of::<Result<NativeObservationQuote, ProviderError>>()
        + size_of::<PacketNativeStartupAllocationRow>()
        + size_of::<Result<PacketNativeStartupAllocationRow, ProviderError>>();

    let arithmetic_views = size_of::<Result<u64, ProviderError>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + size_of::<Result<U64, ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), crucible_node_format::ContractError>>()
        + size_of::<[usize; 3]>()
        + size_of::<[usize; 7]>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<&usize>();

    quote_views + projection_views + arithmetic_views
        + crate::connection::original_restored_suffix_observation_receive_counter_scratch_data()
        + crate::reference_packet::endpoint::original_restored_suffix_observation_endpoint_counter_scratch_data()
        + crate::reference_packet::control::original_restored_suffix_observation_control_counter_scratch_data()
        + super::reservation::projection_counter_scratch_data()
        + restoration_observe::original_installed_restoration_observation_construction_counter_scratch_data()
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |sum, next| {
        sum.checked_add(*next).ok_or_else(invalid)
    })
}

fn quantity(value: usize) -> Result<U64, ProviderError> {
    Ok(U64::new(u64::try_from(value).map_err(|_| invalid())?))
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("recurring Observe construction geometry differs")
}

/// Borrows every portable fixed field of the original DATA row.
///
/// The representation has no decoder, owned identity copy or conversion back
/// to a live construction row. Process-private Controller identity is omitted.
pub struct PacketNativeRestoredSuffixObservationHistoricalData<'a> {
    original: &'a PacketNativeRestoredSuffixObservationStorageData,
}

impl PacketNativeRestoredSuffixObservationStorageData {
    /// Lends all fixed historical axes without allocating or authenticating them.
    pub fn historical_data(&self) -> PacketNativeRestoredSuffixObservationHistoricalData<'_> {
        PacketNativeRestoredSuffixObservationHistoricalData { original: self }
    }

    /// Names the complete borrowed fixed-row historical projection views.
    pub fn historical_counter_scratch_data() -> usize {
        PacketNativeRestoredSuffixStartupStorageData::historical_counter_scratch_data()
            + restoration_observe::OriginalInstalledRestorationObservationConstructionData::historical_counter_scratch_data()
            + size_of::<&PacketNativeStartupAllocationRow>()
            + std::mem::size_of::<PacketNativeRestoredSuffixObservationHistoricalData<'static>>()
            + std::mem::size_of::<&PacketNativeRestoredSuffixObservationStorageData>()
            + 8 * std::mem::size_of::<&usize>()
    }
}

impl serde::Serialize for PacketNativeRestoredSuffixObservationHistoricalData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let PacketNativeRestoredSuffixObservationStorageData {
            startup,
            initial,
            native,
            maximum_restored,
            maximum_underlying,
            requested,
            scratch,
        } = self.original;
        let mut state = serializer
            .serialize_struct("PacketNativeRestoredSuffixObservationHistoricalData", 8)?;
        state.serialize_field(
            "schema",
            "source-private.restored-suffix-observation-storage/1",
        )?;
        state.serialize_field("startup", &(startup.historical_data()))?;
        state.serialize_field("initial", &(initial.historical_data()))?;
        state.serialize_field("native", &(native))?;
        state.serialize_field("maximum_restored", &(maximum_restored))?;
        state.serialize_field("maximum_underlying", &(maximum_underlying))?;
        state.serialize_field("requested", &(requested))?;
        state.serialize_field("scratch", &(scratch))?;
        state.end()
    }
}
