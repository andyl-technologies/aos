//! Quotes a new independent reservation from same-ticket immutable geometry.
//!
//! The cached eight-field model row was privately produced during actual archive
//! validation. It is geometry, never credit or authority. A registered Core
//! holder authenticates the real ticket, Source, declaration, purpose and launch
//! around this pure call, adds all axes independently under policy, and retains
//! its opaque member before the distinct carrier can be written.
//!
//! Ingress covers raw/Envelope/error custody only. Typed action bodies, current
//! model/proof and callback work require a fresh complete per-action quote and
//! debit before allocation. The initial-model action window is finite; progress
//! can exhaust it. No Endpoint, boot owner, action or capture is enabled here.

use super::super::super::PacketNative5SourceLaunch;
use super::*;
use crate::reference_packet::service::complete_restore::{
    activation, restoration_observe, transfer::PacketCompleteRestoreOwnerValidationStorage,
};
use crate::retained_metadata::serialization_storage::{
    OriginalJsonValueStorageExtentData, original_json_value_storage_extent_counter_scratch_data,
    original_json_value_storage_extent_data,
};
use crucible_node_contract::SchemaRef;
use std::mem::size_of;

/// Retains exact prebirth input correspondence and independently funded axes.
///
/// This fixed Copy DATA cannot construct a holder, native owner or action. It
/// deliberately contains no pointer to a temporary cached-row or launch header.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PacketNativeRestoredSuffixStartupStorageData {
    model: PacketCompleteRestoreOwnerValidationStorage,
    launch_digest: [u8; 32],
    launch_bytes: usize,
    frame_bytes: usize,
    originals: usize,
    reservation: PacketRestoredSuffixReservationData,
    retained: usize,
    transient: usize,
    scratch: usize,
    requested: usize,
}

impl PacketNativeRestoredSuffixStartupStorageData {
    /// Copies the distinct complete ingress and initial-model action windows.
    pub const fn reservation_data(&self) -> PacketRestoredSuffixReservationData {
        self.reservation
    }

    /// Returns both independently retained windows and this fixed DATA owner.
    pub const fn native_retained_requested_bytes_data(&self) -> usize {
        self.retained
    }

    /// Returns the additive ingress and initial-model proof phase bounds.
    pub const fn native_maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }

    /// Returns both independent phase scratch demands and the defining counter.
    pub const fn native_counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    /// Returns the checked sum of every independent native axis.
    pub const fn requested_bytes_data(&self) -> usize {
        self.requested
    }

    /// Compares every exact snapshot field after a fresh registered-holder quote.
    ///
    /// # Errors
    /// Refuses any changed cached field, full raw identity, count or produced axis.
    pub fn authenticate_same_quote_data(&self, actual: &Self) -> Result<(), ProviderError> {
        if self != actual {
            return Err(invalid());
        }
        Ok(())
    }

    /// Requotes the same complete immutable inputs and compares every fixed field.
    ///
    /// The genuine holder separately authenticates Source/ticket/launch currentness;
    /// equal DATA is not permission. Temporary header addresses are irrelevant.
    ///
    /// # Errors
    /// Refuses changed geometry, raw identity, count, axis or demand above the supplied cap.
    pub fn authenticate_same_inputs_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
        model: &PacketCompleteRestoreOwnerValidationStorage,
        maximum_originals: usize,
        maximum: usize,
    ) -> Result<(), ProviderError> {
        let actual = original_native_restored_suffix_startup_storage_data(
            launch,
            canonical_launch5,
            model,
            maximum_originals,
            maximum,
        )?;
        if self != &actual {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Projects a finite independent suffix window without decoding metadata.
///
/// The raw canonical launch bank and typed launch are borrowed from the same
/// authenticated prebirth holder, which must check their genuine correspondence
/// before and after this call. The count is the actual admitted scenario operation
/// allowance, passed without truncation; it must also fit the native request
/// limit and this family's finite 256-slot ceiling. Immutable full schemas and selected tuple are
/// checked here; advertisement does not replace that holder's explicit retained
/// Source declaration. Every returned byte is added anew, never taken from the
/// first Observe, restoration, Source, Host or current ticket's existing credit.
///
/// # Errors
/// Refuses an unsupported tuple/schema, malformed eight-field DATA sum, invalid
/// finite limits/raw extent, checked overflow or any complete row above policy.
pub fn original_native_restored_suffix_startup_storage_data(
    launch: &PacketNative5SourceLaunch,
    canonical_launch5: &[u8],
    model: &PacketCompleteRestoreOwnerValidationStorage,
    maximum_originals: usize,
    maximum: usize,
) -> Result<PacketNativeRestoredSuffixStartupStorageData, ProviderError> {
    authenticate_launch_data(launch)?;
    validate_model(model, maximum)?;
    if canonical_launch5.is_empty() || canonical_launch5.len() > 1024 * 1024 {
        return Err(invalid());
    }
    let frame_bytes = usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| invalid())?;
    let originals = maximum_originals;
    if originals == 0
        || originals > 256
        || u64::try_from(originals).map_err(|_| invalid())? > launch.limits.requests.get()
    {
        return Err(invalid());
    }
    let raw = original_json_value_storage_extent_data(frame_bytes)?;
    let scratch = original_native_restored_suffix_startup_counter_scratch_data();
    // Raw literal/DOM and one returned Envelope remain owned even when later
    // method eligibility, typed decoding or proof construction refuses. No
    // arbitrary typed action owner is inferred from a raw encoded byte count.
    let one_ingress_retained = sum(&[
        mul(3, raw.value_dom_requested_bytes)?,
        growth(frame_bytes)?,
        mul(9, size_of::<crate::envelope::Envelope>())?,
        size_of::<crate::connection::ConnectionIncident>(),
        size_of::<Option<crate::envelope::Envelope>>(),
        size_of::<Option<crate::connection::ConnectionIncident>>(),
    ])?;
    let ingress = PacketNativeStartupAllocationRow {
        retained_requested_bytes: u64_data(mul(originals, one_ingress_retained)?)?,
        maximum_simultaneous_transient_bytes: u64_data(sum(&[
            raw.canonical_pass_requested_bytes()?,
            raw.value_dom_requested_bytes,
            growth(frame_bytes)?,
        ])?)?,
        declared_counter_scratch_bytes: u64_data(scratch)?,
    };
    // This is the original closed initial-model proof projection, evaluated
    // from the SAME cached geometry without its old credit or any raw decode.
    // It cannot stand in for an advanced model. A later actual current census
    // must fit remaining axes before constructing any new body/proof/callback.
    let seed = restoration_observe::restoration_observe_cached_model_projection_data(
        launch, model, maximum,
    )?;
    let native = seed.native_allocation_data();
    let actions = PacketNativeStartupAllocationRow {
        retained_requested_bytes: u64_data(mul(
            originals,
            from_u64(native.retained_requested_bytes.get())?,
        )?)?,
        maximum_simultaneous_transient_bytes: native.maximum_simultaneous_transient_bytes,
        declared_counter_scratch_bytes: native.declared_counter_scratch_bytes,
    };
    let reservation = PacketRestoredSuffixReservationData {
        maximum_originals: u64_data(originals)?,
        ingress,
        actions,
    };
    let retained = sum(&[
        from_u64(ingress.retained_requested_bytes.get())?,
        from_u64(actions.retained_requested_bytes.get())?,
        size_of::<PacketNativeRestoredSuffixStartupStorageData>(),
    ])?;
    let transient = sum(&[
        from_u64(ingress.maximum_simultaneous_transient_bytes.get())?,
        from_u64(actions.maximum_simultaneous_transient_bytes.get())?,
    ])?;
    let scratch = sum(&[
        from_u64(ingress.declared_counter_scratch_bytes.get())?,
        from_u64(actions.declared_counter_scratch_bytes.get())?,
        scratch,
    ])?;
    let requested = sum(&[retained, transient, scratch])?;
    if requested > maximum {
        return Err(exhausted());
    }
    Ok(PacketNativeRestoredSuffixStartupStorageData {
        model: *model,
        launch_digest: *blake3::hash(canonical_launch5).as_bytes(),
        launch_bytes: canonical_launch5.len(),
        frame_bytes,
        originals,
        reservation,
        retained,
        transient,
        scratch,
        requested,
    })
}

fn validate_model(
    model: &PacketCompleteRestoreOwnerValidationStorage,
    maximum: usize,
) -> Result<(), ProviderError> {
    let PacketCompleteRestoreOwnerValidationStorage {
        snapshot_bytes,
        journal_bytes,
        control_bytes,
        model_vector_backing_bytes,
        anchor_bytes,
        capture_comparison_bytes,
        declared_scanner_bytes,
        total_bytes,
    } = *model;
    let total = sum(&[
        snapshot_bytes,
        journal_bytes,
        control_bytes,
        model_vector_backing_bytes,
        anchor_bytes,
        capture_comparison_bytes,
        declared_scanner_bytes,
    ])?;
    if total > maximum {
        return Err(exhausted());
    }
    if total != total_bytes
        || total == 0
        || snapshot_bytes == 0
        || journal_bytes == 0
        || control_bytes == 0
        || anchor_bytes == 0
        || capture_comparison_bytes == 0
        || declared_scanner_bytes == 0
    {
        return Err(invalid());
    }
    Ok(())
}

fn authenticate_launch_data(launch: &PacketNative5SourceLaunch) -> Result<(), ProviderError> {
    use crate::reference_packet::service::*;
    launch.storage.validate(&launch.limits)?;
    launch.capture_profile.validate()?;
    launch
        .protocol_metadata_limits
        .ok_or_else(invalid)?
        .validate_data()?;
    if launch.schema_version != 5
        || !matches!(launch.capture_profile, PacketNative5CaptureProfile::OwnedProtocol11 { .. })
        || launch.protocol_metadata_limits.is_none()
        || launch.confirmation_selection != Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5)
        || launch.fresh_restore_allocation_selection != Some(fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
        || launch.native_codec_metadata_extent != Some(crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
        || launch.ack_emitter_selection != Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
        || launch.complete_restore_selection != Some(complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        || launch.restore_input_emitter_selection != Some(complete_restore::PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12)
        || launch.capture_allocation_selection != Some(capture_allocation::PacketNative5CaptureAllocationSelection::OriginalObserve12)
        || launch.selection.realization.bindings.len() != 1
        || launch.selection.realization.owner_bindings.len() != 1
    {
        return Err(invalid());
    }
    for (feature, authenticate) in SCHEMAS {
        formats(
            &launch.selection.provider.implementation.formats,
            feature,
            authenticate,
        )?;
        for binding in &launch.selection.realization.bindings {
            formats(
                &binding.compatibility.implementation.formats,
                feature,
                authenticate,
            )?;
        }
        let mut count = 0usize;
        for one in &launch.selection.provider.extensions_supported {
            if one.as_str() == feature {
                count = count.checked_add(1).ok_or_else(invalid)?;
            }
        }
        if count != 1 {
            return Err(invalid());
        }
    }
    Ok(())
}

type SchemaAuthenticator = fn(&SchemaRef) -> Result<(), ProviderError>;

type SchemaEntry = (&'static str, SchemaAuthenticator);

const SCHEMAS: [SchemaEntry; 4] = [
    (
        PACKET_RESTORATION_SUFFIX_FEATURE,
        restoration_suffix_schema_auth,
    ),
    (
        restoration_observe::PACKET_RESTORATION_OBSERVE_FEATURE,
        restoration_observe::authenticate_restoration_observe_schema_data,
    ),
    (
        activation::PACKET_RESTORATION_ACTIVATION_FEATURE,
        activation::authenticate_restoration_activation_schema_data,
    ),
    (
        activation::upload::PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE,
        activation::upload::authenticate_restoration_activation_upload_schema_data,
    ),
];
fn restoration_suffix_schema_auth(schema: &SchemaRef) -> Result<(), ProviderError> {
    authenticate_restoration_suffix_schema_data(schema)
}

fn formats(
    rows: &[SchemaRef],
    feature: &str,
    authenticate: SchemaAuthenticator,
) -> Result<(), ProviderError> {
    let mut found = None;
    for row in rows {
        if row.id.as_str() == feature && found.replace(row).is_some() {
            return Err(invalid());
        }
    }
    authenticate(found.ok_or_else(invalid)?)
}

fn from_u64(value: u64) -> Result<usize, ProviderError> {
    usize::try_from(value).map_err(|_| exhausted())
}

fn u64_data(value: usize) -> Result<U64, ProviderError> {
    Ok(U64::new(u64::try_from(value).map_err(|_| exhausted())?))
}

fn mul(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_mul(b).ok_or_else(exhausted)
}

fn growth(bytes: usize) -> Result<usize, ProviderError> {
    sum(&[mul(bytes, 4)?, 256])
}

fn sum(parts: &[usize]) -> Result<usize, ProviderError> {
    let mut total = 0usize;
    for part in parts {
        total = total.checked_add(*part).ok_or_else(exhausted)?;
    }
    Ok(total)
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("restored suffix independent startup reservation")
}

/// Names defining fixed quote/comparison views before the holder's callback.
///
/// The Core member, 392-byte preamble, new wire/parser/native owner and all
/// Source/Host callback owners remain independent external obligations.
pub fn original_native_restored_suffix_startup_counter_scratch_data() -> usize {
    crate::reference_packet::service::ack_emitter::original_restored_suffix_native_counter_scratch_data()
        + size_of::<PacketNativeRestoredSuffixStartupStorageData>() * 2
        + size_of::<Result<PacketNativeRestoredSuffixStartupStorageData, ProviderError>>()
        + size_of::<&PacketNativeRestoredSuffixStartupStorageData>() * 2
        + size_of::<PacketCompleteRestoreOwnerValidationStorage>()
        + size_of::<&PacketCompleteRestoreOwnerValidationStorage>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&crate::reference_packet::service::PacketNative5StorageLimits>()
        + size_of::<&crate::handshake::Limits>()
        + size_of::<&crate::reference_packet::service::PacketNative5CaptureProfile>()
        + size_of::<crate::reference_packet::service::PacketNative5ProtocolMetadataLimits>()
        + size_of::<&crate::reference_packet::service::PacketNative5ProtocolMetadataLimits>()
        + size_of::<Option<crate::reference_packet::service::PacketNative5ProtocolMetadataLimits>>()
        + size_of::<Result<crate::reference_packet::service::PacketNative5ProtocolMetadataLimits, ProviderError>>()
        + size_of::<[&U64; 3]>()
        + size_of::<std::array::IntoIter<&U64, 3>>()
        + size_of::<&U64>()
        + size_of::<[U64; 2]>()
        + size_of::<std::slice::Iter<'static, U64>>()
        + size_of::<Result<(), crucible_node_contract::ContractError>>()
        + size_of::<&[u8]>()
        + size_of::<blake3::Hash>()
        + size_of::<[u8; 32]>()

        + size_of::<OriginalJsonValueStorageExtentData>()
        + size_of::<Result<OriginalJsonValueStorageExtentData, ProviderError>>()
        + size_of::<restoration_observe::OriginalInstalledRestorationObservationConstructionData>()
        + size_of::<Result<restoration_observe::OriginalInstalledRestorationObservationConstructionData, ProviderError>>()
        + size_of::<PacketRestoredSuffixReservationData>()
        + size_of::<PacketNativeStartupAllocationRow>() * 2
        + size_of::<activation::PacketRestorationActivationAllocationRow>()

        + size_of::<[SchemaEntry; 4]>()
        + size_of::<std::array::IntoIter<SchemaEntry, 4>>()
        + size_of::<SchemaEntry>()
        + size_of::<&SchemaRef>()
        + size_of::<&[SchemaRef]>()
        + size_of::<Option<&SchemaRef>>()
        + size_of::<Result<&SchemaRef, ProviderError>>()
        + size_of::<std::slice::Iter<'static, SchemaRef>>()
        + size_of::<std::slice::Iter<'static, crucible_node_contract::NodeBinding>>()
        + size_of::<&crucible_node_contract::NodeBinding>()
        + size_of::<std::slice::Iter<'static, crucible_node_contract::Id>>()
        + size_of::<&crucible_node_contract::Id>()

        + size_of::<&str>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<&usize>()
        + size_of::<[usize; 2]>()
        + size_of::<[usize; 3]>()
        + size_of::<[usize; 6]>()
        + size_of::<[usize; 7]>()
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Result<u64, ProviderError>>()
        + size_of::<Result<U64, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()

        + original_json_value_storage_extent_counter_scratch_data()
        + restoration_observe::original_installed_restoration_observation_construction_counter_scratch_data()
        + restoration_suffix_schema_counter_scratch_data()
        + restoration_observe::restoration_observe_schema_counter_scratch_data()
        + activation::restoration_activation_schema_counter_scratch_data()
        + activation::upload::restoration_activation_upload_schema_counter_scratch_data()
}

#[cfg(test)]
#[path = "reservation_tests.rs"]
mod tests;
