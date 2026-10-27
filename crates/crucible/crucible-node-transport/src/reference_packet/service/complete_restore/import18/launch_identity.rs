//! Binds actual typed launch/base5 bytes and the same guarded private-launch Id.
//!
//! Metadata prequote precedes the serialization counter; that admitted complete
//! row precedes Value/JCS construction. No caller-supplied digest can construct
//! this Copy output. The Source/Birth lender independently guards actual operand
//! provenance and currentness; the output itself supplies no phase permission.

use super::*;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::retained_metadata::{
    MetadataObserver, OrdinaryBytesFormatterDemandData,
    ordinary_bytes_formatter_counter_scratch_data, retained_native_launch_counter_scratch_data,
    serialization_storage::{
        OriginalSerializationStorageProjection as Projection,
        original_serialization_counter_scratch_data,
    },
};
use std::mem::size_of;

/// Retains canonical typed-launch and private-launch identities as DATA.
#[derive(Clone, Copy)]
pub struct PacketNativeImport18LaunchIdentityData {
    selected: [u8; 32],
    private: [u8; 32],
}

impl PacketNativeImport18LaunchIdentityData {
    /// Returns the actual complete canonical base5 launch identity.
    pub const fn selected_launch_identity_data(&self) -> [u8; 32] {
        self.selected
    }

    /// Returns the same guarded Birth's actual private-launch Id identity.
    pub const fn private_launch_identity_data(&self) -> [u8; 32] {
        self.private
    }
}

/// Quotes actual hidden Bytes formatting without invoking serialization.
///
/// # Errors
/// Refuses defining launch metadata traversal or arithmetic overflow.
pub fn native_import18_launch_identity_projection_data(
    launch: &PacketNative5SourceLaunch,
) -> Result<(usize, usize), ProviderError> {
    Ok((
        launch_formatter_data(launch)?,
        native_import18_launch_identity_counter_scratch_data(),
    ))
}

/// Quotes complete typed Value/JCS correspondence after formatter admission.
///
/// No validation of the live Source or immutable launch follows from this row.
/// All prior owners remain independently charged while its T/S window is used.
///
/// # Errors
/// Refuses unsupported serialization, overflow or insufficient actual restriction.
pub fn native_import18_launch_identity_construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<(usize, usize), ProviderError> {
    let formatter = launch_formatter_data(launch)?;
    let mut projection = Projection::new(maximum)?;
    projection.add_value(launch)?;
    let shape = projection.finish(maximum)?;
    let temporary = shape
        .dom_and_canonical_scratch_bytes
        .checked_add(shape.canonical_output_requested_bytes)
        .and_then(|value| value.checked_add(formatter))
        .and_then(|value| value.checked_add(size_of::<serde_json::Value>()))
        .and_then(|value| {
            value.checked_add(size_of::<Result<serde_json::Value, serde_json::Error>>())
        })
        .and_then(|value| value.checked_add(size_of::<Vec<u8>>()))
        .and_then(|value| value.checked_add(size_of::<Result<Vec<u8>, ContractError>>()))
        .and_then(|value| value.checked_add(size_of::<PacketNativeImport18LaunchIdentityData>()))
        .and_then(|value| {
            value.checked_add(size_of::<
                Result<PacketNativeImport18LaunchIdentityData, ProviderError>,
            >())
        })
        .ok_or_else(invalid)?;
    let scratch = native_import18_launch_identity_counter_scratch_data();
    if temporary
        .checked_add(scratch)
        .is_none_or(|value| value > maximum)
    {
        return Err(invalid());
    }
    Ok((temporary, scratch))
}

/// Derives identities from actual operands after complete construction admission.
///
/// The actual unstarted Source Birth lends private_launch; the installed holder
/// lends same typed launch and canonical base5. This helper serializes the typed
/// launch and compares every canonical byte before returning fixed identities.
/// It creates no recipe, mechanism, Source, member, phase claim or admission.
///
/// # Errors
/// Refuses an empty/over-bound base5, typed/base5 mismatch or canonical failure.
pub fn native_import18_launch_identity_data(
    launch: &PacketNative5SourceLaunch,
    canonical_base5: &[u8],
    private_launch: &Id,
    maximum_encoded_bytes: usize,
) -> Result<PacketNativeImport18LaunchIdentityData, ProviderError> {
    if canonical_base5.is_empty() || canonical_base5.len() > maximum_encoded_bytes {
        return Err(invalid());
    }
    let value = serde_json::to_value(launch).map_err(ContractError::from)?;
    let bytes = canonical::canonical_json(&value)?;
    if bytes.as_slice() != canonical_base5 || bytes.len() > maximum_encoded_bytes {
        return Err(invalid());
    }
    identity_from_canonical_base5(canonical_base5, private_launch)
}

/// Derives identities from the canonical encoding of the actual borrowed launch.
///
/// Callers admit the formatter prewalk and complete construction row first.
/// The original Source/Birth lender checks provenance and currentness around
/// this DATA construction. No parsed recipe, numeric digest or supplied row
/// enters the derivation, and its output grants no native phase permission.
///
/// # Errors
/// Refuses canonical construction, checked length conversion or an encoded
/// launch above the independently admitted restriction.
pub fn derive_native_import18_launch_identity_data(
    launch: &PacketNative5SourceLaunch,
    private_launch: &Id,
    maximum_encoded_bytes: usize,
) -> Result<PacketNativeImport18LaunchIdentityData, ProviderError> {
    let value = serde_json::to_value(launch).map_err(ContractError::from)?;
    let bytes = canonical::canonical_json(&value)?;
    if bytes.is_empty() || bytes.len() > maximum_encoded_bytes {
        return Err(invalid());
    }
    identity_from_canonical_base5(&bytes, private_launch)
}

fn identity_from_canonical_base5(
    canonical_base5: &[u8],
    private_launch: &Id,
) -> Result<PacketNativeImport18LaunchIdentityData, ProviderError> {
    let mut selected = blake3::Hasher::new_derive_key(
        "source-owned.packet-native-import-selected-launch-identity/18",
    );
    selected.update(canonical_base5);
    let mut private = blake3::Hasher::new_derive_key(
        "source-owned.packet-native-import-private-launch-identity/18",
    );
    private.update(
        &u64::try_from(private_launch.as_str().len())
            .map_err(|_| invalid())?
            .to_be_bytes(),
    );
    private.update(private_launch.as_str().as_bytes());
    Ok(PacketNativeImport18LaunchIdentityData {
        selected: *selected.finalize().as_bytes(),
        private: *private.finalize().as_bytes(),
    })
}

fn launch_formatter_data(launch: &PacketNative5SourceLaunch) -> Result<usize, ProviderError> {
    let mut observer = MetadataObserver::new();
    observer.observe_bootstrap_launch_data(launch)?;
    // Only initialized Bytes are serialized. Parent spare capacity stays in
    // the independently retained owner and cannot change the native quote.
    observer
        .ordinary_bytes_formatter_data()
        .maximum_temporary_requested_bytes_data()
}

/// Names actual metadata, projection, canonical and fixed identity controls.
pub fn native_import18_launch_identity_counter_scratch_data() -> usize {
    retained_native_launch_counter_scratch_data()
        + ordinary_bytes_formatter_counter_scratch_data()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<OrdinaryBytesFormatterDemandData>()
        + original_serialization_counter_scratch_data()
        + canonical::canonical_json_counter_scratch_bytes_data()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&Id>()
        + size_of::<&[u8]>()
        + size_of::<blake3::Hasher>() * 2
        + size_of::<blake3::Hash>() * 2
        + size_of::<[u8; 8]>()
        + size_of::<Projection>()
        + size_of::<Result<(usize, usize), ProviderError>>()
}

#[cfg(test)]
#[path = "launch_identity/tests.rs"]
mod tests;
