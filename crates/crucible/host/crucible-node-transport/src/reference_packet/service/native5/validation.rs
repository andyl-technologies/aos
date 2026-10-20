//! Shares the original pure launch validator with a secret-free input adapter.
//!
//! The ordinary launch still uses its actual complete serializer as the first
//! check. A projected caller counts the same fields and exact opaque JSON
//! extents without manufacturing token bytes, a path or another launch. These
//! inputs and successful validation are DATA only, never installation authority.

use super::*;
use crate::reference_packet::{Native5Policy, service};

#[path = "validation/credit.rs"]
mod credit;
use credit::Credit;

#[cfg(test)]
#[path = "validation/original.rs"]
mod original;

/// Borrows all nonsecret operands of the original launch validator.
///
/// No field borrows the admission token or effects path. Constructing this view
/// neither validates these claims nor authenticates their origin. A worker's
/// owning input codec and the parent's authenticated job remain separate.
#[derive(Clone, Copy)]
pub struct PacketNative5LaunchValidationFields<'a> {
    /// Selects the actual private launch edition.
    pub schema_version: u16,
    /// Borrows the complete portable source selection.
    pub selection: &'a PacketControlSelection,
    /// Borrows the unchanged producer or reactive program.
    pub program: &'a PacketConnectedSourceProgram,
    /// Carries the original controller process number as inert data.
    pub controller_pid: U64,
    /// Carries the original controller user number as inert data.
    pub controller_uid: U64,
    /// Borrows the complete portable executable content reference.
    pub controller_executable: &'a ContentRef,
    /// Borrows the candidate coordinator bytes and complete content reference.
    pub initial_coordinator: &'a InstalledContent,
    /// Borrows the original protocol limits.
    pub limits: &'a Limits,
    /// Borrows the original selected storage limits.
    pub storage: &'a PacketNative5StorageLimits,
    /// Borrows the original byte representation selection.
    pub capture_profile: &'a PacketNative5CaptureProfile,
    /// Carries the original optional confirmation selection.
    pub confirmation_selection: Option<service::PacketNative5ConfirmationSelection>,
    /// Carries the original optional ACK emitter selection.
    pub ack_emitter_selection: Option<service::PacketNative5AckEmitterSelection>,
    /// Carries the original optional native codec extent.
    pub native_codec_metadata_extent: Option<crate::client::CanonicalAckCodecMetadataExtent>,
    /// Carries the original optional protocol metadata limits.
    pub protocol_metadata_limits: Option<service::PacketNative5ProtocolMetadataLimits>,
    /// Carries the original optional complete restoration selection.
    pub complete_restore_selection:
        Option<service::complete_restore::PacketNative5CompleteRestoreSelection>,
    /// Carries the original optional restore-input selection.
    pub restore_input_emitter_selection:
        Option<service::complete_restore::PacketNative5RestoreInputEmitterSelection>,
    /// Carries the original optional Capture allocation selection.
    pub capture_allocation_selection:
        Option<service::capture_allocation::PacketNative5CaptureAllocationSelection>,
    /// Carries the original optional fresh-query allocation selection.
    pub fresh_restore_allocation_selection:
        Option<service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection>,
}

impl<'a> PacketNative5LaunchValidationFields<'a> {
    /// Borrows the real launch's nonsecret fields without decoding or cloning.
    pub fn from_launch_data(launch: &'a PacketNative5SourceLaunch) -> Self {
        let PacketNative5SourceLaunch {
            schema_version,
            selection,
            program,
            controller_pid,
            controller_uid,
            controller_executable,
            initial_coordinator,
            limits,
            storage,
            capture_profile,
            confirmation_selection,
            ack_emitter_selection,
            native_codec_metadata_extent,
            protocol_metadata_limits,
            complete_restore_selection,
            restore_input_emitter_selection,
            capture_allocation_selection,
            fresh_restore_allocation_selection,
            admission_token: _,
            effects: _,
        } = launch;
        Self {
            schema_version: *schema_version,
            selection,
            program,
            controller_pid: *controller_pid,
            controller_uid: *controller_uid,
            controller_executable,
            initial_coordinator,
            limits,
            storage,
            capture_profile,
            confirmation_selection: *confirmation_selection,
            ack_emitter_selection: *ack_emitter_selection,
            native_codec_metadata_extent: *native_codec_metadata_extent,
            protocol_metadata_limits: *protocol_metadata_limits,
            complete_restore_selection: *complete_restore_selection,
            restore_input_emitter_selection: *restore_input_emitter_selection,
            capture_allocation_selection: *capture_allocation_selection,
            fresh_restore_allocation_selection: *fresh_restore_allocation_selection,
        }
    }
}

/// Describes only an effects path's original JSON serialization outcome.
///
/// This is an inert, unauthenticated shape, not a pathname or file capability.
/// The projected credit check consumes it only at the original effects field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketNative5PathSerializationData {
    /// Counts the complete quoted JSON string, including escapes and quotes.
    QuotedUtf8 {
        /// Gives the actual complete serialized string extent in bytes.
        bytes: usize,
    },
    /// Defers the original Path serializer's invalid-UTF8 refusal.
    InvalidUtf8,
    /// Defers inability to represent the complete serialized extent.
    Unrepresentable,
}

impl PacketNative5PathSerializationData {
    /// Measures the real borrowed path through the actual JSON string formatter.
    ///
    /// The counter owns no path text or output buffer. Invalid UTF-8 and checked
    /// overflow are recorded as DATA rather than returned before earlier launch
    /// fields have had their original validation/error precedence.
    pub fn from_path_data(path: &std::path::Path) -> Self {
        credit::path_serialization_data(path)
    }
}

/// Supplies inert secret shapes beside actual nonsecret validation operands.
///
/// Successful validation supplies no Source, process, transport or native grant.
/// The caller independently authenticates the original inputs, installed code,
/// resource budget and result association. The view owns no secret or output.
pub struct PacketNative5LaunchValidationProjection<'a> {
    fields: PacketNative5LaunchValidationFields<'a>,
    token_length: usize,
    path: PacketNative5PathSerializationData,
}

impl<'a> PacketNative5LaunchValidationProjection<'a> {
    /// Records inert projected operands without claiming original-input custody.
    ///
    /// A bounded worker codec can borrow its own decoded fields here. The token
    /// length and path shape remain unauthenticated caller DATA until the parent
    /// authenticates its actual task/input association.
    pub const fn from_parts_data(
        fields: PacketNative5LaunchValidationFields<'a>,
        token_length: usize,
        path: PacketNative5PathSerializationData,
    ) -> Self {
        Self {
            fields,
            token_length,
            path,
        }
    }

    /// Projects an original borrowed launch without retaining its token or path.
    ///
    /// Path measurement performs a bounded-by-input string-format walk; this is
    /// not an admission API. Its caller must independently bound that work before
    /// entry. The ordinary validate method does not call this constructor.
    pub fn from_launch_data(launch: &'a PacketNative5SourceLaunch) -> Self {
        Self::from_parts_data(
            PacketNative5LaunchValidationFields::from_launch_data(launch),
            launch.admission_token.as_slice().len(),
            PacketNative5PathSerializationData::from_path_data(&launch.effects),
        )
    }

    /// Returns the inert nonsecret field view without cloning its children.
    pub const fn fields_data(&self) -> PacketNative5LaunchValidationFields<'a> {
        self.fields
    }

    /// Returns the original token-length claim, never its secret bytes.
    pub const fn token_length_data(&self) -> usize {
        self.token_length
    }

    /// Returns the inert effects-string serialization claim.
    pub const fn path_serialization_data(&self) -> PacketNative5PathSerializationData {
        self.path
    }

    /// Counts complete original JSON using real fields and opaque extents.
    ///
    /// This count emits no launch JSON and cannot be used as an allocation or
    /// execution permission. The maximum restricts the count, not input custody.
    ///
    /// # Errors
    /// Returns the original collapsed whole-frame resource error for formatter
    /// failure, invalid path shape, checked overflow or an exceeded maximum.
    pub fn serialized_credit_data(&self, maximum: usize) -> Result<usize, ProviderError> {
        credit::projected_credit_data(&self.fields, self.token_length, self.path, maximum)
    }

    /// Runs the same pure validator schedule as the original real launch.
    ///
    /// The first check is complete serialized credit, followed by every original
    /// field, coordinator, model and selected immutable-policy check in order.
    /// No effect path is opened and no secret is reconstructed.
    ///
    /// # Errors
    /// Preserves the original validation error/category/order for an exact
    /// projection of the same launch. No authenticity of supplied DATA is implied.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        validate(
            &self.fields,
            Credit::Projected {
                token_length: self.token_length,
                path: self.path,
            },
        )
    }
}

impl PacketNative5SourceLaunch {
    /// Prices the fixed real-input headers introduced by the shared validator.
    ///
    /// Both defining launch-validation rows add this independently of their old
    /// terms before constructing the borrowed view. It owns no heap and prices
    /// no additional scalar decoder, serializer or policy work. Projected credit
    /// and future worker/exporter execution require their own caller boundary.
    pub(crate) const VALIDATION_INPUT_COUNTER_SCRATCH_DATA: usize =
        // from_launch_data's input, initialized view and returned view.
        size_of::<&'static Self>()
            + size_of::<PacketNative5LaunchValidationFields<'static>>()
            + size_of::<PacketNative5LaunchValidationFields<'static>>()
            // The real adapter retains that view through shared validation.
            + size_of::<&'static Self>()
            + size_of::<PacketNative5LaunchValidationFields<'static>>()
            + size_of::<&'static PacketNative5LaunchValidationFields<'static>>()
            // Original selector construction and owned shared-call argument.
            + size_of::<Credit<'static>>()
            + size_of::<Credit<'static>>()
            // The sealed credit dispatch borrows both actual input headers.
            + size_of::<&'static Credit<'static>>()
            + size_of::<&'static PacketNative5LaunchValidationFields<'static>>()
            + size_of::<Result<usize, ProviderError>>()
            // New shared-validator and real-adapter return headers. The old
            // public validate return remains in its existing parent contract.
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<(), ProviderError>>();
}

pub(super) fn validate_real_launch(
    launch: &PacketNative5SourceLaunch,
) -> Result<(), ProviderError> {
    let input = PacketNative5LaunchValidationFields::from_launch_data(launch);
    validate(&input, Credit::Original(launch))
}

fn validate(
    input: &PacketNative5LaunchValidationFields<'_>,
    credit: Credit<'_>,
) -> Result<(), ProviderError> {
    credit.check_data(input, 1024 * 1024)?;
    input.storage.validate(&input.limits)?;
    input.capture_profile.validate()?;
    let owned = matches!(
        input.capture_profile,
        PacketNative5CaptureProfile::OwnedProtocol11 { .. }
    );
    if owned != input.protocol_metadata_limits.is_some() {
        return Err(ProviderError::Correlation(
            "native protocol metadata profile differs",
        ));
    }
    if let Some(metadata) = input.protocol_metadata_limits {
        metadata.validate_data()?;
    }
    if input.capture_allocation_selection.is_some()
        && (!owned
            || input.protocol_metadata_limits.is_none()
            || input.native_codec_metadata_extent
                != Some(crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
            || input.ack_emitter_selection
                != Some(service::PacketNative5AckEmitterSelection::CanonicalSdkBlob5))
    {
        return Err(ProviderError::Correlation(
            "native Capture allocation birth tuple",
        ));
    }
    if input.fresh_restore_allocation_selection.is_some()
            && (!owned
                || input.protocol_metadata_limits.is_none()
                || input.native_codec_metadata_extent != Some(crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
                || input.ack_emitter_selection != Some(service::PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
                || input.complete_restore_selection != Some(service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
                || input.restore_input_emitter_selection != Some(service::complete_restore::PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12))
        {
            return Err(ProviderError::Correlation("native fresh report birth tuple"));
        }
    input.controller_executable.validate()?;
    input.selection.provider.validate()?;
    input.selection.realization.validate()?;
    input.selection.realize.validate()?;
    let schema = crate::reference_packet::continuation_contracts::complete_packet_ingress_schema()?;
    if input.schema_version != 5
        || credit.token_length_data() != 32
        || input.controller_pid.get() == 0
        || input.controller_pid.get() > i32::MAX as u64
        || input.controller_uid.get() > u32::MAX as u64
        || !input
            .selection
            .provider
            .implementation
            .formats
            .contains(&schema)
        || input.limits.requests.get() < 32
        || input.limits.requests.get() > 256
        || input.limits.nesting.get() != 64
        || input.limits.journal_entries.get() > 4096
    {
        return Err(ProviderError::Correlation(
            "native5 complete private launch",
        ));
    }
    input
        .initial_coordinator
        .reference
        .verify(input.initial_coordinator.bytes.as_slice())?;
    if input.initial_coordinator.reference.media_type != "application/json" {
        return Err(ProviderError::Correlation("native5 coordinator media"));
    }
    crate::reference_packet::coordinator::PacketNative5CoordinatorInstallation::decode(
        input.initial_coordinator.bytes.as_slice(),
        &input.selection,
    )?;
    let configuration = match &input.program {
        PacketConnectedSourceProgram::Producer { program }
            if program.schema == "source-owned.packet-program.v1" && program.events.len() == 2 =>
        {
            serde_json::to_value(program)
        }
        PacketConnectedSourceProgram::Reactive { program }
            if program.schema == "source-owned.packet-connected-program/4"
                && !program.connections.is_empty()
                && program.connections.len() <= 4 =>
        {
            serde_json::to_value(program)
        }
        _ => {
            return Err(ProviderError::Correlation(
                "native5 model configuration edition",
            ));
        }
    }
    .map_err(ContractError::from)?;
    input
        .selection
        .realize
        .configuration
        .verify(&canonical::canonical_json(&configuration)?)?;
    if input.restore_input_emitter_selection.is_some() && input.complete_restore_selection != Some(service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12) {
            return Err(ProviderError::Correlation("native restore input selection lacks transfer12"));
        }
    if let Some(restoration) = input.complete_restore_selection {
        Native5Policy::from_original_launch_with_complete_restore(
            input.selection.clone(),
            input.initial_coordinator.clone(),
            input.capture_profile.clone(),
            input
                .confirmation_selection
                .ok_or(ProviderError::Correlation(
                    "restoring native confirmation absent",
                ))?,
            input
                .ack_emitter_selection
                .ok_or(ProviderError::Correlation("restoring native ACK absent"))?,
            input
                .native_codec_metadata_extent
                .ok_or(ProviderError::Correlation(
                    "restoring native codec extent absent",
                ))?,
            input
                .protocol_metadata_limits
                .ok_or(ProviderError::Correlation(
                    "restoring native metadata absent",
                ))?,
            restoration,
        )?
        .with_restore_input_emitter_selection(input.restore_input_emitter_selection)?
        .with_capture_allocation_selection(input.capture_allocation_selection)?
        .with_fresh_restore_allocation_selection(input.fresh_restore_allocation_selection)?;
    } else if let Some(metadata) = input.protocol_metadata_limits {
        Native5Policy::from_original_launch_with_protocol_metadata(
            input.selection.clone(),
            input.initial_coordinator.clone(),
            input.capture_profile.clone(),
            input
                .confirmation_selection
                .ok_or(ProviderError::Correlation(
                    "owned native confirmation absent",
                ))?,
            input
                .ack_emitter_selection
                .ok_or(ProviderError::Correlation("owned native ACK absent"))?,
            input
                .native_codec_metadata_extent
                .ok_or(ProviderError::Correlation(
                    "owned native codec extent absent",
                ))?,
            metadata,
        )?
        .with_capture_allocation_selection(input.capture_allocation_selection)?
        .with_fresh_restore_allocation_selection(input.fresh_restore_allocation_selection)?;
    } else if let Some(emitter) = input.ack_emitter_selection {
        let confirmation = input
            .confirmation_selection
            .ok_or(ProviderError::Correlation(
                "canonical ACK emitter requires selected confirmation",
            ))?;
        if let Some(extent) = input.native_codec_metadata_extent {
            Native5Policy::from_original_launch_with_ack_emitter_metadata_extent(
                input.selection.clone(),
                input.initial_coordinator.clone(),
                input.capture_profile.clone(),
                confirmation,
                emitter,
                extent,
            )?;
        } else {
            Native5Policy::from_original_launch_with_ack_emitter(
                input.selection.clone(),
                input.initial_coordinator.clone(),
                input.capture_profile.clone(),
                confirmation,
                emitter,
            )?;
        }
    } else if input.native_codec_metadata_extent.is_some() {
        return Err(ProviderError::Correlation(
            "native codec extent requires canonical ACK selection",
        ));
    } else if let Some(confirmation) = input.confirmation_selection {
        // Additional source grammar is authenticated before any service
        // allocation or listener effect; selecting it grants no mechanism.
        Native5Policy::from_original_launch_with_confirmation(
            input.selection.clone(),
            input.initial_coordinator.clone(),
            input.capture_profile.clone(),
            confirmation,
        )?;
    } else {
        Native5Policy::from_original_launch(
            input.selection.clone(),
            input.initial_coordinator.clone(),
        )?;
    }
    Ok(())
}

#[cfg(test)]
impl PacketNative5SourceLaunch {
    /// Runs the saved original validator only for crate-local parity controls.
    ///
    /// The oracle lives under the same service visibility boundary as the real
    /// validator; no production policy constructor becomes more visible.
    ///
    /// # Errors
    /// Returns the unchanged original full-launch validation refusal.
    pub(crate) fn validate_original_for_projection_test_data(&self) -> Result<(), ProviderError> {
        original::validate(self)
    }
}
