//! Private birth configuration and finite storage selection for native edition five.
//!
//! Launch bytes select the actual native model, complete coordinator and bounded
//! protocol storage before Hello. They do not install capture, restoration or
//! behavioral qualification. Original launch secrets stay outside public evidence.

use crucible_node_format::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::{super::control::PacketControlSelection, PacketConnectedSourceProgram};
use crate::{ProviderError, handshake::Limits, reference_service::InstalledContent};

#[path = "native5/credit_failure.rs"]
mod credit_failure;
mod profile;
pub use profile::PacketNative5CaptureProfile;

/// Selects finite complete-state storage independently of hard implementation ceilings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNative5StorageLimits {
    /// Bounds the complete native snapshot object, at most eight MiB.
    pub snapshot_bytes: U64,
    /// Bounds its original control/model component before whole-state encoding.
    pub control_snapshot_bytes: U64,
    /// Bounds each independently owned protocol snapshot reservation.
    pub protocol_snapshot_bytes: U64,
    /// Bounds each original literal frame bank across both directions.
    pub frame_bank_bytes: U64,
    /// Bounds each direction's lifetime literal frame descriptor population.
    pub frames_per_direction: U64,
    /// Bounds each independently owned original Hello byte reservation.
    pub hello_bytes: U64,
    /// Bounds the locally retained complete capture settlement journal.
    pub settlement_bytes: U64,
}

impl PacketNative5StorageLimits {
    /// Checks selected positive bounds and complete prefix frame capacity.
    ///
    /// These checks grant no core memory reservation. The installed source
    /// factory must charge both endpoints, metadata, retained and transient
    /// copies across all four owners before any callback or native effect.
    ///
    /// # Errors
    /// Refuses zero, oversized, overflowing or incomplete selected storage.
    pub fn validate(&self, limits: &Limits) -> Result<(), ProviderError> {
        limits.validate()?;
        let snapshot = self.snapshot_bytes.get();
        let chunk = limits.blob_chunk_bytes.get();
        if snapshot == 0
            || snapshot > 8 * 1024 * 1024
            || self.control_snapshot_bytes.get() == 0
            || self.control_snapshot_bytes.get() > snapshot
            || self.protocol_snapshot_bytes.get() == 0
            || self.protocol_snapshot_bytes.get() > 512 * 1024 * 1024
            || self.frame_bank_bytes.get() == 0
            || self.frame_bank_bytes.get() > 512 * 1024 * 1024
            || self.frames_per_direction.get() == 0
            || self.frames_per_direction.get() > 4096
            || self.hello_bytes.get() < 2 * 65_536 + 8
            || self.hello_bytes.get() > 1024 * 1024
            || self.settlement_bytes.get() == 0
            || self.settlement_bytes.get() > 512 * 1024 * 1024
            || chunk == 0
            || chunk > 4096
            || limits.frame_bytes.get() > 65_536
        {
            return Err(ProviderError::ResourceExhausted(
                "native5 selected storage bounds",
            ));
        }
        // Snapshot, control and anchor each require Begin/Finish and every chunk;
        // Capture has one response. Existing lifetime history is charged by the
        // source's original bank, not discarded to make room for this prefix.
        let prefix = snapshot
            .div_ceil(chunk)
            .checked_add(self.control_snapshot_bytes.get().div_ceil(chunk))
            .and_then(|count| count.checked_add(8192_u64.div_ceil(chunk)))
            .and_then(|count| count.checked_add(7))
            .ok_or(ProviderError::ResourceExhausted(
                "native5 selected prefix count",
            ))?;
        if prefix > self.frames_per_direction.get() {
            return Err(ProviderError::ResourceExhausted(
                "native5 selected prefix descriptor credit",
            ));
        }
        Ok(())
    }
}

/// Selects one complete original native source through its inherited private channel.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNative5SourceLaunch {
    /// Selects this closed private launch edition, exactly five.
    pub schema_version: u16,
    /// Binds the complete original native realization and source implementation.
    pub selection: PacketControlSelection,
    /// Retains the unchanged producer1 or reactive4 model configuration.
    pub program: PacketConnectedSourceProgram,
    /// Names the independently installed original controller process.
    pub controller_pid: U64,
    /// Names its authentic operating-system UID.
    pub controller_uid: U64,
    /// Binds its complete independently measured executable bytes.
    pub controller_executable: ContentRef,
    /// Supplies exactly 32 secret private launch capability bytes.
    pub admission_token: Bytes,
    /// Retains the complete zero/uninitialized coordinator-five birth template.
    pub initial_coordinator: InstalledContent,
    /// Selects finite native control and transfer limits, independent of Hello size.
    pub limits: Limits,
    /// Selects actual storage allocations rather than allocating hard maxima.
    pub storage: PacketNative5StorageLimits,
    /// Selects byte encoding and independent protocol bounds, without authority.
    #[serde(
        default,
        skip_serializing_if = "PacketNative5CaptureProfile::is_original_arrays"
    )]
    pub capture_profile: PacketNative5CaptureProfile,
    /// Selects closed confirmation data; only an actual installed service enables it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation_selection: Option<super::PacketNative5ConfirmationSelection>,
    /// Selects canonical ACK data; only a genuine source association installs it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_emitter_selection: Option<super::PacketNative5AckEmitterSelection>,
    /// Selects an independent finite native codec encoding ceiling, without authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_codec_metadata_extent: Option<crate::client::CanonicalAckCodecMetadataExtent>,
    /// Selects independent native before/after metadata banks before private birth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_metadata_limits: Option<super::PacketNative5ProtocolMetadataLimits>,
    /// Selects the separately registered source-signed complete restoration path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub complete_restore_selection:
        Option<super::complete_restore::PacketNative5CompleteRestoreSelection>,
    /// Selects the separately source-authenticated canonical restore-input writer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_input_emitter_selection:
        Option<super::complete_restore::PacketNative5RestoreInputEmitterSelection>,
    /// Selects the separately source-bound original Observe allocation producer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_allocation_selection:
        Option<super::capture_allocation::PacketNative5CaptureAllocationSelection>,
    /// Selects a distinct readonly fresh target query after its actual Admit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fresh_restore_allocation_selection:
        Option<super::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection>,
    /// Names the privately owned native effect receiver.
    pub effects: PathBuf,
}

impl PacketNative5SourceLaunch {
    /// Decodes complete private launch bytes with duplicate and unknown-field refusal.
    ///
    /// # Errors
    /// Refuses oversized, malformed or inconsistent private installation bytes.
    pub fn decode(bytes: &[u8], maximum_bytes: usize) -> Result<Self, ProviderError> {
        let value = canonical::parse_json(bytes, maximum_bytes)?;
        let launch: Self = serde_json::from_value(value).map_err(ContractError::from)?;
        launch.validate()?;
        Ok(launch)
    }

    /// Validates birth configuration before sockets, Hello or native model effects.
    ///
    /// # Errors
    /// Refuses another dialect, changed program or coordinator, invalid original
    /// controller identity, missing fixed format or exhausted selected storage.
    pub fn validate(&self) -> Result<(), ProviderError> {
        crate::connection::serialized_credit(self, 1024 * 1024)?;
        self.storage.validate(&self.limits)?;
        self.capture_profile.validate()?;
        let owned = matches!(
            self.capture_profile,
            PacketNative5CaptureProfile::OwnedProtocol11 { .. }
        );
        if owned != self.protocol_metadata_limits.is_some() {
            return Err(ProviderError::Correlation(
                "native protocol metadata profile differs",
            ));
        }
        if let Some(metadata) = self.protocol_metadata_limits {
            metadata.validate_data()?;
        }
        if self.capture_allocation_selection.is_some()
            && (!owned
                || self.protocol_metadata_limits.is_none()
                || self.native_codec_metadata_extent
                    != Some(crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
                || self.ack_emitter_selection
                    != Some(super::PacketNative5AckEmitterSelection::CanonicalSdkBlob5))
        {
            return Err(ProviderError::Correlation(
                "native Capture allocation birth tuple",
            ));
        }
        if self.fresh_restore_allocation_selection.is_some()
            && (!owned
                || self.protocol_metadata_limits.is_none()
                || self.native_codec_metadata_extent != Some(crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
                || self.ack_emitter_selection != Some(super::PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
                || self.complete_restore_selection != Some(super::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
                || self.restore_input_emitter_selection != Some(super::complete_restore::PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12))
        {
            return Err(ProviderError::Correlation("native fresh report birth tuple"));
        }
        self.controller_executable.validate()?;
        self.selection.provider.validate()?;
        self.selection.realization.validate()?;
        self.selection.realize.validate()?;
        let schema = super::super::continuation_contracts::complete_packet_ingress_schema()?;
        if self.schema_version != 5
            || self.admission_token.as_slice().len() != 32
            || self.controller_pid.get() == 0
            || self.controller_pid.get() > i32::MAX as u64
            || self.controller_uid.get() > u32::MAX as u64
            || !self
                .selection
                .provider
                .implementation
                .formats
                .contains(&schema)
            || self.limits.requests.get() < 32
            || self.limits.requests.get() > 256
            || self.limits.nesting.get() != 64
            || self.limits.journal_entries.get() > 4096
        {
            return Err(ProviderError::Correlation(
                "native5 complete private launch",
            ));
        }
        self.initial_coordinator
            .reference
            .verify(self.initial_coordinator.bytes.as_slice())?;
        if self.initial_coordinator.reference.media_type != "application/json" {
            return Err(ProviderError::Correlation("native5 coordinator media"));
        }
        super::super::coordinator::PacketNative5CoordinatorInstallation::decode(
            self.initial_coordinator.bytes.as_slice(),
            &self.selection,
        )?;
        let configuration = match &self.program {
            PacketConnectedSourceProgram::Producer { program }
                if program.schema == "source-owned.packet-program.v1"
                    && program.events.len() == 2 =>
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
        self.selection
            .realize
            .configuration
            .verify(&canonical::canonical_json(&configuration)?)?;
        if self.restore_input_emitter_selection.is_some() && self.complete_restore_selection != Some(super::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12) {
            return Err(ProviderError::Correlation("native restore input selection lacks transfer12"));
        }
        if let Some(restoration) = self.complete_restore_selection {
            super::super::Native5Policy::from_original_launch_with_complete_restore(
                self.selection.clone(),
                self.initial_coordinator.clone(),
                self.capture_profile.clone(),
                self.confirmation_selection
                    .ok_or(ProviderError::Correlation(
                        "restoring native confirmation absent",
                    ))?,
                self.ack_emitter_selection
                    .ok_or(ProviderError::Correlation("restoring native ACK absent"))?,
                self.native_codec_metadata_extent
                    .ok_or(ProviderError::Correlation(
                        "restoring native codec extent absent",
                    ))?,
                self.protocol_metadata_limits
                    .ok_or(ProviderError::Correlation(
                        "restoring native metadata absent",
                    ))?,
                restoration,
            )?
            .with_restore_input_emitter_selection(self.restore_input_emitter_selection)?
            .with_capture_allocation_selection(self.capture_allocation_selection)?
            .with_fresh_restore_allocation_selection(self.fresh_restore_allocation_selection)?;
        } else if let Some(metadata) = self.protocol_metadata_limits {
            super::super::Native5Policy::from_original_launch_with_protocol_metadata(
                self.selection.clone(),
                self.initial_coordinator.clone(),
                self.capture_profile.clone(),
                self.confirmation_selection
                    .ok_or(ProviderError::Correlation(
                        "owned native confirmation absent",
                    ))?,
                self.ack_emitter_selection
                    .ok_or(ProviderError::Correlation("owned native ACK absent"))?,
                self.native_codec_metadata_extent
                    .ok_or(ProviderError::Correlation(
                        "owned native codec extent absent",
                    ))?,
                metadata,
            )?
            .with_capture_allocation_selection(self.capture_allocation_selection)?
            .with_fresh_restore_allocation_selection(self.fresh_restore_allocation_selection)?;
        } else if let Some(emitter) = self.ack_emitter_selection {
            let confirmation = self
                .confirmation_selection
                .ok_or(ProviderError::Correlation(
                    "canonical ACK emitter requires selected confirmation",
                ))?;
            if let Some(extent) = self.native_codec_metadata_extent {
                super::super::Native5Policy::from_original_launch_with_ack_emitter_metadata_extent(
                    self.selection.clone(),
                    self.initial_coordinator.clone(),
                    self.capture_profile.clone(),
                    confirmation,
                    emitter,
                    extent,
                )?;
            } else {
                super::super::Native5Policy::from_original_launch_with_ack_emitter(
                    self.selection.clone(),
                    self.initial_coordinator.clone(),
                    self.capture_profile.clone(),
                    confirmation,
                    emitter,
                )?;
            }
        } else if self.native_codec_metadata_extent.is_some() {
            return Err(ProviderError::Correlation(
                "native codec extent requires canonical ACK selection",
            ));
        } else if let Some(confirmation) = self.confirmation_selection {
            // Additional source grammar is authenticated before any service
            // allocation or listener effect; selecting it grants no mechanism.
            super::super::Native5Policy::from_original_launch_with_confirmation(
                self.selection.clone(),
                self.initial_coordinator.clone(),
                self.capture_profile.clone(),
                confirmation,
            )?;
        } else {
            super::super::Native5Policy::from_original_launch(
                self.selection.clone(),
                self.initial_coordinator.clone(),
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "native5/storage_geometry_tests.rs"]
mod storage_geometry_tests;
