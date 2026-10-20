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
#[path = "native5/validation.rs"]
mod validation;
pub use validation::{
    PacketNative5LaunchValidationFields, PacketNative5LaunchValidationProjection,
    PacketNative5PathSerializationData,
};

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
        validation::validate_real_launch(self)
    }
}

#[cfg(test)]
#[path = "native5/storage_geometry_tests.rs"]
mod storage_geometry_tests;
