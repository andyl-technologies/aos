//! Private original installation of the connected packet world edition 4.
//!
//! The inherited launch is neither a CNP method nor a behavioral qualification.
//! Its exact independently installed native scope remains bound to actual kernel
//! peer credentials, measured executable bytes and the original all-owner gate.

use std::path::PathBuf;

use crucible_node_format::*;
use serde::{Deserialize, Serialize};

use super::super::{
    PacketProgramDefinition, connected::PacketConnectedDefinition, control::PacketControlSelection,
    coordinator::PacketConnectedCoordinatorInstallation,
};
use crate::{ProviderError, handshake::Limits, reference_service::InstalledContent};

/// Selects one original interpreter without changing existing output-only profiles.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PacketConnectedSourceProgram {
    /// Retains the independently configured source-2 output producer.
    Producer {
        /// Retains its complete unchanged two-event program.
        program: PacketProgramDefinition,
    },
    /// Installs the distinct source-4 relay or sink.
    Reactive {
        /// Retains every declared original input connection and output lane.
        program: PacketConnectedDefinition,
    },
}

/// Installs one original native participant of a connected three-owner world.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketConnectedSourceLaunch {
    /// Selects this distinct private launch edition, exactly four.
    pub schema_version: u16,
    /// Retains the complete independently selected native route and source tuple.
    pub selection: PacketControlSelection,
    /// Selects the source-defined original interpreter and complete configuration.
    pub program: PacketConnectedSourceProgram,
    /// Names the original authentic controller process.
    pub controller_pid: U64,
    /// Names its actual independently installed operating-system UID.
    pub controller_uid: U64,
    /// Binds its complete measured executable bytes.
    pub controller_executable: ContentRef,
    /// Supplies exactly 32 private admission capability bytes.
    pub admission_token: Bytes,
    /// Retains the complete connected coordinator with no predicted preparations.
    pub initial_coordinator: InstalledContent,
    /// Selects the exact finite original connection and proof ceilings.
    pub limits: Limits,
    /// Names the original privately owned native effect receiver.
    pub effects: PathBuf,
}

impl PacketConnectedSourceLaunch {
    /// Decodes complete private bytes through the bounded duplicate-rejecting parser.
    ///
    /// # Errors
    /// Refuses oversized, duplicate, unknown, malformed or changed original fields.
    pub fn decode(bytes: &[u8], maximum_bytes: usize) -> Result<Self, ProviderError> {
        let value = canonical::parse_json(bytes, maximum_bytes)?;
        let launch: Self = serde_json::from_value(value).map_err(ContractError::from)?;
        launch.validate()?;
        Ok(launch)
    }

    /// Verifies this complete finite independently installed original launch.
    ///
    /// # Errors
    /// Refuses another edition, source program, coordinator, native identity or credit.
    pub fn validate(&self) -> Result<(), ProviderError> {
        crate::connection::serialized_credit(self, 1024 * 1024)?;
        self.limits.validate()?;
        self.controller_executable.validate()?;
        self.selection.provider.validate()?;
        self.selection.realization.validate()?;
        self.selection.realize.validate()?;
        let contract = super::super::contracts::connected_ingress_contract()?;
        let definition = canonical::content_ref(&contract, "application/json")?;
        if self.schema_version != 4
            || self.admission_token.as_slice().len() != 32
            || self.controller_pid.get() == 0
            || self.controller_pid.get() > i32::MAX as u64
            || self.controller_uid.get() > u32::MAX as u64
            || self.limits.frame_bytes.get() != 65_536
            || self.limits.requests.get() != 256
            || self.limits.nesting.get() != 64
            || self.limits.blob_chunk_bytes.get() != 4096
            || self.limits.journal_entries.get() != 1024
            || self
                .selection
                .provider
                .implementation
                .formats
                .iter()
                .filter(|schema| {
                    schema.id.as_str() == "source-owned.packet-ingress/4"
                        && schema.version == 4
                        && schema.definition == definition
                        && schema.extensions.is_empty()
                })
                .count()
                != 1
            || self
                .selection
                .provider
                .implementation
                .formats
                .iter()
                .any(|schema| {
                    matches!(
                        schema.id.as_str(),
                        "source-owned.packet-ingress/1"
                            | "source-owned.packet-ingress/2"
                            | "source-owned.packet-ingress/3"
                    )
                })
        {
            return Err(ProviderError::Correlation(
                "packet connected private source launch",
            ));
        }
        let coordinator = &self.initial_coordinator;
        coordinator.reference.verify(coordinator.bytes.as_slice())?;
        if coordinator.reference.media_type != "application/json" {
            return Err(ProviderError::Correlation(
                "packet connected coordinator media",
            ));
        }
        PacketConnectedCoordinatorInstallation::decode(
            coordinator.bytes.as_slice(),
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
                    "packet connected native program edition",
                ));
            }
        }
        .map_err(ContractError::from)?;
        let configuration = canonical::canonical_json(&configuration)?;
        self.selection
            .realize
            .configuration
            .verify(&configuration)?;
        Ok(())
    }
}
