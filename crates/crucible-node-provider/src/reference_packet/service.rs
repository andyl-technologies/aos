//! Private installation of the finite owning packet source process.
//!
//! The launch record arrives only through an inherited private channel. It is
//! not a CNP request, behavioral certificate, public Ready or restoration token.
//! The source exposes only the exact output-only native program and source2
//! control dialect; independent host acceptance remains mandatory for admission.
//!
//! ```text
//! {"schema_version":1,"selection":{...},"program":{...},
//!  "controller_pid":"...","controller_uid":"...","controller_executable":{...},
//!  "admission_token":[...],"initial_coordinator":{...},"limits":{...},
//!  "effects":"/private/original-effects.sock"}
//! ```

use std::{path::PathBuf, rc::Rc};

use crucible_node_contract::*;
use serde::{Deserialize, Serialize};

use super::{PacketProgramDefinition, control::PacketControlSelection};
use crate::{ProviderError, handshake::Limits, reference_service::InstalledContent};

mod security;
mod server;

/// Installs the exact original packet source through a private inherited channel.
///
/// Tokens and paths must never appear in public reports, arguments, content
/// hashes or diagnostics. Possession is private launch authority only; source
/// class acceptance and authentic common grant authority remain independent.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketSourceLaunch {
    /// Selects exact preinstalled ingress 1 or actual post-Arm common ingress 2.
    pub schema_version: u16,
    /// Binds the complete source-selected original realization and native gate.
    pub selection: PacketControlSelection,
    /// Supplies every original native event and payload before effects.
    pub program: PacketProgramDefinition,
    /// Names the authentic original host controller process.
    pub controller_pid: U64,
    /// Names the independently installed original controller kernel UID.
    pub controller_uid: U64,
    /// Binds complete independently measured original controller executable bytes.
    pub controller_executable: ContentRef,
    /// Supplies exactly 32 secret launch capability bytes on the private channel.
    pub admission_token: Bytes,
    /// Supplies independently installed coordinator scope before launch.
    ///
    /// Edition 1 contains the exact complete legacy body. Edition 2 contains
    /// the static template with no preparations; only the actual native Arm
    /// receipt can complete the subsequently published coordinator body.
    pub initial_coordinator: InstalledContent,
    /// Selects original finite source receiving limits, including proof credit.
    pub limits: Limits,
    /// Names the private independently owned effect receiver, never a public URL.
    pub effects: PathBuf,
}

impl PacketSourceLaunch {
    /// Checks complete source, private scope and finite input before realization.
    ///
    /// # Errors
    /// Refuses another grammar/source dialect, changed schema/program/original
    /// installation, invalid native identity, secret size or finite ceilings.
    pub fn validate(&self) -> Result<(), ProviderError> {
        crate::connection::serialized_credit(self, 1024 * 1024)?;
        self.limits.validate()?;
        self.controller_executable.validate()?;
        self.selection.provider.validate()?;
        self.selection.realization.validate()?;
        let (identifier, version, ingress) = match self.schema_version {
            1 => (
                "source-owned.packet-ingress/1",
                1,
                super::contracts::installed_ingress_contract()?,
            ),
            2 => (
                "source-owned.packet-ingress/2",
                2,
                super::contracts::common_ingress_contract()?,
            ),
            _ => return Err(ProviderError::Correlation("packet source launch edition")),
        };
        let definition = canonical::content_ref(&ingress, "application/json")?;
        let schema = self
            .selection
            .provider
            .implementation
            .formats
            .iter()
            .find(|schema| schema.id.as_str() == identifier);
        if self.admission_token.as_slice().len() != 32
            || self.controller_pid.get() == 0
            || self.controller_pid.get() > i32::MAX as u64
            || self.controller_uid.get() > u32::MAX as u64
            || self.program.schema != "source-owned.packet-program.v1"
            || self.program.events.len() != 2
            || self.limits.frame_bytes.get() != 65_536
            || self.limits.requests.get() != 64
            || self.limits.nesting.get() != 64
            || self.limits.blob_chunk_bytes.get() != 4096
            || self.limits.journal_entries.get() != 256
            || schema.is_none_or(|schema| {
                schema.version != version
                    || schema.definition != definition
                    || !schema.extensions.is_empty()
            })
        {
            return Err(ProviderError::Correlation(
                "packet complete private source launch",
            ));
        }
        let coordinator = &self.initial_coordinator;
        if coordinator.bytes.as_slice().len() > 65_536
            || coordinator.reference.media_type != "application/json"
        {
            return Err(ProviderError::ResourceExhausted(
                "packet original initial coordinator",
            ));
        }
        coordinator.reference.verify(coordinator.bytes.as_slice())?;
        let value = canonical::parse_json(coordinator.bytes.as_slice(), 65_536)?;
        if !value.is_object() || canonical::canonical_json(&value)? != coordinator.bytes.as_slice()
        {
            return Err(ProviderError::Correlation(
                "packet installed coordinator codec",
            ));
        }
        if self.schema_version == 2 {
            super::coordinator::PacketCoordinatorInstallation::decode(
                coordinator.bytes.as_slice(),
                &self.selection,
            )?;
        }
        Ok(())
    }
}

/// Retains original negotiation, endpoint and native failure supervision together.
///
/// A returned step failure must retain this owner through authentic containment.
/// Closing a stream does not prove the original program or report custody ended.
#[must_use = "keep the original service until authentic native process containment"]
pub struct PacketSourceService {
    endpoint: super::endpoint::PacketEndpoint<crate::client::DeadlineStream>,
    _handshake: crate::handshake::Handshake,
    _supervisor: Rc<security::Supervisor>,
    deadline: crate::client::ExchangeDeadline,
}

impl PacketSourceService {
    /// Installs a private endpoint and authenticates the actual original controller.
    ///
    /// # Errors
    /// Refuses changed/private paths, kernel peer or executable measurements,
    /// invalid original launch, negotiation or unopened native construction.
    pub fn accept(
        socket: &std::path::Path,
        launch: PacketSourceLaunch,
    ) -> Result<Self, ProviderError> {
        server::accept(socket, launch)
    }

    /// Drives the same original endpoint under its fixed operational deadline.
    ///
    /// # Errors
    /// Returns the original held failure without releasing native custody or
    /// permitting another execution, connection or replacement operation.
    pub fn step(&mut self) -> Result<(), ProviderError> {
        if self.endpoint.is_held() {
            return self.endpoint.step();
        }
        self.deadline.reset(std::time::Duration::from_secs(5))?;
        self.endpoint.step()
    }

    /// Borrows the retained endpoint for independent original data inspection.
    pub fn endpoint(&self) -> &super::endpoint::PacketEndpoint<crate::client::DeadlineStream> {
        &self.endpoint
    }
}
