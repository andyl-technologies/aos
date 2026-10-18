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

pub mod capture_allocation;
pub mod native_startup;
pub mod report_startup;

pub(crate) use ack_emitter::{
    OriginalNativePrepareStartupAllocation, measure_original_prepare_executable_data,
    original_prepare_executable_measurement_counter_scratch_data,
};

pub mod confirmation;
pub use confirmation::PacketNative5ConfirmationSelection;

mod connected;
mod native5;
mod native5_policy;
pub use native5::{
    PacketNative5CaptureProfile, PacketNative5SourceLaunch, PacketNative5StorageLimits,
};
pub(crate) use native5_policy::Native5Policy;
mod security;
mod server;

pub use connected::{PacketConnectedSourceLaunch, PacketConnectedSourceProgram};

/// Installs the exact original packet source through a private inherited channel.
///
/// Tokens and paths must never appear in public reports, arguments, content
/// hashes or diagnostics. Possession is private launch authority only; source
/// class acceptance and authentic common grant authority remain independent.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketSourceLaunch {
    /// Selects exact preinstalled ingress 1, common ingress 2 or three-owner ingress 3.
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
    /// Decodes the complete private launch through the bounded canonical parser.
    ///
    /// # Errors
    /// Rejects oversized JSON, duplicate or unknown fields, invalid scalar
    /// encodings and any original launch invariant checked by [`Self::validate`].
    pub fn decode(bytes: &[u8], maximum_bytes: usize) -> Result<Self, ProviderError> {
        let value = canonical::parse_json(bytes, maximum_bytes)?;
        let launch: Self = serde_json::from_value(value).map_err(ContractError::from)?;
        launch.validate()?;

        Ok(launch)
    }

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
            3 => (
                "source-owned.packet-ingress/3",
                3,
                super::contracts::world_ingress_contract()?,
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
            || self.limits.requests.get() != if self.schema_version == 3 { 256 } else { 64 }
            || self.limits.nesting.get() != 64
            || self.limits.blob_chunk_bytes.get() != 4096
            || self.limits.journal_entries.get()
                != if self.schema_version == 3 { 1024 } else { 256 }
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
        if self.schema_version == 3 {
            super::coordinator::PacketWorldCoordinatorInstallation::decode(
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
    _handshake: OriginalServiceHandshake,
    _private_bootstrap: Option<Box<dyn std::any::Any>>,
    _supervisor: Rc<security::Supervisor>,
    deadline: crate::client::ExchangeDeadline,
}

enum OriginalServiceHandshake {
    Legacy(crate::handshake::Handshake),
    Selected {
        handshake: crate::handshake::ExtensionHandshake,
        registry: Rc<server::complete::birth::EmptyBootExtensions>,
    },
}

impl PacketSourceService {
    /// Authenticates two retained private frames before selected native birth.
    ///
    /// This route issues preparation and a distinct original protocol Admit;
    /// it grants no semantic Arm, Capture, or complete factory qualification.
    ///
    /// # Errors
    /// Refuses malformed boot, changed original kernel peer or executable,
    /// expired original five-second cut, or an unsupported selected mechanism.
    /// Refused original owners remain held until the host reaps this Child.
    pub fn accept_original_private_bootstrap(
        socket: &std::path::Path,
        original: std::io::Stdin,
    ) -> Result<Self, ProviderError> {
        ack_emitter::native_boot::accept(socket, original)
    }

    /// Authenticates the distinct resource-admitted private bootstrap revision.
    ///
    /// The inherited channel consumes its fixed version-fourteen prefix before
    /// private parser/model construction, then authenticates the same birth.
    /// This entry grants neither semantic activation nor whole capture rights.
    ///
    /// # Errors
    /// Refuses missing private origin, changed parent or MAC, widened compiled
    /// owners, expired original cut, or another launch/boot/source revision.
    pub fn accept_original_native_startup_bootstrap(
        socket: &std::path::Path,
    ) -> Result<Self, ProviderError> {
        ack_emitter::native_boot::accept_admitted(socket)
    }

    /// Authenticates the explicit invocation-bound private bootstrap revision.
    ///
    /// Prefix15, launch6, boot7 and Source15 must agree with the same inherited
    /// parent and private birth. The actual installed issuer selects invocation
    /// provenance before Child; this entry supplies no public purpose argument.
    /// Query, Prepare, activation and complete Capture rights remain separate.
    ///
    /// # Errors
    /// Refuses wrong legacy/new editions, foreign parent or MAC, changed full
    /// identities, expired original cut or any component above the same rows.
    pub fn accept_original_native_invocation_bootstrap(
        socket: &std::path::Path,
    ) -> Result<Self, ProviderError> {
        ack_emitter::native_boot::accept_invocation(socket)
    }

    /// Authenticates the separate restored suffix startup16 private channel.
    ///
    /// The inherited parent, prefix16 MAC, exact launch7 and unchanged Source15
    /// and boot7 bodies must agree before this entry retains a native reservation.
    /// Standard suffix dispatch and advanced Capture remain unavailable.
    ///
    /// # Errors
    /// Refuses another private edition, foreign parent/key/birth, changed full
    /// bodies or rows, expired original cut or insufficient independent storage.
    pub fn accept_original_restored_suffix_bootstrap(
        socket: &std::path::Path,
    ) -> Result<Self, ProviderError> {
        ack_emitter::native_boot::accept_restored_suffix(socket)
    }

    /// Authenticates the distinct independently prepaid settled17 bootstrap.
    ///
    /// The genuine inherited prefix17 and complete wrapper8 bind the same
    /// private birth, nested launch and independent native Capture reserve.
    /// This entry alone issues no Source Capture ticket or action permission.
    ///
    /// # Errors
    /// Refuses another edition, foreign peer/key/birth, changed full bodies or
    /// rows, an expired original cut, or insufficient independent construction.
    pub fn accept_original_restored_settled_bootstrap(
        socket: &std::path::Path,
    ) -> Result<Self, ProviderError> {
        ack_emitter::native_boot::accept_restored_settled(socket)
    }

    /// Installs a complete original native source after actual peer authentication.
    ///
    /// # Errors
    /// Refuses changed launch/kernel/executable/Hello, invalid complete source,
    /// unsupported immutable codec or exhausted selected original storage.
    pub fn accept_complete(
        socket: &std::path::Path,
        launch: PacketNative5SourceLaunch,
    ) -> Result<Self, ProviderError> {
        server::accept_complete(socket, launch)
    }

    /// Installs an original participant of the distinct connected packet world.
    ///
    /// # Errors
    /// Refuses changed launch, native peer, executable, coordinator or source contract.
    pub fn accept_connected(
        socket: &std::path::Path,
        launch: PacketConnectedSourceLaunch,
    ) -> Result<Self, ProviderError> {
        server::accept_connected(socket, launch)
    }

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

    /// Drives one complete exchange after idle readiness on the original socket.
    ///
    /// Idle waiting has no native or simulation-time effect. Once request bytes
    /// are available, the unchanged five-second absolute cut covers the whole
    /// frame, validation, native callback, proof publication and acknowledgement.
    ///
    /// # Errors
    /// Returns the original held failure without releasing native custody or
    /// permitting another execution, connection or replacement operation.
    pub fn step(&mut self) -> Result<(), ProviderError> {
        self.endpoint.ensure_complete_origin()?;
        if self.endpoint.is_held() {
            return self.endpoint.step();
        }
        self.endpoint.wait_for_request()?;
        self.deadline.reset(std::time::Duration::from_secs(5))?;
        match &self._handshake {
            OriginalServiceHandshake::Legacy(handshake) => self
                .endpoint
                .step_with_complete_context(Some((handshake, &self.deadline))),
            OriginalServiceHandshake::Selected {
                handshake,
                registry: _,
            } => {
                let context = owned11::OriginalNativeServiceCaptureContext::new(
                    &self._handshake,
                    self._private_bootstrap.as_deref(),
                    &self._supervisor,
                    &self.deadline,
                );
                self.endpoint.step_with_selected_service_context(
                    handshake,
                    &self.deadline,
                    &context,
                )
            }
        }
    }

    /// Borrows the retained endpoint for independent original data inspection.
    pub fn endpoint(&self) -> &super::endpoint::PacketEndpoint<crate::client::DeadlineStream> {
        &self.endpoint
    }
}

#[cfg(test)]
pub(crate) use native5_policy::controlled_native5_policy;

pub mod ack_emitter;
pub use ack_emitter::PacketNative5AckEmitterSelection;

pub use ack_emitter::{PacketCanonicalAckAdmissionContext, PacketCanonicalAckAdmissionProof};

mod protocol_metadata;
pub use protocol_metadata::{
    PacketNative5ProtocolMetadataBankFacts, PacketNative5ProtocolMetadataBirthFacts,
    PacketNative5ProtocolMetadataLimits,
};

mod owned11;
pub(crate) use owned11::{OriginalNativeCaptureContext, OriginalNativeServiceCaptureContext};
pub(crate) use security::{
    HistoricalNativeSupervisorBanks, original_native_supervisor_bank_layouts,
    original_native_supervisor_layout,
};
/// Defines the selected whole native snapshot with exact original protocol bytes.
pub mod native_snapshot;
pub use native_snapshot::{native_owned11_snapshot_contract, native_owned11_snapshot_schema};
pub(crate) use owned11::NativeRestoreServiceAllocationQuote;

pub mod complete_restore;

/// Defines the separately negotiated Source-signed Input/Reactive17 protocol.
pub mod restored_input_reactive17;

// The transport control uses the actual selected immutable policy constructor,
// without widening its production visibility or mutating private selectors.
#[cfg(test)]
pub(crate) fn prepared_blob_proof_codec_for_test(
    selection: crate::reference_packet::control::PacketControlSelection,
    coordinator: crate::reference_service::InstalledContent,
) -> Result<std::rc::Rc<Native5Policy>, crate::ProviderError> {
    let policy = Native5Policy::from_original_launch_with_ack_emitter_metadata_extent(
        selection,
        coordinator,
        PacketNative5CaptureProfile::OriginalArrays6,
        PacketNative5ConfirmationSelection::AfterProtocolPoll5,
        PacketNative5AckEmitterSelection::CanonicalSdkBlob5,
        crate::connection::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB,
    )?;
    Ok(std::rc::Rc::new(policy))
}

/// Defines inert fresh inactive allocation query/report grammar.
pub mod fresh_restore_allocation;

pub use native_snapshot::{
    PacketNativeOwned12SnapshotPlan, native_owned12_snapshot_contract,
    native_owned12_snapshot_schema, packet_native_owned12_snapshot_validation_layouts,
};

pub use native_snapshot::{
    PacketNativeOwned13SnapshotPlan, native_owned13_snapshot_contract,
    native_owned13_snapshot_schema, packet_native_owned13_snapshot_validation_layouts,
};

pub use ack_emitter::{
    PacketNativePrepareStartupStorageData, original_native_prepare_startup_counter_scratch_data,
    original_native_prepare_startup_storage_data,
};

/// Defines the separately negotiated Source-signed Capture17 protocol.
pub mod restored_settled_capture;

/// Defines inert fourth-object confirmation for selected settled Capture17.
pub mod restored_settled_confirmation;

pub(crate) use native5_policy::{HistoricalNativePolicy17, read_native17_policy_root_data};

pub(crate) use security::original_native_supervisor_alignment17_data;

pub(in crate::reference_packet) use owned11::CurrentServiceHistory17;
pub(crate) use owned11::{
    CurrentNativeService17GroupIds, HistoricalCurrentNativeService17, HistoricalNativeRegistrar17,
    NativeRegistrar17GroupIds, read_current_native17_registrar_root_data,
    read_current_native17_service_fields_data, read_rooted_current_native17_service_fields_data,
};
pub(crate) use security::{
    HistoricalNativeSupervisor17, read_current_native17_supervisor_root_data,
};

pub(crate) use owned11::{
    BorrowedCurrentNativeService17LineageData, borrow_current_native17_service_lineage_data,
};
