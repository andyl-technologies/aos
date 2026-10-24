//! Borrows and reads complete launch DTOs while retaining native path backing.
//!
//! Every optional birth selection is emitted explicitly in this new17 view.
//! Native path bytes stay opaque DATA with their original OsString capacity.

use super::current_contracts::*;
use crate::ProviderError;
use crate::connection::settled17::HistoricalByteBank17;
use crate::handshake::Limits;
use crate::protocol_snapshot::{
    compact_bytes::BorrowedCompactBytes,
    owned11::typed::{Fields, HistoricalType, Ledger, invalid, plain_string},
};
use crate::reference_packet::service::*;
use crate::reference_packet::{
    PacketProgramDefinition, connected::PacketConnectedDefinition, control::PacketControlSelection,
};
use crate::reference_service::InstalledContent;
use crate::retained_metadata::MetadataObserver;
use crucible_node_format::{Bytes, ContentRef, U64};
use serde::{Serialize, Serializer, ser::SerializeStruct};

pub(crate) struct BorrowedCurrentLaunch17<'a>(pub(crate) &'a PacketNative5SourceLaunch);
struct PathHistory17<'a>(&'a std::path::PathBuf);
impl Serialize for PathHistory17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (
            self.0.capacity(),
            BorrowedCompactBytes::new(self.0.as_os_str().as_encoded_bytes()),
        )
            .serialize(serializer)
    }
}
impl Serialize for BorrowedCurrentLaunch17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let PacketNative5SourceLaunch {
            schema_version,
            selection,
            program,
            controller_pid,
            controller_uid,
            controller_executable,
            admission_token,
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
            effects,
        } = self.0;
        let mut fields = serializer.serialize_struct("NativeCurrentLaunch17", 21)?;
        fields.serialize_field("schema", "source-private.native-current-source-launch/17")?;
        fields.serialize_field("schema_version", schema_version)?;
        fields.serialize_field("selection", selection)?;
        fields.serialize_field("program", program)?;
        fields.serialize_field("controller_pid", controller_pid)?;
        fields.serialize_field("controller_uid", controller_uid)?;
        fields.serialize_field("controller_executable", controller_executable)?;
        fields.serialize_field("admission_token", admission_token)?;
        fields.serialize_field("initial_coordinator", initial_coordinator)?;
        fields.serialize_field("limits", limits)?;
        fields.serialize_field("storage", storage)?;
        fields.serialize_field("capture_profile", capture_profile)?;
        fields.serialize_field("confirmation_selection", confirmation_selection)?;
        fields.serialize_field("ack_emitter_selection", ack_emitter_selection)?;
        fields.serialize_field("native_codec_metadata_extent", native_codec_metadata_extent)?;
        fields.serialize_field("protocol_metadata_limits", protocol_metadata_limits)?;
        fields.serialize_field("complete_restore_selection", complete_restore_selection)?;
        fields.serialize_field(
            "restore_input_emitter_selection",
            restore_input_emitter_selection,
        )?;
        fields.serialize_field("capture_allocation_selection", capture_allocation_selection)?;
        fields.serialize_field(
            "fresh_restore_allocation_selection",
            fresh_restore_allocation_selection,
        )?;
        fields.serialize_field("effects", &PathHistory17(effects))?;
        fields.end()
    }
}

pub(crate) enum CurrentSourceProgram17 {
    Producer(PacketProgramDefinition),
    Reactive(PacketConnectedDefinition),
}
impl HistoricalType for CurrentSourceProgram17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let kind = plain_string(fields.named("kind")?)?;
        let raw = fields.named("program")?;
        fields.finish()?;
        match kind {
            "producer" => {
                <CurrentDto17<PacketProgramDefinition> as CurrentField17>::read(raw, ledger, build)
                    .map(|value| value.map(Self::Producer))
            }
            "reactive" => ledger
                .read::<PacketConnectedDefinition>(raw, build)
                .map(|value| value.map(Self::Reactive)),
            _ => Err(invalid()),
        }
    }
}

pub(crate) struct CurrentLaunch17 {
    pub(crate) schema_version: u16,
    pub(crate) selection: PacketControlSelection,
    pub(crate) program: CurrentSourceProgram17,
    pub(crate) controller_pid: U64,
    pub(crate) controller_uid: U64,
    pub(crate) controller_executable: ContentRef,
    pub(crate) admission_token: Bytes,
    pub(crate) initial_coordinator: InstalledContent,
    pub(crate) limits: Limits,
    pub(crate) storage: PacketNative5StorageLimits,
    pub(crate) capture_profile: PacketNative5CaptureProfile,
    pub(crate) confirmation_selection: Option<PacketNative5ConfirmationSelection>,
    pub(crate) ack_emitter_selection: Option<PacketNative5AckEmitterSelection>,
    pub(crate) native_codec_metadata_extent: Option<crate::client::CanonicalAckCodecMetadataExtent>,
    pub(crate) protocol_metadata_limits: Option<PacketNative5ProtocolMetadataLimits>,
    pub(crate) complete_restore_selection: Option<crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection>,
    pub(crate) restore_input_emitter_selection: Option<crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection>,
    pub(crate) capture_allocation_selection: Option<crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection>,
    pub(crate) fresh_restore_allocation_selection: Option<crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection>,
    pub(crate) effects: Vec<u8>,
}
impl HistoricalType for CurrentLaunch17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        if plain_string(fields.named("schema")?)?
            != "source-private.native-current-source-launch/17"
        {
            return Err(invalid());
        }
        let schema_version =
            <Plain17<u16> as CurrentField17>::read(fields.named("schema_version")?, ledger, build)?;
        let selection = <Plain17<PacketControlSelection> as CurrentField17>::read(
            fields.named("selection")?,
            ledger,
            build,
        )?;
        let program = ledger.read::<CurrentSourceProgram17>(fields.named("program")?, build)?;
        let controller_pid =
            <Plain17<U64> as CurrentField17>::read(fields.named("controller_pid")?, ledger, build)?;
        let controller_uid =
            <Plain17<U64> as CurrentField17>::read(fields.named("controller_uid")?, ledger, build)?;
        let controller_executable = <Plain17<ContentRef> as CurrentField17>::read(
            fields.named("controller_executable")?,
            ledger,
            build,
        )?;
        let admission_token = <Plain17<Bytes> as CurrentField17>::read(
            fields.named("admission_token")?,
            ledger,
            build,
        )?;
        let initial_coordinator = <CurrentDto17<InstalledContent> as CurrentField17>::read(
            fields.named("initial_coordinator")?,
            ledger,
            build,
        )?;
        let limits =
            <Plain17<Limits> as CurrentField17>::read(fields.named("limits")?, ledger, build)?;
        let storage = <CurrentDto17<PacketNative5StorageLimits> as CurrentField17>::read(
            fields.named("storage")?,
            ledger,
            build,
        )?;
        let capture_profile = <Plain17<PacketNative5CaptureProfile> as CurrentField17>::read(
            fields.named("capture_profile")?,
            ledger,
            build,
        )?;
        let confirmation_selection =
            <Plain17<Option<PacketNative5ConfirmationSelection>> as CurrentField17>::read(
                fields.named("confirmation_selection")?,
                ledger,
                build,
            )?;
        let ack_emitter_selection =
            <Plain17<Option<PacketNative5AckEmitterSelection>> as CurrentField17>::read(
                fields.named("ack_emitter_selection")?,
                ledger,
                build,
            )?;
        let native_codec_metadata_extent = <Plain17<
            Option<crate::client::CanonicalAckCodecMetadataExtent>,
        > as CurrentField17>::read(
            fields.named("native_codec_metadata_extent")?,
            ledger,
            build,
        )?;
        let protocol_metadata_limits =
            <Plain17<Option<PacketNative5ProtocolMetadataLimits>> as CurrentField17>::read(
                fields.named("protocol_metadata_limits")?,
                ledger,
                build,
            )?;
        let complete_restore_selection = <Plain17<
            Option<crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection>
        > as CurrentField17>::read(
            fields.named("complete_restore_selection")?,
            ledger,
            build
        )?;
        let restore_input_emitter_selection = <Plain17<
            Option<crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection>
        > as CurrentField17>::read(
            fields.named("restore_input_emitter_selection")?,
            ledger,
            build
        )?;
        let capture_allocation_selection = <Plain17<
            Option<crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection>
        > as CurrentField17>::read(
            fields.named("capture_allocation_selection")?,
            ledger,
            build
        )?;
        let fresh_restore_allocation_selection = <Plain17<
            Option<crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection>
        > as CurrentField17>::read(
            fields.named("fresh_restore_allocation_selection")?,
            ledger,
            build
        )?;
        let effects = ledger
            .read::<HistoricalByteBank17>(fields.named("effects")?, build)?
            .map(|bank| bank.0);
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema_version: schema_version.ok_or_else(invalid)?,
            selection: selection.ok_or_else(invalid)?,
            program: program.ok_or_else(invalid)?,
            controller_pid: controller_pid.ok_or_else(invalid)?,
            controller_uid: controller_uid.ok_or_else(invalid)?,
            controller_executable: controller_executable.ok_or_else(invalid)?,
            admission_token: admission_token.ok_or_else(invalid)?,
            initial_coordinator: initial_coordinator.ok_or_else(invalid)?,
            limits: limits.ok_or_else(invalid)?,
            storage: storage.ok_or_else(invalid)?,
            capture_profile: capture_profile.ok_or_else(invalid)?,
            confirmation_selection: confirmation_selection.ok_or_else(invalid)?,
            ack_emitter_selection: ack_emitter_selection.ok_or_else(invalid)?,
            native_codec_metadata_extent: native_codec_metadata_extent.ok_or_else(invalid)?,
            protocol_metadata_limits: protocol_metadata_limits.ok_or_else(invalid)?,
            complete_restore_selection: complete_restore_selection.ok_or_else(invalid)?,
            restore_input_emitter_selection: restore_input_emitter_selection.ok_or_else(invalid)?,
            capture_allocation_selection: capture_allocation_selection.ok_or_else(invalid)?,
            fresh_restore_allocation_selection: fresh_restore_allocation_selection
                .ok_or_else(invalid)?,
            effects: effects.ok_or_else(invalid)?,
        }))
    }
}

/// Visits complete real launch children under the enclosing metadata pass.
pub(crate) fn observe_native_launch17(
    value: &PacketNative5SourceLaunch,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    let PacketNative5SourceLaunch {
        schema_version,
        selection,
        program,
        controller_pid,
        controller_uid,
        controller_executable,
        admission_token,
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
        effects,
    } = value;
    observer.observe(schema_version)?;
    observer.observe(selection)?;
    match program {
        PacketConnectedSourceProgram::Producer { program } => program.observe_current(observer)?,
        PacketConnectedSourceProgram::Reactive { program } => observer.observe(program)?,
    }
    observer.observe(controller_pid)?;
    observer.observe(controller_uid)?;
    observer.observe(controller_executable)?;
    observer.observe(admission_token)?;
    observer.observe(initial_coordinator)?;
    observer.observe(limits)?;
    storage.observe_current(observer)?;
    observer.observe(capture_profile)?;
    observer.observe(confirmation_selection)?;
    observer.observe(ack_emitter_selection)?;
    observer.observe(native_codec_metadata_extent)?;
    observer.observe(protocol_metadata_limits)?;
    observer.observe(complete_restore_selection)?;
    observer.observe(restore_input_emitter_selection)?;
    observer.observe(capture_allocation_selection)?;
    observer.observe(fresh_restore_allocation_selection)?;
    observer.vector::<u8>(effects.capacity())?;
    Ok(())
}
