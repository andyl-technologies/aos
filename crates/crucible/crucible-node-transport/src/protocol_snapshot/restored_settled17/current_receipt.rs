//! Reads the actual raw receipt5 DTO including omitted optional birth fields.

use super::current_contracts::*;
use crate::reference_packet::control::{PacketNative5Record, PacketNative5StorageSelection};
use crate::reference_packet::service::complete_restore::*;
use crate::reference_packet::service::*;
use crate::retained_metadata::MetadataObserver;
use crate::{
    ProviderError,
    envelope::Envelope,
    protocol_snapshot::owned11::typed::{Fields, HistoricalType, Ledger, invalid, plain_string},
};
use crucible_node_format::{ContentRef, HashRef, Id, U64};

impl CurrentContract17 for PacketNative5Record {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema =
            <Plain17<String> as CurrentField17>::read(fields.named("schema")?, ledger, build)?;
        let native_pid =
            <Plain17<U64> as CurrentField17>::read(fields.named("native_pid")?, ledger, build)?;
        let original =
            <Plain17<Envelope> as CurrentField17>::read(fields.named("original")?, ledger, build)?;
        let binding_hash = <Plain17<HashRef> as CurrentField17>::read(
            fields.named("binding_hash")?,
            ledger,
            build,
        )?;
        let session =
            <Plain17<Id> as CurrentField17>::read(fields.named("session")?, ledger, build)?;
        let incarnation =
            <Plain17<Id> as CurrentField17>::read(fields.named("incarnation")?, ledger, build)?;
        let node = <Plain17<Id> as CurrentField17>::read(fields.named("node")?, ledger, build)?;
        let owner = <Plain17<Id> as CurrentField17>::read(fields.named("owner")?, ledger, build)?;
        let owner_generation = <Plain17<U64> as CurrentField17>::read(
            fields.named("owner_generation")?,
            ledger,
            build,
        )?;
        let input_epoch =
            <Plain17<Id> as CurrentField17>::read(fields.named("input_epoch")?, ledger, build)?;
        let world =
            <Plain17<HashRef> as CurrentField17>::read(fields.named("world")?, ledger, build)?;
        let native_record = <Plain17<ContentRef> as CurrentField17>::read(
            fields.named("native_record")?,
            ledger,
            build,
        )?;
        let storage_selection =
            <CurrentDto17<PacketNative5StorageSelection> as CurrentField17>::read(
                fields.named("storage_selection")?,
                ledger,
                build,
            )?;

        let mut pending = fields.pair()?;
        let capture_profile =
            if let Some(raw) = optional_raw17(&mut fields, &mut pending, "capture_profile")? {
                ledger.read::<PacketNative5CaptureProfile>(raw, build)?
            } else {
                build.then_some(PacketNative5CaptureProfile::OriginalArrays6)
            };
        let confirmation_selection = optional17::<PacketNative5ConfirmationSelection>(
            &mut fields,
            &mut pending,
            "confirmation_selection",
            ledger,
            build,
        )?;
        let ack_emitter_selection = optional17::<PacketNative5AckEmitterSelection>(
            &mut fields,
            &mut pending,
            "ack_emitter_selection",
            ledger,
            build,
        )?;
        let complete_restore_selection = optional17::<PacketNative5CompleteRestoreSelection>(
            &mut fields,
            &mut pending,
            "complete_restore_selection",
            ledger,
            build,
        )?;
        let protocol_metadata_limits = optional17::<PacketNative5ProtocolMetadataLimits>(
            &mut fields,
            &mut pending,
            "protocol_metadata_limits",
            ledger,
            build,
        )?;
        let protocol_metadata_birth_facts = optional17::<PacketNative5ProtocolMetadataBirthFacts>(
            &mut fields,
            &mut pending,
            "protocol_metadata_birth_facts",
            ledger,
            build,
        )?;
        let restore_input_emitter_selection =
            optional17::<PacketNative5RestoreInputEmitterSelection>(
                &mut fields,
                &mut pending,
                "restore_input_emitter_selection",
                ledger,
                build,
            )?;
        if pending.is_some() {
            return Err(invalid());
        }
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            native_pid: native_pid.ok_or_else(invalid)?,
            original: original.ok_or_else(invalid)?,
            binding_hash: binding_hash.ok_or_else(invalid)?,
            session: session.ok_or_else(invalid)?,
            incarnation: incarnation.ok_or_else(invalid)?,
            node: node.ok_or_else(invalid)?,
            owner: owner.ok_or_else(invalid)?,
            owner_generation: owner_generation.ok_or_else(invalid)?,
            input_epoch: input_epoch.ok_or_else(invalid)?,
            world: world.ok_or_else(invalid)?,
            native_record: native_record.ok_or_else(invalid)?,
            storage_selection: storage_selection.ok_or_else(invalid)?,
            capture_profile: capture_profile.ok_or_else(invalid)?,
            confirmation_selection: confirmation_selection.ok_or_else(invalid)?,
            ack_emitter_selection: ack_emitter_selection.ok_or_else(invalid)?,
            complete_restore_selection: complete_restore_selection.ok_or_else(invalid)?,
            protocol_metadata_limits: protocol_metadata_limits.ok_or_else(invalid)?,
            protocol_metadata_birth_facts: protocol_metadata_birth_facts.ok_or_else(invalid)?,
            restore_input_emitter_selection: restore_input_emitter_selection.ok_or_else(invalid)?,
        }))
    }
    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        <Plain17<String> as CurrentField17>::observe(&self.schema, observer)?;
        <Plain17<U64> as CurrentField17>::observe(&self.native_pid, observer)?;
        <Plain17<Envelope> as CurrentField17>::observe(&self.original, observer)?;
        <Plain17<HashRef> as CurrentField17>::observe(&self.binding_hash, observer)?;
        <Plain17<Id> as CurrentField17>::observe(&self.session, observer)?;
        <Plain17<Id> as CurrentField17>::observe(&self.incarnation, observer)?;
        <Plain17<Id> as CurrentField17>::observe(&self.node, observer)?;
        <Plain17<Id> as CurrentField17>::observe(&self.owner, observer)?;
        <Plain17<U64> as CurrentField17>::observe(&self.owner_generation, observer)?;
        <Plain17<Id> as CurrentField17>::observe(&self.input_epoch, observer)?;
        <Plain17<HashRef> as CurrentField17>::observe(&self.world, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(&self.native_record, observer)?;
        <CurrentDto17<PacketNative5StorageSelection> as CurrentField17>::observe(
            &self.storage_selection,
            observer,
        )?;
        observer.observe(&self.capture_profile)?;
        observer.observe(&self.confirmation_selection)?;
        observer.observe(&self.ack_emitter_selection)?;
        observer.observe(&self.complete_restore_selection)?;
        observer.observe(&self.protocol_metadata_limits)?;
        observer.observe(&self.protocol_metadata_birth_facts)?;
        observer.observe(&self.restore_input_emitter_selection)?;
        Ok(())
    }
}

fn optional_raw17<'a>(
    fields: &mut Fields<'a>,
    pending: &mut Option<(&'a [u8], &'a [u8])>,
    name: &str,
) -> Result<Option<&'a [u8]>, ProviderError> {
    match *pending {
        Some((key, value)) if plain_string(key)? == name => {
            if value == b"null" {
                return Err(invalid());
            }
            *pending = fields.pair()?;
            Ok(Some(value))
        }
        _ => Ok(None),
    }
}
fn optional17<'a, T: HistoricalType>(
    fields: &mut Fields<'a>,
    pending: &mut Option<(&'a [u8], &'a [u8])>,
    name: &str,
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<Option<T>>, ProviderError> {
    match optional_raw17(fields, pending, name)? {
        Some(raw) => ledger.read::<T>(raw, build).map(|value| value.map(Some)),
        None => Ok(build.then_some(None)),
    }
}
