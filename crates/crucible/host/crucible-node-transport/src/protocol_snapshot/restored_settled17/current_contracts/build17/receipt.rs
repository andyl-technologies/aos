//! Retains the exact raw receipt DTO, including omitted optional source fields.

use super::super::*;
use crate::protocol_snapshot::owned11::typed::plain_string;
use crate::protocol_snapshot::restored_settled17::current_build17::{
    BuildCurrentContract17, BuildCurrentField17,
};
use crate::reference_packet::{control::PacketNative5StorageSelection, service::*};

fn fields17(input: &[u8]) -> Result<[&[u8]; 20], ProviderError> {
    let mut f = Fields::object(input)?;
    let schema = f.named("schema")?;
    let native_pid = f.named("native_pid")?;
    let original = f.named("original")?;
    let binding_hash = f.named("binding_hash")?;
    let session = f.named("session")?;
    let incarnation = f.named("incarnation")?;
    let node = f.named("node")?;
    let owner = f.named("owner")?;
    let owner_generation = f.named("owner_generation")?;
    let input_epoch = f.named("input_epoch")?;
    let world = f.named("world")?;
    let native_record = f.named("native_record")?;
    let storage_selection = f.named("storage_selection")?;
    let mut pending = f.pair()?;
    fn optional<'a>(
        f: &mut Fields<'a>,
        pending: &mut Option<(&'a [u8], &'a [u8])>,
        name: &str,
    ) -> Result<Option<&'a [u8]>, ProviderError> {
        match *pending {
            Some((key, value)) if plain_string(key)? == name => {
                if value == b"null" {
                    return Err(invalid());
                }
                *pending = f.pair()?;
                Ok(Some(value))
            }
            _ => Ok(None),
        }
    }
    let capture_profile = optional(&mut f, &mut pending, "capture_profile")?
        .unwrap_or(br#"{"encoding":"original_arrays6"}"#);
    let confirmation_selection =
        optional(&mut f, &mut pending, "confirmation_selection")?.unwrap_or(b"null");
    let ack_emitter_selection =
        optional(&mut f, &mut pending, "ack_emitter_selection")?.unwrap_or(b"null");
    let complete_restore_selection =
        optional(&mut f, &mut pending, "complete_restore_selection")?.unwrap_or(b"null");
    let protocol_metadata_limits =
        optional(&mut f, &mut pending, "protocol_metadata_limits")?.unwrap_or(b"null");
    let protocol_metadata_birth_facts =
        optional(&mut f, &mut pending, "protocol_metadata_birth_facts")?.unwrap_or(b"null");
    let restore_input_emitter_selection =
        optional(&mut f, &mut pending, "restore_input_emitter_selection")?.unwrap_or(b"null");
    if pending.is_some() {
        return Err(invalid());
    }
    f.finish()?;
    Ok([
        schema,
        native_pid,
        original,
        binding_hash,
        session,
        incarnation,
        node,
        owner,
        owner_generation,
        input_epoch,
        world,
        native_record,
        storage_selection,
        capture_profile,
        confirmation_selection,
        ack_emitter_selection,
        complete_restore_selection,
        protocol_metadata_limits,
        protocol_metadata_birth_facts,
        restore_input_emitter_selection,
    ])
}

#[derive(Default)]
pub(crate) struct PacketNative5RecordRaw17ReadAttempt {
    pub(crate) schema: <Plain17<String> as BuildCurrentField17>::Attempt,
    pub(crate) native_pid: <Plain17<U64> as BuildCurrentField17>::Attempt,
    pub(crate) original: <Plain17<Envelope> as BuildCurrentField17>::Attempt,
    pub(crate) binding_hash: <Plain17<HashRef> as BuildCurrentField17>::Attempt,
    pub(crate) session: <Plain17<Id> as BuildCurrentField17>::Attempt,
    pub(crate) incarnation: <Plain17<Id> as BuildCurrentField17>::Attempt,
    pub(crate) node: <Plain17<Id> as BuildCurrentField17>::Attempt,
    pub(crate) owner: <Plain17<Id> as BuildCurrentField17>::Attempt,
    pub(crate) owner_generation: <Plain17<U64> as BuildCurrentField17>::Attempt,
    pub(crate) input_epoch: <Plain17<Id> as BuildCurrentField17>::Attempt,
    pub(crate) world: <Plain17<HashRef> as BuildCurrentField17>::Attempt,
    pub(crate) native_record: <Plain17<ContentRef> as BuildCurrentField17>::Attempt,
    pub(crate) storage_selection:
        <CurrentDto17<PacketNative5StorageSelection> as BuildCurrentField17>::Attempt,
    pub(crate) capture_profile:
        <Plain17<PacketNative5CaptureProfile> as BuildCurrentField17>::Attempt,
    pub(crate) confirmation_selection:
        <Optional17<Plain17<PacketNative5ConfirmationSelection>> as BuildCurrentField17>::Attempt,
    pub(crate) ack_emitter_selection:
        <Optional17<Plain17<PacketNative5AckEmitterSelection>> as BuildCurrentField17>::Attempt,
    pub(crate) complete_restore_selection: <Optional17<
        Plain17<PacketNative5CompleteRestoreSelection>,
    > as BuildCurrentField17>::Attempt,
    pub(crate) protocol_metadata_limits:
        <Optional17<Plain17<PacketNative5ProtocolMetadataLimits>> as BuildCurrentField17>::Attempt,
    pub(crate) protocol_metadata_birth_facts: <Optional17<
        Plain17<PacketNative5ProtocolMetadataBirthFacts>,
    > as BuildCurrentField17>::Attempt,
    pub(crate) restore_input_emitter_selection: <Optional17<
        Plain17<PacketNative5RestoreInputEmitterSelection>,
    > as BuildCurrentField17>::Attempt,
    pub(crate) phase: usize,
    pub(crate) failed: bool,
    completed: Option<PacketNative5Record>,
}

impl BuildCurrentContract17 for PacketNative5Record {
    type Attempt = PacketNative5RecordRaw17ReadAttempt;

    fn preflight_data(input: &[u8], l: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        let [
            schema,
            native_pid,
            original,
            binding_hash,
            session,
            incarnation,
            node,
            owner,
            owner_generation,
            input_epoch,
            world,
            native_record,
            storage_selection,
            capture_profile,
            confirmation_selection,
            ack_emitter_selection,
            complete_restore_selection,
            protocol_metadata_limits,
            protocol_metadata_birth_facts,
            restore_input_emitter_selection,
        ] = fields17(input)?;
        <Plain17<String> as BuildCurrentField17>::preflight_data(schema, l)?;
        <Plain17<U64> as BuildCurrentField17>::preflight_data(native_pid, l)?;
        <Plain17<Envelope> as BuildCurrentField17>::preflight_data(original, l)?;
        <Plain17<HashRef> as BuildCurrentField17>::preflight_data(binding_hash, l)?;
        <Plain17<Id> as BuildCurrentField17>::preflight_data(session, l)?;
        <Plain17<Id> as BuildCurrentField17>::preflight_data(incarnation, l)?;
        <Plain17<Id> as BuildCurrentField17>::preflight_data(node, l)?;
        <Plain17<Id> as BuildCurrentField17>::preflight_data(owner, l)?;
        <Plain17<U64> as BuildCurrentField17>::preflight_data(owner_generation, l)?;
        <Plain17<Id> as BuildCurrentField17>::preflight_data(input_epoch, l)?;
        <Plain17<HashRef> as BuildCurrentField17>::preflight_data(world, l)?;
        <Plain17<ContentRef> as BuildCurrentField17>::preflight_data(native_record, l)?;
        <CurrentDto17<PacketNative5StorageSelection> as BuildCurrentField17>::preflight_data(
            storage_selection,
            l,
        )?;
        <Plain17<PacketNative5CaptureProfile> as BuildCurrentField17>::preflight_data(
            capture_profile,
            l,
        )?;
        <Optional17<Plain17<PacketNative5ConfirmationSelection>> as BuildCurrentField17>::preflight_data(confirmation_selection,l)?;
        <Optional17<Plain17<PacketNative5AckEmitterSelection>> as BuildCurrentField17>::preflight_data(ack_emitter_selection,l)?;
        <Optional17<Plain17<PacketNative5CompleteRestoreSelection>> as BuildCurrentField17>::preflight_data(complete_restore_selection,l)?;
        <Optional17<Plain17<PacketNative5ProtocolMetadataLimits>> as BuildCurrentField17>::preflight_data(protocol_metadata_limits,l)?;
        <Optional17<Plain17<PacketNative5ProtocolMetadataBirthFacts>> as BuildCurrentField17>::preflight_data(protocol_metadata_birth_facts,l)?;
        <Optional17<Plain17<PacketNative5RestoreInputEmitterSelection>> as BuildCurrentField17>::preflight_data(restore_input_emitter_selection,l)?;
        Ok(())
    }

    fn read_into_data(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        a: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if a.failed || a.phase != 0 || a.completed.is_some() {
            return Err(invalid());
        }
        let result = (|| {
            let [
                schema,
                native_pid,
                original,
                binding_hash,
                session,
                incarnation,
                node,
                owner,
                owner_generation,
                input_epoch,
                world,
                native_record,
                storage_selection,
                capture_profile,
                confirmation_selection,
                ack_emitter_selection,
                complete_restore_selection,
                protocol_metadata_limits,
                protocol_metadata_birth_facts,
                restore_input_emitter_selection,
            ] = fields17(input)?;
            <Plain17<String> as BuildCurrentField17>::read_into_data(schema, l, &mut a.schema)?;
            a.phase = 1;
            <Plain17<U64> as BuildCurrentField17>::read_into_data(
                native_pid,
                l,
                &mut a.native_pid,
            )?;
            a.phase = 2;
            <Plain17<Envelope> as BuildCurrentField17>::read_into_data(
                original,
                l,
                &mut a.original,
            )?;
            a.phase = 3;
            <Plain17<HashRef> as BuildCurrentField17>::read_into_data(
                binding_hash,
                l,
                &mut a.binding_hash,
            )?;
            a.phase = 4;
            <Plain17<Id> as BuildCurrentField17>::read_into_data(session, l, &mut a.session)?;
            a.phase = 5;
            <Plain17<Id> as BuildCurrentField17>::read_into_data(
                incarnation,
                l,
                &mut a.incarnation,
            )?;
            a.phase = 6;
            <Plain17<Id> as BuildCurrentField17>::read_into_data(node, l, &mut a.node)?;
            a.phase = 7;
            <Plain17<Id> as BuildCurrentField17>::read_into_data(owner, l, &mut a.owner)?;
            a.phase = 8;
            <Plain17<U64> as BuildCurrentField17>::read_into_data(
                owner_generation,
                l,
                &mut a.owner_generation,
            )?;
            a.phase = 9;
            <Plain17<Id> as BuildCurrentField17>::read_into_data(
                input_epoch,
                l,
                &mut a.input_epoch,
            )?;
            a.phase = 10;
            <Plain17<HashRef> as BuildCurrentField17>::read_into_data(world, l, &mut a.world)?;
            a.phase = 11;
            <Plain17<ContentRef> as BuildCurrentField17>::read_into_data(
                native_record,
                l,
                &mut a.native_record,
            )?;
            a.phase = 12;
            <CurrentDto17<PacketNative5StorageSelection> as BuildCurrentField17>::read_into_data(
                storage_selection,
                l,
                &mut a.storage_selection,
            )?;
            a.phase = 13;
            <Plain17<PacketNative5CaptureProfile> as BuildCurrentField17>::read_into_data(
                capture_profile,
                l,
                &mut a.capture_profile,
            )?;
            a.phase = 14;
            <Optional17<Plain17<PacketNative5ConfirmationSelection>> as BuildCurrentField17>::read_into_data(confirmation_selection,l,&mut a.confirmation_selection)?;
            a.phase = 15;
            <Optional17<Plain17<PacketNative5AckEmitterSelection>> as BuildCurrentField17>::read_into_data(ack_emitter_selection,l,&mut a.ack_emitter_selection)?;
            a.phase = 16;
            <Optional17<Plain17<PacketNative5CompleteRestoreSelection>> as BuildCurrentField17>::read_into_data(complete_restore_selection,l,&mut a.complete_restore_selection)?;
            a.phase = 17;
            <Optional17<Plain17<PacketNative5ProtocolMetadataLimits>> as BuildCurrentField17>::read_into_data(protocol_metadata_limits,l,&mut a.protocol_metadata_limits)?;
            a.phase = 18;
            <Optional17<Plain17<PacketNative5ProtocolMetadataBirthFacts>> as BuildCurrentField17>::read_into_data(protocol_metadata_birth_facts,l,&mut a.protocol_metadata_birth_facts)?;
            a.phase = 19;
            <Optional17<Plain17<PacketNative5RestoreInputEmitterSelection>> as BuildCurrentField17>::read_into_data(restore_input_emitter_selection,l,&mut a.restore_input_emitter_selection)?;
            a.phase = 20;
            if <Plain17<String> as BuildCurrentField17>::output_data(
                    &a.schema
                ).is_none()
                || <Plain17<U64> as BuildCurrentField17>::output_data(
                    &a.native_pid
                ).is_none()
                || <Plain17<Envelope> as BuildCurrentField17>::output_data(
                    &a.original
                ).is_none()
                || <Plain17<HashRef> as BuildCurrentField17>::output_data(
                    &a.binding_hash
                ).is_none()
                || <Plain17<Id> as BuildCurrentField17>::output_data(
                    &a.session
                ).is_none()
                || <Plain17<Id> as BuildCurrentField17>::output_data(
                    &a.incarnation
                ).is_none()
                || <Plain17<Id> as BuildCurrentField17>::output_data(
                    &a.node
                ).is_none()
                || <Plain17<Id> as BuildCurrentField17>::output_data(
                    &a.owner
                ).is_none()
                || <Plain17<U64> as BuildCurrentField17>::output_data(
                    &a.owner_generation
                ).is_none()
                || <Plain17<Id> as BuildCurrentField17>::output_data(
                    &a.input_epoch
                ).is_none()
                || <Plain17<HashRef> as BuildCurrentField17>::output_data(
                    &a.world
                ).is_none()
                || <Plain17<ContentRef> as BuildCurrentField17>::output_data(
                    &a.native_record
                ).is_none()
                || <CurrentDto17<PacketNative5StorageSelection> as BuildCurrentField17>::output_data(
                    &a.storage_selection
                ).is_none()
                || <Plain17<PacketNative5CaptureProfile> as BuildCurrentField17>::output_data(
                    &a.capture_profile
                ).is_none()
                || <Optional17<Plain17<PacketNative5ConfirmationSelection>> as BuildCurrentField17>::output_data(
                    &a.confirmation_selection
                ).is_none()
                || <Optional17<Plain17<PacketNative5AckEmitterSelection>> as BuildCurrentField17>::output_data(
                    &a.ack_emitter_selection
                ).is_none()
                || <Optional17<Plain17<PacketNative5CompleteRestoreSelection>> as BuildCurrentField17>::output_data(
                    &a.complete_restore_selection
                ).is_none()
                || <Optional17<Plain17<PacketNative5ProtocolMetadataLimits>> as BuildCurrentField17>::output_data(
                    &a.protocol_metadata_limits
                ).is_none()
                || <Optional17<Plain17<PacketNative5ProtocolMetadataBirthFacts>> as BuildCurrentField17>::output_data(
                    &a.protocol_metadata_birth_facts
                ).is_none()
                || <Optional17<Plain17<PacketNative5RestoreInputEmitterSelection>> as BuildCurrentField17>::output_data(
                    &a.restore_input_emitter_selection
                ).is_none()
            {
                return Err(invalid());
            }
            a.completed = Some(Self {
                schema: <Plain17<String> as BuildCurrentField17>::take_output_data(
                    &mut a.schema
                ).ok_or_else(invalid)?,
                native_pid: <Plain17<U64> as BuildCurrentField17>::take_output_data(
                    &mut a.native_pid
                ).ok_or_else(invalid)?,
                original: <Plain17<Envelope> as BuildCurrentField17>::take_output_data(
                    &mut a.original
                ).ok_or_else(invalid)?,
                binding_hash: <Plain17<HashRef> as BuildCurrentField17>::take_output_data(
                    &mut a.binding_hash
                ).ok_or_else(invalid)?,
                session: <Plain17<Id> as BuildCurrentField17>::take_output_data(
                    &mut a.session
                ).ok_or_else(invalid)?,
                incarnation: <Plain17<Id> as BuildCurrentField17>::take_output_data(
                    &mut a.incarnation
                ).ok_or_else(invalid)?,
                node: <Plain17<Id> as BuildCurrentField17>::take_output_data(
                    &mut a.node
                ).ok_or_else(invalid)?,
                owner: <Plain17<Id> as BuildCurrentField17>::take_output_data(
                    &mut a.owner
                ).ok_or_else(invalid)?,
                owner_generation: <Plain17<U64> as BuildCurrentField17>::take_output_data(
                    &mut a.owner_generation
                ).ok_or_else(invalid)?,
                input_epoch: <Plain17<Id> as BuildCurrentField17>::take_output_data(
                    &mut a.input_epoch
                ).ok_or_else(invalid)?,
                world: <Plain17<HashRef> as BuildCurrentField17>::take_output_data(
                    &mut a.world
                ).ok_or_else(invalid)?,
                native_record: <Plain17<ContentRef> as BuildCurrentField17>::take_output_data(
                    &mut a.native_record
                ).ok_or_else(invalid)?,
                storage_selection: <CurrentDto17<PacketNative5StorageSelection> as BuildCurrentField17>::take_output_data(
                    &mut a.storage_selection
                ).ok_or_else(invalid)?,
                capture_profile: <Plain17<PacketNative5CaptureProfile> as BuildCurrentField17>::take_output_data(
                    &mut a.capture_profile
                ).ok_or_else(invalid)?,
                confirmation_selection: <Optional17<Plain17<PacketNative5ConfirmationSelection>> as BuildCurrentField17>::take_output_data(
                    &mut a.confirmation_selection
                ).ok_or_else(invalid)?,
                ack_emitter_selection: <Optional17<Plain17<PacketNative5AckEmitterSelection>> as BuildCurrentField17>::take_output_data(
                    &mut a.ack_emitter_selection
                ).ok_or_else(invalid)?,
                complete_restore_selection: <Optional17<Plain17<PacketNative5CompleteRestoreSelection>> as BuildCurrentField17>::take_output_data(
                    &mut a.complete_restore_selection
                ).ok_or_else(invalid)?,
                protocol_metadata_limits: <Optional17<Plain17<PacketNative5ProtocolMetadataLimits>> as BuildCurrentField17>::take_output_data(
                    &mut a.protocol_metadata_limits
                ).ok_or_else(invalid)?,
                protocol_metadata_birth_facts: <Optional17<Plain17<PacketNative5ProtocolMetadataBirthFacts>> as BuildCurrentField17>::take_output_data(
                    &mut a.protocol_metadata_birth_facts
                ).ok_or_else(invalid)?,
                restore_input_emitter_selection: <Optional17<Plain17<PacketNative5RestoreInputEmitterSelection>> as BuildCurrentField17>::take_output_data(
                    &mut a.restore_input_emitter_selection
                ).ok_or_else(invalid)?
            });
            Ok(())
        })();
        if result.is_err() {
            a.failed = true;
        }
        result
    }

    fn output_data(a: &Self::Attempt) -> Option<&Self> {
        a.completed.as_ref()
    }

    fn take_output_data(a: &mut Self::Attempt) -> Option<Self> {
        a.completed.take()
    }

    fn observe_attempt_data(
        a: &Self::Attempt,
        o: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        <Plain17<String> as BuildCurrentField17>::observe_attempt_data(&a.schema, o)?;
        <Plain17<U64> as BuildCurrentField17>::observe_attempt_data(&a.native_pid, o)?;
        <Plain17<Envelope> as BuildCurrentField17>::observe_attempt_data(&a.original, o)?;
        <Plain17<HashRef> as BuildCurrentField17>::observe_attempt_data(&a.binding_hash, o)?;
        <Plain17<Id> as BuildCurrentField17>::observe_attempt_data(&a.session, o)?;
        <Plain17<Id> as BuildCurrentField17>::observe_attempt_data(&a.incarnation, o)?;
        <Plain17<Id> as BuildCurrentField17>::observe_attempt_data(&a.node, o)?;
        <Plain17<Id> as BuildCurrentField17>::observe_attempt_data(&a.owner, o)?;
        <Plain17<U64> as BuildCurrentField17>::observe_attempt_data(&a.owner_generation, o)?;
        <Plain17<Id> as BuildCurrentField17>::observe_attempt_data(&a.input_epoch, o)?;
        <Plain17<HashRef> as BuildCurrentField17>::observe_attempt_data(&a.world, o)?;
        <Plain17<ContentRef> as BuildCurrentField17>::observe_attempt_data(&a.native_record, o)?;
        <CurrentDto17<PacketNative5StorageSelection> as BuildCurrentField17>::observe_attempt_data(
            &a.storage_selection,
            o,
        )?;
        <Plain17<PacketNative5CaptureProfile> as BuildCurrentField17>::observe_attempt_data(
            &a.capture_profile,
            o,
        )?;
        <Optional17<Plain17<PacketNative5ConfirmationSelection>> as BuildCurrentField17>::observe_attempt_data(&a.confirmation_selection,o)?;
        <Optional17<Plain17<PacketNative5AckEmitterSelection>> as BuildCurrentField17>::observe_attempt_data(&a.ack_emitter_selection,o)?;
        <Optional17<Plain17<PacketNative5CompleteRestoreSelection>> as BuildCurrentField17>::observe_attempt_data(&a.complete_restore_selection,o)?;
        <Optional17<Plain17<PacketNative5ProtocolMetadataLimits>> as BuildCurrentField17>::observe_attempt_data(&a.protocol_metadata_limits,o)?;
        <Optional17<Plain17<PacketNative5ProtocolMetadataBirthFacts>> as BuildCurrentField17>::observe_attempt_data(&a.protocol_metadata_birth_facts,o)?;
        <Optional17<Plain17<PacketNative5RestoreInputEmitterSelection>> as BuildCurrentField17>::observe_attempt_data(&a.restore_input_emitter_selection,o)?;
        if let Some(v) = &a.completed {
            v.observe_current(o)?;
        }
        Ok(())
    }
}
