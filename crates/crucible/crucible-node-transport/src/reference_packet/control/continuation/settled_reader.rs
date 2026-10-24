//! Reads displaced raw ControlRecord owners as inert typed historical DATA.
//!
//! The defining serializer order and one enclosing capacity Ledger are preserved.
//! Failed and incomplete control fields remain historical facts; this reader does
//! not call the live Control constructor, install a model, or issue adoption.
//!
//! ```text
//! {schema,captured_process,administrative_cut,local_cursor,model,control:{...}}
//! ```

use super::super::native5::PacketNative5StorageSelection;
use super::*;
use crate::handshake::Limits;
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, historical_struct, invalid, plain_string,
};
use crate::reference_packet::{
    coordinator::{
        PacketConnectedCoordinatorInstallation, PacketCoordinatorInstallation,
        PacketNative5CoordinatorInstallation, PacketWorldCoordinatorInstallation,
    },
    service::{
        PacketNative5AckEmitterSelection, PacketNative5CaptureProfile,
        PacketNative5ConfirmationSelection, PacketNative5ProtocolMetadataBirthFacts,
        PacketNative5ProtocolMetadataLimits, PacketNative5StorageLimits,
        capture_allocation::PacketNative5CaptureAllocationSelection,
        complete_restore::{
            PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
        },
    },
};
use crate::retained_metadata::{MetadataObserver, ObserveMetadata};

/// Owns historical Control fields without constructing a live Control allocation.
#[derive(Serialize)]
#[serde(transparent)]
pub(crate) struct PacketSettledControlRecord17Data(ControlRecord);

impl HistoricalType for PacketSettledControlRecord17Data {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        // Check the edition even in the allocation-free pass. Optional fields
        // below remain literal: null cannot impersonate an omitted selection.
        let mut fields = Fields::object(input)?;
        let schema = plain_string(fields.named("schema")?)?;
        if schema != SCHEMA && schema != CAPTURE_ALLOCATION_SCHEMA {
            return Err(invalid());
        }
        let mut tail = Fields::object(input)?;
        let mut control = None;
        while let Some((key, value)) = tail.pair()? {
            if plain_string(key)? == "control" {
                control = Some(value);
            }
        }
        let mut selected = Fields::object(control.ok_or_else(invalid)?)?;
        let mut allocation = false;
        while let Some((key, value)) = selected.pair()? {
            if plain_string(key)? == "complete_capture_allocation_selection" {
                if value != b"\"original_observe12\"" {
                    return Err(invalid());
                }
                allocation = true;
            }
        }
        if allocation != (schema == CAPTURE_ALLOCATION_SCHEMA) {
            return Err(invalid());
        }
        Ok(ledger.read::<ControlRecord>(input, build)?.map(Self))
    }
}

impl ObserveMetadata for PacketSettledControlRecord17Data {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        self.0.observe_settled_history_metadata_data(observer)
    }
}

impl crate::reference_packet::continuation_models::PreparedControlHistory17
    for PacketSettledControlRecord17Data
{
}

historical_struct!(ControlRecord {
    schema: String,
    captured_process: U64,
    administrative_cut: Position,
    local_cursor: Position,
    model: Value,
    control: ControlState,
});
historical_struct!(OriginalRecord {
    request:Id,
    identity:HashRef,
    response_body:Map<String,Value>,
    evidence:Vec<(ContentRef,Vec<u8>)>,
});

impl HistoricalType for ControlState {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let selection = ledger.read::<PacketControlSelection>(fields.named("selection")?, build)?;
        let originals = ledger.read::<Vec<OriginalRecord>>(fields.named("originals")?, build)?;
        let begins = ledger.read::<BTreeMap<Id, BeginRequest>>(fields.named("begins")?, build)?;
        let begin_requests =
            ledger.read::<BTreeMap<Id, Id>>(fields.named("begin_requests")?, build)?;
        let content = ledger.read::<Vec<(ContentRef, Vec<u8>)>>(fields.named("content")?, build)?;
        let content_bytes = ledger.read::<usize>(fields.named("content_bytes")?, build)?;
        let realized = ledger.read::<bool>(fields.named("realized")?, build)?;
        let admitted = ledger.read::<bool>(fields.named("admitted")?, build)?;
        let staged =
            ledger.read::<Option<(ActivateRequest, ContentRef)>>(fields.named("staged")?, build)?;
        let active = ledger.read::<Option<WorldActivateRequest>>(fields.named("active")?, build)?;
        let fenced = ledger.read::<bool>(fields.named("fenced")?, build)?;
        let native_effect_attempted =
            ledger.read::<bool>(fields.named("native_effect_attempted")?, build)?;
        let immediate = ledger.read::<bool>(fields.named("immediate")?, build)?;
        let current_operation =
            ledger.read::<Option<Id>>(fields.named("current_operation")?, build)?;
        let terminals =
            ledger.read::<BTreeMap<Id, Map<String, Value>>>(fields.named("terminals")?, build)?;
        let common_coordinator = ledger.read::<Option<PacketCoordinatorInstallation>>(
            fields.named("common_coordinator")?,
            build,
        )?;
        let world_coordinator = ledger.read::<Option<PacketWorldCoordinatorInstallation>>(
            fields.named("world_coordinator")?,
            build,
        )?;
        let connected_coordinator = ledger.read::<Option<PacketConnectedCoordinatorInstallation>>(
            fields.named("connected_coordinator")?,
            build,
        )?;
        let complete_coordinator = ledger.read::<Option<PacketNative5CoordinatorInstallation>>(
            fields.named("complete_coordinator")?,
            build,
        )?;
        let complete_storage = ledger.read::<Option<PacketNative5StorageSelection>>(
            fields.named("complete_storage")?,
            build,
        )?;
        // Only these defining trailing fields are omitted for None. One saved
        // pair enforces original order, rejects duplicates and unknown fields,
        // and avoids a normalized DOM that would erase explicit null.
        let mut pending = fields.pair()?;
        let complete_capture_profile = read_optional::<PacketNative5CaptureProfile>(
            "complete_capture_profile",
            &mut fields,
            &mut pending,
            ledger,
            build,
        )?;
        let complete_confirmation_selection = read_optional::<PacketNative5ConfirmationSelection>(
            "complete_confirmation_selection",
            &mut fields,
            &mut pending,
            ledger,
            build,
        )?;
        let complete_ack_emitter_selection = read_optional::<PacketNative5AckEmitterSelection>(
            "complete_ack_emitter_selection",
            &mut fields,
            &mut pending,
            ledger,
            build,
        )?;
        let complete_protocol_metadata_limits = read_optional::<PacketNative5ProtocolMetadataLimits>(
            "complete_protocol_metadata_limits",
            &mut fields,
            &mut pending,
            ledger,
            build,
        )?;
        let complete_protocol_metadata_birth_facts =
            read_optional::<PacketNative5ProtocolMetadataBirthFacts>(
                "complete_protocol_metadata_birth_facts",
                &mut fields,
                &mut pending,
                ledger,
                build,
            )?;
        let complete_restore_selection = read_optional::<PacketNative5CompleteRestoreSelection>(
            "complete_restore_selection",
            &mut fields,
            &mut pending,
            ledger,
            build,
        )?;
        let complete_restore_input_emitter_selection =
            read_optional::<PacketNative5RestoreInputEmitterSelection>(
                "complete_restore_input_emitter_selection",
                &mut fields,
                &mut pending,
                ledger,
                build,
            )?;
        let complete_capture_allocation_selection =
            read_optional::<PacketNative5CaptureAllocationSelection>(
                "complete_capture_allocation_selection",
                &mut fields,
                &mut pending,
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
            selection: selection.ok_or_else(invalid)?,
            originals: originals.ok_or_else(invalid)?,
            begins: begins.ok_or_else(invalid)?,
            begin_requests: begin_requests.ok_or_else(invalid)?,
            content: content.ok_or_else(invalid)?,
            content_bytes: content_bytes.ok_or_else(invalid)?,
            realized: realized.ok_or_else(invalid)?,
            admitted: admitted.ok_or_else(invalid)?,
            staged: staged.ok_or_else(invalid)?,
            active: active.ok_or_else(invalid)?,
            fenced: fenced.ok_or_else(invalid)?,
            native_effect_attempted: native_effect_attempted.ok_or_else(invalid)?,
            immediate: immediate.ok_or_else(invalid)?,
            current_operation: current_operation.ok_or_else(invalid)?,
            terminals: terminals.ok_or_else(invalid)?,
            common_coordinator: common_coordinator.ok_or_else(invalid)?,
            world_coordinator: world_coordinator.ok_or_else(invalid)?,
            connected_coordinator: connected_coordinator.ok_or_else(invalid)?,
            complete_coordinator: complete_coordinator.ok_or_else(invalid)?,
            complete_storage: complete_storage.ok_or_else(invalid)?,
            complete_capture_profile: complete_capture_profile.ok_or_else(invalid)?,
            complete_confirmation_selection: complete_confirmation_selection.ok_or_else(invalid)?,
            complete_ack_emitter_selection: complete_ack_emitter_selection.ok_or_else(invalid)?,
            complete_protocol_metadata_limits: complete_protocol_metadata_limits
                .ok_or_else(invalid)?,
            complete_protocol_metadata_birth_facts: complete_protocol_metadata_birth_facts
                .ok_or_else(invalid)?,
            complete_restore_selection: complete_restore_selection.ok_or_else(invalid)?,
            complete_restore_input_emitter_selection: complete_restore_input_emitter_selection
                .ok_or_else(invalid)?,
            complete_capture_allocation_selection: complete_capture_allocation_selection
                .ok_or_else(invalid)?,
        }))
    }
}

fn read_optional<'a, T: HistoricalType>(
    name: &str,
    fields: &mut Fields<'a>,
    pending: &mut Option<(&'a [u8], &'a [u8])>,
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<Option<T>>, ProviderError> {
    let value = match *pending {
        Some((key, value)) if plain_string(key)? == name => {
            if value == b"null" {
                return Err(invalid());
            }
            *pending = fields.pair()?;
            value
        }
        _ => b"null",
    };
    ledger.read::<Option<T>>(value, build)
}

historical_struct!(BeginRequest {
    kind:BeginKind,
    binding_hash:HashRef,
    owner_generation:U64,
    activation_id:Nullable<Id>,
    world_generation:U64,
    arguments:Map<String,Value>,
    extensions:Extensions,
});
historical_struct!(ActivateRequest {
    admission_id: Id,
    activation_id: Id,
    world_generation: U64,
    prepared_token: Id,
    world_binding_hash: HashRef,
    gate_id: Id,
    extensions: Extensions,
});
historical_struct!(WorldActivateRequest {
    transaction_id: Id,
    activation_id: Id,
    world_generation: U64,
    prepared_token: Id,
    world_binding_hash: HashRef,
    gate_id: Id,
    activation_manifest: ContentRef,
    extensions: Extensions,
});
historical_struct!(PacketCoordinatorInstallation {
    schema: String,
    template: Value,
});
historical_struct!(PacketWorldCoordinatorInstallation {
    schema:String,
    participants:Vec<PacketControlSelection>,
    template:Value,
});
historical_struct!(PacketConnectedCoordinatorInstallation {
    schema:String,
    participants:Vec<PacketControlSelection>,
    host:crate::reference_packet::coordinator::PacketConnectedHostSelection,
    template:Value,
});
historical_struct!(PacketNative5StorageSelection {
    storage: PacketNative5StorageLimits,
    limits: Limits,
});
historical_struct!(PacketNative5StorageLimits {
    snapshot_bytes: U64,
    control_snapshot_bytes: U64,
    protocol_snapshot_bytes: U64,
    frame_bank_bytes: U64,
    frames_per_direction: U64,
    hello_bytes: U64,
    settlement_bytes: U64,
});

macro_rules! enum_data {
    ($type:ty {$($wire:literal=>$variant:ident),+ $(,)?})=> {
        impl HistoricalType for $type {
            fn read(input:&[u8],_:&mut Ledger<'_, '_, '_>,build:bool)->Result<Option<Self>,ProviderError> {
                let value=match plain_string(input)? {$($wire=>Self::$variant,)+_=>return Err(invalid())};
                Ok(build.then_some(value))
            }
        }
    };
}

enum_data!(BeginKind {"exact_run"=>ExactRun,"boundary_settle"=>BoundarySettle,"quantum_begin"=>QuantumBegin,"pause"=>Pause,"capture"=>Capture,"prepare_restore"=>PrepareRestore,"shutdown"=>Shutdown});
enum_data!(PacketNative5CompleteRestoreSelection {"SourceSignedOwned11"=>SourceSignedOwned11,"SourceSignedTransfer12"=>SourceSignedTransfer12});
enum_data!(PacketNative5RestoreInputEmitterSelection {"CanonicalSdkRestoreInputs12"=>CanonicalSdkRestoreInputs12});
enum_data!(PacketNative5CaptureAllocationSelection {"original_observe12"=>OriginalObserve12});

/// Names fixed reader views separately from the enclosing admitted owner banks.
pub(crate) fn settled_control_record17_counter_scratch_data() -> usize {
    use std::mem::size_of;
    let terms = [
        ControlRecord::settled_history_counter_scratch_data(),
        size_of::<PacketSettledControlRecord17Data>(),
        size_of::<ControlRecord>(),
        size_of::<ControlState>(),
        size_of::<OriginalRecord>(),
        3 * size_of::<Fields<'static>>(),
        size_of::<Ledger<'static, 'static, 'static>>(),
        size_of::<Option<(&[u8], &[u8])>>(),
        size_of::<(&[u8], &[u8])>(),
        size_of::<Option<&[u8]>>(),
        size_of::<Result<Option<(&[u8], &[u8])>, ProviderError>>(),
        size_of::<Result<Fields<'static>, ProviderError>>(),
        size_of::<Result<&[u8], ProviderError>>(),
        size_of::<Result<&str, ProviderError>>(),
        size_of::<Result<(), ProviderError>>(),
        size_of::<Option<PacketSettledControlRecord17Data>>(),
        size_of::<Result<Option<PacketSettledControlRecord17Data>, ProviderError>>(),
        size_of::<Option<ControlRecord>>(),
        size_of::<Result<Option<ControlRecord>, ProviderError>>(),
        size_of::<Option<ControlState>>(),
        size_of::<Result<Option<ControlState>, ProviderError>>(),
        size_of::<Option<OriginalRecord>>(),
        size_of::<Result<Option<OriginalRecord>, ProviderError>>(),
        size_of::<Option<PacketControlSelection>>(),
        size_of::<Result<Option<PacketControlSelection>, ProviderError>>(),
        size_of::<Option<Vec<OriginalRecord>>>(),
        size_of::<Result<Option<Vec<OriginalRecord>>, ProviderError>>(),
        size_of::<Option<BTreeMap<Id, BeginRequest>>>(),
        size_of::<Result<Option<BTreeMap<Id, BeginRequest>>, ProviderError>>(),
        size_of::<Option<BTreeMap<Id, Id>>>(),
        size_of::<Result<Option<BTreeMap<Id, Id>>, ProviderError>>(),
        size_of::<Option<Vec<(ContentRef, Vec<u8>)>>>(),
        size_of::<Result<Option<Vec<(ContentRef, Vec<u8>)>>, ProviderError>>(),
        size_of::<Option<usize>>(),
        size_of::<Result<Option<usize>, ProviderError>>(),
        size_of::<Option<bool>>(),
        size_of::<Result<Option<bool>, ProviderError>>(),
        size_of::<Option<Option<(ActivateRequest, ContentRef)>>>(),
        size_of::<Result<Option<Option<(ActivateRequest, ContentRef)>>, ProviderError>>(),
        size_of::<Option<Option<WorldActivateRequest>>>(),
        size_of::<Result<Option<Option<WorldActivateRequest>>, ProviderError>>(),
        size_of::<Option<Option<Id>>>(),
        size_of::<Result<Option<Option<Id>>, ProviderError>>(),
        size_of::<Option<BTreeMap<Id, Map<String, Value>>>>(),
        size_of::<Result<Option<BTreeMap<Id, Map<String, Value>>>, ProviderError>>(),
        size_of::<Option<Option<PacketCoordinatorInstallation>>>(),
        size_of::<Result<Option<Option<PacketCoordinatorInstallation>>, ProviderError>>(),
        size_of::<Option<Option<PacketWorldCoordinatorInstallation>>>(),
        size_of::<Result<Option<Option<PacketWorldCoordinatorInstallation>>, ProviderError>>(),
        size_of::<Option<Option<PacketConnectedCoordinatorInstallation>>>(),
        size_of::<Result<Option<Option<PacketConnectedCoordinatorInstallation>>, ProviderError>>(),
        size_of::<Option<Option<PacketNative5CoordinatorInstallation>>>(),
        size_of::<Result<Option<Option<PacketNative5CoordinatorInstallation>>, ProviderError>>(),
        size_of::<Option<Option<PacketNative5StorageSelection>>>(),
        size_of::<Result<Option<Option<PacketNative5StorageSelection>>, ProviderError>>(),
        size_of::<Option<Option<PacketNative5CaptureProfile>>>(),
        size_of::<Result<Option<Option<PacketNative5CaptureProfile>>, ProviderError>>(),
        size_of::<Option<Option<PacketNative5ConfirmationSelection>>>(),
        size_of::<Result<Option<Option<PacketNative5ConfirmationSelection>>, ProviderError>>(),
        size_of::<Option<Option<PacketNative5AckEmitterSelection>>>(),
        size_of::<Result<Option<Option<PacketNative5AckEmitterSelection>>, ProviderError>>(),
        size_of::<Option<Option<PacketNative5ProtocolMetadataLimits>>>(),
        size_of::<Result<Option<Option<PacketNative5ProtocolMetadataLimits>>, ProviderError>>(),
        size_of::<Option<Option<PacketNative5ProtocolMetadataBirthFacts>>>(),
        size_of::<Result<Option<Option<PacketNative5ProtocolMetadataBirthFacts>>, ProviderError>>(),
        size_of::<Option<Option<PacketNative5CompleteRestoreSelection>>>(),
        size_of::<Result<Option<Option<PacketNative5CompleteRestoreSelection>>, ProviderError>>(),
        size_of::<Option<Option<PacketNative5RestoreInputEmitterSelection>>>(),
        size_of::<Result<Option<Option<PacketNative5RestoreInputEmitterSelection>>, ProviderError>>(
        ),
        size_of::<Option<Option<PacketNative5CaptureAllocationSelection>>>(),
        size_of::<Result<Option<Option<PacketNative5CaptureAllocationSelection>>, ProviderError>>(),
        size_of::<Option<String>>(),
        size_of::<Result<Option<String>, ProviderError>>(),
        size_of::<Option<U64>>(),
        size_of::<Result<Option<U64>, ProviderError>>(),
        size_of::<Option<Position>>(),
        size_of::<Result<Option<Position>, ProviderError>>(),
        size_of::<Option<Value>>(),
        size_of::<Result<Option<Value>, ProviderError>>(),
        size_of::<Option<Id>>(),
        size_of::<Result<Option<Id>, ProviderError>>(),
        size_of::<Option<HashRef>>(),
        size_of::<Result<Option<HashRef>, ProviderError>>(),
        size_of::<Option<BeginKind>>(),
        size_of::<Result<Option<BeginKind>, ProviderError>>(),
        size_of::<Option<Nullable<Id>>>(),
        size_of::<Result<Option<Nullable<Id>>, ProviderError>>(),
        size_of::<Option<Extensions>>(),
        size_of::<Result<Option<Extensions>, ProviderError>>(),
        size_of::<Option<Vec<PacketControlSelection>>>(),
        size_of::<Result<Option<Vec<PacketControlSelection>>, ProviderError>>(),
        size_of::<Option<crate::reference_packet::coordinator::PacketConnectedHostSelection>>(),
        size_of::<
            Result<
                Option<crate::reference_packet::coordinator::PacketConnectedHostSelection>,
                ProviderError,
            >,
        >(),
        size_of::<Option<PacketNative5StorageLimits>>(),
        size_of::<Result<Option<PacketNative5StorageLimits>, ProviderError>>(),
        size_of::<Option<Limits>>(),
        size_of::<Result<Option<Limits>, ProviderError>>(),
        // Every simultaneous local result from each defining struct reader.
        size_of::<(
            Option<String>,
            Option<U64>,
            Option<Position>,
            Option<Position>,
            Option<Value>,
            Option<ControlState>,
        )>(),
        size_of::<(
            Option<PacketControlSelection>,
            Option<Vec<OriginalRecord>>,
            Option<BTreeMap<Id, BeginRequest>>,
            Option<BTreeMap<Id, Id>>,
            Option<Vec<(ContentRef, Vec<u8>)>>,
            Option<usize>,
            Option<bool>,
            Option<bool>,
            Option<Option<(ActivateRequest, ContentRef)>>,
            Option<Option<WorldActivateRequest>>,
            Option<bool>,
            Option<bool>,
            Option<bool>,
            Option<Option<Id>>,
            Option<BTreeMap<Id, Map<String, Value>>>,
            Option<Option<PacketCoordinatorInstallation>>,
            Option<Option<PacketWorldCoordinatorInstallation>>,
            Option<Option<PacketConnectedCoordinatorInstallation>>,
            Option<Option<PacketNative5CoordinatorInstallation>>,
            Option<Option<PacketNative5StorageSelection>>,
            Option<Option<PacketNative5CaptureProfile>>,
            Option<Option<PacketNative5ConfirmationSelection>>,
            Option<Option<PacketNative5AckEmitterSelection>>,
            Option<Option<PacketNative5ProtocolMetadataLimits>>,
            Option<Option<PacketNative5ProtocolMetadataBirthFacts>>,
            Option<Option<PacketNative5CompleteRestoreSelection>>,
            Option<Option<PacketNative5RestoreInputEmitterSelection>>,
            Option<Option<PacketNative5CaptureAllocationSelection>>,
        )>(),
        size_of::<(
            Option<Id>,
            Option<HashRef>,
            Option<Map<String, Value>>,
            Option<Vec<(ContentRef, Vec<u8>)>>,
        )>(),
        size_of::<(
            Option<BeginKind>,
            Option<HashRef>,
            Option<U64>,
            Option<Nullable<Id>>,
            Option<U64>,
            Option<Map<String, Value>>,
            Option<Extensions>,
        )>(),
        size_of::<(
            Option<Id>,
            Option<Id>,
            Option<U64>,
            Option<Id>,
            Option<HashRef>,
            Option<Id>,
            Option<Extensions>,
        )>(),
        size_of::<(
            Option<Id>,
            Option<Id>,
            Option<U64>,
            Option<Id>,
            Option<HashRef>,
            Option<Id>,
            Option<ContentRef>,
            Option<Extensions>,
        )>(),
        size_of::<(Option<String>, Option<Value>)>(),
        size_of::<(
            Option<String>,
            Option<Vec<PacketControlSelection>>,
            Option<Value>,
        )>(),
        size_of::<(
            Option<String>,
            Option<Vec<PacketControlSelection>>,
            Option<crate::reference_packet::coordinator::PacketConnectedHostSelection>,
            Option<Value>,
        )>(),
        size_of::<(Option<PacketNative5StorageLimits>, Option<Limits>)>(),
        size_of::<(
            Option<U64>,
            Option<U64>,
            Option<U64>,
            Option<U64>,
            Option<U64>,
            Option<U64>,
            Option<U64>,
        )>(),
    ];
    std::mem::size_of_val(&terms)
        + size_of::<std::array::IntoIter<usize, 108>>()
        + size_of::<[u8; 128]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<&usize>()
        + terms.into_iter().sum::<usize>()
}

#[cfg(test)]
#[path = "settled_reader/tests.rs"]
mod tests;

mod native17_request_build;

// The archived typed owner uses concrete retained field companions in whole17.
mod retained;
