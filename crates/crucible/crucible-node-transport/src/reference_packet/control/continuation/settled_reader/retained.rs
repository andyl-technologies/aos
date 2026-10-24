//! Retains every archived ControlRecord field beneath its exact old grammar.
//!
//! This new17 owning companion preserves omitted selections and the edition
//! guard. It creates inert ControlRecord/ControlState data only, never Control.

use super::*;
use crate::protocol_snapshot::owned11::typed::{Native17Build, native17_build::native17_struct};
native17_struct!(@guard validate_edition; ControlRecord {
    schema: String,
    captured_process: U64,
    administrative_cut: Position,
    local_cursor: Position,
    model: Value,
    control: ControlState,
});

native17_struct!(OriginalRecord {
    request:Id,
    identity:HashRef,
    response_body:Map<String,Value>,
    evidence:Vec<(ContentRef,Vec<u8>)>,
});

native17_struct!(PacketCoordinatorInstallation {
    schema: String,
    template: Value,
});

native17_struct!(PacketWorldCoordinatorInstallation {
    schema:String,
    participants:Vec<PacketControlSelection>,
    template:Value,
});

native17_struct!(PacketConnectedCoordinatorInstallation {
    schema:String,
    participants:Vec<PacketControlSelection>,
    host:crate::reference_packet::coordinator::PacketConnectedHostSelection,
    template:Value,
});

native17_struct!(PacketNative5StorageSelection {
    storage: PacketNative5StorageLimits,
    limits: Limits,
});

native17_struct!(PacketNative5StorageLimits {
    snapshot_bytes: U64,
    control_snapshot_bytes: U64,
    protocol_snapshot_bytes: U64,
    frame_bank_bytes: U64,
    frames_per_direction: U64,
    hello_bytes: U64,
    settlement_bytes: U64,
});

native17_struct!(ControlState {
    selection: PacketControlSelection,
    originals: Vec<OriginalRecord>,
    begins: BTreeMap<Id, BeginRequest>,
    begin_requests: BTreeMap<Id, Id>,
    content: Vec<(ContentRef, Vec<u8>)>,
    content_bytes: usize,
    realized: bool,
    admitted: bool,
    staged: Option<(ActivateRequest, ContentRef)>,
    active: Option<WorldActivateRequest>,
    fenced: bool,
    native_effect_attempted: bool,
    immediate: bool,
    current_operation: Option<Id>,
    terminals: BTreeMap<Id, Map<String, Value>>,
    common_coordinator: Option<PacketCoordinatorInstallation>,
    world_coordinator: Option<PacketWorldCoordinatorInstallation>,
    connected_coordinator: Option<PacketConnectedCoordinatorInstallation>,
    complete_coordinator: Option<PacketNative5CoordinatorInstallation>,
    complete_storage: Option<PacketNative5StorageSelection>,
    complete_capture_profile: Option<PacketNative5CaptureProfile> => omitted,
    complete_confirmation_selection: Option<PacketNative5ConfirmationSelection> => omitted,
    complete_ack_emitter_selection: Option<PacketNative5AckEmitterSelection> => omitted,
    complete_protocol_metadata_limits: Option<PacketNative5ProtocolMetadataLimits> => omitted,
    complete_protocol_metadata_birth_facts: Option<PacketNative5ProtocolMetadataBirthFacts> => omitted,
    complete_restore_selection: Option<PacketNative5CompleteRestoreSelection> => omitted,
    complete_restore_input_emitter_selection: Option<PacketNative5RestoreInputEmitterSelection> => omitted,
    complete_capture_allocation_selection: Option<PacketNative5CaptureAllocationSelection> => omitted,
});

/// Keeps the actual archived record and its pending concrete typed field list.
#[derive(Default)]
pub(crate) struct PacketSettledControlRecord17ReadAttempt {
    started: bool,
    completed: Option<PacketSettledControlRecord17Data>,
    record: <ControlRecord as Native17Build>::Attempt,
}

impl Native17Build for PacketSettledControlRecord17Data {
    type Attempt = PacketSettledControlRecord17ReadAttempt;
    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if attempt.started {
            return Err(ProviderError::Conflict(
                "native17 archived Control read already attempted",
            ));
        }
        attempt.started = true;
        ControlRecord::read_into_data(input, ledger, &mut attempt.record)?;
        attempt.completed = Some(Self(
            ControlRecord::take_output_data(&mut attempt.record).ok_or_else(invalid)?,
        ));
        Ok(())
    }
    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        ControlRecord::preflight_data(input, ledger)
    }
    fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
        attempt.completed.as_ref()
    }
    fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
        attempt.completed.take()
    }
    fn observe_attempt_data(
        attempt: &Self::Attempt,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(value) = &attempt.completed {
            ControlRecord::observe_output_data(&value.0, observer)?;
        }
        ControlRecord::observe_attempt_data(&attempt.record, observer)
    }
    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        ControlRecord::observe_output_data(&value.0, observer)
    }
}

fn validate_edition(input: &[u8], _: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
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
    Ok(())
}

// These explicit leaves contain fixed numeric fields only. Their existing
// grammar also checks the original finite-limit rules without allocating.
macro_rules! fixed_control_leaf {
    ($ty:ty) => {
        impl Native17Build for $ty {
            type Attempt = Option<Self>;
            fn read_into_data(
                input: &[u8],
                ledger: &mut Ledger<'_, '_, '_>,
                attempt: &mut Self::Attempt,
            ) -> Result<(), ProviderError> {
                if attempt.is_some() {
                    return Err(invalid());
                }
                *attempt = Self::read(input, ledger, true)?;
                if attempt.is_none() {
                    return Err(invalid());
                }
                Ok(())
            }
            fn preflight_data(
                input: &[u8],
                ledger: &mut Ledger<'_, '_, '_>,
            ) -> Result<(), ProviderError> {
                Self::read(input, ledger, false).map(|_| ())
            }
            fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
                attempt.as_ref()
            }
            fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
                attempt.take()
            }
            fn observe_attempt_data(
                attempt: &Self::Attempt,
                observer: &mut MetadataObserver<'_>,
            ) -> Result<(), ProviderError> {
                if let Some(value) = attempt {
                    observer.observe(value)?;
                }
                Ok(())
            }
            fn observe_output_data(
                value: &Self,
                observer: &mut MetadataObserver<'_>,
            ) -> Result<(), ProviderError> {
                observer.observe(value)
            }
        }
    };
}
fixed_control_leaf!(PacketNative5ProtocolMetadataLimits);
fixed_control_leaf!(PacketNative5ProtocolMetadataBirthFacts);

#[cfg(test)]
mod tests;

// All fields are fixed scalar facts; their reader creates no child backing.
fixed_control_leaf!(crate::reference_packet::service::PacketNative5ProtocolMetadataBankFacts);
