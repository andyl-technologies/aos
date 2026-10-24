//! Records exact historical Control allocations without constructing live custody.
//!
//! The class17 graph records this displaced Control owner separately from its
//! current Control and model. Recording metadata never creates a restoration
//! hold, participant, admission, or usable runtime.

use super::*;
use crate::retained_metadata::MetadataObserver;

// These are simultaneous loans introduced by the exhaustive patterns below.
// They add fixed view scratch; their actual owned backing is recorded separately.
type ControlRecordLoans<'a> = (
    &'a String,
    &'a U64,
    &'a Position,
    &'a Position,
    &'a Value,
    &'a ControlState,
);

type ControlStateLoans<'a> = (
    &'a PacketControlSelection,
    &'a Vec<OriginalRecord>,
    &'a BTreeMap<Id, BeginRequest>,
    &'a BTreeMap<Id, Id>,
    &'a Vec<(ContentRef, Vec<u8>)>,
    &'a usize,
    &'a bool,
    &'a bool,
    &'a Option<(ActivateRequest, ContentRef)>,
    &'a Option<WorldActivateRequest>,
    &'a bool,
    &'a bool,
    &'a bool,
    &'a Option<Id>,
    &'a BTreeMap<Id, Map<String, Value>>,
    &'a Option<crate::reference_packet::coordinator::PacketCoordinatorInstallation>,
    &'a Option<crate::reference_packet::coordinator::PacketWorldCoordinatorInstallation>,
    &'a Option<crate::reference_packet::coordinator::PacketConnectedCoordinatorInstallation>,
    &'a Option<crate::reference_packet::coordinator::PacketNative5CoordinatorInstallation>,
    &'a Option<super::super::native5::PacketNative5StorageSelection>,
    &'a Option<crate::reference_packet::service::PacketNative5CaptureProfile>,
    &'a Option<crate::reference_packet::service::PacketNative5ConfirmationSelection>,
    &'a Option<crate::reference_packet::service::PacketNative5AckEmitterSelection>,
    &'a Option<crate::reference_packet::service::PacketNative5ProtocolMetadataLimits>,
    &'a Option<crate::reference_packet::service::PacketNative5ProtocolMetadataBirthFacts>,
    &'a Option<crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection>,
    &'a Option<crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection>,
    &'a Option<crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection>,
);

type OriginalLoans<'a> = (
    &'a Id,
    &'a HashRef,
    &'a Map<String, Value>,
    &'a Vec<(ContentRef, Vec<u8>)>,
);

type ActivateLoans<'a> = (
    &'a Id,
    &'a Id,
    &'a U64,
    &'a Id,
    &'a HashRef,
    &'a Id,
    &'a Extensions,
);

type WorldActivateLoans<'a> = (
    &'a Id,
    &'a Id,
    &'a U64,
    &'a Id,
    &'a HashRef,
    &'a Id,
    &'a ContentRef,
    &'a Extensions,
);

impl ControlRecord {
    /// Records every actual nested allocation in this historical Control owner.
    ///
    /// The caller supplies a separately admitted recording/alias bank. The
    /// exhaustive field patterns make additional retained fields a compile gap.
    ///
    /// # Errors
    /// Refuses exhausted record banks, excessive JSON depth or checked overflow.
    pub(in crate::reference_packet::control) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            schema,
            captured_process,
            administrative_cut,
            local_cursor,
            model,
            control,
        } = self;
        observer.observe(schema)?;
        observer.observe(captured_process)?;
        observer.observe(administrative_cut)?;
        observer.observe(local_cursor)?;
        observer.observe(model)?;
        observe_control_state(control, observer)
    }

    /// Names fixed borrowed views used by the defining historical walk.
    pub(in crate::reference_packet::control) const fn settled_history_counter_scratch_data() -> usize
    {
        use std::mem::size_of;
        size_of::<&ControlRecord>()
            + size_of::<ControlRecordLoans<'static>>()
            + size_of::<ControlStateLoans<'static>>()
            + size_of::<OriginalLoans<'static>>()
            + size_of::<ActivateLoans<'static>>()
            + size_of::<WorldActivateLoans<'static>>()
            + size_of::<(&String, &Value)>()
            + size_of::<(&String, &Vec<PacketControlSelection>, &Value)>()
            + size_of::<(
                &String,
                &Vec<PacketControlSelection>,
                &crate::reference_packet::coordinator::PacketConnectedHostSelection,
                &Value,
            )>()
            + size_of::<(&ContentRef, &Vec<u8>)>()
            + size_of::<Option<(&ContentRef, &Vec<u8>)>>()
            + size_of::<&ControlState>()
            + size_of::<&OriginalRecord>()
            + size_of::<&ActivateRequest>()
            + size_of::<&WorldActivateRequest>()
            + size_of::<&Option<(ActivateRequest, ContentRef)>>()
            + size_of::<&Option<WorldActivateRequest>>()
            + size_of::<&PacketControlSelection>()
            + size_of::<&Vec<OriginalRecord>>()
            + size_of::<&Vec<(ContentRef, Vec<u8>)>>()
            + size_of::<&ContentRef>()
            + size_of::<&Vec<u8>>()
            + size_of::<&Id>()
            + size_of::<&HashRef>()
            + size_of::<&Map<String, Value>>()
            + size_of::<&Value>()
            + size_of::<&String>()
            + size_of::<&Position>()
            + size_of::<&U64>()
            + size_of::<&usize>()
            + size_of::<&bool>()
            + size_of::<&super::super::super::coordinator::PacketCoordinatorInstallation>()
            + size_of::<&super::super::super::coordinator::PacketWorldCoordinatorInstallation>()
            + size_of::<&super::super::super::coordinator::PacketConnectedCoordinatorInstallation>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<std::slice::Iter<'static, OriginalRecord>>()
            + size_of::<std::slice::Iter<'static, (ContentRef, Vec<u8>)>>()
            + size_of::<Option<&OriginalRecord>>()
            + size_of::<Option<&(ContentRef, Vec<u8>)>>()
    }
}

fn observe_control_state(
    state: &ControlState,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    let ControlState {
        selection,
        originals,
        begins,
        begin_requests,
        content,
        content_bytes,
        realized,
        admitted,
        staged,
        active,
        fenced,
        native_effect_attempted,
        immediate,
        current_operation,
        terminals,
        common_coordinator,
        world_coordinator,
        connected_coordinator,
        complete_coordinator,
        complete_storage,
        complete_capture_profile,
        complete_confirmation_selection,
        complete_ack_emitter_selection,
        complete_protocol_metadata_limits,
        complete_protocol_metadata_birth_facts,
        complete_restore_selection,
        complete_restore_input_emitter_selection,
        complete_capture_allocation_selection,
    } = state;

    observer.observe(selection)?;
    observer.vector::<OriginalRecord>(originals.capacity())?;
    for original in originals {
        let OriginalRecord {
            request,
            identity,
            response_body,
            evidence,
        } = original;
        observer.observe(request)?;
        observer.observe(identity)?;
        observer.observe(response_body)?;
        observe_content(evidence, observer)?;
    }
    observer.observe(begins)?;
    observer.observe(begin_requests)?;
    observe_content(content, observer)?;
    observer.observe(content_bytes)?;
    observer.observe(realized)?;
    observer.observe(admitted)?;

    if let Some((request, ready)) = staged {
        observe_activate(request, observer)?;
        observer.observe(ready)?;
    }
    if let Some(request) = active {
        observe_world_activate(request, observer)?;
    }

    observer.observe(fenced)?;
    observer.observe(native_effect_attempted)?;
    observer.observe(immediate)?;
    observer.observe(current_operation)?;
    observer.observe(terminals)?;

    if let Some(installed) = common_coordinator {
        let super::super::super::coordinator::PacketCoordinatorInstallation { schema, template } =
            installed;
        observer.observe(schema)?;
        observer.observe(template)?;
    }
    if let Some(installed) = world_coordinator {
        let super::super::super::coordinator::PacketWorldCoordinatorInstallation {
            schema,
            participants,
            template,
        } = installed;
        observer.observe(schema)?;
        observer.observe(participants)?;
        observer.observe(template)?;
    }
    if let Some(installed) = connected_coordinator {
        let super::super::super::coordinator::PacketConnectedCoordinatorInstallation {
            schema,
            participants,
            host,
            template,
        } = installed;
        observer.observe(schema)?;
        observer.observe(participants)?;
        observer.observe(host)?;
        observer.observe(template)?;
    }

    observer.observe(complete_coordinator)?;
    observer.observe(complete_storage)?;
    observer.observe(complete_capture_profile)?;
    observer.observe(complete_confirmation_selection)?;
    observer.observe(complete_ack_emitter_selection)?;
    observer.observe(complete_protocol_metadata_limits)?;
    observer.observe(complete_protocol_metadata_birth_facts)?;
    observer.observe(complete_restore_selection)?;
    observer.observe(complete_restore_input_emitter_selection)?;
    observer.observe(complete_capture_allocation_selection)
}

fn observe_content(
    content: &Vec<(ContentRef, Vec<u8>)>,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    observer.vector::<(ContentRef, Vec<u8>)>(content.capacity())?;
    for (reference, bytes) in content {
        observer.observe(reference)?;
        observer.observe(bytes)?;
    }
    Ok(())
}

fn observe_activate(
    request: &ActivateRequest,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    let ActivateRequest {
        admission_id,
        activation_id,
        world_generation,
        prepared_token,
        world_binding_hash,
        gate_id,
        extensions,
    } = request;
    observer.observe(admission_id)?;
    observer.observe(activation_id)?;
    observer.observe(world_generation)?;
    observer.observe(prepared_token)?;
    observer.observe(world_binding_hash)?;
    observer.observe(gate_id)?;
    observer.observe(extensions)
}

fn observe_world_activate(
    request: &WorldActivateRequest,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    let WorldActivateRequest {
        transaction_id,
        activation_id,
        world_generation,
        prepared_token,
        world_binding_hash,
        gate_id,
        activation_manifest,
        extensions,
    } = request;
    observer.observe(transaction_id)?;
    observer.observe(activation_id)?;
    observer.observe(world_generation)?;
    observer.observe(prepared_token)?;
    observer.observe(world_binding_hash)?;
    observer.observe(gate_id)?;
    observer.observe(activation_manifest)?;
    observer.observe(extensions)
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These historical DATA controls deliberately panic on failed fixture invariants.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::retained_metadata::records::{MetadataRecordBank, MetadataRecordKind};

    fn content() -> Vec<(ContentRef, Vec<u8>)> {
        let mut bytes = Vec::with_capacity(37);
        bytes.extend_from_slice(b"abc");
        let reference = canonical::content_ref(&bytes, "application/octet-stream").unwrap();
        let mut content = Vec::with_capacity(5);
        content.push((reference, bytes));
        content
    }

    #[test]
    fn content_history_walk_records_actual_outer_and_byte_spare_capacity() {
        let content = content();
        let mut records = MetadataRecordBank::reserve(32).unwrap();
        let mut observer = MetadataObserver::recording(&mut records);

        observe_content(&content, &mut observer).unwrap();
        let facts = observer.finish();

        assert_eq!(facts.vector_banks, 2);
        assert_eq!(
            facts.vector_capacity_bytes,
            content.capacity() * std::mem::size_of::<(ContentRef, Vec<u8>)>()
                + content[0].1.capacity()
        );
        let vectors: Vec<_> = records
            .rows()
            .iter()
            .filter(|row| row.kind == MetadataRecordKind::Vector)
            .collect();
        assert_eq!(vectors.len(), 2);
        assert_eq!(vectors[0].extent, content.capacity());
        assert_eq!(vectors[1].extent, content[0].1.capacity());
        assert_eq!(content[0].1.as_slice(), b"abc");
    }

    #[test]
    fn short_record_bank_refuses_without_growing_or_changing_the_owner() {
        let content = content();
        let mut records = MetadataRecordBank::reserve(1).unwrap();
        let allocated = records.allocated_bytes();
        let mut observer = MetadataObserver::recording(&mut records);

        assert!(observe_content(&content, &mut observer).is_err());
        let _ = observer.finish();

        assert_eq!(records.rows().len(), 1);
        assert_eq!(records.allocated_bytes(), allocated);
        assert_eq!(content.len(), 1);
        assert_eq!(content[0].1.as_slice(), b"abc");
    }
}
