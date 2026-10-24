//! Borrows all current Control/model fields beside immutable restored custody.
//!
//! ```text
//! {schema:"source-owned.packet-native-control-restored-settled/17",
//!  ...every actual Control field, capture_identity_role, program:[kind,data]}
//! ```
//!
//! Physical hold and evidence edges remain distinct from current program state.
//! These owner views do not select Capture, make a live decoder, or grant a
//! physical gate. The actual current administrative cut lives in the enclosing
//! independently authenticated Capture17 object, never the first held cursor.

use super::*;
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};
use std::{
    mem::{size_of, size_of_val},
    rc::Rc,
};

type Originals = BTreeMap<Id, (HashRef, PacketControlReply)>;
type Content = BTreeMap<ContentRef, Vec<u8>>;

struct ControlHistory<'a>(&'a PacketControl, bool, Option<PendingCapture17Fields<'a>>);

struct ProgramHistory<'a>(&'a NativeProgram);

impl Serialize for ProgramHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            NativeProgram::OutputOnly(program) => {
                ("producer", program.borrowed_settled_model_data()).serialize(serializer)
            }
            NativeProgram::Connected(program) => {
                ("reactive", program.borrowed_settled_model_data()).serialize(serializer)
            }
            NativeProgram::RestorationInProgress => {
                ("restoration-in-progress", Option::<()>::None).serialize(serializer)
            }
        }
    }
}

struct OriginalsHistory<'a>(&'a Originals);

impl Serialize for OriginalsHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
        for (id, (hash, reply)) in self.0 {
            rows.serialize_element(&(id, hash, &reply.body, &reply.evidence))?;
        }
        rows.end()
    }
}

struct ContentHistory<'a>(&'a Content);

impl Serialize for ContentHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
        for row in self.0 {
            rows.serialize_element(&row)?;
        }
        rows.end()
    }
}

impl PacketControl {
    fn authenticate_restored_settled_history_edges_data(&self) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation("Control17 historical origin"));
        }
        if let Some(hold) = &self.complete_restored_hold {
            hold.authenticate_settled_history_control_identity_data(&self.capture_identity)?;
        }
        if let Some(evidence) = &self.complete_restored_evidence {
            let hold = self
                .complete_restored_hold
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "Control17 evidence has no same physical hold",
                ))?;
            evidence.authenticate_settled_history_hold_data(hold)?;
        }
        Ok(())
    }

    /// Borrows the defining Hold payload before the aggregate Boot traversal.
    ///
    /// # Errors
    /// Refuses a foreign Control origin or inconsistent actual Hold/evidence edges.
    pub(crate) fn borrowed_settled17_root_hold_data(
        &self,
    ) -> Result<Option<impl Serialize + '_>, ProviderError> {
        self.authenticate_restored_settled_history_edges_data()?;
        Ok(self
            .complete_restored_hold
            .as_ref()
            .map(|hold| hold.borrowed_settled_history_data()))
    }

    /// Records the actual Control identity and complete Hold before Boot edges.
    ///
    /// The later complete Control walk repeats these same actual allocations.
    /// This appends to the aggregate observer without resetting either bank.
    ///
    /// # Errors
    /// Refuses a foreign or inconsistent origin, exhausted banks or overflow.
    pub(crate) fn observe_settled17_root_hold_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_restored_settled_history_edges_data()?;
        observer.shared_original(
            MetadataSharedKind::NativeControlIdentity,
            self.capture_identity.as_ref(),
        )?;
        if let Some(hold) = &self.complete_restored_hold {
            observer.shared_original(
                MetadataSharedKind::NativeRestoredPhysicalHold,
                hold.as_ref(),
            )?;
            hold.observe_settled_history_metadata_data(observer)?;
        }
        Ok(())
    }

    /// Names the additional root-Hold lender and nonresetting observer views.
    pub(crate) fn settled17_root_hold_counter_scratch_data() -> usize {
        field_view_bytes(|value: &'static PacketControl| value.borrowed_settled17_root_hold_data())
            + size_of::<&PacketControl>()
            + size_of::<&mut MetadataObserver<'_>>()
            + size_of::<Option<&Rc<restore_model::PacketCompleteRestorePhysicalHold>>>()
            + size_of::<Result<(), ProviderError>>()
    }

    /// Borrows complete current Control and model owners as inert historical data.
    ///
    /// The owning native Capture scope separately checks currentness and pays
    /// complete output/error/partial demands before constructing any byte bank.
    /// This view preserves failed and incomplete state without opening a gate.
    ///
    /// # Errors
    /// Refuses foreign origin or inconsistent actual Control/evidence/hold edges.
    pub(crate) fn borrowed_restored_settled_history_data(
        &self,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.authenticate_restored_settled_history_edges_data()?;
        Ok(ControlHistory(self, false, None))
    }

    /// Borrows a rooted graph view whose Hold payload is defined by its prelude.
    ///
    /// The complete standalone Control output keeps its original schema and
    /// full Hold. This distinct internal grammar carries the same current fields
    /// and source metadata walk while naming that exact prelude Hold once.
    ///
    /// # Errors
    /// Refuses foreign origin or inconsistent actual Control/evidence/Hold edges.
    pub(crate) fn borrowed_rooted_current17_data(
        &self,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.authenticate_restored_settled_history_edges_data()?;
        Ok(ControlHistory(self, true, None))
    }

    /// Walks every retained child under the caller's nonresetting graph observer.
    ///
    /// # Errors
    /// Refuses foreign or inconsistent edges, busy Boot/Commit evidence loans,
    /// exhausted admitted metadata rows or checked overflow. Mutable Boot/Commit
    /// loans must end before this walk; complete payloads are defined once by
    /// their native17 owners and the evidence records only real shared edges.
    pub(crate) fn observe_restored_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_restored_settled_history_edges_data()?;
        let Self {
            selection,
            program,
            complete_restored_evidence,
            complete_restored_hold,
            restoration_activation_required,
            capture_creator,
            capture_identity,
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
            complete_restore_selection,
            complete_protocol_metadata_limits,
            complete_protocol_metadata_birth_facts,
            complete_restore_input_emitter_selection,
            complete_capture_allocation_selection,
        } = self;
        observer.observe(selection)?;
        match program {
            NativeProgram::OutputOnly(program) => observer.observe(program)?,
            NativeProgram::Connected(program) => observer.observe(program)?,
            NativeProgram::RestorationInProgress => {}
        }
        if let Some(hold) = complete_restored_hold {
            observer.shared_original(
                MetadataSharedKind::NativeRestoredPhysicalHold,
                hold.as_ref(),
            )?;
            hold.observe_settled_history_metadata_data(observer)?;
        }
        if let Some(evidence) = complete_restored_evidence {
            evidence.observe_settled_history_metadata_data(observer)?;
        }
        observer.observe(restoration_activation_required)?;
        observer.observe(capture_creator)?;
        observer.shared_original(
            MetadataSharedKind::NativeControlIdentity,
            capture_identity.as_ref(),
        )?;
        observe_originals(originals, observer)?;
        observer.observe(begins)?;
        observer.observe(begin_requests)?;
        observer.observe(content)?;
        observer.observe(content_bytes)?;
        observer.observe(realized)?;
        observer.observe(admitted)?;
        if let Some((request, reference)) = staged {
            observe_activate(request, observer)?;
            observer.observe(reference)?;
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
            let crate::reference_packet::coordinator::PacketCoordinatorInstallation {
                schema,
                template,
            } = installed;
            observer.observe(schema)?;
            observer.observe(template)?;
        }
        if let Some(installed) = world_coordinator {
            let crate::reference_packet::coordinator::PacketWorldCoordinatorInstallation {
                schema,
                participants,
                template,
            } = installed;
            observer.observe(schema)?;
            observer.observe(participants)?;
            observer.observe(template)?;
        }
        if let Some(installed) = connected_coordinator {
            let crate::reference_packet::coordinator::PacketConnectedCoordinatorInstallation {
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

    /// Reports complete defining model/hold/evidence, borrowed and iterator views.
    pub(crate) fn restored_settled_history_counter_scratch_data() -> usize {
        use crate::reference_packet::service::ack_emitter::NativeRestoredControlEvidence;
        use crate::reference_packet::{PacketProgram, connected::PacketConnectedProgram};
        let terms = [
            size_of::<Self>(),
            size_of::<&Self>(),
            size_of::<ControlHistory<'_>>(),
            size_of::<Result<ControlHistory<'_>, ProviderError>>(),
            size_of::<ProgramHistory<'_>>(),
            size_of::<OriginalsHistory<'_>>(),
            size_of::<ContentHistory<'_>>(),
            size_of::<&mut MetadataObserver<'_>>(),
            size_of::<&Originals>(),
            size_of::<&Content>(),
            size_of::<std::collections::btree_map::Iter<'_, Id, (HashRef, PacketControlReply)>>(),
            size_of::<Option<(&Id, &(HashRef, PacketControlReply))>>(),
            size_of::<(&Id, &HashRef, &PacketControlReply)>(),
            size_of::<(
                &Id,
                &HashRef,
                &Map<String, Value>,
                &Vec<(ContentRef, Vec<u8>)>,
            )>(),
            size_of::<std::collections::btree_map::Iter<'_, ContentRef, Vec<u8>>>(),
            size_of::<Option<(&ContentRef, &Vec<u8>)>>(),
            size_of::<(&ContentRef, &Vec<u8>)>(),
            size_of::<std::slice::Iter<'_, (ContentRef, Vec<u8>)>>(),
            size_of::<Option<&(ContentRef, Vec<u8>)>>(),
            size_of::<Option<&Rc<restore_model::PacketCompleteRestorePhysicalHold>>>(),
            size_of::<Result<&Rc<restore_model::PacketCompleteRestorePhysicalHold>, ProviderError>>(
            ),
            size_of::<Option<&NativeRestoredControlEvidence>>(),
            field_view_bytes(|value: &'static PacketControl| {
                let PacketControl {
                    selection,
                    program,
                    complete_restored_evidence,
                    complete_restored_hold,
                    restoration_activation_required,
                    capture_creator,
                    capture_identity,
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
                    complete_restore_selection,
                    complete_protocol_metadata_limits,
                    complete_protocol_metadata_birth_facts,
                    complete_restore_input_emitter_selection,
                    complete_capture_allocation_selection,
                } = value;
                (
                    selection,
                    program,
                    complete_restored_evidence,
                    complete_restored_hold,
                    restoration_activation_required,
                    capture_creator,
                    capture_identity,
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
                    complete_restore_selection,
                    complete_protocol_metadata_limits,
                    complete_protocol_metadata_birth_facts,
                    complete_restore_input_emitter_selection,
                    complete_capture_allocation_selection,
                )
            }),
            field_view_bytes(|value: &'static PacketControl| {
                value
                    .complete_restored_hold
                    .as_ref()
                    .map(|hold| hold.borrowed_settled_history_data())
            }),
            field_view_bytes(|value: &'static PacketControl| {
                value
                    .complete_restored_evidence
                    .as_ref()
                    .map(|evidence| evidence.borrowed_settled_history_data())
            }),
            continuation::ControlRecord::settled_history_counter_scratch_data(),
            PacketProgram::settled_model_counter_scratch_data(),
            PacketConnectedProgram::settled_model_counter_scratch_data(),
            restore_model::PacketCompleteRestorePhysicalHold::settled_history_counter_scratch_data(
            ),
            NativeRestoredControlEvidence::settled_history_counter_scratch_data(),
            size_of::<Result<(), ProviderError>>(),
        ];
        size_of_val(&terms)
            + size_of::<std::array::IntoIter<usize, 31>>()
            + terms.into_iter().sum::<usize>()
    }
}

impl Serialize for ControlHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .authenticate_restored_settled_history_edges_data()
            .map_err(serde::ser::Error::custom)?;
        let PacketControl {
            selection,
            program,
            complete_restored_evidence,
            complete_restored_hold,
            restoration_activation_required,
            capture_creator,
            capture_identity,
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
            complete_restore_selection,
            complete_protocol_metadata_limits,
            complete_protocol_metadata_birth_facts,
            complete_restore_input_emitter_selection,
            complete_capture_allocation_selection,
        } = self.0;
        let mut state = serializer.serialize_struct("ControlRestoredSettledHistory", 35)?;
        state.serialize_field(
            "schema",
            if self.1 {
                "source-private.native-rooted-control/17"
            } else {
                "source-owned.packet-native-control-restored-settled/17"
            },
        )?;
        state.serialize_field("selection", selection)?;
        state.serialize_field("program", &ProgramHistory(program))?;
        state.serialize_field(
            "complete_restored_evidence",
            &complete_restored_evidence
                .as_ref()
                .map(|evidence| evidence.borrowed_settled_history_data()),
        )?;
        if self.1 {
            state.serialize_field(
                "complete_restored_hold",
                &complete_restored_hold
                    .as_ref()
                    .map(|_| "current-native-control-hold"),
            )?;
        } else {
            state.serialize_field(
                "complete_restored_hold",
                &complete_restored_hold
                    .as_ref()
                    .map(|hold| hold.borrowed_settled_history_data()),
            )?;
        }
        state.serialize_field(
            "restoration_activation_required",
            restoration_activation_required,
        )?;
        state.serialize_field("capture_creator", capture_creator)?;
        let _ = capture_identity;
        state.serialize_field("capture_identity_role", "current-native-control-identity")?;
        if let Some(pending) = &self.2 {
            state.serialize_field("originals", &pending.originals_data(originals))?;
            state.serialize_field("begins", &pending.begins_data(begins))?;
            state.serialize_field(
                "begin_requests",
                &pending.begin_requests_data(begin_requests),
            )?;
        } else {
            state.serialize_field("originals", &OriginalsHistory(originals))?;
            state.serialize_field("begins", begins)?;
            state.serialize_field("begin_requests", begin_requests)?;
        }
        state.serialize_field("content", &ContentHistory(content))?;
        state.serialize_field("content_bytes", content_bytes)?;
        state.serialize_field("realized", realized)?;
        state.serialize_field("admitted", admitted)?;
        state.serialize_field("staged", staged)?;
        state.serialize_field("active", active)?;
        state.serialize_field("fenced", fenced)?;
        state.serialize_field("native_effect_attempted", native_effect_attempted)?;
        state.serialize_field("immediate", immediate)?;
        if let Some(pending) = &self.2 {
            state.serialize_field("current_operation", &Some(pending.operation_data()))?;
        } else {
            state.serialize_field("current_operation", current_operation)?;
        }
        state.serialize_field("terminals", terminals)?;
        state.serialize_field("common_coordinator", common_coordinator)?;
        state.serialize_field("world_coordinator", world_coordinator)?;
        state.serialize_field("connected_coordinator", connected_coordinator)?;
        state.serialize_field("complete_coordinator", complete_coordinator)?;
        state.serialize_field("complete_storage", complete_storage)?;
        state.serialize_field("complete_capture_profile", complete_capture_profile)?;
        state.serialize_field(
            "complete_confirmation_selection",
            complete_confirmation_selection,
        )?;
        state.serialize_field(
            "complete_ack_emitter_selection",
            complete_ack_emitter_selection,
        )?;
        state.serialize_field("complete_restore_selection", complete_restore_selection)?;
        state.serialize_field(
            "complete_protocol_metadata_limits",
            complete_protocol_metadata_limits,
        )?;
        state.serialize_field(
            "complete_protocol_metadata_birth_facts",
            complete_protocol_metadata_birth_facts,
        )?;
        state.serialize_field(
            "complete_restore_input_emitter_selection",
            complete_restore_input_emitter_selection,
        )?;
        state.serialize_field(
            "complete_capture_allocation_selection",
            complete_capture_allocation_selection,
        )?;
        state.end()
    }
}

fn observe_originals(
    originals: &Originals,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    observer.tree::<Id, (HashRef, PacketControlReply)>(originals.len())?;
    for (id, (hash, reply)) in originals {
        observer.observe(id)?;
        observer.observe(hash)?;
        observer.observe(&reply.body)?;
        observer.vector::<(ContentRef, Vec<u8>)>(reply.evidence.capacity())?;
        for (reference, bytes) in &reply.evidence {
            observer.observe(reference)?;
            observer.observe(bytes)?;
        }
    }
    Ok(())
}

const fn field_view_bytes<T: 'static, U>(_: fn(&'static T) -> U) -> usize {
    size_of::<U>()
}

pub(super) fn observe_activate(
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

pub(super) fn observe_world_activate(
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
mod tests {
    use super::*;
    use crate::retained_metadata::records::MetadataRecordBank;

    fn json<T: Serialize>(value: T) -> Result<Value, ProviderError> {
        serde_json::to_value(value)
            .map_err(|_| ProviderError::Correlation("Control17 history DATA serialization"))
    }

    #[test]
    fn actual_nonstring_content_keys_and_spare_bytes_stream_as_complete_pairs()
    -> Result<(), ProviderError> {
        let mut bytes = Vec::with_capacity(37);
        bytes.extend_from_slice(b"abc");
        let reference = canonical::content_ref(&bytes, "application/octet-stream")?;
        let mut content = BTreeMap::new();
        content.insert(reference.clone(), bytes);
        let before_capacity = content.get(&reference).map(Vec::capacity);

        let encoded = json(ContentHistory(&content))?;
        assert_eq!(encoded, serde_json::json!([[reference, [97, 98, 99]]]));
        let mut observer = MetadataObserver::new();
        observer.observe(&content)?;
        let facts = observer.finish();
        assert_eq!(facts.tree_containers, 1);
        assert_eq!(facts.vector_banks, 1);
        assert_eq!(facts.vector_capacity_bytes, before_capacity.unwrap_or(0));
        assert_eq!(content.get(&reference).map(Vec::capacity), before_capacity);
        Ok(())
    }

    #[test]
    fn partial_original_reply_keeps_evidence_capacity_and_short_record_custody()
    -> Result<(), ProviderError> {
        let mut bytes = Vec::with_capacity(37);
        bytes.extend_from_slice(b"abc");
        let reference = canonical::content_ref(&bytes, "application/octet-stream")?;
        let mut evidence = Vec::with_capacity(7);
        evidence.push((reference, bytes));
        let requested =
            evidence.capacity() * size_of::<(ContentRef, Vec<u8>)>() + evidence[0].1.capacity();
        let request = Id::new("history/partial")?;
        let body = Map::new();
        let hash = canonical::json_hash("cnp.request.v1", &body)?;
        let originals = BTreeMap::from([(
            request.clone(),
            (hash.clone(), PacketControlReply { body, evidence }),
        )]);

        let encoded = json(OriginalsHistory(&originals))?;
        assert_eq!(encoded[0][0], json(&request)?);
        assert_eq!(encoded[0][1], json(&hash)?);
        assert_eq!(encoded[0][2], serde_json::json!({}));
        assert_eq!(encoded[0][3][0][1], serde_json::json!([97, 98, 99]));
        let mut observer = MetadataObserver::new();
        observe_originals(&originals, &mut observer)?;
        assert_eq!(observer.finish().vector_capacity_bytes, requested);

        let mut records = MetadataRecordBank::reserve(1)?;
        let capacity = records.capacity_rows();
        let mut observer = MetadataObserver::recording(&mut records);
        assert!(observe_originals(&originals, &mut observer).is_err());
        let _ = observer.finish();
        assert_eq!(records.capacity_rows(), capacity);
        assert_eq!(records.rows().len(), 1);
        assert_eq!(json(OriginalsHistory(&originals))?, encoded);
        Ok(())
    }
}

mod pending_capture17;
use pending_capture17::PendingCapture17Fields;
pub(crate) use pending_capture17::{
    NativePendingCapture17ControlStorageData, NativePendingCapture17RequestHashAttempt,
    NativePendingCapture17RequestHashStorageData,
};
