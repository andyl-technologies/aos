//! Quotes the real stopped Control serializer before snapshot copies exist.
//!
//! Row adapters borrow the actual BTreeMap entries in the same order as
//! capture_control_state. They create neither its temporary row Vecs nor a DOM.
//! The model child is counted from its actual closed serializer independently.

use super::*;
use crate::reference_packet::serialization_storage::{
    NativeControlCaptureEncodingData, actual_serialization_storage_data,
};
use crate::retained_metadata::MetadataObserver;
use serde::ser::SerializeSeq;
use std::mem::size_of;

#[derive(Serialize)]
struct BorrowedControlView<'a> {
    selection: &'a PacketControlSelection,
    originals: OriginalRows<'a>,
    begins: &'a BTreeMap<Id, BeginRequest>,
    begin_requests: &'a BTreeMap<Id, Id>,
    content: ContentRows<'a>,
    content_bytes: usize,
    realized: bool,
    admitted: bool,
    staged: &'a Option<(ActivateRequest, ContentRef)>,
    active: &'a Option<WorldActivateRequest>,
    fenced: bool,
    native_effect_attempted: bool,
    immediate: bool,
    current_operation: &'a Option<Id>,
    terminals: &'a BTreeMap<Id, Map<String, Value>>,
    common_coordinator: &'a Option<super::super::coordinator::PacketCoordinatorInstallation>,
    world_coordinator: &'a Option<super::super::coordinator::PacketWorldCoordinatorInstallation>,
    connected_coordinator:
        &'a Option<super::super::coordinator::PacketConnectedCoordinatorInstallation>,
    complete_coordinator:
        &'a Option<super::super::coordinator::PacketNative5CoordinatorInstallation>,
    complete_storage: &'a Option<super::native5::PacketNative5StorageSelection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    complete_capture_profile: &'a Option<super::super::service::PacketNative5CaptureProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    complete_confirmation_selection:
        &'a Option<super::super::service::PacketNative5ConfirmationSelection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    complete_ack_emitter_selection:
        &'a Option<super::super::service::PacketNative5AckEmitterSelection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    complete_protocol_metadata_limits:
        &'a Option<super::super::service::PacketNative5ProtocolMetadataLimits>,
    #[serde(skip_serializing_if = "Option::is_none")]
    complete_protocol_metadata_birth_facts:
        &'a Option<super::super::service::PacketNative5ProtocolMetadataBirthFacts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    complete_restore_selection:
        &'a Option<super::super::service::complete_restore::PacketNative5CompleteRestoreSelection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    complete_restore_input_emitter_selection: &'a Option<
        super::super::service::complete_restore::PacketNative5RestoreInputEmitterSelection,
    >,
    #[serde(skip_serializing_if = "Option::is_none")]
    complete_capture_allocation_selection: &'a Option<
        super::super::service::capture_allocation::PacketNative5CaptureAllocationSelection,
    >,
}

#[derive(Serialize)]
struct OriginalView<'a> {
    request: &'a Id,
    identity: &'a HashRef,
    response_body: &'a Map<String, Value>,
    evidence: &'a [(ContentRef, Vec<u8>)],
}

struct OriginalRows<'a>(&'a BTreeMap<Id, (HashRef, PacketControlReply)>);

impl Serialize for OriginalRows<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
        for (request, (identity, reply)) in self.0 {
            rows.serialize_element(&OriginalView {
                request,
                identity,
                response_body: &reply.body,
                evidence: &reply.evidence,
            })?;
        }
        rows.end()
    }
}

struct ContentRows<'a>(&'a BTreeMap<ContentRef, Vec<u8>>);

impl Serialize for ContentRows<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
        for (reference, bytes) in self.0 {
            rows.serialize_element(&(reference, bytes.as_slice()))?;
        }
        rows.end()
    }
}

// This shape-only root is never encoded, returned, or used as model evidence.
// The null child's zero dynamic storage is replaced by the actual independently
// measured full model child below. Its four encoded octets are overcounted.
#[derive(Serialize)]
struct SnapshotShape<'a> {
    schema: &'static str,
    captured_process: U64,
    administrative_cut: DecimalPositionBound,
    local_cursor: Position,
    model: (),
    control: BorrowedControlView<'a>,
}

#[derive(Serialize)]
struct DecimalPositionBound {
    time_ps: &'static str,
    microstep: &'static str,
    phase: Phase,
}

impl PacketControl {
    pub(crate) fn quote_original_live_capture_encoding(
        &self,
        maximum: usize,
    ) -> Result<NativeControlCaptureEncodingData, ProviderError> {
        let mut observer = MetadataObserver::new();
        let local_cursor = self.observe_live_capture_children(&mut observer)?;
        let fields = observer.finish();
        let model = match &self.program {
            NativeProgram::OutputOnly(program) => {
                program.quote_original_live_capture_encoding(maximum)?
            }
            NativeProgram::Connected(program) => {
                program.quote_original_live_capture_encoding(maximum)?
            }
            NativeProgram::RestorationInProgress => {
                return Err(ProviderError::Conflict("native Control model incomplete"));
            }
        };
        let control = self.borrowed_capture_control();
        let shape = SnapshotShape {
            schema: if self.complete_capture_allocation_selection.is_some() {
                "source-owned.packet-native-control-state/6"
            } else {
                "source-owned.packet-native-control-state/5"
            },
            captured_process: U64::new(u64::from(std::process::id())),
            // A future administrative cut is not present during Observe. These
            // are the closed decimal/phase extents, not a fabricated Position.
            administrative_cut: DecimalPositionBound {
                time_ps: "18446744073709551615",
                microstep: "18446744073709551615",
                phase: Phase::Reaction,
            },
            local_cursor,
            model: (),
            control,
        };
        let control = actual_serialization_storage_data(&shape, fields, maximum)?;
        let rows = self
            .originals
            .len()
            .checked_mul(size_of::<OriginalView<'_>>())
            .and_then(|bytes| {
                self.content
                    .len()
                    .checked_mul(size_of::<(&ContentRef, &[u8])>())
                    .and_then(|content| bytes.checked_add(content))
            })
            .ok_or(ProviderError::ResourceExhausted(
                "native Control serializer row slots",
            ))?;
        NativeControlCaptureEncodingData::from_original_parts(
            model,
            control,
            rows,
            self.content.len(),
            maximum,
        )
    }
}

impl PacketControl {
    fn borrowed_capture_control(&self) -> BorrowedControlView<'_> {
        BorrowedControlView {
            selection: &self.selection,
            originals: OriginalRows(&self.originals),
            begins: &self.begins,
            begin_requests: &self.begin_requests,
            content: ContentRows(&self.content),
            content_bytes: self.content_bytes,
            realized: self.realized,
            admitted: self.admitted,
            staged: &self.staged,
            active: &self.active,
            fenced: self.fenced,
            native_effect_attempted: self.native_effect_attempted,
            immediate: self.immediate,
            current_operation: &self.current_operation,
            terminals: &self.terminals,
            common_coordinator: &self.common_coordinator,
            world_coordinator: &self.world_coordinator,
            connected_coordinator: &self.connected_coordinator,
            complete_coordinator: &self.complete_coordinator,
            complete_storage: &self.complete_storage,
            complete_capture_profile: &self.complete_capture_profile,
            complete_confirmation_selection: &self.complete_confirmation_selection,
            complete_ack_emitter_selection: &self.complete_ack_emitter_selection,
            complete_protocol_metadata_limits: &self.complete_protocol_metadata_limits,
            complete_protocol_metadata_birth_facts: &self.complete_protocol_metadata_birth_facts,
            complete_restore_selection: &self.complete_restore_selection,
            complete_restore_input_emitter_selection: &self
                .complete_restore_input_emitter_selection,
            complete_capture_allocation_selection: &self.complete_capture_allocation_selection,
        }
    }

    // The actual selected producer uses the same row ordering and skipped
    // fields as the prospective counter, without collecting row-reference Vecs.
    pub(super) fn borrowed_capture_control_data(&self) -> impl Serialize + '_ {
        self.borrowed_capture_control()
    }
}
