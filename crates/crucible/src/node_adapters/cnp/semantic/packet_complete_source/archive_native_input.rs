//! Joins cold common input custody to exact native staged and consumed records.
//!
//! These predicates read the same complete host owner and authenticated archive
//! closure retained by the cold holder. They do not construct a live scope,
//! native process, input permission, Core ticket or fresh registration.

use super::archive_semantics::{PacketCompleteArchivedSemantics, data::*};
use super::*;
use crate::node_state::VerifiedStateContent;
use crucible_node_provider::{
    client::ClientOriginal,
    envelope::{Envelope, Method},
    protocol_snapshot::owned11::{
        native::outer::HistoricalNativeState, outer::HistoricalControllerState,
    },
    reference_packet::{
        connected::{PacketCommitRecord, PacketStageRecord},
        control::PacketControlSelection,
        input::{PacketInputContext, PacketInputCut},
    },
};
use serde::{Serialize, de::DeserializeOwned};
use std::{cell::Cell, mem::size_of, ops::Deref};

#[path = "archive_native_input/input.rs"]
mod input;
#[cfg(test)]
#[path = "archive_native_input/population_tests.rs"]
mod population_tests;
#[path = "archive_native_input/projection.rs"]
mod projection;

#[path = "archive_native_input/selection.rs"]
mod selection;
pub(super) use selection::NativeInputSelection;

use super::archive_owner::ArchivedContentData;

const MAXIMUM_RECORD_BYTES: usize = 65_536;

/// Borrows actual archive owners while charging transient data comparisons.
pub(super) struct NativeInputData<'a> {
    pub(super) selection: NativeInputSelection<'a>,
    pub(super) host: &'a HistoricalControllerState,
    pub(super) native: &'a HistoricalNativeState,
    pub(super) content: ArchivedContentData<'a>,
    pub(super) retained: usize,
    pub(super) maximum: usize,
    pub(super) scratch: Cell<usize>,
    pub(super) construction:
        Option<&'a super::archive_semantics::construction_storage::ValidationConstructionCounter>,
}

impl PacketCompleteSemanticSource {
    /// Checks complete staged, acknowledged and consumed historical input cuts.
    ///
    /// Every first ancestry cut is checked independently of current common
    /// custody. Publication object references are resolved through the same
    /// authenticated Core closure; reference-only ancestry never creates a leaf
    /// exemption for a missing body. Runtime and full native scheduling checks
    /// remain separate mandatory factory predicates.
    ///
    /// # Errors
    /// Refuses another source allocation, incomplete cold owners, old inline
    /// ancestry on the complete route, changed native records or custody
    /// receipts, missing original bodies and exhausted comparison storage.
    pub fn authenticate_archived_native_input_data(
        &self,
        cold: &PacketCompleteArchivedOwnerData<'_>,
        semantics: &PacketCompleteArchivedSemantics,
        additional_retained_bytes: usize,
        maximum_total_bytes: usize,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        let content = cold.source_content_data(self)?;
        let retained = additional_retained_bytes
            .checked_add(cold.known_requested_bytes()?)
            .and_then(|n| n.checked_add(20 + 256))
            .filter(|n| *n <= maximum_total_bytes)
            .ok_or_else(|| refused("cold native input aggregate storage exhausted"))?;
        let data = NativeInputData {
            selection: NativeInputSelection::Live(self),
            host: cold.host()?,
            native: cold.native_after()?,
            content: ArchivedContentData::Verified(content),
            retained,
            maximum: maximum_total_bytes,
            scratch: Cell::new(0),
            construction: None,
        };
        data.host.require_complete_reader_state().map_err(unknown)?;
        self.authenticate_original_native_input_history_data(&data, semantics)
    }

    // The same concrete predicates serve both the original archive validator
    // and the genuinely retained grouped-cold view. Neither path invents input
    // ACKs or projects Runtime7 IDs into native knowledge.
    pub(super) fn authenticate_original_native_input_history_data(
        &self,
        data: &NativeInputData<'_>,
        semantics: &PacketCompleteArchivedSemantics,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        data.selection.authenticate_same_source_data(self)?;
        data.authenticate_input_history_data(semantics)?;
        data.selection.authenticate_same_source_data(self)?;
        self.ensure_origin()
    }
}

impl NativeInputData<'_> {
    /// Checks the complete native Input population using its original DATA selection.
    pub(super) fn authenticate_input_history_data(
        &self,
        semantics: &PacketCompleteArchivedSemantics,
    ) -> Result<(), OperationFailure> {
        self.selection.authenticate_origin_data()?;
        let state = semantics.source_common_data();
        self.input_population(state)?;
        if state.inputs.is_empty() && self.selection.reactive_definition_data()?.is_none() {
            if !semantics
                .source_reference_ancestry_data()?
                .lineages
                .is_empty()
            {
                return Err(refused("producer invented original input ancestry"));
            }
            return Ok(());
        }
        if self.selection.reactive_definition_data()?.is_none() {
            return Err(refused("producer invented input custody"));
        }
        for input in state.inputs.values() {
            self.input(input)?;
        }
        for lineage in &semantics.source_reference_ancestry_data()?.lineages {
            self.original_batch(&lineage.original)?;
            let staged = self.find_stage(&lineage.original)?;
            self.stage(&staged, &lineage.original)?;
            for publication in &lineage.publications {
                for reference in &publication.objects {
                    reference
                        .verify(
                            self.content.get(reference).ok_or_else(|| {
                                refused("reference ancestry full object body absent")
                            })?,
                        )
                        .map_err(unknown)?;
                }
            }
        }
        self.selection.authenticate_origin_data()
    }

    fn observe_construction(&self, scratch: usize) -> Result<(), OperationFailure> {
        if let Some(counter) = self.construction {
            counter.observe(self.retained, scratch)?;
        }
        Ok(())
    }

    pub(super) fn counter_scratch_data() -> usize {
        // These are actual simultaneous typed/result/lease headers, distinct
        // from the per-node heap geometry and the immutable input byte banks.
        use crucible_node_provider::reference_packet::{
            continuation_models::PacketModelCaptureBoundaryData,
            control::{
                PacketDecodedControlSnapshot, PacketNative5Record, PacketNative5UnderlyingRecord,
            },
        };
        size_of::<Self>()
            + size_of::<[NativeScratch<'_>; 3]>()
            + size_of::<[NativeObject<'_, PacketStageRecord>; 2]>()
            + size_of::<NativeObject<'_, PacketCommitRecord>>()
            + size_of::<NativeObject<'_, InputRequest>>()
            + size_of::<NativeObject<'_, InputResult>>()
            + size_of::<NativeObject<'_, WorldActivateRequest>>()
            + size_of::<NativeObject<'_, ControlReceipt>>()
            + size_of::<NativeObject<'_, InputCustodyRecord>>()
            + size_of::<NativeObject<'_, Vec<crate::node_scheduling::event::Delivery>>>()
            + size_of::<NativeObject<'_, ContentRef>>()
            + size_of::<NativeObject<'_, PacketDecodedControlSnapshot>>()
            + size_of::<NativeObject<'_, PacketNative5Record>>()
            + size_of::<NativeObject<'_, PacketNative5UnderlyingRecord>>()
            + size_of::<NativeObject<'_, serde_json::Value>>()
            + size_of::<Result<NativeObject<'_, PacketDecodedControlSnapshot>, OperationFailure>>()
            + size_of::<Result<NativeObject<'_, PacketNative5UnderlyingRecord>, OperationFailure>>()
            + size_of::<Result<PacketModelCaptureBoundaryData, OperationFailure>>()
            + NodeRuntime::capture_selected_json_decode_counter_scratch_data()
            + NodeRuntime::capture_serialization_counter_scratch_data()
    }

    fn selection(&self) -> &PacketControlSelection {
        &self.native.connection.policy.selection
    }

    fn pid(&self) -> u32 {
        self.native.service.endpoint_boot.creator
    }

    fn body(&self, reference: &ContentRef) -> Result<&[u8], OperationFailure> {
        let bytes = self.host.custody.content.get(reference).map_err(unknown)?;
        reference.verify(bytes).map_err(unknown)?;
        if let Some(archived) = self.content.get(reference)
            && archived != bytes
        {
            return Err(refused(
                "native input body differs from full archive object",
            ));
        }
        Ok(bytes)
    }

    fn object<T: DeserializeOwned + Serialize>(
        &self,
        reference: &ContentRef,
    ) -> Result<NativeObject<'_, T>, OperationFailure> {
        let bytes = self.body(reference)?;
        if bytes.len() > MAXIMUM_RECORD_BYTES {
            return Err(refused("cold native input record exceeds source bound"));
        }
        // Three complete records can coexist: receipt/commit/stage, plus their
        // parser and roundtrip Value owners. The per-node layout also covers
        // small typed vectors and the full request envelopes inside each record.
        let slot = [
            size_of::<PacketStageRecord>(),
            size_of::<PacketCommitRecord>(),
            size_of::<InputCustodyRecord>(),
            size_of::<ControlReceipt>(),
            size_of::<Envelope>(),
            size_of::<PacketInputCut>(),
            size_of::<Event>(),
            size_of::<crate::node_scheduling::event::Delivery>(),
            size_of::<serde_json::Value>(),
        ]
        .into_iter()
        .max()
        .ok_or_else(|| refused("cold native input layout absent"))?
        .max(crucible_node_provider::reference_packet::control::packet_control_snapshot_validation_layouts().maximum_typed_slot_bytes);
        let demand = NodeRuntime::capture_selected_json_decode_storage(
            bytes,
            slot,
            NodeRuntime::capture_map_node_storage::<String, serde_json::Value>(),
            self.maximum,
        )
        .map_err(unknown)?;
        // The lease remains with the typed object, so nested Stage/Commit and
        // receipt decoders add their simultaneous demand rather than reusing a
        // per-call ceiling. Four copies cover typed/DOM/roundtrip and the bounded
        // request/canonical comparison temporaries of this closed grammar.
        let demand = demand
            .checked_mul(4)
            .ok_or_else(|| refused("cold native input parser storage overflow"))?;
        let scratch = self
            .scratch
            .get()
            .checked_add(demand)
            .ok_or_else(|| refused("cold native input scratch overflow"))?;
        self.retained
            .checked_add(scratch)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| refused("cold native input transient storage exhausted"))?;
        self.observe_construction(scratch)?;
        self.scratch.set(scratch);
        let charge = NativeScratch {
            total: &self.scratch,
            bytes: demand,
        };
        let value = canonical::parse_json(bytes, MAXIMUM_RECORD_BYTES).map_err(unknown)?;
        if canonical::canonical_json(&value).map_err(unknown)? != bytes {
            return Err(refused("cold native input body is noncanonical"));
        }
        let typed = strict_typed_record(&value)?;
        Ok(NativeObject {
            value: typed,
            _charge: charge,
        })
    }

    fn original(&self, envelope: &Envelope) -> Result<&ClientOriginal, OperationFailure> {
        let id = envelope
            .request_id
            .0
            .as_ref()
            .ok_or_else(|| refused("cold native original request id absent"))?;
        let original = self
            .host
            .custody
            .controller
            .get(id)
            .ok_or_else(|| refused("cold native original request absent"))?;
        if &original.request != envelope {
            return Err(refused("cold native original full envelope differs"));
        }
        Ok(original)
    }

    fn charge_envelope(&self, envelope: &Envelope) -> Result<NativeScratch<'_>, OperationFailure> {
        // This walk observes the retained full Value, before request/response
        // decoding clones any nested fields. Closed packet inputs additionally
        // cap their event population before typed decoding.
        let bytes = NodeRuntime::capture_future_decode_storage(envelope, self.maximum)
            .map_err(unknown)?
            .checked_mul(8)
            .and_then(|n| n.checked_add(size_of::<InputRequest>() + size_of::<Event>() * 4))
            .ok_or_else(|| refused("cold original decoder scratch overflow"))?;
        let scratch = self
            .scratch
            .get()
            .checked_add(bytes)
            .ok_or_else(|| refused("cold original simultaneous scratch overflow"))?;
        self.retained
            .checked_add(scratch)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| refused("cold original decoder storage exhausted"))?;
        self.observe_construction(scratch)?;
        self.scratch.set(scratch);
        Ok(NativeScratch {
            total: &self.scratch,
            bytes,
        })
    }

    fn input_request(
        &self,
        envelope: &Envelope,
    ) -> Result<NativeObject<'_, InputRequest>, OperationFailure> {
        self.original(envelope)?;
        if envelope
            .body
            .get("events")
            .and_then(serde_json::Value::as_array)
            .is_none_or(|events| events.len() > 4)
        {
            return Err(refused("cold Input event population is not bounded"));
        }
        let charge = self.charge_envelope(envelope)?;
        match decode_request(envelope.method, &envelope.body).map_err(unknown)? {
            RequestBody::Input(request) => Ok(NativeObject {
                value: request,
                _charge: charge,
            }),
            _ => Err(refused("cold native original is not Input")),
        }
    }

    fn activation_before(
        &self,
        before: U64,
    ) -> Result<NativeObject<'_, WorldActivateRequest>, OperationFailure> {
        let mut active = None;
        for original in self.host.custody.controller.values() {
            if original.request.method != Method::WorldActivate
                || original.request.sequence >= before
            {
                continue;
            }
            let charge = self.charge_envelope(&original.request)?;
            let RequestBody::WorldActivate(request) =
                decode_request(original.request.method, &original.request.body).map_err(unknown)?
            else {
                return Err(refused("cold native activation method changed"));
            };
            if active.is_some() || original.response.is_none() {
                return Err(refused("cold native activation absent or renewed"));
            }
            active = Some(NativeObject {
                value: request,
                _charge: charge,
            });
        }
        active.ok_or_else(|| refused("cold native input precedes original activation"))
    }
}

// A data-only parser lease keeps all simultaneously retained native records in
// the checked comparison budget, including nested error paths.
struct NativeScratch<'a> {
    total: &'a Cell<usize>,
    bytes: usize,
}

impl Drop for NativeScratch<'_> {
    fn drop(&mut self) {
        self.total.set(self.total.get().saturating_sub(self.bytes));
    }
}

struct NativeObject<'a, T> {
    value: T,
    _charge: NativeScratch<'a>,
}

impl<T> Deref for NativeObject<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

fn strict_typed_record<T: DeserializeOwned + Serialize>(
    value: &serde_json::Value,
) -> Result<T, OperationFailure> {
    let typed = T::deserialize(value).map_err(unknown)?;
    if serde_json::to_value(&typed).map_err(unknown)? != *value {
        return Err(refused("cold native typed record loses original fields"));
    }
    Ok(typed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod correspondence_tests {
    use super::*;

    #[test]
    fn native_event_nullable_field_is_preserved_or_refused() {
        let endpoint = Endpoint {
            node_id: Id::new("node").unwrap(),
            port_id: Id::new("port").unwrap(),
            lane_id: Id::new("lane").unwrap(),
        };
        let reference =
            canonical::content_ref(b"original bytes", "application/octet-stream").unwrap();
        let event = Event {
            schema_version: 1,
            id: Id::new("event").unwrap(),
            source: endpoint.clone(),
            destination: endpoint,
            source_sequence: U64::new(1),
            provenance_ref: reference.clone(),
            causal_parent_ids: Vec::new(),
            stage: EventStage::Delivery,
            position: Position::new(U64::new(3), U64::new(0), Phase::Delivery),
            publication_position: Position::new(U64::new(1), U64::new(1), Phase::Publication),
            delivery_position: None,
            payload: reference,
            extensions: Extensions::new(),
        };
        let mut value = serde_json::to_value(&event).unwrap();
        assert_eq!(strict_typed_record::<Event>(&value).unwrap(), event);
        value.as_object_mut().unwrap().remove("delivery_position");
        assert!(strict_typed_record::<Event>(&value).is_err());
    }
}
