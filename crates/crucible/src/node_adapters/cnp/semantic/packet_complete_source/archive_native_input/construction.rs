//! Quotes the original archived native predicates from their actual operands.
//!
//! Defining parser and Control lease formulas are shared with their callers.
//! These DATA walks perform no decode, model transition or authority issuance.

use super::*;
use crucible_node_provider::reference_packet::control::{
    PacketNative5Record, packet_control_snapshot_validation_layouts,
};

// Mirrors the actual immutable content dictionary's borrowed values iterator.
type ContentObject = (ContentRef, std::rc::Rc<Vec<u8>>);

impl NativeInputData<'_> {
    /// Quotes the existing complete typed-object lease without constructing it.
    ///
    /// # Errors
    /// Refuses the defining record limit, malformed syntax or checked layout excess.
    pub(super) fn object_construction_requested_data(
        &self,
        bytes: &[u8],
    ) -> Result<usize, OperationFailure> {
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
        Ok(demand)
    }

    /// Quotes the existing original-request/reply decoder lease.
    ///
    /// # Errors
    /// Refuses the defining serializer walk or checked requested-layout overflow.
    pub(super) fn envelope_construction_requested_data(
        &self,
        envelope: &Envelope,
    ) -> Result<usize, OperationFailure> {
        let bytes = NodeRuntime::capture_future_decode_storage(envelope, self.maximum)
            .map_err(unknown)?
            .checked_mul(8)
            .and_then(|n| n.checked_add(size_of::<InputRequest>() + size_of::<Event>() * 4))
            .ok_or_else(|| refused("cold original decoder scratch overflow"))?;
        Ok(bytes)
    }

    /// Quotes the existing complete Control/model lease from its actual body.
    ///
    /// # Errors
    /// Refuses a missing body, the selected encoded bound or defining layout excess.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn control_construction_requested_data<
        'a,
    >(
        &'a self,
        reference: &ContentRef,
    ) -> Result<(&'a [u8], usize, usize), OperationFailure> {
        let bytes = self
            .content
            .get(reference)
            .ok_or_else(|| refused("cold complete Control body absent"))?;
        let selected = self.selection.storage_data()?;
        let (demand, maximum) =
            PacketCompleteSemanticSource::original_control_snapshot_construction_data(
                bytes,
                selected.storage.control_snapshot_bytes,
                self.maximum,
            )?;
        Ok((bytes, demand, maximum))
    }
}

impl NativeInputData<'_> {
    /// Quotes the complete existing native predicates from the same inert owners.
    ///
    /// The caller separately funds the ordinary formatter and dictionary-hash floor and
    /// this helper's fixed controls before entering. No typed body is decoded.
    /// Each real constructor frame below has an independent temporary window;
    /// summing sequential alternatives deliberately earns no overlap refund.
    ///
    /// # Errors
    /// Refuses another archived selection, absent Control, arithmetic overflow
    /// or a complete independently summed phase above the unchanged ceiling.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn original_semantic_validation_construction_data(
        &self,
        semantics: &PacketCompleteArchivedSemantics,
        journal: &PacketCompleteSettledJournal,
    ) -> Result<(usize, usize), OperationFailure> {
        self.selection.authenticate_origin_data()?;
        let mut object_peak = 0usize;
        let mut reference_peak = 0usize;
        for reference in self.host.custody.content.references() {
            reference_peak = reference_peak
                .max(NodeRuntime::capture_reference_storage(reference).map_err(unknown)?);
            let bytes = self.host.custody.content.get(reference).map_err(unknown)?;
            // This dictionary also contains arbitrary application payloads. A
            // body rejected by the defining prospective parser cannot reach an
            // object constructor. It is not accepted as a native proof here;
            // the later actual reference/schema predicates remain mandatory.
            if let Ok(demand) = self.object_construction_requested_data(bytes) {
                object_peak = object_peak.max(demand);
            }
        }
        let mut envelope_peak = 0usize;
        for original in self.host.custody.controller.values() {
            envelope_peak =
                envelope_peak.max(self.envelope_construction_requested_data(&original.request)?);
            if let Some(response) = &original.response {
                envelope_peak =
                    envelope_peak.max(self.envelope_construction_requested_data(response)?);
            }
        }
        // object() has eight owning call sites in this nonrecursive call graph.
        // A loop drops its previous object before visiting the next original.
        // Naming every site also covers alternatives that cannot coexist.
        let objects = ObjectFrames {
            ancestry_stage: object_peak,
            common_stage: object_peak,
            common_commit: object_peak,
            input_receipt: object_peak,
            input_custody: object_peak,
            delivery_inventory: object_peak,
            native_wrapper: object_peak,
            native_record: object_peak,
        };
        // input_request may be retained by input() while stage()/commit() owns
        // its separate request. The other named charge sites are nonrecursive.
        let envelopes = EnvelopeFrames {
            outer_input_request: envelope_peak,
            nested_input_request: envelope_peak,
            prior_activation: envelope_peak,
            input_response: envelope_peak,
            retirement_request: envelope_peak,
            retirement_response: envelope_peak,
            population_retire: envelope_peak,
            population_begin: envelope_peak,
            root_original: envelope_peak,
            root_response: envelope_peak,
            root_poll_request: envelope_peak,
        };
        let (_, control, _) = self.control_construction_requested_data(&journal.native_control)?;
        let common = semantics.source_common_data();
        // Expected PacketInputCut, verified batch and complete delivery keys are
        // cloned from these actual operands even on a changed-record refusal.
        // Their independent owning DOM/typed-string windows are larger than
        // any one cloned child and do not borrow the immutable owner's credit.
        let common_expected =
            NodeRuntime::capture_serialization_storage(common, self.maximum).map_err(unknown)?;
        let selection_expected =
            NodeRuntime::capture_serialization_storage(self.selection(), self.maximum)
                .map_err(unknown)?;
        let node_expected =
            NodeRuntime::capture_serialization_storage(&self.host.node, self.maximum)
                .map_err(unknown)?;
        let owner_expected =
            NodeRuntime::capture_serialization_storage(&self.host.execution_owner, self.maximum)
                .map_err(unknown)?;
        let consumption = self.consumption_projection_construction_data(semantics)?;
        let hash = "blake3-256".len() + 64 + "source-owned.packet-connected-inventory/4".len();
        let mut total = 20usize + 256;
        for bytes in [
            objects.total_data()?,
            envelopes.total_data()?,
            control,
            common_expected,
            selection_expected,
            node_expected,
            owner_expected,
            consumption,
            reference_peak,
            reference_peak,
            hash,
        ] {
            total = total
                .checked_add(bytes)
                .filter(|total| *total <= self.maximum)
                .ok_or_else(|| {
                    refused("initial15 native semantic construction exceeds its ceiling")
                })?;
        }
        Ok((
            total,
            Self::semantic_validation_construction_counter_scratch_data(),
        ))
    }

    /// Names dictionary get's actual hash strings beside ordinary formatting.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) const fn semantic_validation_quote_transient_data()
    -> usize {
        20 + "blake3-256".len() + "cnp.blob.v1".len() + 64
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn semantic_validation_construction_counter_scratch_data()
    -> usize {
        Self::counter_scratch_data()
            + size_of::<ObjectFrames>()
            + size_of::<EnvelopeFrames>()
            + size_of::<[usize; 12]>()
            + size_of::<std::array::IntoIter<usize, 12>>()
            + size_of::<Result<(usize, usize), OperationFailure>>()
            + size_of::<Result<usize, OperationFailure>>()
            + size_of::<PacketNative5Record>()
            + size_of::<crucible_node_provider::reference_packet::control::PacketControlSnapshotValidationLayouts>()
            + size_of::<std::collections::btree_map::Values<'static, Id, ClientOriginal>>()
            + size_of::<std::collections::btree_map::Values<'static, String, ContentObject>>()
            + size_of::<Option<&'static Envelope>>()
            + size_of::<Result<&'static [u8], crucible_node_provider::ProviderError>>()
            + size_of::<Result<usize, crate::node_contract::RuntimeError>>()
            + size_of::<std::slice::Iter<'static, Id>>()
            + NodeRuntime::capture_serialization_counter_scratch_data()
    }
}

struct ObjectFrames {
    ancestry_stage: usize,
    common_stage: usize,
    common_commit: usize,
    input_receipt: usize,
    input_custody: usize,
    delivery_inventory: usize,
    native_wrapper: usize,
    native_record: usize,
}

impl ObjectFrames {
    fn total_data(self) -> Result<usize, OperationFailure> {
        let Self {
            ancestry_stage,
            common_stage,
            common_commit,
            input_receipt,
            input_custody,
            delivery_inventory,
            native_wrapper,
            native_record,
        } = self;
        sum_data([
            ancestry_stage,
            common_stage,
            common_commit,
            input_receipt,
            input_custody,
            delivery_inventory,
            native_wrapper,
            native_record,
        ])
    }
}

struct EnvelopeFrames {
    outer_input_request: usize,
    nested_input_request: usize,
    prior_activation: usize,
    input_response: usize,
    retirement_request: usize,
    retirement_response: usize,
    population_retire: usize,
    population_begin: usize,
    root_original: usize,
    root_response: usize,
    root_poll_request: usize,
}

impl EnvelopeFrames {
    fn total_data(self) -> Result<usize, OperationFailure> {
        let Self {
            outer_input_request,
            nested_input_request,
            prior_activation,
            input_response,
            retirement_request,
            retirement_response,
            population_retire,
            population_begin,
            root_original,
            root_response,
            root_poll_request,
        } = self;
        sum_data([
            outer_input_request,
            nested_input_request,
            prior_activation,
            input_response,
            retirement_request,
            retirement_response,
            population_retire,
            population_begin,
            root_original,
            root_response,
            root_poll_request,
        ])
    }
}

fn sum_data<const N: usize>(values: [usize; N]) -> Result<usize, OperationFailure> {
    values.into_iter().try_fold(0usize, |bytes, value| {
        bytes
            .checked_add(value)
            .ok_or_else(|| refused("initial15 native semantic frame overflow"))
    })
}

impl PacketCompleteSemanticSource {
    /// Quotes the defining existing Control parser from the actual immutable body.
    ///
    /// The caller binds the selected control bound to its genuine code template.
    /// This pure helper supplies requested layout only, never model provenance,
    /// a native grant, a fresh Source or startup credit.
    ///
    /// # Errors
    /// Refuses the unchanged original Control bound, malformed syntax, checked
    /// geometry overflow or the caller's independent requested ceiling.
    pub(crate) fn original_control_snapshot_construction_data(
        bytes: &[u8],
        selected_control_bytes: U64,
        maximum_requested: usize,
    ) -> Result<(usize, usize), OperationFailure> {
        let layouts = packet_control_snapshot_validation_layouts();
        let maximum = usize::try_from(selected_control_bytes.get())
            .map_err(|_| refused("cold Control selected bound is not representable"))?
            .min(layouts.maximum_control_bytes);
        if bytes.len() > maximum {
            return Err(refused(
                "cold complete Control exceeds original selected bound",
            ));
        }
        // One conservative pinned node for every possible typed entry/container
        // covers the actual private map K/V layouts and alignments. The scanner
        // counts the actual raw syntax, including empty containers, before DOM.
        let node = NodeRuntime::capture_protocol_tree_storage(
            1,
            0,
            layouts.maximum_tree_key_value_bytes,
            layouts.maximum_tree_entry_alignment,
            maximum_requested,
        )
        .map_err(unknown)?;
        let one = NodeRuntime::capture_selected_json_decode_storage(
            bytes,
            layouts.maximum_typed_slot_bytes,
            node,
            maximum_requested,
        )
        .map_err(unknown)?;
        let projections = layouts
            .maximum_simultaneous_control_dom_views
            .checked_add(layouts.maximum_simultaneous_typed_model_views)
            .ok_or_else(|| refused("cold model projection count overflow"))?;
        let encoded = bytes
            .len()
            .checked_mul(4)
            .and_then(|n| n.checked_add(8))
            .and_then(|n| n.checked_mul(layouts.maximum_simultaneous_control_encoded_banks))
            .ok_or_else(|| refused("cold model canonical bank extent overflow"))?;
        let demand = one
            .checked_mul(projections)
            .and_then(|n| n.checked_add(encoded))
            .and_then(|n| n.checked_add(layouts.control_record_bytes))
            .and_then(|n| n.checked_add(layouts.model_record_bytes))
            .and_then(|n| {
                n.checked_add(
                    layouts
                        .producer_state_bytes
                        .max(layouts.reactive_state_bytes),
                )
            })
            .ok_or_else(|| refused("cold model decoder storage overflow"))?;
        Ok((demand, maximum))
    }

    /// Names the existing defining Control quotation and layout controls.
    pub(crate) fn original_control_snapshot_construction_counter_scratch_data() -> usize {
        NativeInputData::semantic_validation_construction_counter_scratch_data()
    }
}

#[path = "construction/complete_control.rs"]
mod complete_control;
