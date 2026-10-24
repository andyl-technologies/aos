//! Prices selected Observe17 SDK assignment, terminal and failure owners.
//!
//! The causal provider Blob receiver has its own independent row. This component
//! prices the initiating controller original, its exact protocol DTO phases and
//! the whole terminating frame, including an error or a rejected roster. The
//! original literal byte/descriptor bank is already completely allocated before
//! child creation and appended without allocation; its current census remains
//! charged independently and supplies no credit to these new owners.

use super::*;
use crate::reference_packet::service::restored_input_reactive17::{
    MAXIMUM_RESTORED_INPUT_REACTIVE17_ARTIFACT_BYTES, PacketRestoredInputReactive17Artifact,
    PacketRestoredInputReactive17Context, PacketRestoredInputReactive17Request,
    observation_geometry::{Observation17OriginalData, PacketRestoredObservation17ProspectiveData},
};
use crate::retained_metadata::requested_storage::tree_storage_data;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
    original_json_value_storage_extent_data,
};
use std::mem::{align_of, size_of};

/// Keeps independently priced SDK axes as inert construction DATA.
///
/// This counts new backing only. The defining Source retains its SDK attempt
/// inline in its own priced history slot and separately owns this result header.
pub struct OriginalRestoredObservation17AssignmentStorageData {
    retained: usize,
    transient: usize,
    scratch: usize,
}

impl OriginalRestoredObservation17AssignmentStorageData {
    /// Returns newly retained SDK backing independently of existing census.
    pub fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }

    /// Returns the independently priced simultaneous SDK work allowance.
    pub fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }

    /// Returns the defining explicit counters and borrowed control views.
    pub fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("selected Observe17 SDK assignment and terminal storage")
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |total, term| {
        total.checked_add(*term).ok_or_else(exhausted)
    })
}

fn multiply(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(exhausted)
}

fn observe_body(
    value: &ObserveRequest,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut out = Projection::new(maximum)?;
    out.add_object()?;
    for name in [
        "binding_hash",
        "owner_generation",
        "after_observation_sequence",
        "maximum_items",
        "extensions",
    ] {
        out.add_field(name)?;
    }
    out.add_value(&value.binding_hash)?;
    for value in [
        value.owner_generation,
        value.after_observation_sequence,
        value.maximum_items,
    ] {
        let digits = value.get().checked_ilog10().unwrap_or(0) as usize + 1;
        out.add_unescaped_ascii_extent(digits)?;
    }
    if !value.extensions.is_empty() {
        return Err(exhausted());
    }
    out.add_object()?;
    out.finish(maximum)
}

// Any balanced BTree internal node has at least two children, so a retained
// n-entry map's height is at most floor(log2(n+1)). One insertion can split at
// most one node per level and allocate one new root. Each new node is charged
// at the defining pinned maximum internal-node layout, without spare credit.
fn insertion_node_bound(entries: usize) -> Result<usize, ProviderError> {
    let values = entries.checked_add(1).ok_or_else(exhausted)?;
    let height = values.checked_ilog2().unwrap_or(0) as usize;
    height.checked_add(2).ok_or_else(exhausted)
}

impl CnpController {
    /// Names this exact SDK quote's fixed visitors before construction begins.
    ///
    /// The Source can independently admit these actual borrowed layouts before
    /// walking prospective fields. This includes the same assignment and raw
    /// receiver controls that the returned storage row records, without lending
    /// currentness, allocation permission or credit from another protocol phase.
    pub fn original_restored_observation17_assignment_counter_scratch_data(&self) -> usize {
        let originals = self
            .custody
            .originals_by_origin(crate::envelope::RequestOrigin::Controller);
        counter_scratch_data()
            + std::mem::size_of_val(&originals)
            + self
                .session
                .original_restored_observation17_response_counter_scratch_data()
            + crate::reference_packet::service::restored_input_reactive17::observation_geometry::prospective_counter_scratch_data()
    }

    /// Quotes this exact actual idle SDK assignment and bounded terminal path.
    ///
    /// Scope and baseline body are compared against the actual private first
    /// Complete slot, while the new sequence must be the real idle frontier.
    /// Current model/native authority remains a separate Source/Window duty.
    /// No DTO, frame, reference, grant or operational cut is constructed here.
    ///
    /// # Errors
    /// Refuses another emitter/body/scope, incomplete first custody, busy or stale
    /// current SDK frontier, excessive complete wire extents or a short bound.
    pub fn original_restored_observation17_assignment_storage_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        prospective: &PacketRestoredObservation17ProspectiveData<'_>,
        maximum: usize,
    ) -> Result<OriginalRestoredObservation17AssignmentStorageData, ProviderError> {
        emitter.authenticate_original(self)?;
        self.authenticate_native5_source_codec()?;
        crate::reference_packet::service::restored_input_reactive17::authenticate_restored_input_reactive17_selection_data(self.session.fresh_restore_query_selection()?, self.authority())?;
        self.session
            .ensure_original_observation_receiver_idle_data()?;
        let first = self.original_completed_installed_restoration_observation(emitter)?;
        let first_frontier = first.completed_frontier_data();
        let first = self.original_completed_restoration_checkpoint17_cache_data(
            emitter,
            first_frontier,
            false,
        )?;
        if prospective.scope != &first.request_data().scope
            || prospective.observe != first.body_data()
            || prospective.frontier != self.session.fresh_restore_query_sequence()?
        {
            return Err(refused());
        }
        let frame = self.maximum_frame()?;
        let mut out = Projection::new(maximum)?;
        Observation17OriginalData::Prospective(prospective).project(&mut out)?;
        let original = out.finish(maximum)?;
        let body = observe_body(prospective.observe, maximum)?;
        let mut out = Projection::new(maximum)?;
        prospective.request(&mut out)?;
        let request = out.finish(maximum)?;
        let mut out = Projection::new(maximum)?;
        prospective.context(&mut out)?;
        let context = out.finish(maximum)?;
        let mut out = Projection::new(maximum)?;
        prospective.artifact(&mut out)?;
        let artifact = out.finish(maximum)?;
        // Wire limits constrain the independently counted serialized extent.
        // Canonical writer growth remains a separate construction-work term.
        if original.maximum_encoded_bytes > frame
            || context.maximum_encoded_bytes > MAXIMUM_RESTORED_INPUT_REACTIVE17_ARTIFACT_BYTES
            || artifact.maximum_encoded_bytes > MAXIMUM_RESTORED_INPUT_REACTIVE17_ARTIFACT_BYTES
        {
            return Err(exhausted());
        }

        let raw = original_json_value_storage_extent_data(frame)?;
        let id = "cnp-restored-current17-"
            .len()
            .checked_add(20)
            .ok_or_else(exhausted)?;
        let identity = "blake3-256".len() + "cnp.request.v1".len() + 64;
        let originals = self
            .custody
            .originals_by_origin(crate::envelope::RequestOrigin::Controller);
        let controller_entries = originals.count();
        let controller_node = tree_storage_data(
            0,
            insertion_node_bound(controller_entries)?,
            size_of::<Id>() + size_of::<ClientOriginal>(),
            align_of::<(Id, ClientOriginal)>(),
        )?;
        let guard_node = tree_storage_data(
            1,
            1,
            size_of::<Id>() + size_of::<Envelope>(),
            align_of::<(Id, Envelope)>(),
        )?;
        // Extensions is a concrete BTreeMap even when serde_json::Map has an
        // independently unified representation. Price its one selected entry.
        let extension_node = tree_storage_data(
            1,
            1,
            size_of::<String>() + size_of::<Value>(),
            align_of::<(String, Value)>(),
        )?;
        let original_backing = sum(&[original.retained_value_backing_bytes, extension_node])?;
        let raw_extension_nodes = tree_storage_data(
            1,
            raw.maximum_object_members,
            size_of::<String>() + size_of::<Value>(),
            align_of::<(String, Value)>(),
        )?;
        let terminal_backing = sum(&[raw.value_dom_requested_bytes, raw_extension_nodes])?;

        // The predecode guard permits one empty ObservationBatch. A fresh Vec
        // can request the pinned minimum of four slots before its one push.
        // Its three ID, four HashRef and media leaves are independently bounded
        // by that guard; wrong raw fields are retained without typed decoding.
        let batch_ids = multiply(3, 128)?;
        let batch_hashes = multiply(4, 32 + 128 + 128)?;
        let batch_media = 128;
        let typed_observation = sum(&[
            size_of::<ResponseBody>(),
            multiply(4, size_of::<crucible_node_format::ObservationBatch>())?,
            batch_ids,
            batch_hashes,
            batch_media,
            // ResponseShape retains a separate result Map or Error.details Map.
            // ErrorRecord has these strings and no typed ObservationBatch.
            128,
            4096,
            raw.value_dom_requested_bytes,
        ])?;
        // Generic suffix discovery can also inspect Error.details. Successful
        // references are disjoint complete leaf objects; a candidate clone that
        // later refuses remains a separate transient term below.
        let roots = raw.maximum_value_nodes.min(4096);
        let roots_slots = multiply(
            roots.checked_mul(2).ok_or_else(exhausted)?.max(4),
            size_of::<ContentRef>(),
        )?;
        let roots_backing = sum(&[roots_slots, raw.maximum_decoded_string_bytes])?;
        let incident_ids = sum(&[
            self.authority().session_id().as_str().len(),
            self.authority().incarnation_id().as_str().len(),
            self.authority().connection_id().as_str().len(),
        ])?;
        let retained = sum(&[
            id,                // Attempt's moved request ID.
            original_backing,  // Attempt's immutable original.
            terminal_backing,  // Attempt's raw terminal, including rejected input.
            typed_observation, // Attempt's independently boxed selected reply.
            controller_node,
            id,
            identity,
            original_backing,
            terminal_backing, // ClientCustody original/pair.
            guard_node,
            id,
            original_backing, // Actual pending correlation.
            size_of::<crate::connection::ConnectionIncident>(),
            incident_ids,
            // Outgoing main original and at most one accepted incoming Blob
            // occupy separate collect() Vec banks, each with a four-slot floor.
            multiply(8, size_of::<Envelope>())?,
            original_backing,
            terminal_backing, // Incident's independently cloned incoming Blob.
            roots_backing,
        ])?;

        // Request/Context/Artifact are closed field trees: all heap leaves are
        // String/Id or exact 32 Bytes represented by 43 base64 bytes. Their DOM
        // backing therefore bounds each independent typed clone's heap; inline
        // DTO headers and formatter temporaries are separate named terms.
        let typed_request = request.retained_value_backing_bytes;
        let typed_context = context.retained_value_backing_bytes;
        let typed_artifact = artifact.retained_value_backing_bytes;
        let transient = sum(&[
            // Ordinary baseline assignment decodes and validates the body.
            body.requested_total()?,
            body.retained_value_backing_bytes,
            size_of::<RequestBody>(),
            id,
            // Unsigned request Value inserted into the assigned Envelope.
            request.requested_total()?,
            43,
            // Assignment/digest validates an independently decoded request and
            // baseline body, then owns whole-Envelope Value+canonical banks.
            typed_request,
            size_of::<PacketRestoredInputReactive17Request>(),
            body.requested_total()?,
            original.requested_total()?,
            // Sealing owns its request, context DTO/DOM/canonical and complete
            // artifact conversion before replacing the retained unsigned Value.
            typed_request,
            typed_context,
            typed_artifact,
            size_of::<PacketRestoredInputReactive17Context>(),
            size_of::<PacketRestoredInputReactive17Artifact>(),
            context.requested_total()?,
            artifact.requested_total()?,
            43,
            43,
            43,                          // Explicit context/request/proof Bytes formatters.
            original.requested_total()?, // Seal's second assigned digest.
            // Sending owns a whole original Value/canonical buffer, request
            // identity hash and the guard's cloned argument before publication.
            original.requested_total()?,
            identity,
            // Whole raw parse/canonical work is independent of the successful
            // typed roster; malformed and wrong terminals get the same budget.
            frame,
            raw.canonical_pass_requested_bytes()?,
            raw.value_dom_requested_bytes, // Envelope deserialize/clone phase.
            body.requested_total()?,       // validate_body's original request decode.
            raw.canonical_pass_requested_bytes()?, // ResponseShape object().
            raw.value_dom_requested_bytes, // from_value consuming second clone.
            raw.canonical_pass_requested_bytes()?, // ObserveResult object().
            typed_observation,
            raw.value_dom_requested_bytes, // ErrorRecord.details validation clone.
            raw.canonical_pass_requested_bytes()?,
            raw.value_dom_requested_bytes, // One generic evidence-root candidate.
            frame,                         // Root candidate's consumed typed string leaves.
            // Journal envelope_bytes computes its complete request/terminal
            // canonical identity after actual terminal custody was retained.
            raw.canonical_pass_requested_bytes()?,
            // A serde refusal can quote an untrusted raw field name. The same
            // lexical escaped-string and geometric output bounds cover that
            // separately live diagnostic, without treating raw bytes as a DTO.
            raw.canonical_work_requested_bytes,
            roots_slots, // Previous discovery bank remains live during growth.
        ])?;
        let scratch = self.original_restored_observation17_assignment_counter_scratch_data();
        if sum(&[retained, transient, scratch])? > maximum {
            return Err(exhausted());
        }
        self.original_completed_restoration_checkpoint17_cache_data(
            emitter,
            first_frontier,
            false,
        )?;
        self.session
            .ensure_original_observation_receiver_idle_data()?;
        if prospective.frontier != self.session.fresh_restore_query_sequence()? {
            return Err(refused());
        }
        Ok(OriginalRestoredObservation17AssignmentStorageData {
            retained,
            transient,
            scratch,
        })
    }
}

fn counter_scratch_data() -> usize {
    size_of::<OriginalRestoredObservation17AssignmentStorageData>()
        + size_of::<Result<OriginalRestoredObservation17AssignmentStorageData, ProviderError>>()
        + size_of::<PacketRestoredObservation17ProspectiveData<'static>>()
        + size_of::<Observation17OriginalData<'static>>()
        + size_of::<[OriginalSerializationStorageData; 5]>()
        + size_of::<Projection>()
        + size_of::<[usize; 38]>()
        + size_of::<[usize; 18]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<[&str; 5]>()
        + size_of::<std::array::IntoIter<&'static str, 5>>()
        + size_of::<[U64; 3]>()
        + size_of::<std::array::IntoIter<U64, 3>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<U64>()
        + size_of::<[usize; 3]>()
        + CnpController::original_completed_restoration_checkpoint17_cache_counter_scratch_data()
        + crate::reference_packet::service::restored_input_reactive17::restored_input_reactive17_contract_counter_scratch_data()
        + OriginalRestoredSuffixHostAttempt::counter_scratch_data()
        + PreparedOriginalRestoredInputReactive17HostAttempt::counter_scratch_data()
        + crate::retained_metadata::serialization_storage::original_json_value_storage_extent_counter_scratch_data()
}
