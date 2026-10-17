//! Retains every reactive model field and reconstructs fresh native socket ownership.
//!
//! Historical request/reply native PIDs remain captured data. Only the actual
//! live model PID fence changes; original input/event namespaces never change.

use super::super::continuation_models::{
    ModelCapacities, PacketDecodedModelSnapshot, PacketModelKind, PacketOriginalModelSnapshot,
    capture_model, check_definition,
};
use super::*;

#[derive(Serialize)]
struct ConnectedView<'a> {
    definition: &'a PacketConnectedDefinition,
    native_pid: u32,
    reached: Position,
    gate_closed: bool,
    reactions: &'a [PacketReaction],
    delivered_inputs: &'a [PacketDeliveredInput],
    publications: &'a [PacketPendingPublication],
    outputs: &'a [PacketConnectedPublication],
    stages: &'a [OriginalStage],
    grants: &'a BTreeMap<Id, PacketConnectedGrant>,
    retired: &'a BTreeMap<Id, Vec<Id>>,
    reactions_completed: u64,
    packet_effects: u64,
    failed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectedState {
    definition: PacketConnectedDefinition,
    native_pid: u32,
    reached: Position,
    gate_closed: bool,
    reactions: Vec<PacketReaction>,
    delivered_inputs: Vec<PacketDeliveredInput>,
    publications: Vec<PacketPendingPublication>,
    outputs: Vec<PacketConnectedPublication>,
    stages: Vec<OriginalStage>,
    grants: BTreeMap<Id, PacketConnectedGrant>,
    retired: BTreeMap<Id, Vec<Id>>,
    reactions_completed: u64,
    packet_effects: u64,
    failed: bool,
}

impl PacketConnectedProgram {
    /// Captures complete reactive model history at its actual stopped cursor.
    ///
    /// Control/transport journals, quiescent effect-channel custody and capture
    /// settlement remain separate mandatory parts of the enclosing Native5 owner.
    ///
    /// # Errors
    /// Refuses foreign live PID, failure, another cursor, incomplete grants or excess.
    pub fn capture_state(
        &self,
        cut: Position,
        maximum_bytes: usize,
    ) -> Result<PacketOriginalModelSnapshot, ProviderError> {
        self.current()?;
        if cut != self.reached || self.grants.values().any(|row| !row.complete) {
            return Err(ProviderError::Correlation(
                "connected model capture boundary",
            ));
        }
        capture_model(
            ConnectedView {
                definition: &self.definition,
                native_pid: self.native_pid,
                reached: self.reached,
                gate_closed: self.gate_closed,
                reactions: &self.reactions,
                delivered_inputs: &self.delivered_inputs,
                publications: &self.publications,
                outputs: &self.outputs,
                stages: &self.stages,
                grants: &self.grants,
                retired: &self.retired,
                reactions_completed: self.reactions_completed,
                packet_effects: self.packet_effects,
                failed: self.failed,
            },
            PacketModelKind::Reactive,
            &self.definition,
            cut,
            ModelCapacities {
                events: 0,
                reactions: self.reactions.capacity(),
                delivered_inputs: self.delivered_inputs.capacity(),
                publications: self.publications.capacity(),
                outputs: self.outputs.capacity(),
                stages: self.stages.capacity(),
            },
            maximum_bytes,
        )
    }

    /// Reconstructs the complete reactive model around a genuine fresh datagram.
    ///
    /// This helper grants no target activation. The outer installed adopter must
    /// authenticate the complete snapshot/settlement/transport association and
    /// keep its separate restore gate held. Captured model gate state is preserved.
    ///
    /// # Errors
    /// Refuses another model, changed configuration, incomplete/overwide history
    /// or unavailable vector credit before returning any reconstructed owner.
    pub fn adopt_model_state(
        snapshot: PacketDecodedModelSnapshot,
        effect_socket: UnixDatagram,
    ) -> Result<Self, ProviderError> {
        let mut snapshot = Some(snapshot);
        let mut effect_socket = Some(effect_socket);
        let mut attempt = None;
        Self::adopt_model_state_retained_into(&mut snapshot, &mut effect_socket, &mut attempt)?;
        let mut completed = None;
        attempt
            .as_mut()
            .ok_or(ProviderError::Conflict("model adoption owner absent"))?
            .take_completed_into(&mut completed)?;
        completed.ok_or(ProviderError::Conflict("model adoption completion absent"))
    }
}

fn verify_record(reference: &ContentRef, record: &impl Serialize) -> Result<(), ProviderError> {
    let value = serde_json::to_value(record).map_err(ContractError::from)?;
    let bytes = canonical::canonical_json(&value)?;
    if canonical::content_ref(&bytes, "application/json")? != *reference {
        return Err(ProviderError::Correlation(
            "connected model original record bytes",
        ));
    }
    Ok(())
}

fn verify_reply(reply: &PacketInputReply) -> Result<(), ProviderError> {
    for (reference, bytes) in &reply.evidence {
        reference.verify(bytes)?;
    }
    Ok(())
}

fn authenticate_connected_data(
    record: &super::super::continuation_models::ModelRecord,
    state: &ConnectedState,
) -> Result<(), ProviderError> {
    if u64::from(state.native_pid) != record.captured_process.get()
        || state.reached != record.cut
        || state.failed
        || state.grants.len() > MAXIMUM_OPERATIONS
        || state.retired.len() > state.grants.len()
        || state
            .grants
            .iter()
            .any(|(id, grant)| id != &grant.operation || !grant.complete)
        || state
            .retired
            .keys()
            .any(|id| !state.grants.contains_key(id))
        || record.capacities.events != 0
        || state.stages.len() > MAXIMUM_BATCHES
        || state
            .stages
            .iter()
            .map(|stage| stage.record.batch.events.len())
            .sum::<usize>()
            > MAXIMUM_EVENTS
    {
        return Err(ProviderError::Correlation(
            "connected complete model snapshot",
        ));
    }
    check_definition(record, &state.definition)?;
    for stage in &state.stages {
        verify_record(&stage.record_ref, &stage.record)?;
        verify_reply(&stage.reply)?;
        if let Some(commit) = &stage.commit {
            verify_record(&commit.record_ref, &commit.record)?;
            verify_reply(&commit.reply)?;
            if commit.record.staged_record != stage.record_ref
                || commit.record.cut != stage.record.cut
            {
                return Err(ProviderError::Correlation(
                    "connected original staged/commit snapshot",
                ));
            }
        }
    }
    for (length, capacity, maximum) in [
        (
            state.reactions.len(),
            record.capacities.reactions,
            MAXIMUM_EVENTS,
        ),
        (
            state.delivered_inputs.len(),
            record.capacities.delivered_inputs,
            MAXIMUM_EVENTS,
        ),
        (
            state.publications.len(),
            record.capacities.publications,
            MAXIMUM_EVENTS,
        ),
        (
            state.outputs.len(),
            record.capacities.outputs,
            MAXIMUM_EVENTS,
        ),
        (
            state.stages.len(),
            record.capacities.stages,
            MAXIMUM_BATCHES,
        ),
    ] {
        if length > capacity || capacity > maximum {
            return Err(ProviderError::ResourceExhausted(
                "packet model vector capacity",
            ));
        }
    }
    Ok(())
}

struct ConnectedInventoryData<'a>(&'a ConnectedState);
impl Serialize for ConnectedInventoryData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let state = self.0;
        let mut fields = serializer.serialize_struct("PacketConnectedInventory", 10)?;
        fields.serialize_field("reached", &state.reached)?;
        fields.serialize_field("gate_closed", &state.gate_closed)?;
        fields.serialize_field("reactions", &state.reactions)?;
        fields.serialize_field("delivered_inputs", &state.delivered_inputs)?;
        fields.serialize_field("publications", &state.publications)?;
        fields.serialize_field("retained_outputs", &state.outputs)?;
        fields.serialize_field("reactions_completed", &U64::new(state.reactions_completed))?;
        fields.serialize_field("packet_effects", &U64::new(state.packet_effects))?;
        fields.serialize_field(
            "stages",
            &crate::protocol_snapshot::Sequence(|| {
                state.stages.iter().map(|stage| &stage.record_ref)
            }),
        )?;
        fields.serialize_field(
            "commits",
            &crate::protocol_snapshot::Sequence(|| {
                state
                    .stages
                    .iter()
                    .filter_map(|stage| stage.commit.as_ref().map(|commit| &commit.record_ref))
            }),
        )?;
        fields.end()
    }
}

pub(in crate::reference_packet) fn capture_boundary_data(
    record: &super::super::continuation_models::ModelRecord,
) -> Result<super::super::continuation_models::PacketModelCaptureBoundaryData, ProviderError> {
    let state = ConnectedState::deserialize(&record.state).map_err(ContractError::from)?;
    authenticate_connected_data(record, &state)?;
    let mut earliest = state.publications.iter().map(|row| row.publication).min();
    for reaction in &state.reactions {
        let completion = if state.definition.output.is_some() {
            reaction.evaluation.reaction_publication(U64::new(16))?
        } else {
            reaction.evaluation
        };
        earliest = Some(earliest.map_or(completion, |prior| prior.min(completion)));
    }
    crate::connection::serialized_credit(&ConnectedInventoryData(&state), MAXIMUM_RECORD)?;
    Ok(
        super::super::continuation_models::PacketModelCaptureBoundaryData {
            local_cursor: state.reached,
            gate_closed: state.gate_closed,
            retained_outputs: state.outputs.len(),
            earliest_pending_completion: earliest,
            inventory_hash: canonical::json_hash(
                "source-owned.packet-connected-inventory/4",
                &ConnectedInventoryData(&state),
            )?,
        },
    )
}

#[path = "connected_retained.rs"]
mod retained_adoption;
pub(crate) use retained_adoption::PacketDisplacedReactiveModel;
pub use retained_adoption::PacketReactiveModelAdoption;

pub(in crate::reference_packet) fn authenticate_record_history_data(
    model: &super::super::continuation_models::ModelRecord,
    record: &PacketConnectedNativeRecord,
    original: &crate::envelope::Envelope,
    expectation: super::super::continuation_models::PacketModelRecordExpectation,
) -> Result<(), ProviderError> {
    use super::super::continuation_models::record_history::{
        PacketModelRecordExpectation, authenticate_grant_request,
    };
    let refused =
        || ProviderError::Correlation("packet archived reactive record differs from model history");
    if record.schema != "source-owned.packet-native/4"
        || record.native_pid != model.captured_process
        || &record.original != original
    {
        return Err(refused());
    }
    let state = ConnectedState::deserialize(&model.state).map_err(ContractError::from)?;
    authenticate_connected_data(model, &state)?;
    super::validate_connected_program_definition(&state.definition)?;
    match expectation {
        PacketModelRecordExpectation::CompletedGrant => {
            let grant = record.grant.as_ref().ok_or_else(refused)?;
            authenticate_grant_request(original, &grant.operation, grant.start, grant.limit)?;
            if !grant.complete
                || state.grants.get(&grant.operation) != Some(grant)
                || record.inventory != grant.inventory
            {
                return Err(refused());
            }
        }
        PacketModelRecordExpectation::FinalObservation => {
            let inventory = &record.inventory;
            if original.method != crate::envelope::Method::Observe
                || record.grant.is_some()
                || inventory.reached != state.reached
                || inventory.gate_closed != state.gate_closed
                || inventory.reactions != state.reactions
                || inventory.delivered_inputs != state.delivered_inputs
                || inventory.publications != state.publications
                || inventory.retained_outputs != state.outputs
                || inventory.reactions_completed != U64::new(state.reactions_completed)
                || inventory.packet_effects != U64::new(state.packet_effects)
                || !inventory
                    .stages
                    .iter()
                    .eq(state.stages.iter().map(|stage| &stage.record_ref))
                || !inventory.commits.iter().eq(state
                    .stages
                    .iter()
                    .filter_map(|stage| stage.commit.as_ref().map(|commit| &commit.record_ref)))
            {
                return Err(refused());
            }
            crate::bodies::decode_request(original.method, &original.body)?;
        }
    }
    Ok(())
}

pub(in crate::reference_packet) fn original_validation_layouts() -> [usize; 4] {
    use std::mem::{align_of, size_of};
    let slots = [
        size_of::<ConnectedState>(),
        size_of::<OriginalStage>(),
        size_of::<OriginalCommit>(),
        size_of::<PacketConnectedDefinition>(),
        size_of::<PacketReaction>(),
        size_of::<PacketDeliveredInput>(),
        size_of::<PacketPendingPublication>(),
        size_of::<PacketConnectedPublication>(),
        size_of::<PacketConnectedInventory>(),
        size_of::<PacketConnectedGrant>(),
        size_of::<PacketConnectedNativeRecord>(),
    ];
    let alignments = [
        align_of::<ConnectedState>(),
        align_of::<OriginalStage>(),
        align_of::<OriginalCommit>(),
        align_of::<PacketConnectedDefinition>(),
        align_of::<PacketReaction>(),
        align_of::<PacketDeliveredInput>(),
        align_of::<PacketPendingPublication>(),
        align_of::<PacketConnectedPublication>(),
        align_of::<PacketConnectedInventory>(),
        align_of::<PacketConnectedGrant>(),
        align_of::<PacketConnectedNativeRecord>(),
    ];
    [
        slots.into_iter().max().unwrap_or(0),
        alignments.into_iter().max().unwrap_or(1),
        size_of::<ConnectedState>(),
        size_of::<OriginalStage>().max(size_of::<OriginalCommit>()),
    ]
}

impl PacketConnectedProgram {
    pub(crate) fn quote_original_live_capture_encoding(
        &self,
        maximum: usize,
    ) -> Result<super::super::serialization_storage::NativeModelCaptureEncodingData, ProviderError>
    {
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        let cursor = self.observe_original_live_capture_metadata(&mut observer)?;
        let facts = observer.finish();
        let state = ConnectedView {
            definition: &self.definition,
            native_pid: self.native_pid,
            reached: self.reached,
            gate_closed: self.gate_closed,
            reactions: &self.reactions,
            delivered_inputs: &self.delivered_inputs,
            publications: &self.publications,
            outputs: &self.outputs,
            stages: &self.stages,
            grants: &self.grants,
            retired: &self.retired,
            reactions_completed: self.reactions_completed,
            packet_effects: self.packet_effects,
            failed: self.failed,
        };
        super::super::serialization_storage::model_encoding_storage_data(
            &self.definition,
            &state,
            cursor,
            [
                0,
                self.reactions.capacity(),
                self.delivered_inputs.capacity(),
                self.publications.capacity(),
                self.outputs.capacity(),
                self.stages.capacity(),
            ],
            facts,
            maximum,
        )
    }
}

pub(in crate::reference_packet) fn capture_boundary_counter_scratch_data() -> usize {
    std::mem::size_of::<ConnectedState>()
        + std::mem::size_of::<ConnectedInventoryData<'static>>()
        + std::mem::size_of::<Option<Position>>()
}

#[path = "connected_settled_history.rs"]
mod settled_history;

#[path = "connected_settled_reader.rs"]
pub(in crate::reference_packet) mod settled_reader;
