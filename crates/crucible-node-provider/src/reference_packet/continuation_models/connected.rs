//! Retains every reactive model field and reconstructs fresh native socket ownership.
//!
//! Historical request/reply native PIDs remain captured data. Only the actual
//! live model PID fence changes; original input/event namespaces never change.

use super::super::continuation_models::{
    ModelCapacities, PacketDecodedModelSnapshot, PacketModelKind, PacketOriginalModelSnapshot,
    capture_model, check_definition, decode_state, restore_vec,
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

#[derive(Deserialize)]
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
        let mut record = snapshot.record;
        if record.kind != PacketModelKind::Reactive {
            return Err(ProviderError::Correlation("connected model snapshot kind"));
        }
        let state: ConnectedState = decode_state(&mut record)?;
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
        check_definition(&record, &state.definition)?;
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
        let mut model = Self::new(state.definition, effect_socket)?;
        // New live owner only. Historical record/reply PIDs and IDs are retained.
        model.reached = state.reached;
        model.gate_closed = state.gate_closed;
        model.reactions =
            restore_vec(state.reactions, record.capacities.reactions, MAXIMUM_EVENTS)?;
        model.delivered_inputs = restore_vec(
            state.delivered_inputs,
            record.capacities.delivered_inputs,
            MAXIMUM_EVENTS,
        )?;
        model.publications = restore_vec(
            state.publications,
            record.capacities.publications,
            MAXIMUM_EVENTS,
        )?;
        model.outputs = restore_vec(state.outputs, record.capacities.outputs, MAXIMUM_EVENTS)?;
        model.stages = restore_vec(state.stages, record.capacities.stages, MAXIMUM_BATCHES)?;
        model.grants = state.grants;
        model.retired = state.retired;
        model.reactions_completed = state.reactions_completed;
        model.packet_effects = state.packet_effects;
        model.failed = state.failed;
        Ok(model)
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
