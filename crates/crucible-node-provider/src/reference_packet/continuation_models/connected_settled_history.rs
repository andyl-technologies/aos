//! Borrows complete reactive model state without exporting its live socket.

use super::*;
use crate::reference_packet::continuation_models::settled_history as history;
use crate::retained_metadata::{MetadataObserver, ObserveMetadata};
use serde::ser::SerializeStruct;
use std::mem::size_of;

type ReactiveStateLoans<'a> = (
    &'a PacketConnectedDefinition,
    &'a u32,
    &'a Position,
    &'a bool,
    &'a Vec<PacketReaction>,
    &'a Vec<PacketDeliveredInput>,
    &'a Vec<PacketPendingPublication>,
    &'a Vec<PacketConnectedPublication>,
    &'a Vec<OriginalStage>,
    &'a BTreeMap<Id, PacketConnectedGrant>,
    &'a BTreeMap<Id, Vec<Id>>,
    &'a u64,
    &'a u64,
    &'a bool,
);
type ReactiveProgramLoans<'a> = (ReactiveStateLoans<'a>, &'a UnixDatagram);

pub(in crate::reference_packet) struct ReactiveProgramHistory<'a>(&'a PacketConnectedProgram);

impl PacketConnectedProgram {
    pub(in crate::reference_packet) fn borrowed_settled_model_data(
        &self,
    ) -> ReactiveProgramHistory<'_> {
        ReactiveProgramHistory(self)
    }

    pub(crate) fn settled_model_counter_scratch_data() -> usize {
        history::counter_scratch_data::<ReactiveProgramHistory<'static>>()
            + size_of::<ReactiveProgramHistory<'static>>()
            + size_of::<&Self>()
            + size_of::<Option<&Self>>()
            + size_of::<Option<ReactiveProgramHistory<'static>>>()
            + size_of::<ReactiveProgramLoans<'static>>()
            + size_of::<ReactiveStateLoans<'static>>()
            + size_of::<(
                &OriginalStage,
                &PacketStageRecord,
                &ContentRef,
                &PacketInputReply,
                &Option<OriginalCommit>,
            )>()
            + size_of::<(
                &OriginalCommit,
                &PacketCommitRecord,
                &ContentRef,
                &PacketInputReply,
            )>()
            + size_of::<(
                &PacketInputReply,
                &crate::bodies::InputResult,
                &Vec<(ContentRef, Vec<u8>)>,
            )>()
            + size_of::<std::slice::Iter<'static, (ContentRef, Vec<u8>)>>()
            + size_of::<Option<&(ContentRef, Vec<u8>)>>()
            + size_of::<(&ContentRef, &Vec<u8>)>()
    }
}

impl Serialize for ReactiveProgramHistory<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let PacketConnectedProgram {
            definition,
            native_pid,
            effect_socket: _,
            reached,
            gate_closed,
            reactions,
            delivered_inputs,
            publications,
            outputs,
            stages,
            grants,
            retired,
            reactions_completed,
            packet_effects,
            failed,
        } = self.0;
        let mut state = serializer.serialize_struct("ReactiveProgramHistory", 15)?;
        state.serialize_field("definition", definition)?;
        state.serialize_field("native_pid", native_pid)?;
        state.serialize_field("reached", reached)?;
        state.serialize_field("gate_closed", gate_closed)?;
        state.serialize_field("reactions", reactions)?;
        state.serialize_field("delivered_inputs", delivered_inputs)?;
        state.serialize_field("publications", publications)?;
        state.serialize_field("outputs", outputs)?;
        state.serialize_field("stages", stages)?;
        state.serialize_field("grants", grants)?;
        state.serialize_field("retired", retired)?;
        state.serialize_field("reactions_completed", reactions_completed)?;
        state.serialize_field("packet_effects", packet_effects)?;
        state.serialize_field("failed", failed)?;
        state.serialize_field("effect_socket_role", "model-effect-socket")?;
        state.end()
    }
}

macro_rules! fields {
    ($ty:ty, $($field:ident),+ $(,)?) => {
        impl ObserveMetadata for $ty {
            fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
                let Self { $($field),+ } = self;
                $(observer.observe($field)?;)+
                Ok(())
            }
        }
    };
}

fields!(
    ConnectedState,
    definition,
    native_pid,
    reached,
    gate_closed,
    reactions,
    delivered_inputs,
    publications,
    outputs,
    stages,
    grants,
    retired,
    reactions_completed,
    packet_effects,
    failed
);
fields!(OriginalStage, record, record_ref, reply, commit);
fields!(OriginalCommit, record, record_ref, reply);
impl ObserveMetadata for PacketInputReply {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self { result, evidence } = self;
        observer.observe(result)?;
        observer.vector::<(ContentRef, Vec<u8>)>(evidence.capacity())?;
        for (reference, bytes) in evidence {
            observer.observe(reference)?;
            observer.observe(bytes)?;
        }
        Ok(())
    }
}

impl ObserveMetadata for PacketConnectedProgram {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            definition,
            native_pid,
            effect_socket: _,
            reached,
            gate_closed,
            reactions,
            delivered_inputs,
            publications,
            outputs,
            stages,
            grants,
            retired,
            reactions_completed,
            packet_effects,
            failed,
        } = self;
        observer.observe(definition)?;
        observer.observe(native_pid)?;
        observer.observe(reached)?;
        observer.observe(gate_closed)?;
        observer.observe(reactions)?;
        observer.observe(delivered_inputs)?;
        observer.observe(publications)?;
        observer.observe(outputs)?;
        observer.observe(stages)?;
        observer.observe(grants)?;
        observer.observe(retired)?;
        observer.observe(reactions_completed)?;
        observer.observe(packet_effects)?;
        observer.observe(failed)?;
        Ok(())
    }
}
