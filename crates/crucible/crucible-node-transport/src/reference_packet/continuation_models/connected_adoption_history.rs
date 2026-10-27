//! Borrows adoption and displacement partials without restoring live authority.
//!
//! A decoded historical socket role is never a descriptor. Every independently
//! retained raw snapshot, typed state and moved vector remains represented even
//! after failure; the owning walk records actual spare backing separately.

use super::*;
use crate::reference_packet::continuation_models::settled_history as history;
use crate::retained_metadata::{
    MetadataObserver, ObserveMetadata, aliases::MetadataAliasBank, records::MetadataRecordBank,
};
use serde::ser::SerializeStruct;
use std::mem::size_of;

type AdoptionLoans<'a> = (
    &'a Option<PacketDecodedModelSnapshot>,
    &'a Option<UnixDatagram>,
    &'a Option<ConnectedState>,
    &'a Vec<PacketReaction>,
    &'a Vec<PacketDeliveredInput>,
    &'a Vec<PacketPendingPublication>,
    &'a Vec<PacketConnectedPublication>,
    &'a Vec<OriginalStage>,
    &'a Option<PacketConnectedProgram>,
    &'a bool,
);

struct AdoptionHistory<'a>(&'a PacketReactiveModelAdoption);

impl PacketReactiveModelAdoption {
    /// Appends this exact child's capacities without clearing aggregate banks.
    ///
    /// # Errors
    /// Refuses traversal or the outer owner's remaining finite bank capacity.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(self)
    }

    /// Borrows the defining fields after the enclosing graph has recorded them.
    pub(crate) fn borrowed_settled_model_data(&self) -> impl Serialize + '_ {
        AdoptionHistory(self)
    }

    /// Borrows exact raw and typed partials with independent precharged banks.
    ///
    /// # Errors
    /// Refuses traversal or finite bank exhaustion, preserving recorded partials.
    /// This does not authenticate the attempt or create a model/socket owner.
    pub(crate) fn borrowed_settled_history_data<'a>(
        &'a self,
        records: &'a mut MetadataRecordBank,
        aliases: &'a mut MetadataAliasBank,
    ) -> Result<history::ModelHistory<'a, impl Serialize + 'a>, ProviderError> {
        history::borrow(self, AdoptionHistory(self), records, aliases)
    }

    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        history::counter_scratch_data::<AdoptionHistory<'static>>()
            + PacketConnectedProgram::settled_model_counter_scratch_data()
            + size_of::<AdoptionHistory<'static>>()
            + size_of::<Option<AdoptionHistory<'static>>>()
            + size_of::<AdoptionLoans<'static>>()
            + size_of::<Option<&PacketDecodedModelSnapshot>>()
            + size_of::<&Self>()
            + size_of::<Option<&Self>>()
            + size_of::<Option<&str>>()
            + size_of::<Option<&crate::reference_packet::continuation_models::ModelRecord>>()
            + size_of::<super::super::settled_history::ReactiveProgramHistory<'static>>()
            + size_of::<Option<super::super::settled_history::ReactiveProgramHistory<'static>>>()
    }
}

impl Serialize for AdoptionHistory<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let PacketReactiveModelAdoption {
            snapshot,
            effect_socket,
            state: typed,
            reactions,
            delivered_inputs,
            publications,
            outputs,
            stages,
            completed,
            ready,
        } = self.0;
        let mut state = serializer.serialize_struct("ModelAdoptionHistory", 10)?;
        state.serialize_field("snapshot", &snapshot.as_ref().map(|value| &value.record))?;
        state.serialize_field(
            "effect_socket_role",
            &effect_socket.as_ref().map(|_| "model-effect-socket"),
        )?;
        state.serialize_field("state", typed)?;
        state.serialize_field("reactions", reactions)?;
        state.serialize_field("delivered_inputs", delivered_inputs)?;
        state.serialize_field("publications", publications)?;
        state.serialize_field("outputs", outputs)?;
        state.serialize_field("stages", stages)?;
        state.serialize_field(
            "completed",
            &completed
                .as_ref()
                .map(|value| value.borrowed_settled_model_data()),
        )?;
        state.serialize_field("ready", ready)?;
        state.end()
    }
}

impl ObserveMetadata for PacketReactiveModelAdoption {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            snapshot,
            effect_socket: _,
            state,
            reactions,
            delivered_inputs,
            publications,
            outputs,
            stages,
            completed,
            ready,
        } = self;
        observer.observe(snapshot)?;
        observer.observe(state)?;
        observer.observe(reactions)?;
        observer.observe(delivered_inputs)?;
        observer.observe(publications)?;
        observer.observe(outputs)?;
        observer.observe(stages)?;
        observer.observe(completed)?;
        observer.observe(ready)
    }
}

struct DisplacedHistory<'a>(&'a PacketDisplacedReactiveModel);

impl PacketDisplacedReactiveModel {
    /// Appends this exact child's capacities without clearing aggregate banks.
    ///
    /// # Errors
    /// Refuses traversal or the outer owner's remaining finite bank capacity.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(self)
    }

    /// Borrows the displaced fields after the enclosing graph has recorded them.
    pub(crate) fn borrowed_settled_model_data(&self) -> impl Serialize + '_ {
        DisplacedHistory(self)
    }

    /// Borrows displaced original state without renewing its fresh-model predicate.
    ///
    /// # Errors
    /// Refuses traversal or finite bank exhaustion; no socket or hold is created.
    pub(crate) fn borrowed_settled_history_data<'a>(
        &'a self,
        records: &'a mut MetadataRecordBank,
        aliases: &'a mut MetadataAliasBank,
    ) -> Result<history::ModelHistory<'a, impl Serialize + 'a>, ProviderError> {
        history::borrow(self, DisplacedHistory(self), records, aliases)
    }

    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        history::counter_scratch_data::<DisplacedHistory<'static>>()
            + PacketConnectedProgram::settled_model_counter_scratch_data()
            + size_of::<DisplacedHistory<'static>>()
            + size_of::<Option<DisplacedHistory<'static>>>()
            + size_of::<&Self>()
            + size_of::<&ConnectedState>()
    }
}

impl Serialize for DisplacedHistory<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let PacketDisplacedReactiveModel { state } = self.0;
        state.serialize(serializer)
    }
}

impl ObserveMetadata for PacketDisplacedReactiveModel {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self { state } = self;
        observer.observe(state)
    }
}
