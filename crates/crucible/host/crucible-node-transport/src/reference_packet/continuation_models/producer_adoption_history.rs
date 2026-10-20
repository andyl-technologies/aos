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
    &'a Option<ProducerState>,
    &'a Vec<PacketEvent>,
    &'a Vec<PacketPublication>,
    &'a Option<PacketProgram>,
    &'a bool,
);

struct AdoptionHistory<'a>(&'a PacketProducerModelAdoption);

impl PacketProducerModelAdoption {
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
            + PacketProgram::settled_model_counter_scratch_data()
            + size_of::<AdoptionHistory<'static>>()
            + size_of::<Option<AdoptionHistory<'static>>>()
            + size_of::<AdoptionLoans<'static>>()
            + size_of::<Option<&PacketDecodedModelSnapshot>>()
            + size_of::<&Self>()
            + size_of::<Option<&Self>>()
            + size_of::<Option<&str>>()
            + size_of::<Option<&ModelRecord>>()
            + size_of::<history::ProducerProgramHistory<'static>>()
            + size_of::<Option<history::ProducerProgramHistory<'static>>>()
    }
}

impl Serialize for AdoptionHistory<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let PacketProducerModelAdoption {
            snapshot,
            effect_socket,
            state: typed,
            events,
            outputs,
            completed,
            ready,
        } = self.0;
        let mut state = serializer.serialize_struct("ModelAdoptionHistory", 7)?;
        state.serialize_field("snapshot", &snapshot.as_ref().map(|value| &value.record))?;
        state.serialize_field(
            "effect_socket_role",
            &effect_socket.as_ref().map(|_| "model-effect-socket"),
        )?;
        state.serialize_field("state", typed)?;
        state.serialize_field("events", events)?;
        state.serialize_field("outputs", outputs)?;
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

impl ObserveMetadata for PacketProducerModelAdoption {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            snapshot,
            effect_socket: _,
            state,
            events,
            outputs,
            completed,
            ready,
        } = self;
        observer.observe(snapshot)?;
        observer.observe(state)?;
        observer.observe(events)?;
        observer.observe(outputs)?;
        observer.observe(completed)?;
        observer.observe(ready)
    }
}

struct DisplacedHistory<'a>(&'a PacketDisplacedProducerModel);

impl PacketDisplacedProducerModel {
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
            + PacketProgram::settled_model_counter_scratch_data()
            + size_of::<DisplacedHistory<'static>>()
            + size_of::<Option<DisplacedHistory<'static>>>()
            + size_of::<&Self>()
            + size_of::<&ProducerState>()
    }
}

impl Serialize for DisplacedHistory<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let PacketDisplacedProducerModel { state } = self.0;
        state.serialize(serializer)
    }
}

impl ObserveMetadata for PacketDisplacedProducerModel {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self { state } = self;
        observer.observe(state)
    }
}

// crucible-lint: allow panic-shortcut -- inert partial/capacity controls intentionally panic on wrong observed history.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "actual historical encoding and capacity observations are test assertions"
)]
mod tests {
    use super::*;
    use crate::retained_metadata::RetainedProtocolMetadataFacts;

    fn partial() -> PacketProducerModelAdoption {
        let position = Position::new(U64::new(4), U64::new(0), Phase::BoundaryControl);
        let mut events = Vec::with_capacity(5);
        events.push(PacketEvent {
            id: Id::new("retained-typed-event").unwrap(),
            evaluation: position,
            completion: position,
            payload: Some(Bytes::new(b"typed payload".to_vec())),
        });
        let state = ProducerState {
            events,
            next_event: 0,
            reached: position,
            gate_closed: false,
            outputs: Vec::with_capacity(3),
            grants: BTreeMap::new(),
            private_mutations: 1,
            packet_effects: 0,
            retired: BTreeMap::new(),
            failed: true,
        };
        let record = ModelRecord {
            schema: MODEL_SCHEMA.to_owned(),
            kind: PacketModelKind::Producer,
            captured_process: U64::new(17),
            configuration: canonical::content_ref(b"definition data", "application/json").unwrap(),
            cut: position,
            capacities: ModelCapacities {
                events: 1,
                reactions: 0,
                delivered_inputs: 0,
                publications: 0,
                outputs: 3,
                stages: 0,
            },
            state: serde_json::json!({"next_event": "raw-invalid-partial"}),
        };

        // Inert contradictory partials test the owning projection, never an
        // authenticated adopter or an invitation to reopen a failed attempt.
        PacketProducerModelAdoption {
            snapshot: Some(PacketDecodedModelSnapshot { record }),
            effect_socket: None,
            state: Some(state),
            events: Vec::with_capacity(7),
            outputs: Vec::with_capacity(9),
            completed: None,
            ready: false,
        }
    }

    fn facts(owner: &PacketProducerModelAdoption) -> RetainedProtocolMetadataFacts {
        let mut observer = MetadataObserver::new();
        observer.observe(owner).unwrap();
        observer.finish()
    }

    #[test]
    fn failed_adoption_history_preserves_raw_typed_and_moved_vector_owners() {
        let owner = partial();
        let expected = facts(&owner);
        let mut records = MetadataRecordBank::reserve(expected.capacity_records).unwrap();
        let mut aliases = MetadataAliasBank::reserve(1).unwrap();
        let history = owner
            .borrowed_settled_history_data(&mut records, &mut aliases)
            .unwrap();
        let value = serde_json::to_value(history).unwrap();

        assert_eq!(
            value["data"]["snapshot"]["state"]["next_event"],
            "raw-invalid-partial"
        );
        assert_eq!(
            value["data"]["state"]["events"][0]["id"],
            "retained-typed-event"
        );
        assert_eq!(value["data"]["state"]["failed"], true);
        assert_eq!(value["data"]["events"], serde_json::json!([]));
        assert_eq!(value["data"]["ready"], false);
        assert!(value["data"]["effect_socket_role"].is_null());
        assert!(value["data"]["completed"].is_null());
        assert_eq!(records.rows().len(), expected.capacity_records);
        for capacity in [5, 7, 9] {
            assert!(records.rows().iter().any(|row| {
                row.kind == crate::retained_metadata::records::MetadataRecordKind::Vector
                    && row.extent == capacity
            }));
        }
        assert_eq!(facts(&owner), expected);
    }

    #[test]
    fn failed_adoption_history_one_short_keeps_partial_rows_without_reallocating() {
        let owner = partial();
        let expected = facts(&owner);
        let mut records = MetadataRecordBank::reserve(expected.capacity_records - 1).unwrap();
        let mut aliases = MetadataAliasBank::reserve(1).unwrap();
        let before = records.capacity_rows();

        assert!(
            owner
                .borrowed_settled_history_data(&mut records, &mut aliases)
                .is_err()
        );

        assert_eq!(records.rows().len(), expected.capacity_records - 1);
        assert_eq!(records.capacity_rows(), before);
        assert_eq!(facts(&owner), expected);
    }
}
