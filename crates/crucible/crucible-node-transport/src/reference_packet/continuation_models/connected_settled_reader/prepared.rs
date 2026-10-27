//! Reads reactive adoption partials beside their defining private state fields.

use super::*;
use crate::reference_packet::continuation_models::ModelRecord;
use crate::reference_packet::continuation_models::settled_reader::prepared::{
    SocketRole, inert_fields,
};
use crate::retained_metadata::{MetadataObserver, ObserveMetadata};
use serde::ser::SerializeStruct;

impl HistoricalType for ReactiveModel17Data {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_fields(input, ledger, build, false)
    }
}

impl Serialize for ReactiveModel17Data {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl ObserveMetadata for ReactiveModel17Data {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        // The transparent wrapper keeps the original model's traversal count.
        self.0.observe_metadata(observer)
    }
}

pub(in crate::reference_packet) struct ReactiveProgram17Data(ReactiveModel17Data);

impl HistoricalType for ReactiveProgram17Data {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Ok(ReactiveModel17Data::read_current(input, ledger, build)?.map(Self))
    }
}

impl ObserveMetadata for ReactiveProgram17Data {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        self.0.observe_metadata(observer)
    }
}

impl Serialize for ReactiveProgram17Data {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize_program17_data(serializer)
    }
}

impl ReactiveModel17Data {
    /// Serializes the complete inert program fields and its closed socket role.
    ///
    /// # Errors
    /// Propagates errors reported by the destination serializer.
    pub(in crate::reference_packet) fn serialize_program17_data<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let ConnectedState {
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
            failed,
        } = &self.0;
        let mut fields = serializer.serialize_struct("InertReactiveProgram17", 15)?;
        fields.serialize_field("definition", definition)?;
        fields.serialize_field("native_pid", native_pid)?;
        fields.serialize_field("reached", reached)?;
        fields.serialize_field("gate_closed", gate_closed)?;
        fields.serialize_field("reactions", reactions)?;
        fields.serialize_field("delivered_inputs", delivered_inputs)?;
        fields.serialize_field("publications", publications)?;
        fields.serialize_field("outputs", outputs)?;
        fields.serialize_field("stages", stages)?;
        fields.serialize_field("grants", grants)?;
        fields.serialize_field("retired", retired)?;
        fields.serialize_field("reactions_completed", reactions_completed)?;
        fields.serialize_field("packet_effects", packet_effects)?;
        fields.serialize_field("failed", failed)?;
        fields.serialize_field("effect_socket_role", "model-effect-socket")?;
        fields.end()
    }
}

inert_fields!(ReactiveAdoption17Data {
    snapshot: Option<ModelRecord>,
    effect_socket_role: Option<SocketRole>,
    state: Option<ReactiveModel17Data>,
    reactions: Vec<PacketReaction>,
    delivered_inputs: Vec<PacketDeliveredInput>,
    publications: Vec<PacketPendingPublication>,
    outputs: Vec<PacketConnectedPublication>,
    stages: Vec<OriginalStage>,
    completed: Option<ReactiveProgram17Data>,
    ready: bool,
});

/// Names the direct private stage-vector and reactive adoption parser views.
pub(in crate::reference_packet) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<Vec<OriginalStage>>()
        + size_of::<Option<Vec<OriginalStage>>>()
        + size_of::<Result<Option<Vec<OriginalStage>>, ProviderError>>()
        + size_of::<Result<Vec<OriginalStage>, ProviderError>>()
        + size_of::<&Vec<OriginalStage>>()
        + size_of::<ReactiveProgram17Data>()
        + size_of::<Option<ReactiveProgram17Data>>()
        + size_of::<Result<Option<ReactiveProgram17Data>, ProviderError>>()
        + size_of::<ReactiveAdoption17Data>()
        + size_of::<Option<ReactiveAdoption17Data>>()
        + size_of::<Result<Option<ReactiveAdoption17Data>, ProviderError>>()
}

// crucible-lint: allow panic-shortcut -- real failed-adopter DATA controls assert complete retained field closure.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "assertions inspect actual inert reactive adoption partials"
)]
mod tests {
    use super::*;
    use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
    use crate::retained_metadata::records::{MetadataRecordBank, ValidatedMetadataRecords};

    #[test]
    fn actual_failed_reactive_adopter_preserves_nonempty_raw_and_typed_inboxes() {
        let (effect, _peer) = UnixDatagram::pair().unwrap();
        let endpoint = |node| Endpoint {
            node_id: Id::new(node).unwrap(),
            port_id: Id::new("packet-port").unwrap(),
            lane_id: Id::new("packet-lane").unwrap(),
        };
        let definition = PacketConnectedDefinition {
            schema: "source-owned.packet-connected-program/4".to_owned(),
            connections: vec![PacketInputConnection {
                id: Id::new("reactive-adoption-connection").unwrap(),
                policy: canonical::content_ref(b"logical policy", "application/json").unwrap(),
                producer: endpoint("reader-producer"),
                consumer: endpoint("reader-reactive"),
                delay_ps: U64::new(0),
            }],
            output: None,
        };
        let mut original = PacketConnectedProgram::new(definition, effect).unwrap();
        let mut payload = Vec::with_capacity(29);
        payload.extend_from_slice(b"retained pending reaction");
        // These are inert field-fixture bytes, not a staged native input permit.
        original.reactions.push(PacketReaction {
            input_event: Id::new("logical-input-event").unwrap(),
            input_producer: Id::new("reader-producer").unwrap(),
            input_sequence: U64::new(0),
            stage_operation: Id::new("logical-stage").unwrap(),
            commit_request: Id::new("logical-commit").unwrap(),
            payload: Bytes::new(payload),
            parent: Position::new(U64::new(5), U64::new(0), Phase::Delivery),
            evaluation: Position::new(U64::new(5), U64::new(0), Phase::Reaction),
        });
        let snapshot = original.capture_state(original.reached, 262_144).unwrap();
        let mut snapshot =
            crate::reference_packet::continuation_models::decode_packet_model_snapshot(
                snapshot.bytes(),
                snapshot.reference(),
                262_144,
            )
            .unwrap();
        snapshot.record.state["failed"] = serde_json::Value::Bool(true);
        let mut incoming = Some(snapshot);
        let mut attempt = None;
        assert!(
            PacketConnectedProgram::prepare_model_state_retained_into(&mut incoming, &mut attempt)
                .is_err()
        );
        let actual = attempt.as_ref().unwrap();
        let bytes = serde_json::to_vec(&actual.borrowed_settled_model_data()).unwrap();
        let mut bank = MetadataRecordBank::reserve(2048).unwrap();
        let mut observer = MetadataObserver::recording(&mut bank);
        observer.observe(actual).unwrap();
        let facts = observer.finish();
        let encoded = serde_json::to_vec(&bank).unwrap();
        let rows =
            ValidatedMetadataRecords::validate(&encoded, facts.capacity_records, 64 * 1024 * 1024)
                .unwrap();
        let limits = HistoricalJsonLimits {
            maximum_input_bytes: 262_144,
            maximum_nodes: 16_384,
            maximum_depth: 64,
            maximum_owned_backing_bytes: 64 * 1024 * 1024,
            maximum_tree_entries: 4096,
        };

        let mut preflight = Ledger::new(rows.rows(), limits);
        assert!(
            preflight
                .read::<ReactiveAdoption17Data>(&bytes, false)
                .unwrap()
                .is_none()
        );
        assert!(preflight.rows.next().is_none());
        let mut reconstruction = Ledger::new(rows.rows(), limits);
        let retained = Some(
            reconstruction
                .read::<ReactiveAdoption17Data>(&bytes, true)
                .unwrap()
                .unwrap(),
        );
        assert!(reconstruction.rows.next().is_none());
        let decoded = retained.as_ref().unwrap();

        assert_eq!(serde_json::to_vec(decoded).unwrap(), bytes);
        assert!(decoded.snapshot.is_some());
        assert!(decoded.state.as_ref().unwrap().0.failed);
        assert_eq!(
            decoded.state.as_ref().unwrap().0.reactions,
            original.reactions
        );
        assert!(decoded.reactions.is_empty());
        assert!(decoded.completed.is_none());
        assert!(!decoded.ready);
        let mut observed = MetadataObserver::new();
        observed.observe(decoded).unwrap();
        assert_eq!(observed.finish(), facts);
    }

    #[test]
    fn actual_completed_reactive_adopter_preserves_program_metadata_without_wrapper_nodes() {
        let (effect, _peer) = UnixDatagram::pair().unwrap();
        let endpoint = |node| Endpoint {
            node_id: Id::new(node).unwrap(),
            port_id: Id::new("packet-port").unwrap(),
            lane_id: Id::new("packet-lane").unwrap(),
        };
        let definition = PacketConnectedDefinition {
            schema: "source-owned.packet-connected-program/4".to_owned(),
            connections: vec![PacketInputConnection {
                id: Id::new("completed-reactive-connection").unwrap(),
                policy: canonical::content_ref(b"logical policy", "application/json").unwrap(),
                producer: endpoint("reader-producer"),
                consumer: endpoint("reader-reactive"),
                delay_ps: U64::new(0),
            }],
            output: None,
        };
        let original = PacketConnectedProgram::new(definition, effect).unwrap();
        let snapshot = original.capture_state(original.reached, 262_144).unwrap();
        let mut incoming = Some(
            crate::reference_packet::continuation_models::decode_packet_model_snapshot(
                snapshot.bytes(),
                snapshot.reference(),
                262_144,
            )
            .unwrap(),
        );
        let mut attempt = None;
        PacketConnectedProgram::prepare_model_state_retained_into(&mut incoming, &mut attempt)
            .unwrap();
        let (effect, _peer) = UnixDatagram::pair().unwrap();
        let mut effect = Some(effect);
        attempt
            .as_mut()
            .unwrap()
            .bind_original_socket(&mut effect)
            .unwrap();
        let actual = attempt.as_ref().unwrap();
        let bytes = serde_json::to_vec(&actual.borrowed_settled_model_data()).unwrap();
        let mut bank = MetadataRecordBank::reserve(2048).unwrap();
        let mut observer = MetadataObserver::recording(&mut bank);
        observer.observe(actual).unwrap();
        let facts = observer.finish();
        let encoded = serde_json::to_vec(&bank).unwrap();
        let rows =
            ValidatedMetadataRecords::validate(&encoded, facts.capacity_records, 64 * 1024 * 1024)
                .unwrap();
        let limits = HistoricalJsonLimits {
            maximum_input_bytes: 262_144,
            maximum_nodes: 16_384,
            maximum_depth: 64,
            maximum_owned_backing_bytes: 64 * 1024 * 1024,
            maximum_tree_entries: 4096,
        };

        let mut preflight = Ledger::new(rows.rows(), limits);
        assert!(
            preflight
                .read::<ReactiveAdoption17Data>(&bytes, false)
                .unwrap()
                .is_none()
        );
        assert!(preflight.rows.next().is_none());
        let mut reconstruction = Ledger::new(rows.rows(), limits);
        let retained = reconstruction
            .read::<ReactiveAdoption17Data>(&bytes, true)
            .unwrap()
            .unwrap();
        assert!(reconstruction.rows.next().is_none());

        assert!(effect.is_none());
        assert!(retained.snapshot.is_some());
        assert!(retained.state.is_none());
        assert!(retained.completed.is_some());
        assert_eq!(serde_json::to_vec(&retained).unwrap(), bytes);
        let mut observed = MetadataObserver::new();
        observed.observe(&retained).unwrap();
        assert_eq!(observed.finish(), facts);
    }
}

// The new17 owning path keeps typed children in the outer attempt on errors.
#[path = "prepared/retained.rs"]
pub(in crate::reference_packet) mod retained;
