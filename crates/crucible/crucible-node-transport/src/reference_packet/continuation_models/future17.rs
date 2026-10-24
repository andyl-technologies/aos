//! Projects actual decoded model inventory without a second typed state parse.
//!
//! The enclosing Initial15 reader retains the complete validated Control/model
//! owner. This borrowed Value walk supplies geometry DATA only; it cannot prove
//! a current native owner, custody or a native phase allowance.

use super::*;
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection as Projection;
use serde_json::{Map, Value};
use std::mem::size_of;

impl PacketDecodedModelSnapshot {
    /// Returns the retained model kind for a closed prospective DATA visitor.
    pub(crate) fn capture17_future_kind_data(&self) -> PacketModelKind {
        self.record.kind
    }

    /// Projects the actual final inventory without cloning or deserializing state.
    ///
    /// The defining full Control decoder's retained result is the intended
    /// caller. Structural refusal here remains independent of native authority.
    ///
    /// # Errors
    /// Refuses missing/wrong field kinds, failed or incomplete state, invalid
    /// pending coordinates, counter overflow or a short supplied maximum.
    pub(crate) fn project_capture17_inventory_future_data(
        &self,
        out: &mut Projection,
    ) -> Result<(), ProviderError> {
        let state = self.record.state.as_object().ok_or_else(refused)?;
        if field(state, "failed")?.as_bool() != Some(false) {
            return Err(refused());
        }
        for grant in field(state, "grants")?
            .as_object()
            .ok_or_else(refused)?
            .values()
        {
            if grant.get("complete").and_then(Value::as_bool) != Some(true) {
                return Err(refused());
            }
        }

        out.add_object()?;
        match self.record.kind {
            PacketModelKind::Producer => {
                for name in [
                    "reached",
                    "gate_closed",
                    "pending",
                    "retained_outputs",
                    "private_mutations",
                    "packet_effects",
                ] {
                    out.add_field(name)?;
                }
                out.add_value(field(state, "reached")?)?;
                out.add_value(field(state, "gate_closed")?)?;
                let events = field(state, "events")?.as_array().ok_or_else(refused)?;
                let next =
                    usize::try_from(field(state, "next_event")?.as_u64().ok_or_else(refused)?)
                        .map_err(|_| refused())?;
                let pending = events.get(next..).ok_or_else(refused)?;
                out.add_array_extent(pending.len())?;
                for event in pending {
                    out.add_value(event)?;
                }
                out.add_value(field(state, "outputs")?)?;
                count(out, state, "private_mutations")?;
                count(out, state, "packet_effects")
            }
            PacketModelKind::Reactive => {
                for name in [
                    "reached",
                    "gate_closed",
                    "reactions",
                    "delivered_inputs",
                    "publications",
                    "retained_outputs",
                    "reactions_completed",
                    "packet_effects",
                    "stages",
                    "commits",
                ] {
                    out.add_field(name)?;
                }
                for name in [
                    "reached",
                    "gate_closed",
                    "reactions",
                    "delivered_inputs",
                    "publications",
                    "outputs",
                ] {
                    out.add_value(field(state, name)?)?;
                }
                count(out, state, "reactions_completed")?;
                count(out, state, "packet_effects")?;
                let stages = field(state, "stages")?.as_array().ok_or_else(refused)?;
                out.add_array_extent(stages.len())?;
                let mut committed = 0usize;
                for stage in stages {
                    out.add_value(stage.get("record_ref").ok_or_else(refused)?)?;
                    if !stage.get("commit").ok_or_else(refused)?.is_null() {
                        committed = committed.checked_add(1).ok_or_else(refused)?;
                    }
                }
                out.add_array_extent(committed)?;
                for stage in stages {
                    let commit = stage.get("commit").ok_or_else(refused)?;
                    if !commit.is_null() {
                        out.add_value(commit.get("record_ref").ok_or_else(refused)?)?;
                    }
                }
                Ok(())
            }
        }
    }

    /// Names typed payload formatter demand from the actual decoded inventory.
    ///
    /// The retained Value already contains canonical base64 text. The exact
    /// closed payload paths below are the future inventory's typed Bytes leaves;
    /// their text lengths bound each separately live formatter bank without
    /// decoding them again. Historical grants and unrelated raw banks are not
    /// treated as current inventory payloads.
    ///
    /// # Errors
    /// Refuses missing or wrongly typed fields and invalid pending coordinates.
    pub(crate) fn capture17_inventory_future_formatter_data(&self) -> Result<usize, ProviderError> {
        let state = self.record.state.as_object().ok_or_else(refused)?;
        let mut maximum = 0usize;
        match self.record.kind {
            PacketModelKind::Producer => {
                let events = array(state, "events")?;
                let next =
                    usize::try_from(field(state, "next_event")?.as_u64().ok_or_else(refused)?)
                        .map_err(|_| refused())?;
                for event in events.get(next..).ok_or_else(refused)? {
                    maximum = maximum.max(payload(event, true)?);
                }
                for output in array(state, "outputs")? {
                    maximum = maximum.max(payload(output, false)?);
                }
            }
            PacketModelKind::Reactive => {
                for reaction in array(state, "reactions")? {
                    maximum = maximum.max(payload(reaction, false)?);
                }
                for delivery in array(state, "delivered_inputs")? {
                    maximum = maximum.max(payload(
                        delivery.get("reaction").ok_or_else(refused)?,
                        false,
                    )?);
                }
                for publication in array(state, "publications")? {
                    maximum = maximum.max(payload(
                        publication.get("reaction").ok_or_else(refused)?,
                        false,
                    )?);
                }
                for output in array(state, "outputs")? {
                    maximum =
                        maximum.max(payload(output.get("output").ok_or_else(refused)?, false)?);
                    let pending = output.get("pending").ok_or_else(refused)?;
                    maximum = maximum.max(payload(
                        pending.get("reaction").ok_or_else(refused)?,
                        false,
                    )?);
                }
            }
        }
        Ok(maximum)
    }

    /// Names the actual borrowed field, map and array iterator controls.
    pub(crate) fn capture17_inventory_future_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<Projection>()
            + size_of::<&Map<String, Value>>()
            + size_of::<&Value>() * 4
            + size_of::<&[Value]>() * 2
            + size_of::<&Vec<Value>>()
            + size_of::<serde_json::map::Values<'static>>()
            + size_of::<std::slice::Iter<'static, Value>>() * 2
            + size_of::<[&str; 10]>()
            + size_of::<std::array::IntoIter<&'static str, 10>>()
            + size_of::<[&str; 6]>()
            + size_of::<std::array::IntoIter<&'static str, 6>>()
            + size_of::<std::ops::RangeFrom<usize>>()
            + size_of::<Option<&'static [Value]>>()
            + size_of::<usize>() * 2
            + size_of::<U64>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<&'static Value, ProviderError>>()
            + size_of::<Option<&'static Value>>()
            + size_of::<Result<&'static [Value], ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<bool>()
            + size_of::<&String>()
            + size_of::<Option<u64>>()
            + size_of::<Result<usize, std::num::TryFromIntError>>()
            + size_of::<&str>()
            + crate::retained_metadata::serialization_storage::original_serialization_counter_scratch_data()
    }
}

fn field<'a>(state: &'a Map<String, Value>, name: &str) -> Result<&'a Value, ProviderError> {
    state.get(name).ok_or_else(refused)
}

fn array<'a>(state: &'a Map<String, Value>, name: &str) -> Result<&'a [Value], ProviderError> {
    match field(state, name)? {
        Value::Array(values) => Ok(values),
        _ => Err(refused()),
    }
}

// Only PacketEvent permits a null payload. The other inventory payload leaves
// are required Bytes; their already-decoded text is the formatter's exact extent.
fn payload(value: &Value, optional: bool) -> Result<usize, ProviderError> {
    match value.get("payload").ok_or_else(refused)? {
        Value::String(text) => Ok(text.len()),
        Value::Null if optional => Ok(0),
        _ => Err(refused()),
    }
}

fn count(
    out: &mut Projection,
    state: &Map<String, Value>,
    name: &str,
) -> Result<(), ProviderError> {
    let value = field(state, name)?.as_u64().ok_or_else(refused)?;
    out.add_value(&U64::new(value))
}

fn refused() -> ProviderError {
    ProviderError::Correlation("decoded Capture17 inventory geometry")
}

// Future payload additions must update the defining raw-field walk. These
// exhaustive borrowed patterns construct no model and perform no validation.
const _: fn(
    &PacketEvent,
    &PacketPublication,
    &crate::reference_packet::connected::PacketReaction,
    &crate::reference_packet::connected::PacketDeliveredInput,
    &crate::reference_packet::connected::PacketPendingPublication,
    &crate::reference_packet::connected::PacketConnectedPublication,
) = |event, publication, reaction, delivery, pending, connected_output| {
    let PacketEvent {
        id: _,
        evaluation: _,
        completion: _,
        payload: _,
    } = event;
    let PacketPublication {
        event: _,
        operation: _,
        sequence: _,
        evaluation: _,
        publication: _,
        payload: _,
    } = publication;
    let crate::reference_packet::connected::PacketReaction {
        input_event: _,
        input_producer: _,
        input_sequence: _,
        stage_operation: _,
        commit_request: _,
        payload: _,
        parent: _,
        evaluation: _,
    } = reaction;
    let crate::reference_packet::connected::PacketDeliveredInput {
        reaction: _,
        delivery_operation: _,
    } = delivery;
    let crate::reference_packet::connected::PacketPendingPublication {
        event: _,
        reaction: _,
        reaction_operation: _,
        publication: _,
    } = pending;
    let crate::reference_packet::connected::PacketConnectedPublication {
        output: _,
        pending: _,
    } = connected_output;
};

const _: fn(&PacketInventory, &crate::reference_packet::connected::PacketConnectedInventory) =
    |producer, reactive| {
        let PacketInventory {
            reached: _,
            gate_closed: _,
            pending: _,
            retained_outputs: _,
            private_mutations: _,
            packet_effects: _,
        } = producer;
        let crate::reference_packet::connected::PacketConnectedInventory {
            reached: _,
            gate_closed: _,
            reactions: _,
            delivered_inputs: _,
            publications: _,
            retained_outputs: _,
            reactions_completed: _,
            packet_effects: _,
            stages: _,
            commits: _,
        } = reactive;
    };

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained_metadata::serialization_storage::actual_serialization_storage_data;
    use serde_json::json;

    const MAXIMUM: usize = 64 * 1024 * 1024;
    const FULL_WIDTH_MODEL_COUNTER: u64 = 10_000_000_000_000_000_000;

    // These are genuine bounded model decodes used for geometry DATA only.
    // They deliberately do not claim the enclosing full Control/native seal.
    fn decoded(kind: &str, state: Value) -> PacketDecodedModelSnapshot {
        let configuration = canonical::content_ref(b"{}", "application/json").unwrap();
        let value = json!({
            "schema": MODEL_SCHEMA,
            "kind": kind,
            "captured_process": "1",
            "configuration": configuration,
            "cut": {"time_ps":"0", "microstep":"0", "phase":0},
            "capacities": {"events":3,"reactions":0,"delivered_inputs":0,"publications":0,"outputs":0,"stages":0},
            "state": state
        });
        let bytes = canonical::canonical_json(&value).unwrap();
        let reference = canonical::content_ref(&bytes, "application/json").unwrap();
        decode_packet_model_snapshot(&bytes, &reference, bytes.len()).unwrap()
    }

    fn projection(
        model: &PacketDecodedModelSnapshot,
    ) -> Result<
        crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
        ProviderError,
    > {
        let mut out = Projection::new(MAXIMUM)?;
        model.project_capture17_inventory_future_data(&mut out)?;
        out.finish(MAXIMUM)
    }

    fn facts(
        value: &crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
    ) -> [usize; 11] {
        let crate::retained_metadata::serialization_storage::OriginalSerializationStorageData {
            dom_and_canonical_scratch_bytes,
            retained_value_backing_bytes,
            projected_parser_requested_bytes,
            canonical_output_requested_bytes,
            serializer_temporary_requested_bytes,
            declared_counter_scratch_bytes,
            maximum_encoded_bytes,
            sequence_elements,
            sequence_containers,
            serialized_value_nodes,
            serialized_capacity_records,
        } = value;
        [
            *dom_and_canonical_scratch_bytes,
            *retained_value_backing_bytes,
            *projected_parser_requested_bytes,
            *canonical_output_requested_bytes,
            *serializer_temporary_requested_bytes,
            *declared_counter_scratch_bytes,
            *maximum_encoded_bytes,
            *sequence_elements,
            *sequence_containers,
            *serialized_value_nodes,
            *serialized_capacity_records,
        ]
    }

    #[test]
    fn decoded_producer_projects_actual_pending_suffix_and_decimal_counters() {
        let reached = json!({"time_ps":"0", "microstep":"0", "phase":0});
        let pending = json!([{"payload":"escaped \" / \u{03bb}"},{"payload":"tail"}]);
        let model = decoded(
            "producer",
            json!({
                "events":[{"payload":"already completed"},pending[0],pending[1]],
                "next_event":1,"reached":reached,"gate_closed":false,"outputs":[],
                "grants":{},"private_mutations":FULL_WIDTH_MODEL_COUNTER,"packet_effects":0,
                "retired":{},"failed":false
            }),
        );
        let expected = json!({
            "reached":reached,"gate_closed":false,"pending":pending,
            "retained_outputs":[],"private_mutations":FULL_WIDTH_MODEL_COUNTER.to_string(),
            "packet_effects":"0"
        });

        let projected = projection(&model).unwrap();
        let actual =
            actual_serialization_storage_data(&expected, Default::default(), MAXIMUM).unwrap();
        assert_eq!(facts(&projected), facts(&actual));
    }

    #[test]
    fn decoded_reactive_projects_only_actual_stage_and_commit_references() {
        let reached = json!({"time_ps":"0", "microstep":"0", "phase":0});
        let stage_a = canonical::content_ref(b"a", "application/json").unwrap();
        let stage_b = canonical::content_ref(b"b", "application/json").unwrap();
        let commit = canonical::content_ref(b"c", "application/json").unwrap();
        let model = decoded(
            "reactive",
            json!({
                "reached":reached,"gate_closed":true,"reactions":[],"delivered_inputs":[],
                "publications":[],"outputs":[],"grants":{},"failed":false,
                "reactions_completed":50,"packet_effects":FULL_WIDTH_MODEL_COUNTER,
                "stages":[{"record_ref":stage_a,"commit":null},
                    {"record_ref":stage_b,"commit":{"record_ref":commit}}]
            }),
        );
        let expected = json!({
            "reached":reached,"gate_closed":true,"reactions":[],"delivered_inputs":[],
            "publications":[],"retained_outputs":[],"reactions_completed":"50",
            "packet_effects":FULL_WIDTH_MODEL_COUNTER.to_string(),"stages":[stage_a,stage_b],"commits":[commit]
        });

        assert_eq!(
            facts(&projection(&model).unwrap()),
            facts(
                &actual_serialization_storage_data(&expected, Default::default(), MAXIMUM).unwrap()
            )
        );
    }

    #[test]
    fn numeric_model_and_typed_inventory_keep_their_distinct_integer_encodings() {
        // Model counters use JSON numbers and must survive the actual JCS
        // number round trip. This exact binary integer still has twenty digits.
        let encoded = canonical::canonical_json(&json!(FULL_WIDTH_MODEL_COUNTER)).unwrap();
        assert_eq!(encoded, b"10000000000000000000");
        let decoded = canonical::parse_json(&encoded, encoded.len()).unwrap();
        assert_eq!(decoded.as_u64(), Some(FULL_WIDTH_MODEL_COUNTER));

        // The real inventory DTO uses decimal-string U64 fields, so its full
        // u64 boundary is independent of the older numeric model grammar.
        let inventory = PacketInventory {
            reached: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
            gate_closed: false,
            pending: Vec::new(),
            retained_outputs: Vec::new(),
            private_mutations: U64::new(u64::MAX),
            packet_effects: U64::new(u64::MAX),
        };
        let value = serde_json::to_value(&inventory).unwrap();
        let encoded = canonical::canonical_json(&value).unwrap();
        let decoded = canonical::parse_json(&encoded, encoded.len()).unwrap();
        for field in ["private_mutations", "packet_effects"] {
            assert_eq!(decoded[field].as_str(), Some("18446744073709551615"));
        }
    }

    #[test]
    fn formatter_bound_uses_actual_base64_payload_paths_and_skips_completed_events() {
        let encoded =
            |bytes| serde_json::to_value(crucible_node_format::Bytes::new(vec![7; bytes])).unwrap();
        let large_completed = encoded(32_768);
        let pending = encoded(4_096);
        let retained = encoded(8_192);
        let model = decoded(
            "producer",
            json!({
                "events":[{"payload":large_completed},{"payload":pending}],"next_event":1,
                "outputs":[{"payload":retained}],"failed":false,"grants":{}
            }),
        );

        assert_eq!(
            model.capture17_inventory_future_formatter_data().unwrap(),
            retained.as_str().unwrap().len()
        );
        assert!(retained.as_str().unwrap().len() > pending.as_str().unwrap().len());

        let mut invalid = json!({"events":[],"next_event":0,"outputs":[{"payload":[]} ]});
        assert!(
            decoded("producer", invalid.clone())
                .capture17_inventory_future_formatter_data()
                .is_err()
        );
        invalid["outputs"][0]["payload"] = Value::Null;
        assert!(
            decoded("producer", invalid)
                .capture17_inventory_future_formatter_data()
                .is_err()
        );
    }

    #[test]
    fn reactive_formatter_visits_every_actual_nested_inventory_payload() {
        let encoded =
            |bytes| serde_json::to_value(crucible_node_format::Bytes::new(vec![7; bytes])).unwrap();
        for selected in 0..5 {
            let small = encoded(3);
            let large = encoded(12_289);
            let bytes = |index| {
                if index == selected {
                    large.clone()
                } else {
                    small.clone()
                }
            };
            let model = decoded(
                "reactive",
                json!({
                    "reactions":[{"payload":bytes(0)}],
                    "delivered_inputs":[{"reaction":{"payload":bytes(1)}}],
                    "publications":[{"reaction":{"payload":bytes(2)}}],
                    "outputs":[{"output":{"payload":bytes(3)},"pending":{"reaction":{"payload":bytes(4)}}}]
                }),
            );

            assert_eq!(
                model.capture17_inventory_future_formatter_data().unwrap(),
                large.as_str().unwrap().len()
            );
        }
    }

    #[test]
    fn decoded_inventory_refuses_failed_incomplete_and_impossible_pending_states() {
        let state = json!({"events":[],"next_event":0,"reached":{},"gate_closed":false,
            "outputs":[],"grants":{},"private_mutations":0,"packet_effects":0,"failed":false});
        for (field, value) in [
            ("failed", json!(true)),
            ("grants", json!({"g":{"complete":false}})),
            ("next_event", json!(1)),
        ] {
            let mut changed = state.clone();
            changed[field] = value;
            assert!(projection(&decoded("producer", changed)).is_err());
        }
    }
}

#[cfg(test)]
mod formatter_tests {
    use super::*;

    #[test]
    fn formatter_extent_matches_actual_optional_event_and_required_publication()
    -> Result<(), ProviderError> {
        let at = Position::new(U64::new(1), U64::new(0), Phase::Reaction);
        let mut event = PacketEvent {
            id: Id::new("future-payload-event")?,
            evaluation: at,
            completion: at,
            payload: None,
        };
        let absent = serde_json::to_value(&event).map_err(ContractError::from)?;
        assert_eq!(payload(&absent, true)?, 0);
        assert!(payload(&absent, false).is_err());

        let bytes = Bytes::new(vec![0, 1, 2, 3, 254, 255, 17]);
        let encoded = serde_json::to_value(&bytes).map_err(ContractError::from)?;
        let expected = encoded.as_str().ok_or_else(refused)?.len();
        event.payload = Some(bytes.clone());
        let present = serde_json::to_value(&event).map_err(ContractError::from)?;
        assert_eq!(payload(&present, true)?, expected);

        let publication = PacketPublication {
            event: event.id,
            operation: Id::new("future-payload-operation")?,
            sequence: U64::new(0),
            evaluation: at,
            publication: at,
            payload: bytes,
        };
        let required = serde_json::to_value(&publication).map_err(ContractError::from)?;
        assert_eq!(payload(&required, false)?, expected);
        Ok(())
    }

    #[test]
    fn formatter_paths_refuse_missing_and_wrong_payload_or_array_kinds() -> Result<(), ProviderError>
    {
        for invalid in [
            serde_json::json!({}),
            serde_json::json!({"payload": 1}),
            serde_json::json!({"payload": []}),
            serde_json::json!({"payload": {}}),
        ] {
            assert!(payload(&invalid, true).is_err());
            assert!(payload(&invalid, false).is_err());
        }

        for invalid in [
            serde_json::json!({}),
            serde_json::json!({"events": null}),
            serde_json::json!({"events": {}}),
        ] {
            assert!(array(invalid.as_object().ok_or_else(refused)?, "events").is_err());
        }
        let actual = serde_json::json!({"events": [null, "literal"]});
        assert_eq!(
            array(actual.as_object().ok_or_else(refused)?, "events")?.len(),
            2
        );
        Ok(())
    }
}
