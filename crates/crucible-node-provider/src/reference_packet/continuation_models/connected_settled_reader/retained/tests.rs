//! Exercises later grammar, target and correspondence errors without live actors.

use super::*;
use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
use crate::retained_metadata::records::{MetadataRecordBank, ValidatedMetadataRecords};

fn limits() -> HistoricalJsonLimits {
    HistoricalJsonLimits {
        maximum_input_bytes: 4 * 1024 * 1024,
        maximum_nodes: 131072,
        maximum_depth: 64,
        maximum_owned_backing_bytes: 64 * 1024 * 1024,
        maximum_tree_entries: 32768,
    }
}

fn actual_model(output_capacity: usize) -> Result<ReactiveModel17Data, ProviderError> {
    let endpoint = |name| -> Result<Endpoint, ProviderError> {
        Ok(Endpoint {
            node_id: Id::new(name)?,
            port_id: Id::new("retained-port")?,
            lane_id: Id::new("retained-lane")?,
        })
    };
    let definition = PacketConnectedDefinition {
        schema: "source-owned.packet-connected-program/4".to_owned(),
        connections: vec![PacketInputConnection {
            id: Id::new("retained-connection")?,
            policy: canonical::content_ref(b"inert-policy", "application/json")?,
            producer: endpoint("retained-producer")?,
            consumer: endpoint("retained-consumer")?,
            delay_ps: U64::new(0),
        }],
        output: None,
    };
    let mut payload = Vec::with_capacity(61);
    payload.extend_from_slice(b"pending-before-late-error");
    let mut reactions = Vec::with_capacity(7);
    reactions.push(PacketReaction {
        input_event: Id::new("retained-input")?,
        input_producer: Id::new("retained-producer")?,
        input_sequence: U64::new(0),
        stage_operation: Id::new("retained-stage")?,
        commit_request: Id::new("retained-commit")?,
        payload: Bytes::new(payload),
        parent: Position::new(U64::new(5), U64::new(0), Phase::Delivery),
        evaluation: Position::new(U64::new(5), U64::new(0), Phase::Reaction),
    });
    Ok(ReactiveModel17Data(ConnectedState {
        definition,
        native_pid: 0,
        reached: Position::new(U64::new(5), U64::new(0), Phase::Reaction),
        gate_closed: false,
        reactions,
        delivered_inputs: Vec::with_capacity(11),
        publications: Vec::with_capacity(13),
        outputs: Vec::with_capacity(output_capacity),
        stages: Vec::with_capacity(19),
        grants: BTreeMap::new(),
        retired: BTreeMap::new(),
        reactions_completed: 0,
        packet_effects: 0,
        failed: true,
    }))
}

fn source_rows(actual: &ReactiveModel17Data) -> Result<(Vec<u8>, usize), ProviderError> {
    let mut bank = MetadataRecordBank::reserve(4096)?;
    let mut observer = MetadataObserver::recording(&mut bank);
    actual.observe_settled_history_metadata_data(&mut observer)?;
    let facts = observer.finish();
    Ok((
        serde_json::to_vec(&bank).map_err(crucible_node_contract::ContractError::from)?,
        facts.capacity_records,
    ))
}

struct ProgramView<'a>(&'a ReactiveModel17Data);
impl Serialize for ProgramView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize_program17_data(serializer)
    }
}

#[test]
fn final_program_role_error_keeps_same_payload_and_every_prior_vector_capacity()
-> Result<(), ProviderError> {
    let actual = actual_model(17)?;
    let input = serde_json::to_vec(&ProgramView(&actual))
        .map_err(crucible_node_contract::ContractError::from)?;
    let (encoded, count) = source_rows(&actual)?;
    let rows =
        ValidatedMetadataRecords::validate(&encoded, count, limits().maximum_owned_backing_bytes)?;
    let changed = std::str::from_utf8(&input)
        .map_err(|_| invalid())?
        .replacen(
            "\"effect_socket_role\":\"model-effect-socket\"",
            "\"effect_socket_role\":\"invalid-effect-role\"",
            1,
        );
    assert_ne!(changed.as_bytes(), input);
    let mut ledger = Ledger::new(rows.rows(), limits());
    ledger.begin_native17_targets_data(limits().maximum_owned_backing_bytes)?;
    ledger.native17_target_embedded_root_data()?;
    let mut attempt = ReactiveModel17ReadAttempt::default();
    assert!(
        attempt
            .read_fields_into_data(changed.as_bytes(), &mut ledger, true)
            .is_err()
    );
    let reactions = attempt.reactions.as_ref().ok_or_else(invalid)?;
    assert_eq!(reactions.capacity(), 7);
    assert_eq!(reactions[0].payload.allocation_capacity(), 61);
    let pointer = reactions[0].payload.as_slice().as_ptr();
    assert_eq!(
        attempt
            .delivered_inputs
            .as_ref()
            .ok_or_else(invalid)?
            .capacity(),
        11
    );
    assert_eq!(
        attempt
            .publications
            .as_ref()
            .ok_or_else(invalid)?
            .capacity(),
        13
    );
    assert_eq!(attempt.outputs.as_ref().ok_or_else(invalid)?.capacity(), 17);
    assert_eq!(attempt.stages.as_ref().ok_or_else(invalid)?.capacity(), 19);
    let mut observer = MetadataObserver::new();
    attempt.observe_attempt_data(&mut observer)?;
    let retained = observer.finish();
    let consumed = ledger.rows.encoded_position();
    assert!(
        attempt
            .read_fields_into_data(&input, &mut ledger, true)
            .is_err()
    );
    assert_eq!(ledger.rows.encoded_position(), consumed);
    assert_eq!(
        attempt.reactions.as_ref().ok_or_else(invalid)?[0]
            .payload
            .as_slice()
            .as_ptr(),
        pointer
    );
    let mut observer = MetadataObserver::new();
    attempt.observe_attempt_data(&mut observer)?;
    assert_eq!(observer.finish(), retained);
    Ok(())
}

#[test]
fn later_vector_target_refusal_keeps_earlier_reaction_and_definition() -> Result<(), ProviderError>
{
    let actual = actual_model(4096)?;
    let input = serde_json::to_vec(&actual).map_err(crucible_node_contract::ContractError::from)?;
    let (encoded, count) = source_rows(&actual)?;
    let rows =
        ValidatedMetadataRecords::validate(&encoded, count, limits().maximum_owned_backing_bytes)?;
    // Quote the exact preceding fields with their real retained child banks.
    // Outputs are the first unfunded vector, independently of later fields.
    let (prefix_requested, prefix_source_position) = {
        let mut preflight = Ledger::new(rows.rows(), limits());
        preflight.begin_native17_targets_data(limits().maximum_owned_backing_bytes)?;
        preflight.native17_target_embedded_root_data()?;
        let mut fields = Fields::object(&input)?;
        PacketConnectedDefinition::preflight_data(fields.named("definition")?, &mut preflight)?;
        u32::preflight_data(fields.named("native_pid")?, &mut preflight)?;
        Position::preflight_data(fields.named("reached")?, &mut preflight)?;
        bool::preflight_data(fields.named("gate_closed")?, &mut preflight)?;
        Vec::<PacketReaction>::preflight_data(fields.named("reactions")?, &mut preflight)?;
        Vec::<PacketDeliveredInput>::preflight_data(
            fields.named("delivered_inputs")?,
            &mut preflight,
        )?;
        Vec::<PacketPendingPublication>::preflight_data(
            fields.named("publications")?,
            &mut preflight,
        )?;
        let source_position = preflight.rows.encoded_position();
        (preflight.finish_native17_targets_data()?, source_position)
    };

    let mut ledger = Ledger::new(rows.rows(), limits());
    ledger.begin_native17_targets_data(prefix_requested)?;
    ledger.native17_target_embedded_root_data()?;
    let mut attempt = ReactiveModel17ReadAttempt::default();
    let result = ReactiveModel17Data::read_into_data(&input, &mut ledger, &mut attempt);
    assert!(matches!(
        result,
        Err(ProviderError::ResourceExhausted(
            "native17 decoded target storage"
        ))
    ));
    assert!(ledger.rows.encoded_position() > prefix_source_position);

    assert!(attempt.delivered_inputs.is_some());
    assert!(attempt.publications.is_some());
    assert!(attempt.outputs.is_none());
    assert!(attempt.stages.is_none());
    assert!(attempt.definition.is_some());
    let reactions = attempt.reactions.as_ref().ok_or_else(invalid)?;
    assert_eq!(reactions.capacity(), 7);
    assert_eq!(reactions[0].payload.allocation_capacity(), 61);
    let pointer = reactions[0].payload.as_slice().as_ptr();
    let consumed = ledger.rows.encoded_position();
    assert!(ReactiveModel17Data::read_into_data(&input, &mut ledger, &mut attempt).is_err());
    assert_eq!(ledger.rows.encoded_position(), consumed);
    assert_eq!(
        attempt.reactions.as_ref().ok_or_else(invalid)?[0]
            .payload
            .as_slice()
            .as_ptr(),
        pointer
    );
    Ok(())
}

#[test]
fn correspondence_error_keeps_completed_model_inside_attempt() -> Result<(), ProviderError> {
    let actual = actual_model(17)?;
    let input = serde_json::to_vec(&actual).map_err(crucible_node_contract::ContractError::from)?;
    let (encoded, count) = source_rows(&actual)?;
    let rows =
        ValidatedMetadataRecords::validate(&encoded, count, limits().maximum_owned_backing_bytes)?;
    let mut ledger = Ledger::new(rows.rows(), limits());
    ledger.begin_native17_targets_data(limits().maximum_owned_backing_bytes)?;
    ledger.native17_target_embedded_root_data()?;
    let mut attempt = ReactiveModel17ReadAttempt::default();
    ReactiveModel17Data::read_into_data(&input, &mut ledger, &mut attempt)?;
    let model = attempt.output_data().ok_or_else(invalid)?;
    let pointer = model.0.reactions[0].payload.as_slice().as_ptr();
    assert!(model.authenticate_current_data().is_err());
    assert_eq!(
        attempt.output_data().ok_or_else(invalid)?.0.reactions[0]
            .payload
            .as_slice()
            .as_ptr(),
        pointer
    );
    assert_eq!(
        attempt
            .output_data()
            .ok_or_else(invalid)?
            .0
            .reactions
            .capacity(),
        7
    );
    Ok(())
}
