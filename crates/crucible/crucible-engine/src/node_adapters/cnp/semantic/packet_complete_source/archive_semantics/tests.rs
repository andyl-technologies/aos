//! Checks closed historical decoding without constructing native permissions.

use super::*;
use serde_json::{Value, json};

fn semantic() -> Value {
    json!({
        "schema": "source-owned.packet-semantic-custody/5",
        "arm_attempt": null,
        "ready": null,
        "prepared_owner": null,
        "activate_response": null,
        "observe_sequence": "9",
        "activation_attempt": null,
        "active": null,
        "inputs": {},
        "operations": {},
        "watermark": "3",
        "observation": null,
        "reclaimed": null,
        "retained_credit": 1234,
        "quarantined": true
    })
}

fn ancestry() -> Value {
    json!({"schema": "source-owned.packet-original-ancestry/5", "lineages": []})
}

fn with_operation() -> Result<Value, Box<dyn std::error::Error>> {
    use crate::node_contract::{OperationOutcome, ProgressEvidence, SavedRuntimeActivation};

    let admission = crate::node_contract::test_original_admission("archive-common-data");
    let route = admission.token().route();
    let activation: SavedRuntimeActivation = admission.activation().record().into();
    let receipt = canonical::content_ref(b"historical-only", "application/octet-stream")?;
    let outcome = OperationOutcome {
        operation: admission.token().operation().clone(),
        node: route.node.clone(),
        owners: route.owners.clone(),
        progress: ProgressEvidence::Paused {
            reached: None,
            stop_receipt: receipt,
        },
        retained_outputs: Vec::new(),
        scheduling: None,
    };
    let begin = crucible_node_transport::bodies::BeginRequest {
        kind: crucible_node_transport::bodies::BeginKind::Pause,
        binding_hash: canonical::json_hash("cnp.owner-binding.v1", &"historical-only")?,
        owner_generation: route.owners[0].generation,
        activation_id: crucible_node_transport::envelope::Nullable(Some(
            activation.activation_id.clone(),
        )),
        world_generation: activation.generation,
        arguments: serde_json::Map::new(),
        extensions: crucible_node_format::Extensions::new(),
    };
    let operation = json!({
        "operation": admission.token().operation(), "route": route,
        "request": admission.request(), "activation": activation, "inputs": null,
        "begin": begin, "outcome": outcome, "failure": null, "polls": "0",
        "begin_acknowledged": false, "cancellation": ["not-attempted", null],
        "acknowledged": false, "retirement": null
    });
    let mut value = semantic();
    value["operations"][admission.token().operation().as_str()] = operation;
    Ok(value)
}

#[test]
fn nested_outcome_nulls_and_unknown_enum_fields_are_not_projected_away()
-> Result<(), Box<dyn std::error::Error>> {
    let original = with_operation()?;
    let ancestry = encoded(&ancestry())?;
    let decode = |value: &Value| -> Result<bool, Box<dyn std::error::Error>> {
        Ok(PacketCompleteArchivedSemantics::decode_data(
            &encoded(value)?,
            &ancestry,
            65_536,
            0,
            64 * 1024 * 1024,
        )
        .is_ok())
    };
    assert!(decode(&original)?);

    for change in ["scheduling", "reached", "extra"] {
        let mut changed = original.clone();
        let outcome = changed["operations"]
            .as_object_mut()
            .ok_or("operation map absent")?
            .values_mut()
            .next()
            .ok_or("operation absent")?
            .get_mut("outcome")
            .ok_or("outcome absent")?;
        if change == "scheduling" {
            outcome
                .as_object_mut()
                .ok_or("outcome map absent")?
                .remove("scheduling");
        } else if change == "reached" {
            outcome["progress"]["Paused"]
                .as_object_mut()
                .ok_or("paused map absent")?
                .remove("reached");
        } else {
            outcome["progress"]["Paused"]["extra"] = json!("must remain visible");
        }
        assert!(!decode(&changed)?, "changed {change}");
    }
    Ok(())
}

fn encoded(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(canonical::canonical_json(value)?)
}

#[test]
fn complete_fields_roundtrip_without_granting_a_runtime_activation()
-> Result<(), Box<dyn std::error::Error>> {
    let before = semantic();
    let ancestry_before = ancestry();
    let semantic_bytes = encoded(&before)?;
    let ancestry_bytes = encoded(&ancestry_before)?;

    let owner = PacketCompleteArchivedSemantics::decode_data(
        &semantic_bytes,
        &ancestry_bytes,
        65_536,
        0,
        64 * 1024 * 1024,
    )
    .map_err(|error| error.reason)?;

    assert_eq!(serde_json::to_value(&owner.semantic)?, before);
    assert_eq!(serde_json::to_value(&owner.ancestry)?, ancestry_before);
    assert!(owner.semantic.active.is_none());
    assert!(owner.semantic.quarantined);
    assert_eq!(owner.semantic.retained_credit, 1234);
    Ok(())
}

#[test]
fn nullable_omission_unknown_fields_and_duplicate_keys_refuse()
-> Result<(), Box<dyn std::error::Error>> {
    let ancestry = encoded(&ancestry())?;
    for field in [
        "arm_attempt",
        "ready",
        "prepared_owner",
        "activate_response",
        "activation_attempt",
        "active",
        "observation",
        "reclaimed",
    ] {
        let mut missing = semantic();
        missing
            .as_object_mut()
            .ok_or("expected fixture map")?
            .remove(field);
        let missing = encoded(&missing)?;
        assert!(
            PacketCompleteArchivedSemantics::decode_data(
                &missing,
                &ancestry,
                65_536,
                0,
                64 * 1024 * 1024,
            )
            .is_err(),
            "missing {field}"
        );
    }
    let mut unknown = semantic();
    unknown["unretained_future_state"] = json!(true);
    let unknown = encoded(&unknown)?;
    assert!(
        PacketCompleteArchivedSemantics::decode_data(
            &unknown,
            &ancestry,
            65_536,
            0,
            64 * 1024 * 1024,
        )
        .is_err()
    );
    assert!(
        PacketCompleteArchivedSemantics::decode_data(
            br#"{"schema":"first","schema":"second"}"#,
            &ancestry,
            65_536,
            0,
            64 * 1024 * 1024,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn both_decoder_owners_and_additional_storage_must_fit_before_parse()
-> Result<(), Box<dyn std::error::Error>> {
    let semantic = encoded(&semantic())?;
    let ancestry = encoded(&ancestry())?;
    let demand = PacketCompleteArchivedSemantics::decode_demand_data(
        &semantic,
        &ancestry,
        65_536,
        64 * 1024 * 1024,
    )
    .map_err(|error| error.reason)?;

    assert!(
        PacketCompleteArchivedSemantics::decode_data(&semantic, &ancestry, 65_536, 0, demand,)
            .is_ok()
    );
    assert!(
        PacketCompleteArchivedSemantics::decode_data(&semantic, &ancestry, 65_536, 1, demand,)
            .is_err()
    );
    assert!(
        PacketCompleteArchivedSemantics::decode_data(
            &semantic,
            &ancestry,
            semantic.len() - 1,
            0,
            demand,
        )
        .is_err()
    );
    assert!(
        PacketCompleteArchivedSemantics::decode_data(
            &semantic,
            &ancestry,
            65_536,
            usize::MAX,
            demand,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn reference_ancestry_schema_selects_one_grammar_and_preserves_reference_roles()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::node_contract::SavedRuntimeActivation;
    use crucible_node_format::{Endpoint, Event, EventStage, Extensions, Phase, Position};

    let admission = crate::node_contract::test_original_admission("archive-reference-grammar");
    let route = admission.token().route();
    let activation: SavedRuntimeActivation = admission.activation().record().into();
    let body = b"body remains in verified content";
    let reference = canonical::content_ref(body, "application/octet-stream")?;
    let position = Position::new(5.into(), 1.into(), Phase::Publication);
    let endpoint = Endpoint {
        node_id: route.node.clone(),
        port_id: Id::new("data")?,
        lane_id: Id::new("output")?,
    };
    let event = Event {
        schema_version: 1,
        id: Id::new("original-publication")?,
        source: endpoint.clone(),
        destination: endpoint,
        position,
        stage: EventStage::Publication,
        publication_position: position,
        delivery_position: None,
        source_sequence: 7.into(),
        causal_parent_ids: Vec::new(),
        payload: reference.clone(),
        provenance_ref: reference.clone(),
        extensions: Extensions::new(),
    };
    let owner = &route.owners[0];
    let batch = json!({
        "activation": activation, "node": route.node,
        "stage_operation": "original-stage", "batch": "original-batch",
        "owners": route.owners, "cutoff": position, "inventory": reference,
        "deliveries": [], "payloads": []
    });
    let mut scope = batch.clone();
    let scope_map = scope.as_object_mut().ok_or("scope map absent")?;
    let activation = scope_map.remove("activation").ok_or("activation absent")?;
    scope_map.insert("source_activation".into(), activation);
    scope_map.remove("deliveries");
    scope_map.remove("payloads");
    let original = json!({
        "schema": "source-owned.packet-original-ancestry/12",
        "lineages": [{
            "source_scope": scope, "original": batch,
            "publications": [{
                "event": event,
                "origin": {
                    "owner_binding_hash": canonical::json_hash("cnp.owner-binding.v1", &"data")?,
                    "execution_owner_id": owner.owner, "session_id": "original-session",
                    "world_binding_hash": admission.activation().record().world_binding_hash,
                    "activation_id": admission.activation().record().activation_id,
                    "world_generation": admission.activation().record().generation,
                    "incarnation_id": owner.incarnation, "owner_generation": owner.generation,
                    "operation_id": "original-operation", "grant_id": "original-grant",
                    "observation_batch": reference, "stop_receipt": reference,
                    "measurement": reference
                },
                "published": reference, "objects": [reference],
                "rows": [{"object": reference, "dependencies": []}]
            }]
        }]
    });
    let semantic = encoded(&semantic())?;
    let decode =
        |value: &Value| -> Result<PacketCompleteArchivedSemantics, Box<dyn std::error::Error>> {
            Ok(PacketCompleteArchivedSemantics::decode_data(
                &semantic,
                &encoded(value)?,
                65_536,
                0,
                64 * 1024 * 1024,
            )
            .map_err(|error| error.reason)?)
        };
    let owner = decode(&original)?;
    assert_eq!(serde_json::to_value(&owner.ancestry)?, original);
    let record = owner
        .source_reference_ancestry_data()
        .map_err(|error| error.reason)?;
    assert_eq!(
        record.lineages[0].publications[0].objects,
        [reference.clone()]
    );

    // A schema change must not reinterpret a reference as an inline payload.
    let mut changed = original.clone();
    changed["schema"] = json!("source-owned.packet-original-ancestry/5");
    assert!(decode(&changed).is_err());
    changed["lineages"][0]["publications"][0]["objects"][0] =
        json!({"reference": reference, "bytes": body});
    let inline = decode(&changed)?;
    assert!(inline.source_reference_ancestry_data().is_err());
    assert_eq!(serde_json::to_value(&inline.ancestry)?, changed);

    changed["schema"] = json!("source-owned.packet-original-ancestry/12");
    assert!(decode(&changed).is_err());
    changed["schema"] = json!("source-owned.packet-original-ancestry/13");
    assert!(decode(&changed).is_err());
    Ok(())
}
