//! Exercises exact inventory codec identity and pre-copy aggregate credits.
//!
//! These synthetic data controls issue no native input or preservation authority.

use super::*;
use crate::node_scheduling::event::Delivery;
use crucible_node_contract::{Id, Phase, Position, U64};

type ModelResult = Result<(), StateError>;

#[test]
fn original_empty_inventory_is_retained_as_a_known_codec_leaf() -> ModelResult {
    let input = input(Vec::new())?;
    let inputs = [input];
    let reserved = credit(&inputs, StateLimits::default())?;
    let prepared = prepare(&inputs, &reserved)?;

    assert_eq!(prepared.len(), 1);
    assert_eq!(prepared[0].body.bytes, b"[]");
    assert_eq!(prepared[0].body.reference, inputs[0].inventory);
    assert!(prepared[0].dependencies.is_empty());
    Ok(())
}

#[test]
fn original_nonempty_inventory_keeps_all_three_positive_full_reference_roles() -> ModelResult {
    let delivery = delivery()?;
    let expected = [
        delivery.payload.clone(),
        delivery.provenance_ref.clone(),
        delivery
            .connection_policy_ref
            .clone()
            .ok_or_else(|| refused("fixture policy absent"))?,
    ];
    let inputs = [input(vec![delivery])?];
    let reserved = credit(&inputs, StateLimits::default())?;
    let prepared = prepare(&inputs, &reserved)?;

    assert_eq!(prepared[0].body.reference, inputs[0].inventory);
    assert_eq!(prepared[0].dependencies.len(), 3);
    for reference in expected {
        assert!(prepared[0].dependencies.contains(&reference));
    }
    Ok(())
}

#[test]
fn changed_original_media_or_delivery_encoding_refuses() -> ModelResult {
    let mut inputs = [input(Vec::new())?];
    inputs[0].inventory.media_type = "application/json".into();
    assert!(credit(&inputs, StateLimits::default()).is_err());

    inputs[0].inventory.media_type = INVENTORY_MEDIA.into();
    inputs[0].deliveries.push(delivery()?);
    // The borrowed count refuses the two-byte extent before body preparation.
    assert!(credit(&inputs, StateLimits::default()).is_err());

    let mut inputs = [input(vec![delivery()?])?];
    inputs[0].inventory.hash.digest = "0".repeat(64);
    let reserved = credit(&inputs, StateLimits::default())?;
    assert!(prepare(&inputs, &reserved).is_err());
    Ok(())
}

#[test]
fn complete_inventory_occurrences_charge_object_and_byte_credit() -> ModelResult {
    let inputs = [input(Vec::new())?, input(Vec::new())?, input(Vec::new())?];
    let mut limits = StateLimits {
        maximum_content_objects: 2,
        ..StateLimits::default()
    };
    assert!(credit(&inputs, limits).is_err());

    limits.maximum_content_objects = 3;
    limits.maximum_total_content_bytes = 5;
    assert!(credit(&inputs, limits).is_err());

    limits.maximum_total_content_bytes = 6;
    let reserved = credit(&inputs, limits)?;
    assert_eq!(reserved.objects, 3);
    assert_eq!(reserved.bytes, 6);
    Ok(())
}

#[test]
fn original_inventory_aggregate_edges_refuse_before_body_preparation() -> ModelResult {
    let inputs = [input(vec![delivery()?])?, input(vec![delivery()?])?];
    let mut limits = StateLimits {
        maximum_dependency_edges: 5,
        ..StateLimits::default()
    };
    assert!(credit(&inputs, limits).is_err());

    limits.maximum_dependency_edges = 6;
    let reserved = credit(&inputs, limits)?;
    assert_eq!(prepare(&inputs, &reserved)?.len(), 2);
    Ok(())
}

#[test]
fn missing_positive_connection_policy_has_no_empty_row_fallback() -> ModelResult {
    let mut delivery = delivery()?;
    delivery.connection_policy_ref = None;
    let inputs = [input(vec![delivery])?];

    assert!(credit(&inputs, StateLimits::default()).is_err());
    Ok(())
}

fn input(deliveries: Vec<Delivery>) -> Result<OriginalLineageInputRecord, StateError> {
    let bytes = canonical::canonical_json(&serde_json::to_value(&deliveries).map_err(schema)?)
        .map_err(schema)?;
    Ok(OriginalLineageInputRecord {
        node: Id::new("consumer").map_err(schema)?,
        stage_operation: Id::new("stage/consumer/0").map_err(schema)?,
        batch: Id::new("batch/consumer/0").map_err(schema)?,
        owners: Vec::new(),
        cutoff: Position::new(U64::new(1), U64::new(0), Phase::BoundaryControl),
        inventory: canonical::content_ref(&bytes, INVENTORY_MEDIA).map_err(schema)?,
        deliveries,
        payloads: Vec::new(),
        provenance: None,
        lineage: None,
        acknowledgement: None,
        failure: None,
        committed: false,
        coordinator_committed: false,
    })
}

fn delivery() -> Result<Delivery, StateError> {
    // This closed synthetic Delivery supplies typed identities only. No source
    // publication, native receipt or installed connection is authenticated here.
    let payload = canonical::content_ref(b"payload", "application/octet-stream").map_err(schema)?;
    let measurement = canonical::content_ref(b"measurement", "application/json").map_err(schema)?;
    let policy = canonical::content_ref(b"policy", "application/json").map_err(schema)?;
    serde_json::from_value(serde_json::json!({
        "publication_id":"event/0", "producer":"producer", "consumer":"consumer",
        "producer_endpoint":{"node_id":"producer","port_id":"data","lane_id":"output"},
        "consumer_endpoint":{"node_id":"consumer","port_id":"data","lane_id":"input"},
        "connection_id":"connection/producer/consumer", "connection_policy_ref":policy,
        "provenance_ref":measurement, "external_root":null, "native_sequence":"1",
        "source_sequence":"0", "evaluation":null, "causal_parents":[],
        "publication":{"time_ps":"0","microstep":"0","phase":1},
        "delivery":{"time_ps":"0","microstep":"0","phase":2}, "payload":payload,
    }))
    .map_err(schema)
}
