//! Checks the exact whole source seal before any retained Event/origin copy.

use super::*;
use crucible_node_contract::{Endpoint, EventStage, Extensions, Id, Phase, Position};

#[test]
fn borrowed_whole_seal_is_byte_exact_and_undercredit_copies_nothing()
-> Result<(), Box<dyn std::error::Error>> {
    let id = Id::new("inert-original")?;
    let reference = canonical::content_ref(b"original body", "application/json")?;
    let hash = canonical::json_hash("inert.scope", &serde_json::json!({"scope": 1}))?;
    let position = Position {
        time_ps: U64::new(1000),
        microstep: U64::new(0),
        phase: Phase::Publication,
    };
    let endpoint = Endpoint {
        node_id: id.clone(),
        port_id: id.clone(),
        lane_id: id.clone(),
    };
    let event = Event {
        schema_version: 1,
        id: id.clone(),
        source: endpoint.clone(),
        destination: endpoint,
        position,
        stage: EventStage::Publication,
        publication_position: position,
        delivery_position: None,
        source_sequence: U64::new(1),
        causal_parent_ids: Vec::new(),
        payload: reference.clone(),
        provenance_ref: reference.clone(),
        extensions: Extensions::new(),
    };
    let borrowed = BorrowedWindowSeal {
        quantum: U64::new(0),
        receipt: &reference,
        checksum: U64::new(0),
        published: &reference,
        event: &event,
        origin: BorrowedOrigin {
            owner_binding_hash: &hash,
            execution_owner_id: &id,
            session_id: &id,
            world_binding_hash: &hash,
            activation_id: &id,
            world_generation: U64::new(1),
            incarnation_id: &id,
            owner_generation: U64::new(1),
            operation_id: &id,
            grant_id: &id,
            observation_batch: &reference,
            stop_receipt: &reference,
            measurement: &reference,
        },
    };
    let encoded = serde_json::to_vec(&borrowed)?;

    COPIES.with(|copies| copies.set(0));
    assert!(retain_seal(&borrowed, encoded.len() - 1).is_err());
    assert!(retain_seal(&borrowed, 0).is_err());
    assert_eq!(COPIES.with(std::cell::Cell::get), 0);

    let retained = retain_seal(&borrowed, encoded.len())?;
    assert_eq!(serde_json::to_vec(&retained)?, encoded);
    assert_eq!(COPIES.with(std::cell::Cell::get), 1);
    assert_eq!(retained.event, event);
    Ok(())
}
