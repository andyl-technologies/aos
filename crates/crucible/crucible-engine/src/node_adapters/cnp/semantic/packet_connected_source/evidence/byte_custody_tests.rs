//! Exercises source-owned byte classification independently of emission or cache presence.
//!
//! These controls use the production classifier with closed native inventory
//! fixtures. Actual Child/operation authentication remains with its caller.

use crucible_node_format::Bytes;
use crucible_node_transport::reference_packet::connected::{
    PacketDeliveredInput, PacketPendingPublication, PacketReaction,
};
use std::cell::Cell;

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn reaction(bytes: &[u8]) -> TestResult<PacketReaction> {
    Ok(PacketReaction {
        input_event: Id::new("original-input")?,
        input_producer: Id::new("original-producer")?,
        input_sequence: U64::new(0),
        stage_operation: Id::new("original-stage")?,
        commit_request: Id::new("original-commit")?,
        payload: Bytes::new(bytes.to_vec()),
        parent: Position::new(U64::new(6), U64::new(0), Phase::Delivery),
        evaluation: Position::new(U64::new(6), U64::new(0), Phase::Reaction),
    })
}

#[test]
fn cached_raw_originals_remain_bytes_before_and_after_delivery() -> TestResult {
    let raw = [0xff, 0, b'\n', b'o', b'c', b't', b'e', b't'];
    assert!(canonical::parse_json(&raw, 1024).is_err());
    let reference = canonical::content_ref(&raw, "application/octet-stream")?;
    let original = reaction(&raw)?;
    let mut inventory = super::super::native::initial_inventory();
    inventory.gate_closed = false;
    inventory.reactions.push(original.clone());
    let mut delivered = inventory.clone();
    delivered.reactions.clear();
    delivered.delivered_inputs.push(PacketDeliveredInput {
        reaction: original.clone(),
        delivery_operation: Id::new("original-delivery-grant")?,
    });
    let mut pending = delivered.clone();
    pending.publications.push(PacketPendingPublication {
        event: Id::new("original-future-publication")?,
        reaction: original,
        reaction_operation: Id::new("original-reaction-grant")?,
        publication: Position::new(U64::new(6), U64::new(1), Phase::Publication),
    });
    for state in [inventory, delivered, pending] {
        let before = state.clone();
        for cached in [None, Some(raw.as_slice())] {
            let parsed = Cell::new(false);
            let bytes = original_evidence_bytes(&state, &reference, cached, || {
                parsed.set(true);
                Err(refused("payload must not enter native JSON reader"))
            })
            .map_err(|failure| failure.reason)?;
            assert_eq!(bytes, raw);
            assert!(!parsed.get());
        }
        assert_eq!(state, before);
        assert!(state.retained_outputs.is_empty());
        assert_eq!(state.packet_effects, U64::new(0));
    }
    Ok(())
}

#[test]
fn cache_or_json_shape_cannot_supply_native_payload_authority() -> TestResult {
    let raw = b"{\"schema\":\"looks-like-a-native-record\"}";
    let reference = canonical::content_ref(raw, "application/octet-stream")?;
    let mut inventory = super::super::native::initial_inventory();
    inventory.reactions.push(reaction(raw)?);
    assert_eq!(
        original_evidence_bytes(&inventory, &reference, Some(raw), || {
            Err(refused("original octets must retain their role"))
        })
        .map_err(|failure| failure.reason)?,
        raw
    );
    assert!(original_evidence_bytes(&inventory, &reference, Some(b"changed"), || Ok(())).is_err());

    let foreign = canonical::content_ref(b"foreign cached octets", "application/octet-stream")?;
    let wrong_role = canonical::content_ref(raw, "application/json")?;
    let empty = super::super::native::initial_inventory();
    for (state, reference, bytes) in [
        (&inventory, &foreign, b"foreign cached octets".as_slice()),
        (&inventory, &wrong_role, raw.as_slice()),
        (&empty, &reference, raw.as_slice()),
    ] {
        let validated = Cell::new(false);
        assert!(
            original_evidence_bytes(state, reference, Some(bytes), || {
                validated.set(true);
                Err(refused("no original native record authenticates this body"))
            })
            .is_err()
        );
        assert!(validated.get());
    }
    let native = canonical::content_ref(b"{}", "application/json")?;
    let validated = Cell::new(false);
    assert_eq!(
        original_evidence_bytes(&empty, &native, Some(b"{}"), || {
            validated.set(true);
            Ok(())
        })
        .map_err(|failure| failure.reason)?,
        b"{}"
    );
    assert!(validated.get());
    Ok(())
}
