//! Checks real legacy reservations and failed typed/normalized body partials.
//!
//! These controls construct no Core ticket, SDK mapping or signing authority.

use super::*;
use crucible_node_format::Bytes;

fn reserved() -> OriginalAckPeerAssociation {
    let mut slot = None;
    OriginalAckPeerAssociation::reserve_into(8192, &mut slot).unwrap();
    let mut association = slot.unwrap();
    association.reserve_complete_restore_banks(8192).unwrap();
    association
}

fn bytes(capacity: usize) -> Bytes {
    Bytes::new(Vec::with_capacity(capacity))
}

fn failed_context() -> PacketCompleteRestoreContext {
    PacketCompleteRestoreContext {
        schema: String::with_capacity(173),
        algorithm: String::with_capacity(179),
        source_birth: bytes(181),
        kernel_binding: bytes(191),
        policy_binding: bytes(193),
        host_registration: bytes(197),
        native_registration: bytes(199),
        hello_request: bytes(211),
        hello_response: bytes(223),
        assigned_restore: bytes(227),
        archive_binding: bytes(229),
        target_binding: bytes(233),
        mapping_binding: bytes(239),
        request_binding: bytes(241),
    }
}

#[test]
fn legacy_restoration_capacity_keeps_typed_and_normalized_failed_partials_independently() {
    let mut association = reserved();
    let restore = association.restore.as_mut().unwrap();
    let raw_bytes = restore.allocated_bytes().unwrap();
    restore.prepared = true;
    restore.signing_started = true;
    restore.publishing_started = true;
    restore.context = Some(failed_context());
    let mut text = String::with_capacity(251);
    text.push_str("failed normalized copy");
    let mut values = Vec::with_capacity(3);
    values.push(serde_json::Value::String(text));
    let normalized_bytes = values.capacity() * size_of::<serde_json::Value>();
    restore.normalized[5] = Some(serde_json::Value::Array(values));
    let mut typed = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);
    typed.observe(&restore.context).unwrap();
    let typed = typed.finish();

    let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);
    restore.record_body_capacity_data(&mut census).unwrap();
    let facts = census.finish();

    assert_eq!(facts.capacity_records, 8 + typed.capacity_records);
    assert_eq!(facts.vector_banks, 7 + typed.vector_banks);
    assert_eq!(
        facts.vector_capacity_bytes,
        raw_bytes + normalized_bytes + typed.vector_capacity_bytes
    );
    assert_eq!(facts.string_banks, 1 + typed.string_banks);
    assert_eq!(
        facts.string_capacity_bytes,
        251 + typed.string_capacity_bytes
    );
    assert_eq!(restore.allocated_bytes().unwrap(), raw_bytes);
    assert!(restore.ticket().is_err());
    assert!(restore.mapping().is_err());
    assert!(!restore.ready);
    assert!(!restore.sealed);
}

#[test]
fn legacy_restoration_capacity_short_rows_preserve_prior_component_and_bank_prefix() {
    let association = reserved();
    let restore = association.restore.as_ref().unwrap();
    let prefix = String::with_capacity(257);
    let mut census = OriginalOwnerCapacityMetadataData::new(4, None);
    census.observe(&prefix).unwrap();

    assert_eq!(
        restore.record_body_capacity_data(&mut census),
        Err(RuntimeError::ResourceLimit)
    );

    let partial = census.finish();
    assert_eq!(partial.capacity_records, 4);
    assert_eq!(
        partial.vector_capacity_bytes,
        restore.banks[..3].iter().map(Vec::capacity).sum::<usize>()
    );
    assert_eq!(partial.string_capacity_bytes, prefix.capacity());
    assert!(restore.ticket.is_none());
    assert!(!restore.prepared);
}

fn source() -> PacketCompleteSemanticSource {
    use crate::node_adapters::cnp::semantic::packet_complete_source::tests::{
        coordinator, installation, producer, storage_selection,
    };
    let coordinator = coordinator();
    PacketCompleteSemanticSource::new_producer_for_collecting_world(
        installation(&coordinator, 0),
        producer(),
        coordinator,
        storage_selection(),
    )
    .unwrap()
}

#[test]
fn legacy_restoration_capacity_source_projection_keeps_actual_six_banks() {
    let mut source = source();
    assert_eq!(
        source
            .original_legacy_restoration_body_capacity_data(None)
            .unwrap()
            .capacity_records,
        0
    );
    OriginalAckPeerAssociation::reserve_into(8192, source.ack_peer_association.get_mut()).unwrap();
    let association = source.ack_peer_association.get_mut().as_mut().unwrap();
    association.reserve_complete_restore_banks(8192).unwrap();
    let independent = association
        .restore
        .as_ref()
        .unwrap()
        .allocated_bytes()
        .unwrap();

    let facts = source
        .original_legacy_restoration_body_capacity_data(None)
        .unwrap();

    assert_eq!(facts.capacity_records, 6);
    assert_eq!(facts.vector_banks, 6);
    assert_eq!(facts.vector_capacity_bytes, independent);
    assert!(source.authenticate_current_native().is_err());
    assert!(
        PacketCompleteSemanticSource::original_legacy_restoration_body_capacity_counter_scratch_data(
        ) > 0
    );
}

#[test]
fn legacy_restoration_capacity_source_foreign_origin_precedes_busy_custody() {
    let mut source = source();
    let held = source.ack_peer_association.borrow_mut();
    assert_eq!(
        source.original_legacy_restoration_body_capacity_data(None),
        Err(RuntimeError::OwnerBusy)
    );
    drop(held);
    source.process = source.process.wrapping_add(1);
    let held = source.ack_peer_association.borrow_mut();

    assert_eq!(
        source.original_legacy_restoration_body_capacity_data(None),
        Err(RuntimeError::ForeignAuthority)
    );

    drop(held);
    source.process = std::process::id();
    assert!(
        source
            .original_legacy_restoration_body_capacity_data(None)
            .is_ok()
    );
}
