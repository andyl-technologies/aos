//! Checks actual protocol banks and incomplete association DATA without authority.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::tests::{
    coordinator, installation, producer, reactive, storage_selection,
};
use crucible_node_format::Bytes;

fn source(member: usize) -> PacketCompleteSemanticSource {
    let coordinator = coordinator();
    let installation = installation(&coordinator, member);
    if member == 0 {
        PacketCompleteSemanticSource::new_producer_for_collecting_world(
            installation,
            producer(),
            coordinator,
            storage_selection(),
        )
        .unwrap()
    } else {
        let definition = reactive(&coordinator, member);
        PacketCompleteSemanticSource::new_reactive_for_collecting_world(
            installation,
            definition,
            coordinator,
            storage_selection(),
        )
        .unwrap()
    }
}

fn context() -> PacketCanonicalAckAdmissionContext {
    fn bytes(capacity: usize) -> Bytes {
        let mut data = Vec::with_capacity(capacity);
        data.push(7);
        Bytes::new(data)
    }
    let mut schema = String::with_capacity(113);
    schema.push_str("incomplete retained schema");
    let mut algorithm = String::with_capacity(127);
    algorithm.push_str("incomplete retained algorithm");
    PacketCanonicalAckAdmissionContext {
        schema,
        algorithm,
        source_birth: bytes(131),
        kernel_binding: bytes(137),
        policy_binding: bytes(139),
        host_registration: bytes(149),
        native_registration: bytes(151),
        hello_request: bytes(157),
        hello_response: bytes(163),
        assigned_admit: bytes(167),
    }
}

#[test]
fn ack_protocol_capacity_keeps_real_reserved_banks_for_all_three_source_declarations() {
    for member in 0..3 {
        let mut source = source(member);
        assert_eq!(
            source
                .original_ack_protocol_capacity_data(None)
                .unwrap()
                .capacity_records,
            0
        );
        OriginalAckPeerAssociation::reserve_into(8192, source.ack_peer_association.get_mut())
            .unwrap();
        let association = source.ack_peer_association.borrow();
        let original = association.as_ref().unwrap();
        let expected: usize = original.banks.iter().map(Vec::capacity).sum();
        let legacy = original.retained_heap_storage_data(usize::MAX).unwrap();
        assert_eq!(legacy, expected);
        drop(association);

        let facts = source.original_ack_protocol_capacity_data(None).unwrap();

        assert_eq!(facts.vector_banks, 5);
        assert_eq!(facts.capacity_records, 5);
        assert_eq!(facts.vector_capacity_bytes, expected);
        assert_eq!(facts.observed_nodes, 0);
        assert!(source.ack_peer_birth.borrow().is_none());
        assert!(source.authenticate_current_native().is_err());
    }
}

#[test]
fn ack_protocol_capacity_preserves_failed_context_json_spares_and_unchanged_flags() {
    let mut source = source(0);
    OriginalAckPeerAssociation::reserve_into(8192, source.ack_peer_association.get_mut()).unwrap();
    let association = source.ack_peer_association.get_mut().as_mut().unwrap();
    association.context = Some(context());
    association.failed = true;
    let mut text = String::with_capacity(173);
    text.push_str("failed original body");
    let mut values = Vec::with_capacity(3);
    values.push(serde_json::Value::String(text));
    let json_bytes = values.capacity() * size_of::<serde_json::Value>();
    association.normalized[2] = Some(serde_json::Value::Array(values));
    let context = association.context.as_ref().unwrap();
    let bytes = [
        &context.source_birth,
        &context.kernel_binding,
        &context.policy_binding,
        &context.host_registration,
        &context.native_registration,
        &context.hello_request,
        &context.hello_response,
        &context.assigned_admit,
    ]
    .into_iter()
    .map(Bytes::allocation_capacity)
    .sum::<usize>();
    let banks = association.banks.iter().map(Vec::capacity).sum::<usize>();
    let strings = context.schema.capacity() + context.algorithm.capacity() + 173;

    let facts = source.original_ack_protocol_capacity_data(None).unwrap();

    assert_eq!(facts.capacity_records, 17);
    assert_eq!(facts.vector_banks, 14);
    assert_eq!(facts.vector_capacity_bytes, banks + bytes + json_bytes);
    assert_eq!(facts.string_banks, 3);
    assert_eq!(facts.string_capacity_bytes, strings);
    let association = source.ack_peer_association.borrow();
    let original = association.as_ref().unwrap();
    assert!(original.failed && !original.ready && !original.attempted);
    assert!(!original.completed_mechanism.get());
    assert!(original.native.is_none() && original.emitter.is_none());
    assert!(source.authenticate_current_native().is_err());
}

#[test]
fn ack_protocol_capacity_short_rows_busy_and_foreign_origin_preserve_prefixes() {
    let mut source = source(0);
    OriginalAckPeerAssociation::reserve_into(8192, source.ack_peer_association.get_mut()).unwrap();
    let association = source.ack_peer_association.borrow();
    let original = association.as_ref().unwrap();
    let prefix = String::with_capacity(179);
    let mut census = OriginalOwnerCapacityMetadataData::new(3, None);
    census.observe(&prefix).unwrap();
    assert_eq!(
        original.record_protocol_capacity_data(&mut census),
        Err(RuntimeError::ResourceLimit)
    );
    let facts = census.finish();
    assert_eq!(facts.capacity_records, 3);
    assert_eq!(facts.string_capacity_bytes, prefix.capacity());
    assert_eq!(
        facts.vector_capacity_bytes,
        original.banks[..2].iter().map(Vec::capacity).sum::<usize>()
    );
    drop(association);
    let before = source.original_ack_protocol_capacity_data(None).unwrap();
    let held = source.ack_peer_association.borrow_mut();
    assert_eq!(
        source.original_ack_protocol_capacity_data(None),
        Err(RuntimeError::OwnerBusy)
    );
    drop(held);
    source.process = source.process.wrapping_add(1);
    let held = source.ack_peer_association.borrow_mut();
    assert_eq!(
        source.original_ack_protocol_capacity_data(None),
        Err(RuntimeError::ForeignAuthority)
    );
    drop(held);
    source.process = std::process::id();
    assert_eq!(
        source.original_ack_protocol_capacity_data(None).unwrap(),
        before
    );
    assert!(
        PacketCompleteSemanticSource::original_ack_protocol_capacity_counter_scratch_data() > 0
    );
}
