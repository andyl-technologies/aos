//! Checks the pre-typed query data predicate without inventing startup authority.
//!
//! crucible-lint: panic-shortcut: fixture assertions intentionally stop the test.

use super::*;
use crate::envelope::Nullable;
use crucible_node_format::{Bytes, Extensions};
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn selected_observe(selection: &PacketControlSelection) -> Result<Envelope, ProviderError> {
    let binding = &selection.realization.bindings[0];
    let body = serde_json::to_value(crate::bodies::ObserveRequest {
        binding_hash: selection.realization.owner_bindings[0].identity()?,
        owner_generation: binding.authority.owner_generation,
        after_observation_sequence: U64::new(0),
        maximum_items: U64::new(1),
        extensions: Extensions::new(),
    })
    .map_err(crucible_node_format::ContractError::from)?;
    let Value::Object(body) = body else {
        return Err(query_error());
    };
    Ok(Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(binding.authority.session_id.clone())),
        incarnation_id: Nullable(Some(binding.authority.incarnation_id.clone())),
        node_id: Nullable(Some(binding.compatibility.node_id.clone())),
        execution_owner_id: Nullable(Some(binding.compatibility.execution_owner.id.clone())),
        capture_owner_id: Nullable(None),
        operation_id: Nullable(None),
        request_id: Nullable(Some(Id::new("startup-query")?)),
        sequence: U64::new(2),
        method: Method::Observe,
        body,
        extensions: Extensions::new(),
    })
}

#[test]
fn real_observe_contract_scope_passes_closed_header_predicate() -> TestResult {
    let (_handshake, _authority, selection, _) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let query = selected_observe(&selection)?;

    authenticate_original_report_query_header_data(&selection, Purpose::OriginalObserve12, &query)?;
    assert!(matches!(
        crate::bodies::decode_request(query.method, &query.body)?,
        RequestBody::Observe(_)
    ));
    Ok(())
}

#[test]
fn foreign_scope_wrong_method_response_and_number_refuse_before_typed_decode() -> TestResult {
    let (_handshake, _authority, selection, _) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let query = selected_observe(&selection)?;
    authenticate_original_report_query_header_data(&selection, Purpose::OriginalObserve12, &query)?;
    for changed in 0..6 {
        let mut wrong = query.clone();
        match changed {
            0 => wrong.session_id = Nullable(Some(Id::new("foreign-session")?)),
            1 => wrong.execution_owner_id = Nullable(Some(Id::new("foreign-owner")?)),
            2 => wrong.method = Method::Realize,
            3 => wrong.message = MessageKind::Response,
            4 => {
                wrong
                    .body
                    .insert("owner_generation".into(), serde_json::json!(1));
            }
            5 => {
                wrong.body.insert(
                    "maximum_items".into(),
                    serde_json::json!("18446744073709551616"),
                );
            }
            _ => unreachable!(),
        }
        assert!(
            authenticate_original_report_query_header_data(
                &selection,
                Purpose::OriginalObserve12,
                &wrong
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn fresh_query_requires_exact_sole_nonce_and_completed_admit_extension() -> TestResult {
    let (_handshake, _authority, selection, _) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let mut query = selected_observe(&selection)?;
    let data = PacketNativeFreshRestoreAllocationQuery {
        schema: PACKET_FRESH_RESTORE_ALLOCATION_QUERY.into(),
        nonce: Bytes::new(vec![1; 32]),
        completed_admit_request: Bytes::new(vec![2; 32]),
        completed_admit_response: Bytes::new(vec![3; 32]),
    };
    query.extensions.insert(
        PACKET_FRESH_RESTORE_ALLOCATION_QUERY.into(),
        serde_json::to_value(&data)?,
    );
    authenticate_original_report_query_header_data(
        &selection,
        Purpose::FreshCompletedAdmit13,
        &query,
    )?;
    assert!(
        authenticate_original_report_query_header_data(
            &selection,
            Purpose::OriginalObserve12,
            &query
        )
        .is_err()
    );

    let mut changed = query.clone();
    changed.extensions.insert("extra".into(), Value::Null);
    assert!(
        authenticate_original_report_query_header_data(
            &selection,
            Purpose::FreshCompletedAdmit13,
            &changed
        )
        .is_err()
    );
    let value = query
        .extensions
        .get_mut(PACKET_FRESH_RESTORE_ALLOCATION_QUERY)
        .and_then(Value::as_object_mut)
        .ok_or_else(query_error)?;
    value.insert("nonce".into(), Value::String("short".into()));
    assert!(
        authenticate_original_report_query_header_data(
            &selection,
            Purpose::FreshCompletedAdmit13,
            &query
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn query_storage_keeps_full_raw_receive_separate_from_original_clone() -> TestResult {
    let (_handshake, authority, _selection, _) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let active = query_receive_storage_from_limits(authority.limits(), Purpose::OriginalObserve12)?;
    let fresh =
        query_receive_storage_from_limits(authority.limits(), Purpose::FreshCompletedAdmit13)?;
    let raw = usize::try_from(authority.limits().frame_bytes.get())?;

    assert_eq!(active.maximum_frame_body_bytes, raw);
    assert!(active.raw_and_envelope_requested_bytes > acknowledgements::open_ack_storage(raw)?);
    assert!(fresh.typed_query_requested_bytes > active.typed_query_requested_bytes);
    assert_eq!(active.original_literal_required_bytes, raw + 4);
    assert_eq!(
        active.original_descriptor_required_bytes,
        crate::transport::original_frames::original_frame_slot_layout()
    );
    assert_eq!(
        active.declared_counter_scratch_bytes,
        original_report_query_receive_counter_scratch_data()
    );
    assert!(fresh.requested_bytes()? > active.requested_bytes()?);
    Ok(())
}

#[test]
fn returned_observe_box_backing_fits_the_carried_typed_query_row() -> TestResult {
    let (_handshake, authority, selection, _) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let query = selected_observe(&selection)?;
    authenticate_original_report_query_header_data(&selection, Purpose::OriginalObserve12, &query)?;
    let returned = Box::new(crate::bodies::decode_request(query.method, &query.body)?);
    let RequestBody::Observe(observed) = returned.as_ref() else {
        return Err("restricted typed Observe absent".into());
    };
    let mut fields = crate::retained_metadata::MetadataObserver::new();
    fields.observe(&observed.binding_hash)?;
    fields.observe(&observed.owner_generation)?;
    fields.observe(&observed.after_observation_sequence)?;
    fields.observe(&observed.maximum_items)?;
    fields.observe(&observed.extensions)?;
    let children =
        crate::retained_metadata::requested_metadata_backing_storage_data(&fields.finish())?;
    let actual = std::mem::size_of_val(returned.as_ref())
        .checked_add(children)
        .ok_or_else(query_error)?;
    let receive =
        query_receive_storage_from_limits(authority.limits(), Purpose::OriginalObserve12)?;

    assert!(children > 0);
    let carried =
        OriginalPacketPrefixStorageData::native_observe_returned_query_storage_data(&receive)?;
    assert!(observed.extensions.is_empty());
    // Observe the two backing populations independently. The typed receive
    // row has conservative header/string-growth allowances, so it may already
    // dominate this fixture's backing. Root attribution must not depend on
    // that incidental headroom.
    let mut hash_fields = crate::retained_metadata::MetadataObserver::new();
    hash_fields.observe(&observed.binding_hash)?;
    let hash_backing =
        crate::retained_metadata::requested_metadata_backing_storage_data(&hash_fields.finish())?;
    let mut extension_fields = crate::retained_metadata::MetadataObserver::new();
    extension_fields.observe(&observed.extensions)?;
    let extension_facts = extension_fields.finish();
    let empty_root =
        crate::retained_metadata::requested_metadata_backing_storage_data(&extension_facts)?;

    assert_eq!(extension_facts.tree_containers, 1);
    assert_eq!(extension_facts.tree_entries, 0);
    assert!(empty_root > 0);
    assert_eq!(
        children,
        hash_backing
            .checked_add(empty_root)
            .ok_or_else(query_error)?
    );
    // Omitting the root from the carry fails this equality even when the
    // receive row's unrelated conservative terms cover the actual total.
    assert_eq!(
        carried,
        receive
            .typed_query_requested_bytes
            .checked_add(empty_root)
            .ok_or_else(query_error)?
    );
    assert!(actual <= carried);
    assert!(receive.requested_bytes()? > carried);
    assert_eq!(
        observed.binding_hash,
        selection.realization.owner_bindings[0].identity()?
    );
    // Keep the actual decoded owner live through the metadata comparison; the
    // Source encoding row carries its allowance after the receive phase ends.
    assert!(matches!(returned.as_ref(), RequestBody::Observe(_)));
    Ok(())
}

#[test]
fn selected_query_refines_only_canonical_output_and_keeps_fresh_fallback() -> TestResult {
    let (_handshake, authority, _selection, _) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let limits = authority.limits();
    let selected = native_query_receive_storage_from_limits(limits, Purpose::OriginalObserve12)?;
    let old = query_receive_storage_from_limits(limits, Purpose::OriginalObserve12)?;
    let fresh = native_query_receive_storage_from_limits(limits, Purpose::FreshCompletedAdmit13)?;
    let old_fresh = query_receive_storage_from_limits(limits, Purpose::FreshCompletedAdmit13)?;
    let raw = usize::try_from(limits.frame_bytes.get())?;
    let old_ack = acknowledgements::open_ack_lifetime_storage_data(raw)?;
    let new_ack = acknowledgements::native_original_open_ack_lifetime_storage_data(raw)?;

    assert_eq!(new_ack.retained, old_ack.retained);
    assert!(new_ack.returning < old_ack.returning);
    assert_eq!(
        old.raw_and_envelope_requested_bytes - selected.raw_and_envelope_requested_bytes,
        old_ack.returning - new_ack.returning
    );
    assert_eq!(
        selected.maximum_frame_body_bytes,
        old.maximum_frame_body_bytes
    );
    assert_eq!(
        selected.typed_query_requested_bytes,
        old.typed_query_requested_bytes
    );
    assert_eq!(
        selected.correlation_requested_bytes,
        old.correlation_requested_bytes
    );
    assert_eq!(
        selected.original_literal_required_bytes,
        old.original_literal_required_bytes
    );
    assert_eq!(
        selected.original_descriptor_required_bytes,
        old.original_descriptor_required_bytes
    );
    assert_eq!(fresh.requested_bytes()?, old_fresh.requested_bytes()?);
    assert_eq!(
        fresh.raw_and_envelope_requested_bytes,
        old_fresh.raw_and_envelope_requested_bytes
    );
    Ok(())
}
