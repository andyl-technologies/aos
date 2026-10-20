//! UNRUN complete-graph ordinary Inventory and exact pending-child vectors.
//!
//! Hosted beneath the existing Pending fixture module to reuse signed DATA
//! without exposing a fixture, constructing Live authority or duplicating cuts.

use super::*;
use crate::mount_source_acquisition_state::*;
use crate::mount_source_acquisition_state::native_held_completion::recovery_v2::head_predecessor;
use aos_sandbox_source_provider_protocol::{
    InventorySourceRequestV1, InventorySourceResponseV1, SourceProviderAuthorityV1,
    SourceProviderInventoryV1, SourceProviderMethod, SourceProviderResponseStatusV1,
    SourceProviderStatus, decode_inventory_request, digest_inventory_request,
    digest_signed_request, empty_descriptor_set_commitment_v1, encode_inventory_request,
    encode_inventory_response, response_result_digest_v1, sign_inventory, sign_request,
    sign_response_status,
};
use sha2::{Digest as _, Sha256};

fn phase11_graph() -> (Fixture, RootNativeHeldGraphV2) {
    let (fixture, _, pending) = pending_graphs();
    let old = &pending.sidecars()[&fixture.attempt.attempt_id];
    let mut controls = old.suffix().controls().to_vec();
    controls.push(sign(old.suffix().prepared().unwrap().clone()));
    let stored = RootNativeHeldSidecarV2::new(
        *old.original_scope(),
        [0; 16],
        old.disposition().cloned(),
        None,
        None,
        NativeHeldCompletionSuffixV1::new(
            Owner::Root, 11, old.suffix().flight(), None, controls,
        ).unwrap(),
        old.admission_cut().clone(),
        old.disposition_cut().cloned(),
        None,
    ).unwrap();
    let mut records = pending.canonical_records().clone();
    records.insert(native_root_sidecar_key_v2(fixture.attempt.attempt_id).unwrap(),
        stored.to_canonical_bytes().unwrap());
    (fixture, checked_v2(&records).unwrap())
}

fn head(graph: &RootNativeHeldGraphV2) -> &SourceProviderHeadV2 {
    graph.legacy().provider_heads.values().next().unwrap()
}

fn query_ref(query: &SourceProviderQueryAttemptV2) -> RecordRefV2 {
    RecordRefV2 {
        id: query.attempt_id,
        revision: query.revision,
        record_digest: query.record_digest,
    }
}

fn put(records: &mut BTreeMap<Vec<u8>, Vec<u8>>, record: StoredRecordV2) {
    let record = seal_record(record).unwrap();
    let (key, value) = encode_mount_source_state_record_v2(&record).unwrap();
    records.insert(key, value);
}

fn reserve_records(
    graph: &RootNativeHeldGraphV2,
    recovery_root: Option<[u8; 32]>,
) -> (BTreeMap<Vec<u8>, Vec<u8>>, SourceProviderQueryAttemptV2, [u8; 16]) {
    let current = head(graph);
    let session = &graph.legacy().provider_sessions[&current.current_session_id];
    let mut entries = graph.legacy().acquisitions.values()
        .filter(|row| row.scope == current.scope)
        .filter_map(inventory_correlation_for_row_v2).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.provider_acquisition.acquisition_id);
    let correlations = inventory_correlation_set_v2(entries).unwrap();
    let intent = ProviderIntentV2::Inventory {
        value: InventoryIntentV2 {
            scope: current.scope,
            known_inventory_generation: current.inventory_floor.as_ref()
                .map(|floor| floor.inventory_generation),
            known_inventory_digest: current.inventory_floor.as_ref()
                .map(|floor| floor.inventory_digest),
            known_catalog_generation: current.inventory_floor.as_ref()
                .map(|floor| floor.catalog_generation),
            known_catalog_digest: current.inventory_floor.as_ref()
                .map(|floor| floor.catalog_digest),
            known_observation_ordinal: current.inventory_observation_ordinal,
            recovery_root_attempt_id: recovery_root,
            correlation_digest: correlations.digest,
        },
    };

    let previous = if recovery_root.is_some() {
        current.recovery_barrier.as_ref().unwrap().recovery_inventory_tail
    } else {
        current.last_inventory_attempt
    };
    let predecessor = previous.map(|reference| &graph.legacy().provider_attempts[&reference.id]);
    let reset = recovery_root.is_none() && predecessor
        .is_some_and(|attempt| attempt.attempt_number == format::MAXIMUM_LINEAGE_ATTEMPTS as u64);
    let mut query = graph.legacy().provider_attempts.values().next().unwrap().clone();
    query.attempt_id = [0; 32];
    query.revision = 1;
    query.scope = current.scope;
    query.method = ProviderMethodV2::Inventory;
    query.owner = ProviderQueryOwnerV2::Inventory;
    query.immutable_intent_digest = intent_digest(&intent).unwrap();
    query.intent = intent;
    query.provider_acquisition = None;
    query.lineage_root_attempt_id = if reset { [0; 32] } else {
        predecessor.map_or([0; 32], |attempt| attempt.lineage_root_attempt_id)
    };
    query.previous_attempt_id = if reset {
        None
    } else {
        previous.map(|reference| reference.id)
    };
    query.attempt_number = if reset {
        1
    } else {
        predecessor.map_or(1, |attempt| attempt.attempt_number + 1)
    };
    query.session_id = session.session_id;
    query.session_record_digest = session.record_digest;
    query.signer_set_commitment = session.signer_set_commitment;
    query.trust_digest = session.trust_digest;
    query.revocation_digest = session.revocation_digest;
    query.route_digest = session.route_digest;
    query.process_execution_digest = session.provider_execution.process_execution_digest;
    query.normalized_acquire_intent = None;
    query.acquire_verification_floor = None;
    query.inventory_correlations = Some(correlations);
    query.request_sequence = current.next_request_sequence;
    query.owner_predecessor_revision = current.revision;
    query.owner_predecessor_digest = current.record_digest;
    query.owner_predecessor = Some(OwnerPredecessorWitnessV2::ProviderHead {
        value: head_predecessor(current),
    });
    query.state = ProviderAttemptStateV2::Reserved;
    query.record_digest = [0; 32];
    query.attempt_id = attempt_id(&query);
    if query.lineage_root_attempt_id == [0; 32] {
        query.lineage_root_attempt_id = query.attempt_id;
    }
    query.request_id = request_id(query.attempt_id);

    let request = InventorySourceRequestV1::new(
        ObjectDigest::from_bytes(session.session_binding),
        query.request_sequence,
        query.request_id,
        current.scope.holder_authority_id,
        session.root_mount_authority_generation,
        ObjectDigest::from_bytes(session.root_mount_authority_digest),
        current.inventory_floor.as_ref().map(|floor| ObjectDigest::from_bytes(floor.inventory_digest)),
        session.current_valid_until_seconds,
    ).unwrap();
    let key = SigningKey::from_bytes(&[12; 32]);
    let signer = fixture::signer(
        current.scope.holder_authority_id,
        [22; 16],
        SourceProviderKeyUsageV1::RootMountRecord,
        &key,
    );
    let signed = sign_request(
        SourceProviderMethod::Inventory, encode_inventory_request(&request), signer, &key,
    ).unwrap();
    query.signed_request_digest = *digest_signed_request(&signed).as_bytes();
    query.signed_request = signed.to_canonical_bytes();
    let StoredRecordV2::ProviderQueryAttempt { value: query } =
        seal_record(StoredRecordV2::ProviderQueryAttempt { value: query }).unwrap()
    else {
        panic!("sealed query");
    };

    let next_head = derive_inventory_reservation_head_v2(current, query_ref(&query)).unwrap();
    let transaction = owner_transaction(graph, &next_head, &query, MutationTagV2::ReserveRetry);
    let mut records = graph.canonical_records().clone();
    put(&mut records, StoredRecordV2::ProviderQueryAttempt { value: query.clone() });
    put(&mut records, StoredRecordV2::ProviderHead { value: next_head });
    (records, query, transaction)
}

fn owner_transaction(
    graph: &RootNativeHeldGraphV2,
    next: &SourceProviderHeadV2,
    query: &SourceProviderQueryAttemptV2,
    tag: MutationTagV2,
) -> [u8; 16] {
    transaction_id(
        tag,
        next.scope.holder_authority_id,
        next.scope.provider_authority_id,
        graph.legacy().holder_sequences.get(&next.scope.holder_authority_id)
            .map_or(0, |row| row.revision),
        next.revision,
        None,
        None,
        Some(query.attempt_id),
        Some(query.revision),
        None,
    )
}

fn consume_records(
    graph: &RootNativeHeldGraphV2,
    status: SourceProviderStatus,
) -> (BTreeMap<Vec<u8>, Vec<u8>>, SourceProviderQueryAttemptV2, [u8; 16]) {
    let current = head(graph);
    let mut query = graph.legacy().provider_attempts[&current.pending_attempt.unwrap().id].clone();
    let session = &graph.legacy().provider_sessions[&query.session_id];
    let key = SigningKey::from_bytes(&[14; 32]);
    let signer = fixture::signer(
        session.scope.provider_authority_id,
        [24; 16],
        SourceProviderKeyUsageV1::ProviderOutcome,
        &key,
    );
    let request_envelope = aos_sandbox_source_provider_protocol::SignedSourceProviderRequestV1::from_canonical_bytes(&query.signed_request).unwrap();
    let request = decode_inventory_request(request_envelope.subject()).unwrap();
    let result = if status == SourceProviderStatus::Complete {
        let provider = SourceProviderAuthorityV1::new(
            session.scope.provider_authority_id,
            session.provider_authority_generation,
            ObjectDigest::from_bytes(session.provider_authority_digest),
        ).unwrap();
        let inventory = SourceProviderInventoryV1::new(
            query.request_id,
            digest_inventory_request(&request),
            session.scope.holder_authority_id,
            session.root_mount_authority_generation,
            ObjectDigest::from_bytes(session.root_mount_authority_digest),
            provider,
            session.provider_process_instance,
            1,
            digest(62),
            current.inventory_observation_ordinal + 1,
            Vec::new(),
        ).unwrap();
        Some(sign_inventory(inventory, signer.clone(), &key).unwrap().to_canonical_bytes())
    } else {
        None
    };

    let result_digest = response_result_digest_v1(SourceProviderMethod::Inventory, status, result.as_deref());
    let response_status = SourceProviderResponseStatusV1::new(
        SourceProviderMethod::Inventory,
        query.request_id,
        ObjectDigest::from_bytes(query.signed_request_digest),
        status,
        session.provider_process_instance,
        ObjectDigest::from_bytes(session.session_binding),
        query.request_sequence,
        result_digest,
        empty_descriptor_set_commitment_v1(),
    ).unwrap();
    let signed_status = sign_response_status(response_status, signer, &key).unwrap();
    let response = InventorySourceResponseV1::new(signed_status.clone(), result.clone()).unwrap();
    let mut anchor = OutcomeVerificationAnchorV2 {
        verification_started_seconds: 110,
        verification_completed_seconds: 111,
        kernel_boot_id: session.kernel_boot_id,
        trusted_clock_evidence_digest: session.trusted_clock_evidence_digest,
        anchor_digest: [0; 32],
    };
    anchor.anchor_digest = outcome_verification_anchor_digest_v2(
        &anchor,
        session.session_id,
        query.attempt_id,
        query.request_sequence,
        query.request_sequence,
        Sha256::digest(encode_inventory_response(&response)).into(),
    );

    query.revision = 2;
    query.state = ProviderAttemptStateV2::DispositionConsumed {
        response_sequence: query.request_sequence,
        verification_anchor: anchor,
        status: match status {
            SourceProviderStatus::Complete => ProviderStatusV2::Complete,
            SourceProviderStatus::Pending => ProviderStatusV2::Pending,
            SourceProviderStatus::Rejected => ProviderStatusV2::Rejected,
            SourceProviderStatus::Unavailable => ProviderStatusV2::Unavailable,
        },
        signed_status_digest: Sha256::digest(signed_status.to_canonical_bytes()).into(),
        signed_status: signed_status.to_canonical_bytes(),
        signed_result: result.unwrap_or_default(),
        signed_result_digest: *result_digest.as_bytes(),
    };
    let StoredRecordV2::ProviderQueryAttempt { value: query } =
        seal_record(StoredRecordV2::ProviderQueryAttempt { value: query }).unwrap()
    else {
        panic!("sealed consumed query");
    };

    let next_head = derive_inventory_disposition_head_v2(
        current,
        &query,
        query_ref(&query),
        &graph.legacy().provider_sessions,
        &graph.legacy().provider_attempts,
        &graph.legacy().acquisitions,
    ).unwrap();
    let transaction = owner_transaction(graph, &next_head, &query, MutationTagV2::CompleteInventory);
    let mut records = graph.canonical_records().clone();
    put(&mut records, StoredRecordV2::ProviderQueryAttempt { value: query.clone() });
    put(&mut records, StoredRecordV2::ProviderHead { value: next_head });
    (records, query, transaction)
}

#[test]
fn first_ordinary_reservation_and_all_signed_consumptions_preserve_native_two() {
    for status in [
        SourceProviderStatus::Pending,
        SourceProviderStatus::Rejected,
        SourceProviderStatus::Unavailable,
        SourceProviderStatus::Complete,
    ] {
        let (fixture, before) = phase11_graph();
        let root = fixture.attempt.attempt_id;
        let (records, query, tx) = reserve_records(&before, None);
        let reserved = checked_v2(&records).unwrap();

        let proposal = validate_original_inventory_transition_v6(
            &before, &reserved, root, query.attempt_id, tx,
        ).unwrap();
        let head_key = provider_head_key(query.scope.holder_authority_id, query.scope.provider_authority_id);

        assert_eq!(proposal.kind, OriginalInventoryTransitionKindV6::Reserved);
        assert_eq!(proposal.puts.len(), 2);
        assert_eq!(proposal.before_images[&provider_attempt_key(query.attempt_id)], None);
        assert_eq!(proposal.before_images[&head_key].as_ref(), before.canonical_records().get(&head_key));
        assert_eq!(original_root_remaining_v5(&reserved, root).unwrap(), 2);
        assert!(validate_original_inventory_transition_v6(&before, &reserved, root, query.attempt_id, [0; 16]).is_err());
        assert!(validate_original_inventory_transition_v6(&before, &reserved, root, query.attempt_id, [177; 16]).is_err());
        assert!(validate_original_root_transition_v5(&before, &reserved, root, tx).is_err());
        assert!(validate_native_root_transition_v2(&before, &reserved, root, tx).is_err());

        let (records, consumed, tx) = consume_records(&reserved, status);
        let after = checked_v2(&records).unwrap();

        let proposal = validate_original_inventory_transition_v6(
            &reserved, &after, root, query.attempt_id, tx,
        ).unwrap();
        let expected_kind = if status == SourceProviderStatus::Complete {
            OriginalInventoryTransitionKindV6::CompleteConsumed
        } else {
            OriginalInventoryTransitionKindV6::NonCompleteConsumed
        };

        assert_eq!(proposal.kind, expected_kind);
        assert_eq!(proposal.puts.len(), 2);
        assert_eq!(original_root_remaining_v5(&after, root).unwrap(), 2);
        assert_eq!(before.sidecars(), after.sidecars());
        assert_eq!(before.legacy().acquisitions, after.legacy().acquisitions);
        assert_eq!(before.legacy().provider_sessions, after.legacy().provider_sessions);
        assert_eq!(
            head(&after).inventory_observation_ordinal,
            u64::from(status == SourceProviderStatus::Complete),
        );
        if status == SourceProviderStatus::Complete {
            let floor = head(&after).inventory_floor.as_ref().unwrap();
            let reconciliation = reproduce_reconciliation(
                head(&after), &after.legacy().provider_attempts, &after.legacy().acquisitions,
            ).unwrap();

            assert_eq!(floor.attempt, query_ref(&consumed));
            assert_eq!(floor.provider_outcome_signer_digest, fixture.session.signers[3].public_key_fingerprint);
            assert_eq!(head(&after).last_reconciliation.as_ref(), Some(&reconciliation));
        } else {
            assert_eq!(head(&after).inventory_floor, head(&before).inventory_floor);
            assert_eq!(head(&after).last_reconciliation, head(&before).last_reconciliation);
        }
    }
}

#[test]
fn linked_ordinary_child_after_noncomplete_or_complete_keeps_exact_consumed_tail() {
    for status in [SourceProviderStatus::Pending, SourceProviderStatus::Complete] {
        let (fixture, before) = phase11_graph();
        let (records, _, _) = reserve_records(&before, None);
        let reserved = checked_v2(&records).unwrap();
        let (records, old, _) = consume_records(&reserved, status);
        let consumed = checked_v2(&records).unwrap();
        let (records, child, tx) = reserve_records(&consumed, None);
        let after = checked_v2(&records).unwrap();

        assert_eq!(child.previous_attempt_id, Some(old.attempt_id));
        assert_eq!(child.attempt_number, 2);
        assert_eq!(head(&after).last_inventory_attempt, Some(query_ref(&old)));
        assert_eq!(head(&after).pending_attempt, Some(query_ref(&child)));
        assert_eq!(after.legacy().provider_attempts[&old.attempt_id], old);
        assert_eq!(validate_original_inventory_transition_v6(&consumed, &after,
            fixture.attempt.attempt_id, child.attempt_id, tx).unwrap().puts.len(), 2);
    }
}

#[test]
fn ordinary_lineage_rollover_uses_symbol_for_complete_and_noncomplete_history() {
    for status in [SourceProviderStatus::Pending, SourceProviderStatus::Complete] {
        let (fixture, mut graph) = phase11_graph();
        let original = graph.canonical_records().clone();
        let mut tail = [0; 32];
        for number in 1..=format::MAXIMUM_LINEAGE_ATTEMPTS {
            let (records, query, tx) = reserve_records(&graph, None);
            assert_eq!(query.attempt_number, number as u64);
            let reserved = checked_v2(&records).unwrap();
            validate_original_inventory_transition_v6(&graph, &reserved, fixture.attempt.attempt_id, query.attempt_id, tx).unwrap();
            let (records, query, tx) = consume_records(&reserved, status);
            let after = checked_v2(&records).unwrap();
            validate_original_inventory_transition_v6(&reserved, &after, fixture.attempt.attempt_id, query.attempt_id, tx).unwrap();
            tail = query.attempt_id;
            graph = after;
        }
        let (records, query, tx) = reserve_records(&graph, None);
        let after = checked_v2(&records).unwrap();

        assert_eq!(query.previous_attempt_id, None);
        assert_eq!(query.attempt_number, 1);
        assert_eq!(query.lineage_root_attempt_id, query.attempt_id);
        assert_eq!(head(&after).last_inventory_attempt.unwrap().id, tail);
        assert_eq!(after.legacy().provider_attempts.len(), format::MAXIMUM_LINEAGE_ATTEMPTS + 2);
        let head_key = provider_head_key(query.scope.holder_authority_id, query.scope.provider_authority_id);
        for (key, bytes) in original {
            if key != head_key {
                assert_eq!(after.canonical_records().get(&key), Some(&bytes));
            }
        }
        validate_original_inventory_transition_v6(&graph, &after, fixture.attempt.attempt_id, query.attempt_id, tx).unwrap();
    }
}

#[test]
fn full_graph_rejects_stale_absent_or_nonreserved_pending_child_and_extra_successor() {
    let (_, before) = phase11_graph();
    let (records, _, _) = reserve_records(&before, None);
    let reserved = checked_v2(&records).unwrap();
    let (records, _, _) = consume_records(&reserved, SourceProviderStatus::Pending);
    let consumed = checked_v2(&records).unwrap();
    let (records, child, _) = reserve_records(&consumed, None);
    let good = checked_v2(&records).unwrap();

    for case in ["absent", "digest", "revision", "consumed"] {
        let mut changed = records.clone();
        let mut next_head = head(&good).clone();
        match case {
            "absent" => { next_head.pending_attempt = None; next_head.next_response_sequence += 1; }
            "digest" => next_head.pending_attempt.as_mut().unwrap().record_digest = [201; 32],
            "revision" => next_head.pending_attempt.as_mut().unwrap().revision += 1,
            "consumed" => {
                let (response, _, _) = consume_records(&good, SourceProviderStatus::Pending);
                changed.insert(provider_attempt_key(child.attempt_id), response[&provider_attempt_key(child.attempt_id)].clone());
            }
            _ => unreachable!(),
        }
        put(&mut changed, StoredRecordV2::ProviderHead { value: next_head });
        assert!(checked_v2(&changed).is_err(), "{case}");
    }
    for case in ["scope", "owner", "method", "fork", "grandchild"] {
        let mut changed = records.clone();
        let mut invalid = child.clone();
        match case {
            "scope" => invalid.scope.route_id = [202; 16],
            "owner" => invalid.owner = ProviderQueryOwnerV2::Acquire { acquisition_id: [203; 32] },
            "method" => invalid.method = ProviderMethodV2::Acquire,
            "fork" => { invalid.attempt_id = [204; 32]; }
            "grandchild" => { invalid.attempt_id = [205; 32]; invalid.previous_attempt_id = Some(child.attempt_id); invalid.attempt_number += 1; }
            _ => unreachable!(),
        }
        put(&mut changed, StoredRecordV2::ProviderQueryAttempt { value: invalid });
        assert!(checked_v2(&changed).is_err(), "{case}");
    }
}

#[test]
fn phase10_and_unrelated_valid_holder_change_or_record_removal_refuse() {
    let (fixture, _, phase10) = pending_graphs();
    let (records, query, tx) = reserve_records(&phase10, None);
    let after = checked_v2(&records).unwrap();
    assert!(validate_original_inventory_transition_v6(&phase10, &after, fixture.attempt.attempt_id, query.attempt_id, tx).is_err());

    let (fixture, before) = phase11_graph();
    let (mut records, query, tx) = reserve_records(&before, None);
    let mut holder = before.legacy().holder_sequences.values().next().unwrap().clone();
    holder.revision += 1;
    put(&mut records, StoredRecordV2::HolderSequence { value: holder });
    let after = checked_v2(&records).unwrap();
    assert!(validate_original_inventory_transition_v6(&before, &after, fixture.attempt.attempt_id, query.attempt_id, tx).is_err());
    records.remove(&provider_session_key(fixture.session.session_id));
    assert!(checked_v2(&records).is_err());
}

#[test]
fn barrier_noncomplete_retry_is_full_graph_data_and_cannot_enter_original_owner() {
    use crate::mount_source_acquisition_state::validation::native_settlement_tests::{canonical_records, native_absence_stages};
    let stages = native_absence_stages();
    let initial = checked_v2(&canonical_records(&stages.inventory_reserved)).unwrap();
    let root = head(&initial).recovery_barrier.as_ref().unwrap().root_attempt.id;
    let (records, consumed, _) = consume_records(&initial, SourceProviderStatus::Pending);
    let before = checked_v2(&records).unwrap();
    let (records, query, _) = reserve_records(&before, Some(root));
    let after = checked_v2(&records).unwrap();

    assert_eq!(query.previous_attempt_id, Some(consumed.attempt_id));
    assert_eq!(head(&after).recovery_barrier.as_ref().unwrap().recovery_inventory_tail, Some(query_ref(&consumed)));
    assert_eq!(head(&after).pending_attempt, Some(query_ref(&query)));
    assert!(validate_original_inventory_transition_v6(&before, &after, root, query.attempt_id, [221; 16]).is_err());
}

#[test]
fn barrier_lineage_keeps_symbolic_bound_and_refuses_overlong_retry_without_reset() {
    use crate::mount_source_acquisition_state::validation::native_settlement_tests::{
        canonical_records, native_absence_stages,
    };

    let stages = native_absence_stages();
    let mut reserved = checked_v2(&canonical_records(&stages.inventory_reserved)).unwrap();
    let root = head(&reserved).recovery_barrier.as_ref().unwrap().root_attempt.id;
    for number in 1..=format::MAXIMUM_LINEAGE_ATTEMPTS {
        let (records, tail, _) = consume_records(&reserved, SourceProviderStatus::Pending);
        assert_eq!(tail.attempt_number, number as u64);
        let consumed = checked_v2(&records).unwrap();

        let (records, child, _) = reserve_records(&consumed, Some(root));
        assert_eq!(child.previous_attempt_id, Some(tail.attempt_id));
        assert_eq!(child.attempt_number, number as u64 + 1);
        assert_eq!(child.lineage_root_attempt_id, tail.lineage_root_attempt_id);
        if number == format::MAXIMUM_LINEAGE_ATTEMPTS {
            assert!(checked_v2(&records).is_err());
        } else {
            reserved = checked_v2(&records).unwrap();
        }
    }
}

#[test]
fn shared_projection_successor_and_error_provenance_match_existing_owner_math() {
    let (_, before) = phase11_graph();
    let (records, query, _) = reserve_records(&before, None);
    let reserved = checked_v2(&records).unwrap();
    let current = head(&reserved);
    let rows = &reserved.legacy().acquisitions;
    let next_rows = BTreeMap::new();
    let entries = projection_entries(current.scope, &next_rows);
    let projection = projection_from_entries(current.scope, current.current_projection_epoch + 1, &entries).unwrap();
    let mut legacy = current.clone();
    legacy.revision += 1;
    legacy.next_response_sequence += 1;
    legacy.pending_attempt = None;
    legacy.current_projection_epoch += 1;
    legacy.current_projection_digest = projection.digest;
    legacy.last_reconciliation = None;
    legacy.record_digest = [0; 32];

    let derived = derive_provider_completed_head_v2(current, rows, &next_rows).unwrap();
    assert_eq!(derived, legacy);
    assert_eq!(encode_mount_source_state_record_v2(&seal_record(StoredRecordV2::ProviderHead { value: derived }).unwrap()).unwrap(),
        encode_mount_source_state_record_v2(&seal_record(StoredRecordV2::ProviderHead { value: legacy }).unwrap()).unwrap());

    let mut overflow = current.clone();
    overflow.current_projection_epoch = u64::MAX;
    assert_eq!(derive_provider_completed_head_v2(&overflow, rows, &next_rows),
        Err(InventoryOwnerDerivationErrorV2::Invariant("SourceProvider projection epoch is exhausted")));
    let mut invalid_rows = rows.clone();
    invalid_rows.values_mut().next().unwrap().provider_acquisition.acquisition_id = [0; 32];
    assert!(matches!(derive_provider_completed_head_v2(current, rows, &invalid_rows),
        Err(InventoryOwnerDerivationErrorV2::Canonical(_))));

    assert_eq!(derive_inventory_disposition_head_v2(current, &query, query_ref(&query),
        &reserved.legacy().provider_sessions, &reserved.legacy().provider_attempts, rows),
        Err(InventoryOwnerDerivationErrorV2::Invariant("provider attempt is not disposition-consumed")));
    let (_, consumed, _) = consume_records(&reserved, SourceProviderStatus::Complete);
    assert_eq!(derive_inventory_disposition_head_v2(current, &consumed, query_ref(&consumed),
        &BTreeMap::new(), &reserved.legacy().provider_attempts, rows),
        Err(InventoryOwnerDerivationErrorV2::Invariant("Inventory outcome session is absent")));
    overflow = current.clone();
    overflow.inventory_observation_ordinal = u64::MAX;
    assert_eq!(derive_inventory_disposition_head_v2(&overflow, &consumed, query_ref(&consumed),
        &reserved.legacy().provider_sessions, &reserved.legacy().provider_attempts, rows),
        Err(InventoryOwnerDerivationErrorV2::Invariant("provider Inventory observation ordinal is exhausted")));
    let mut invalid = consumed;
    let ProviderAttemptStateV2::DispositionConsumed { signed_result, .. } = &mut invalid.state else {
        panic!("consumed fixture");
    };
    signed_result.clear();
    assert_eq!(derive_inventory_disposition_head_v2(current, &invalid, query_ref(&invalid),
        &reserved.legacy().provider_sessions, &reserved.legacy().provider_attempts, rows),
        Err(InventoryOwnerDerivationErrorV2::Invariant("Complete Inventory is invalid")));
}

#[test]
fn malformed_correlation_immutable_request_and_original_archives_fail_fullgraph() {
    let (fixture, before) = phase11_graph();
    let (records, query, _) = reserve_records(&before, None);
    for case in ["omitted", "captured_ref", "expectation", "digest", "session", "predecessor"] {
        let mut changed = records.clone();
        let mut invalid = query.clone();
        match case {
            "omitted" => invalid.inventory_correlations.as_mut().unwrap().entries.clear(),
            "captured_ref" => invalid.inventory_correlations.as_mut().unwrap().entries[0].acquisition_record.revision += 1,
            "expectation" => invalid.inventory_correlations.as_mut().unwrap().entries[0].expectation = InventoryCorrelationExpectationV2::ReleasedOrAbsent,
            "digest" => invalid.inventory_correlations.as_mut().unwrap().digest = [225; 32],
            "session" => invalid.session_record_digest = [226; 32],
            "predecessor" => invalid.owner_predecessor_revision += 1,
            _ => unreachable!(),
        }
        put(&mut changed, StoredRecordV2::ProviderQueryAttempt { value: invalid });
        assert!(checked_v2(&changed).is_err(), "{case}");
    }
    for case in ["attempt", "session", "acquisition", "sidecar"] {
        let mut changed = records.clone();
        match case {
            "attempt" => {
                let mut original = before.legacy().provider_attempts[&fixture.attempt.attempt_id].clone();
                let ProviderAttemptStateV2::DispositionConsumed { verification_anchor, .. } = &mut original.state else {
                    panic!("original Pending fixture");
                };
                verification_anchor.anchor_digest = [227; 32];
                put(&mut changed, StoredRecordV2::ProviderQueryAttempt { value: original });
            }
            "session" => {
                let mut session = fixture.session.clone();
                session.trust_digest = [228; 32];
                put(&mut changed, StoredRecordV2::ProviderSession { value: session });
            }
            "acquisition" => {
                let mut row = before.legacy().acquisitions.values().next().unwrap().clone();
                row.record_digest = [229; 32];
                row.revision += 1;
                put(&mut changed, StoredRecordV2::Acquisition { value: row });
            }
            "sidecar" => {
                let key = native_root_sidecar_key_v2(fixture.attempt.attempt_id).unwrap();
                changed.get_mut(&key).unwrap()[16] ^= 1;
            }
            _ => unreachable!(),
        }
        assert!(checked_v2(&changed).is_err(), "{case}");
    }
}

#[test]
fn another_valid_signed_request_cannot_replace_the_reserved_immutable_request() {
    let (fixture, before) = phase11_graph();
    let (records, mut query, _) = reserve_records(&before, None);
    let reserved = checked_v2(&records).unwrap();
    let session = &reserved.legacy().provider_sessions[&query.session_id];
    let request = InventorySourceRequestV1::new(
        ObjectDigest::from_bytes(session.session_binding),
        query.request_sequence,
        query.request_id,
        query.scope.holder_authority_id,
        session.root_mount_authority_generation,
        ObjectDigest::from_bytes(session.root_mount_authority_digest),
        None,
        session.current_valid_until_seconds - 1,
    ).unwrap();
    let key = SigningKey::from_bytes(&[12; 32]);
    let signer = fixture::signer(
        query.scope.holder_authority_id, [22; 16], SourceProviderKeyUsageV1::RootMountRecord, &key,
    );
    let signed = sign_request(
        SourceProviderMethod::Inventory, encode_inventory_request(&request), signer, &key,
    ).unwrap();
    query.signed_request_digest = *digest_signed_request(&signed).as_bytes();
    query.signed_request = signed.to_canonical_bytes();
    let StoredRecordV2::ProviderQueryAttempt { value: query } =
        seal_record(StoredRecordV2::ProviderQueryAttempt { value: query }).unwrap()
    else {
        panic!("alternate sealed request");
    };
    let mut alternate_head = head(&reserved).clone();
    alternate_head.pending_attempt = Some(query_ref(&query));
    let mut alternate_records = records;
    put(&mut alternate_records, StoredRecordV2::ProviderQueryAttempt { value: query.clone() });
    put(&mut alternate_records, StoredRecordV2::ProviderHead { value: alternate_head });
    let alternate_reserved = checked_v2(&alternate_records).unwrap();

    let (records, _, tx) = consume_records(&alternate_reserved, SourceProviderStatus::Pending);
    let after = checked_v2(&records).unwrap();

    // Both complete snapshots have authentic canonical artifacts. Their DATA
    // does not establish receipt; the before/after immutable join must agree.
    assert!(validate_original_inventory_transition_v6(
        &reserved, &after, fixture.attempt.attempt_id, query.attempt_id, tx,
    ).is_err());
}
