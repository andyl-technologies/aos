//! UNRUN actual full-graph Query6 framing, preservation and replay vectors.
//!
//! The existing phase11 and Protocol signer fixtures supply signed DATA only.
//! No protected Journal, snapshot, Live owner, carrier, guard or I/O is created.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol as protocol;
use aos_sandbox_source_provider_protocol::{
    InventorySourceRequestV1, InventorySourceResponseV1, SourceProviderAuthorityV1,
    SourceProviderInventoryV1, SourceProviderKeyUsageV1, SourceProviderMethod,
    SourceProviderResponseStatusV1, SourceProviderStatus, SignedSourceProviderRequestV1,
    decode_inventory_request, digest_inventory_request, digest_signed_request,
    empty_descriptor_set_commitment_v1, encode_inventory_request, encode_inventory_response,
    response_result_digest_v1, sign_inventory, sign_request, sign_response_status,
};
use ed25519_dalek::SigningKey;
use protocol::mount_source_acquisition_state::format::MAXIMUM_PROVIDER_ATTEMPT_VALUE_BYTES;
use protocol::mount_source_acquisition_state::*;
use sha2::{Digest as _, Sha256};

use super::*;
use crate::journal::{encoded_transaction_append_bytes, root_original_native::phase11_funded_data};

#[path = "../../../../aos-sandbox-protocol/src/mount_source_acquisition_state/native_held_completion/tests/fixture.rs"]
mod fixture;

fn head(checked: &RootNativeHeldGraphV2) -> &SourceProviderHeadV2 {
    checked.legacy().provider_heads.values().next().unwrap()
}

fn root(state: &State) -> [u8; 32] {
    *graph(state).unwrap().sidecars().keys().next().unwrap()
}

fn predecessor(head: &SourceProviderHeadV2) -> ProviderHeadPredecessorWitnessV2 {
    let mut id = [0; 32];
    id[..16].copy_from_slice(&head.scope.holder_authority_id);
    id[16..].copy_from_slice(&head.scope.provider_authority_id);
    ProviderHeadPredecessorWitnessV2 {
        record: RecordRefV2 {
            id,
            revision: head.revision,
            record_digest: head.record_digest,
        },
        scope: head.scope,
        holder_authority_generation: head.holder_authority_generation,
        holder_authority_digest: head.holder_authority_digest,
        provider_authority_generation: head.provider_authority_generation,
        provider_authority_digest: head.provider_authority_digest,
        current_session_id: head.current_session_id,
        current_session_record_digest: head.current_session_record_digest,
        next_request_sequence: head.next_request_sequence,
        next_response_sequence: head.next_response_sequence,
        pending_attempt: head.pending_attempt,
        inventory_observation_ordinal: head.inventory_observation_ordinal,
        inventory_floor: head.inventory_floor.clone(),
        last_inventory_attempt: head.last_inventory_attempt,
        current_projection_epoch: head.current_projection_epoch,
        current_projection_digest: head.current_projection_digest,
        last_reconciliation: head.last_reconciliation.clone(),
        recovery_barrier: head.recovery_barrier.clone(),
    }
}

/// Produces only ordinary owner DATA using the actual shared Head arithmetic.
fn owner_transaction(
    checked: &RootNativeHeldGraphV2,
    query: SourceProviderQueryAttemptV2,
    next: SourceProviderHeadV2,
    tag: MutationTagV2,
) -> JournalTransaction {
    let id = transaction_id(
        tag,
        next.scope.holder_authority_id,
        next.scope.provider_authority_id,
        checked.legacy().holder_sequences.get(&next.scope.holder_authority_id)
            .map_or(0, |row| row.revision),
        next.revision,
        None,
        None,
        Some(query.attempt_id),
        Some(query.revision),
        None,
    );
    let records = [
        StoredRecordV2::ProviderQueryAttempt { value: query },
        StoredRecordV2::ProviderHead { value: next },
    ].into_iter()
        .map(|record| {
            let sealed = seal_record(record).unwrap();
            let (key, value) = encode_mount_source_state_record_v2(&sealed).unwrap();
            JournalRecord::put(RecordNamespace::MountSourceAcquisition, key, value)
        })
        .collect();

    JournalTransaction::new(id, records).unwrap()
}

fn reservation(state: &State) -> ([u8; 32], JournalTransaction) {
    let checked = graph(state).unwrap();
    let current = head(&checked);
    let session = &checked.legacy().provider_sessions[&current.current_session_id];
    let entries = checked.legacy().acquisitions.values()
        .filter(|row| row.scope == current.scope)
        .filter_map(inventory_correlation_for_row_v2)
        .collect();
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
            recovery_root_attempt_id: None,
            correlation_digest: correlations.digest,
        },
    };
    let previous = current.last_inventory_attempt
        .map(|reference| &checked.legacy().provider_attempts[&reference.id]);

    let mut query = checked.legacy().provider_attempts[&root(state)].clone();
    query.attempt_id = [0; 32];
    query.revision = 1;
    query.method = ProviderMethodV2::Inventory;
    query.owner = ProviderQueryOwnerV2::Inventory;
    query.immutable_intent_digest = intent_digest(&intent).unwrap();
    query.intent = intent;
    query.provider_acquisition = None;
    query.lineage_root_attempt_id = previous.map_or([0; 32], |attempt| attempt.lineage_root_attempt_id);
    query.previous_attempt_id = previous.map(|attempt| attempt.attempt_id);
    query.attempt_number = previous.map_or(1, |attempt| attempt.attempt_number + 1);
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
        value: predecessor(current),
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
        current.inventory_floor.as_ref()
            .map(|floor| ObjectDigest::from_bytes(floor.inventory_digest)),
        session.current_valid_until_seconds,
    ).unwrap();
    let key = SigningKey::from_bytes(&[12; 32]);
    let signer = fixture::signer(
        current.scope.holder_authority_id, [22; 16], SourceProviderKeyUsageV1::RootMountRecord, &key,
    );
    let signed = sign_request(
        SourceProviderMethod::Inventory, encode_inventory_request(&request), signer, &key,
    ).unwrap();
    query.signed_request_digest = *digest_signed_request(&signed).as_bytes();
    query.signed_request = signed.to_canonical_bytes();
    let StoredRecordV2::ProviderQueryAttempt { value: query } =
        seal_record(StoredRecordV2::ProviderQueryAttempt { value: query }).unwrap()
    else {
        panic!("sealed Query1");
    };
    let next = derive_inventory_reservation_head_v2(current, reference(&query)).unwrap();

    (query.attempt_id, owner_transaction(&checked, query, next, MutationTagV2::ReserveRetry))
}

fn disposition(state: &State, status: SourceProviderStatus) -> JournalTransaction {
    let checked = graph(state).unwrap();
    let current = head(&checked);
    let mut query = checked.legacy().provider_attempts[&current.pending_attempt.unwrap().id].clone();
    let session = &checked.legacy().provider_sessions[&query.session_id];
    let key = SigningKey::from_bytes(&[14; 32]);
    let signer = fixture::signer(
        session.scope.provider_authority_id, [24; 16], SourceProviderKeyUsageV1::ProviderOutcome, &key,
    );
    let request = SignedSourceProviderRequestV1::from_canonical_bytes(&query.signed_request).unwrap();
    let request = decode_inventory_request(request.subject()).unwrap();
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
            ObjectDigest::from_bytes([62; 32]),
            current.inventory_observation_ordinal + 1,
            Vec::new(),
        ).unwrap();
        Some(sign_inventory(inventory, signer.clone(), &key).unwrap().to_canonical_bytes())
    } else {
        None
    };

    let result_digest = response_result_digest_v1(SourceProviderMethod::Inventory, status, result.as_deref());
    let status_record = SourceProviderResponseStatusV1::new(
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
    let signed = sign_response_status(status_record, signer, &key).unwrap();
    let response = InventorySourceResponseV1::new(signed.clone(), result.clone()).unwrap();
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
        signed_status: signed.to_canonical_bytes(),
        signed_status_digest: Sha256::digest(signed.to_canonical_bytes()).into(),
        signed_result: result.unwrap_or_default(),
        signed_result_digest: *result_digest.as_bytes(),
    };
    let StoredRecordV2::ProviderQueryAttempt { value: query } =
        seal_record(StoredRecordV2::ProviderQueryAttempt { value: query }).unwrap()
    else {
        panic!("sealed Query2");
    };
    let next = derive_inventory_disposition_head_v2(
        current,
        &query,
        reference(&query),
        &checked.legacy().provider_sessions,
        &checked.legacy().provider_attempts,
        &checked.legacy().acquisitions,
    ).unwrap();

    owner_transaction(&checked, query, next, MutationTagV2::CompleteInventory)
}

fn admitted() -> (State, [u8; 32], [u8; 32], DerivedAppend) {
    let before = phase11_funded_data();
    let root = root(&before);
    let (query, owners) = reservation(&before);
    let derived = derive(&before, &owners, root, query, JournalLimits::default()).unwrap();
    validate_derived(&before, &derived, JournalLimits::default()).unwrap();
    (materialize(&before, &derived.transaction), root, query, derived)
}

#[test]
fn all_actual_shapes_preserve_root_native_two_and_charge_exact_frames() {
    for status in [
        SourceProviderStatus::Pending,
        SourceProviderStatus::Rejected,
        SourceProviderStatus::Unavailable,
        SourceProviderStatus::Complete,
    ] {
        let before = phase11_funded_data();
        let original = graph(&before).unwrap();
        let (reserved, root, query, admission) = admitted();
        let owner_values: usize = admission.owners_bytes();
        assert_eq!(admission.transaction.records().len(), 3);
        assert_eq!(
            encoded_transaction_append_bytes(&admission.transaction).unwrap(),
            937 + owner_values as u64,
        );
        assert_eq!(admission.floor.as_ref().unwrap().data().remaining_transactions, 2);
        assert!(replay_edge(&before, &admission.transaction, JournalLimits::default())
            .unwrap().is_some());

        let owners = disposition(&reserved, status);
        let response = derive(&reserved, &owners, root, query, JournalLimits::default()).unwrap();
        validate_derived(&reserved, &response, JournalLimits::default()).unwrap();
        let next = materialize(&reserved, &response.transaction);
        let complete = status == SourceProviderStatus::Complete;
        assert_eq!(response.transaction.records().len(), if complete { 3 } else { 4 });
        assert_eq!(
            encoded_transaction_append_bytes(&response.transaction).unwrap(),
            (if complete { 637 } else { 1091 }) + response.owners_bytes() as u64,
        );
        assert_eq!(
            response.floor.as_ref().map(|floor| floor.data().remaining_transactions),
            if complete { None } else { Some(1) },
        );
        assert!(replay_edge(&reserved, &response.transaction, JournalLimits::default())
            .unwrap().is_some());
        assert_eq!(original_root_remaining_v5(&graph(&next).unwrap(), root).unwrap(), 2);
        assert_eq!(graph(&next).unwrap().sidecars(), original.sidecars());
        let root_floor = root_floor(&before, &original, root)
            .unwrap().to_journal_record().unwrap();
        assert_eq!(
            next.get(&(root_floor.namespace(), root_floor.key().to_vec())).map(Vec::as_slice),
            root_floor.value(),
        );
    }
}

impl DerivedAppend {
    fn owners_bytes(&self) -> usize {
        self.transaction.records().iter()
            .filter(|record| record.namespace() == RecordNamespace::MountSourceAcquisition)
            .map(|record| record.value().unwrap().len())
            .sum()
    }
}

#[test]
fn prior_uncertain_debt_survives_independent_query_and_later_complete() {
    let (reserved, root, query, _) = admitted();
    let response = derive(
        &reserved,
        &disposition(&reserved, SourceProviderStatus::Pending),
        root, query, JournalLimits::default(),
    ).unwrap();
    let uncertain = materialize(&reserved, &response.transaction);
    let old = response.floor.as_ref().unwrap().to_journal_record();
    let immutable = graph(&uncertain).unwrap().legacy().provider_attempts[&query].clone();

    let (child, owners) = reservation(&uncertain);
    let admission = derive(&uncertain, &owners, root, child, JournalLimits::default()).unwrap();
    validate_derived(&uncertain, &admission, JournalLimits::default()).unwrap();
    let child_state = materialize(&uncertain, &admission.transaction);
    let complete = derive(
        &child_state,
        &disposition(&child_state, SourceProviderStatus::Complete),
        root, child, JournalLimits::default(),
    ).unwrap();
    validate_derived(&child_state, &complete, JournalLimits::default()).unwrap();
    let after = materialize(&child_state, &complete.transaction);

    assert_eq!(
        after.get(&(old.namespace(), old.key().to_vec())).map(Vec::as_slice),
        old.value(),
    );
    assert_eq!(graph(&after).unwrap().legacy().provider_attempts[&query], immutable);
    assert_eq!(pending(&after, JournalLimits::default()).unwrap().len(), 1);

    let mut forged = complete.transaction.records().to_vec();
    forged.push(JournalRecord::delete(old.namespace(), old.key().to_vec()));
    let forged = JournalTransaction::new(*complete.transaction.id(), forged).unwrap();
    assert!(validate_edge(
        &child_state, &forged, root, child, complete.kind, JournalLimits::default(),
    ).is_err());
    assert!(replay_edge(&child_state, &forged, JournalLimits::default()).is_err());
}

#[test]
fn metadata_rejoin_preserves_historical_union_after_current_head_changes() {
    let (reserved, root, query, admission) = admitted();
    let response = derive(
        &reserved,
        &disposition(&reserved, SourceProviderStatus::Unavailable),
        root, query, JournalLimits::default(),
    ).unwrap();
    let state = materialize(&reserved, &response.transaction);
    let floor = response.floor.as_ref().unwrap();
    assert_eq!(
        floor.data().admission_native_preservation_union_digest,
        admission.floor.as_ref().unwrap().data().admission_native_preservation_union_digest,
    );
    assert_eq!(bindings::rejoin(&state, &graph(&state).unwrap(), floor).unwrap(), root);
    let bytes = state.iter().map(|((_, key), value)| key.len() + value.len()).sum();
    assert!(validate_rejoined_capacity(&state, bytes, 100_000, 10, JournalLimits::default(), 1000).is_ok());

    let mut orphan = state.clone();
    let session = graph(&state).unwrap().legacy().provider_attempts[&query].session_id;
    orphan.remove(&(RecordNamespace::MountSourceAcquisition, provider_session_key(session)));
    assert!(pending(&orphan, JournalLimits::default()).is_err());
}

#[test]
fn retained_holder_revision_and_exact_immutable_refs_cannot_be_replaced() {
    let (state, _, query, _) = admitted();
    let checked = graph(&state).unwrap();
    let scope = checked.legacy().provider_attempts[&query].scope;
    let key = holder_sequence_key(scope.holder_authority_id);
    let mut holder = checked.legacy().holder_sequences[&scope.holder_authority_id].clone();
    holder.revision += 1;
    let changed = seal_record(StoredRecordV2::HolderSequence { value: holder }).unwrap();
    let (changed_key, value) = encode_mount_source_state_record_v2(&changed).unwrap();
    assert_eq!(changed_key, key);
    let transaction = JournalTransaction::new(
        [187; 16], vec![JournalRecord::put(RecordNamespace::MountSourceAcquisition, key.clone(), value)],
    ).unwrap();

    // Fixed300 preserves a commitment, not a historical HolderSequence archive.
    // Supported later Queries/Session changes require this captured row unchanged.
    assert!(preserve_other_owner(&state, &transaction, JournalLimits::default()).is_err());
    let mut unavailable = state.clone();
    unavailable.remove(&(RecordNamespace::MountSourceAcquisition, key));
    assert!(pending(&unavailable, JournalLimits::default()).is_err());
}

#[test]
fn every_floor_is_checked_before_selection_and_duplicate_query_owners_refuse() {
    let (state, _, _, admission) = admitted();
    let mut malformed = state.clone();
    malformed.insert((RecordNamespace::GlobalCapacityReservation, vec![255; 75]), b"bad".to_vec());
    assert!(pending(&malformed, JournalLimits::default()).is_err());

    let mut data = admission.floor.as_ref().unwrap().data();
    data.admission_transaction = [177; 16];
    let duplicate = QueryCapacityRecordV6::new(data).unwrap().to_journal_record();
    let mut duplicate_state = state.clone();
    duplicate_state.insert((duplicate.namespace(), duplicate.key().to_vec()), duplicate.value().unwrap().to_vec());
    assert!(pending(&duplicate_state, JournalLimits::default()).is_err());
}

#[test]
fn replay_refuses_wrong_root_scope_kind_owner_only_and_bare_floor_mutations() {
    let (state, root, query, admission) = admitted();
    let floor = admission.floor.as_ref().unwrap().to_journal_record();
    let bare = JournalTransaction::new([177; 16], vec![floor.clone()]).unwrap();
    assert!(replay_edge(&phase11_funded_data(), &bare, JournalLimits::default()).is_err());
    let delete = JournalTransaction::new(
        [178; 16], vec![JournalRecord::delete(floor.namespace(), floor.key().to_vec())],
    ).unwrap();
    assert!(replay_edge(&state, &delete, JournalLimits::default()).is_err());
    assert!(require_generic_transaction(&state, &delete, JournalLimits::default()).is_err());
    assert!(validate_edge(
        &phase11_funded_data(), &admission.transaction, [179; 32], query,
        Kind::Reserved, JournalLimits::default(),
    ).is_err());
    assert!(validate_edge(
        &phase11_funded_data(), &admission.transaction, root, query,
        Kind::CompleteConsumed, JournalLimits::default(),
    ).is_err());
    assert!(require_generic_transaction(
        &state, &disposition(&state, SourceProviderStatus::Complete), JournalLimits::default(),
    ).is_err());
}

#[test]
fn actual_admission_replay_rejects_forged_historical_commitments_and_tx() {
    let before = phase11_funded_data();
    let (_, _, _, admission) = admitted();
    let actual = admission.floor.as_ref().unwrap();

    for index in 0..4 {
        let mut data = actual.data();
        match index {
            0 => data.original_owner_cut_digest = [181; 32],
            1 => data.admission_owner_mutation_digest = [182; 32],
            2 => data.admission_native_preservation_union_digest = [183; 32],
            3 => data.remaining_profile_digest = [184; 32],
            _ => unreachable!(),
        }
        let forged_floor = QueryCapacityRecordV6::new(data).unwrap().to_journal_record();
        let mut records = admission.transaction.records().to_vec();
        let last = records.last_mut().unwrap();
        assert_eq!(last.namespace(), RecordNamespace::GlobalCapacityReservation);
        *last = forged_floor;
        let forged = JournalTransaction::new(*admission.transaction.id(), records).unwrap();

        assert!(replay_edge(&before, &forged, JournalLimits::default()).is_err());
    }

    let forged_tx = JournalTransaction::new(
        [185; 16], admission.transaction.records().to_vec(),
    ).unwrap();
    assert!(replay_edge(&before, &forged_tx, JournalLimits::default()).is_err());
    assert_eq!(pending(&before, JournalLimits::default()).unwrap().len(), 0);
}

#[test]
fn an_independent_append_cannot_spend_future_debt_then_hide_it_with_complete() {
    let (state, _, _, _) = admitted();
    let materialized: usize = state.iter().map(|((_, key), value)| key.len() + value.len()).sum();
    let future_bytes: u64 = super::super::capacity_reservation::accounting_reservations(&state)
        .unwrap().values().map(|floor| floor.maximum_bytes).sum();
    let physical_bytes = 100_000;
    let limits = JournalLimits {
        maximum_journal_bytes: physical_bytes + future_bytes,
        ..JournalLimits::default()
    };
    assert!(validate_rejoined_capacity(&state, materialized, physical_bytes, 10, limits, 1000).is_ok());

    let independent = JournalTransaction::new(
        [186; 16],
        vec![JournalRecord::put(RecordNamespace::Operation, b"independent".to_vec(), vec![1])],
    ).unwrap();
    preserve_other_owner(&state, &independent, limits).unwrap();
    let after = materialize(&state, &independent);
    let after_bytes = after.iter().map(|((_, key), value)| key.len() + value.len()).sum();
    let following_bytes = physical_bytes + encoded_transaction_append_bytes(&independent).unwrap();

    // The same post-state-only helper is used at each physical logical replay
    // prefix. Later deletion of this Query's floor cannot hide this failure.
    assert!(super::super::validate_reserved_capacity(
        &after, after_bytes, &[], None, following_bytes, 11, limits, None,
    ).is_err());
}

#[test]
fn all_eight_opened_limits_and_actual_next_sequence_are_independent_checks() {
    let (state, _, _, _) = admitted();
    let materialized = state.iter().map(|((_, key), value)| key.len() + value.len()).sum();
    let base = JournalLimits::default();
    let mut cases = Vec::new();
    cases.push(JournalLimits { maximum_key_bytes: 74, ..base });
    cases.push(JournalLimits { maximum_record_bytes: MAXIMUM_PROVIDER_ATTEMPT_VALUE_BYTES, ..base });
    cases.push(JournalLimits { maximum_records_per_transaction: 4, ..base });
    cases.push(JournalLimits { maximum_transaction_bytes: 2 * MAXIMUM_PROVIDER_ATTEMPT_VALUE_BYTES, ..base });
    cases.push(JournalLimits { maximum_journal_bytes: 100_000, ..base });
    cases.push(JournalLimits { maximum_transactions: 10, ..base });
    cases.push(JournalLimits { maximum_materialized_bytes: materialized, ..base });
    cases.push(JournalLimits { maximum_materialized_records: state.len(), ..base });
    for (index, limits) in cases.into_iter().enumerate() {
        assert!(
            validate_rejoined_capacity(&state, materialized, 100_000, 10, limits, 1000).is_err(),
            "limit={index}",
        );
    }

    assert!(require_sequence_headroom(&state, u64::MAX - 1).is_err());
    let independent = JournalTransaction::new(
        [199; 16],
        vec![JournalRecord::put(RecordNamespace::Operation, b"independent".to_vec(), vec![1])],
    ).unwrap();
    assert!(require_append_sequence_headroom(&state, &independent, u64::MAX - 1).is_err());
    assert!(preserve_other_owner(&state, &independent, base).is_ok());
}
