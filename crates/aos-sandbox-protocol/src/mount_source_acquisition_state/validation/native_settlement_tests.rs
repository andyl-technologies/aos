//! Signed canonical native recovery fixtures and adverse terminal graph checks.
//!
//! Fixtures reproduce the existing four/two/four/three legacy replacements.
//! They contain no protected journal, live clock, descriptor, or owner authority.

use super::*;
use crate::mount_source_acquisition_state::{
    encode_mount_source_state_record_v2, seal_record, validate_mount_source_state_graph_v2,
};
use aos_proto::aos::sandbox::local::v1::AcquireMountSourceRequest;
use aos_sandbox_source_provider_protocol::{
    AcquireSourceRequestV1, InventorySourceRequestV1, InventorySourceResponseV1,
    NativeAcquireCatalogBindingV3, NativeRecoveryTerminalDigestsV1, SourceProviderInventoryV1,
    SourceProviderMethod, SourceProviderResponseStatusV1, SourceProviderStatus,
    digest_signed_request, empty_descriptor_set_commitment_v1, encode_acquire_request,
    encode_inventory_request, encode_inventory_response, response_result_digest_v1, sign_inventory,
    sign_request, sign_response_status,
};
use buffa::Message as _;
use ed25519_dalek::SigningKey;

#[path = "../native_held_completion/tests/fixture.rs"]
mod fixture;

fn digest(value: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([value; 32])
}

/// Captures the canonical legacy snapshots used by native v2 transition tests.
pub(in crate::mount_source_acquisition_state) struct NativeAbsenceStages {
    /// Original canonical native admission companions.
    pub initial: SourceAcquisitionTableV2,
    /// Original dead replacement with exact root/tail2 and new Session.
    pub replacement: SourceAcquisitionTableV2,
    /// Exact pending Inventory1 and its immutable Head before-image.
    pub inventory_reserved: SourceAcquisitionTableV2,
    /// Signed Complete Inventory2 and the resolved original root/tail3.
    pub resolved: SourceAcquisitionTableV2,
    /// Dedicated signed unavailable wrapper4 and the no-evidence Faulted row.
    pub settled: SourceAcquisitionTableV2,
}

pub(in crate::mount_source_acquisition_state) fn native_absence_stages() -> NativeAbsenceStages {
    let initial = initial_native_graph();
    let replacement = unresolved_graph_from(initial.clone());
    let inventory_reserved = reserve_inventory(replacement.clone(), true);
    let resolved = resolve_absent_inventory(inventory_reserved.clone());
    let settled = settle_graph(resolved.clone());
    NativeAbsenceStages {
        initial,
        replacement,
        inventory_reserved,
        resolved,
        settled,
    }
}

pub(in crate::mount_source_acquisition_state) fn canonical_records(
    table: &SourceAcquisitionTableV2,
) -> BTreeMap<Vec<u8>, Vec<u8>> {
    table
        .provider_sessions
        .values()
        .cloned()
        .map(|value| StoredRecordV2::ProviderSession { value })
        .chain(
            table
                .provider_attempts
                .values()
                .cloned()
                .map(|value| StoredRecordV2::ProviderQueryAttempt { value }),
        )
        .chain(
            table
                .acquisitions
                .values()
                .cloned()
                .map(|value| StoredRecordV2::Acquisition { value }),
        )
        .chain(
            table
                .provider_heads
                .values()
                .cloned()
                .map(|value| StoredRecordV2::ProviderHead { value }),
        )
        .chain(
            table
                .holder_sequences
                .values()
                .cloned()
                .map(|value| StoredRecordV2::HolderSequence { value }),
        )
        .map(|record| encode_mount_source_state_record_v2(&record).unwrap())
        .collect()
}

pub(in crate::mount_source_acquisition_state) fn initial_native_graph() -> SourceAcquisitionTableV2
{
    initial_graph(true)
}

fn initial_graph(native: bool) -> SourceAcquisitionTableV2 {
    let session = fixture::signed_session([19; 16], 31);
    let catalog = NativeAcquireCatalogBindingV3::new(
        digest(10),
        1,
        digest(62),
        1,
        digest(62),
        digest(63),
        digest(64),
    )
    .unwrap();
    let records = fixture::initial_signed_graph_with_catalog(
        session,
        500,
        [62; 32],
        [63; 32],
        native.then_some(catalog),
    )
    .into_iter()
    .map(|record| encode_mount_source_state_record_v2(&record).unwrap())
    .collect::<BTreeMap<_, _>>();
    validate_mount_source_state_graph_v2(
        records
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .unwrap()
}

pub(in crate::mount_source_acquisition_state) fn unresolved_graph() -> SourceAcquisitionTableV2 {
    unresolved_graph_from(initial_native_graph())
}

pub(in crate::mount_source_acquisition_state) fn reserved_inventory_graph()
-> SourceAcquisitionTableV2 {
    reserve_inventory(unresolved_graph(), true)
}

pub(in crate::mount_source_acquisition_state) fn resolved_absent_graph() -> SourceAcquisitionTableV2
{
    resolve_absent_inventory(reserved_inventory_graph())
}

pub(in crate::mount_source_acquisition_state) fn settled_absent_graph() -> SourceAcquisitionTableV2
{
    settle_graph(resolved_absent_graph())
}

pub(in crate::mount_source_acquisition_state) fn settled_unresolved_graph()
-> SourceAcquisitionTableV2 {
    settle_graph(unresolved_graph())
}

fn original(table: &SourceAcquisitionTableV2) -> &SourceProviderQueryAttemptV2 {
    table
        .provider_attempts
        .values()
        .find(|attempt| {
            attempt.method == ProviderMethodV2::Acquire
                && attempt.previous_attempt_id.is_none()
                && attempt
                    .provider_acquisition
                    .is_some_and(|identity| identity.acquisition_sequence == 1)
        })
        .unwrap()
}

fn reference(attempt: &SourceProviderQueryAttemptV2) -> RecordRefV2 {
    RecordRefV2 {
        id: attempt.attempt_id,
        revision: attempt.revision,
        record_digest: attempt.record_digest,
    }
}

fn sealed_attempt(value: SourceProviderQueryAttemptV2) -> SourceProviderQueryAttemptV2 {
    match seal_record(StoredRecordV2::ProviderQueryAttempt { value }).unwrap() {
        StoredRecordV2::ProviderQueryAttempt { value } => value,
        _ => panic!("fixture attempt kind"),
    }
}

fn sealed_row(value: SourceAcquisitionRowV2) -> SourceAcquisitionRowV2 {
    match seal_record(StoredRecordV2::Acquisition { value }).unwrap() {
        StoredRecordV2::Acquisition { value } => value,
        _ => panic!("fixture row kind"),
    }
}

fn sealed_head(value: SourceProviderHeadV2) -> SourceProviderHeadV2 {
    match seal_record(StoredRecordV2::ProviderHead { value }).unwrap() {
        StoredRecordV2::ProviderHead { value } => value,
        _ => panic!("fixture head kind"),
    }
}

fn successor(predecessor: &SourceProviderSessionV2, nonce: u8) -> SourceProviderSessionV2 {
    let mut session = fixture::signed_session([nonce; 16], nonce);
    session.predecessor_session_id = Some(predecessor.session_id);
    match seal_record(StoredRecordV2::ProviderSession { value: session }).unwrap() {
        StoredRecordV2::ProviderSession { value } => value,
        _ => panic!("fixture session kind"),
    }
}

fn abandoned(
    original: &SourceProviderQueryAttemptV2,
    old: &SourceProviderSessionV2,
    successor: &SourceProviderSessionV2,
) -> SourceProviderQueryAttemptV2 {
    let mut execution = DeadProviderExecutionProjectionV2 {
        proof_kind: DeadProviderExecutionProofKindV2::PidfdExited,
        old_session_id: old.session_id,
        old_session_record_digest: old.record_digest,
        node_id: old.node_id,
        old_kernel_boot_id: old.kernel_boot_id,
        provider_process_instance: old.provider_process_instance,
        process_execution_digest: old.provider_execution.process_execution_digest,
        observed_kernel_boot_id: old.kernel_boot_id,
        death_evidence_digest: [0; 32],
    };
    execution.death_evidence_digest = death_digest(&execution).unwrap();
    let mut attempt = original.clone();
    attempt.revision = 2;
    attempt.state = ProviderAttemptStateV2::AbandonedIndeterminate {
        dead_execution: execution,
        successor_session_id: successor.session_id,
        recovery_root_attempt_id: original.attempt_id,
        outcome_may_exist: true,
        resolution: None,
    };
    sealed_attempt(attempt)
}

fn unresolved_graph_from(mut table: SourceAcquisitionTableV2) -> SourceAcquisitionTableV2 {
    let root = original(&table).clone();
    let old = table.provider_sessions[&root.session_id].clone();
    let session = successor(&old, 32);
    let root = abandoned(&root, &old, &session);
    let root_reference = reference(&root);
    let mut row = table.acquisitions.values().next().unwrap().clone();
    row.revision += 1;
    row.acquire_lineage.root = root_reference;
    row.acquire_lineage.tail = root_reference;
    row.recovery = AcquisitionRecoveryV2::InventoryRequired {
        root_attempt: root_reference,
    };
    let row = sealed_row(row);
    let mut head = table.provider_heads.values().next().unwrap().clone();
    head.revision += 1;
    head.current_session_id = session.session_id;
    head.current_session_record_digest = session.record_digest;
    head.next_request_sequence = 1;
    head.next_response_sequence = 1;
    head.pending_attempt = None;
    head.recovery_barrier = Some(RecoveryBarrierV2 {
        root_attempt: root_reference,
        required_session_id: session.session_id,
        replacement_count: 1,
        baseline_inventory_ordinal: head.inventory_observation_ordinal,
        recovery_inventory_tail: None,
    });
    let head = sealed_head(head);
    table.provider_sessions.insert(session.session_id, session);
    table.provider_attempts.insert(root.attempt_id, root);
    table.acquisitions.insert(row.acquisition_id, row);
    table.provider_heads.insert(
        (
            head.scope.holder_authority_id,
            head.scope.provider_authority_id,
        ),
        head,
    );
    table
}

fn idle_replacement(mut table: SourceAcquisitionTableV2, nonce: u8) -> SourceAcquisitionTableV2 {
    let head = table.provider_heads.values().next().unwrap().clone();
    let old = &table.provider_sessions[&head.current_session_id];
    let barrier = head.recovery_barrier.as_ref().unwrap();
    let replacement_count = barrier.replacement_count + 1;
    let mut session = successor(old, nonce);
    session.barrier_idle_replacement = Some(BarrierIdleReplacementWitnessV2 {
        root_attempt: barrier.root_attempt,
        predecessor_head: Box::new(head.clone()),
        replacement_count,
        predecessor_observation: BarrierIdlePredecessorObservationV2::Live,
    });
    let StoredRecordV2::ProviderSession { value: session } =
        seal_record(StoredRecordV2::ProviderSession { value: session }).unwrap()
    else {
        panic!("idle fixture session kind");
    };
    let mut next_head = head;
    next_head.revision += 1;
    next_head.current_session_id = session.session_id;
    next_head.current_session_record_digest = session.record_digest;
    let barrier = next_head.recovery_barrier.as_mut().unwrap();
    barrier.required_session_id = session.session_id;
    barrier.replacement_count = replacement_count;
    let next_head = sealed_head(next_head);
    table.provider_sessions.insert(session.session_id, session);
    table.provider_heads.insert(
        (
            next_head.scope.holder_authority_id,
            next_head.scope.provider_authority_id,
        ),
        next_head,
    );
    table
}

pub(in crate::mount_source_acquisition_state) fn resolved_absent_after_idle_graph()
-> SourceAcquisitionTableV2 {
    let replacement = idle_replacement(idle_replacement(unresolved_graph(), 34), 35);
    resolve_absent_inventory(reserve_inventory(replacement, true))
}

fn head_predecessor(head: &SourceProviderHeadV2) -> OwnerPredecessorWitnessV2 {
    let mut head_id = [0; 32];
    head_id[..16].copy_from_slice(&head.scope.holder_authority_id);
    head_id[16..].copy_from_slice(&head.scope.provider_authority_id);
    OwnerPredecessorWitnessV2::ProviderHead {
        value: ProviderHeadPredecessorWitnessV2 {
            record: RecordRefV2 {
                id: head_id,
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
            last_reconciliation: head.last_reconciliation,
            recovery_barrier: head.recovery_barrier.clone(),
        },
    }
}

fn reserve_inventory(
    mut table: SourceAcquisitionTableV2,
    recovery: bool,
) -> SourceAcquisitionTableV2 {
    let head = table.provider_heads.values().next().unwrap().clone();
    let session = table.provider_sessions[&head.current_session_id].clone();
    let correlations = inventory_correlation_set_v2(
        table
            .acquisitions
            .values()
            .filter_map(inventory_correlation_for_row_v2)
            .collect(),
    )
    .unwrap();
    let intent = ProviderIntentV2::Inventory {
        value: InventoryIntentV2 {
            scope: head.scope,
            known_inventory_generation: head
                .inventory_floor
                .as_ref()
                .map(|floor| floor.inventory_generation),
            known_inventory_digest: head
                .inventory_floor
                .as_ref()
                .map(|floor| floor.inventory_digest),
            known_catalog_generation: head
                .inventory_floor
                .as_ref()
                .map(|floor| floor.catalog_generation),
            known_catalog_digest: head
                .inventory_floor
                .as_ref()
                .map(|floor| floor.catalog_digest),
            known_observation_ordinal: head.inventory_observation_ordinal,
            recovery_root_attempt_id: recovery.then(|| original(&table).attempt_id),
            correlation_digest: correlations.digest,
        },
    };
    let mut inventory = SourceProviderQueryAttemptV2 {
        attempt_id: [0; 32],
        revision: 1,
        scope: head.scope,
        method: ProviderMethodV2::Inventory,
        owner: ProviderQueryOwnerV2::Inventory,
        immutable_intent_digest: intent_digest(&intent).unwrap(),
        intent,
        provider_acquisition: None,
        lineage_root_attempt_id: [0; 32],
        previous_attempt_id: None,
        attempt_number: 1,
        session_id: session.session_id,
        session_record_digest: session.record_digest,
        signer_set_commitment: session.signer_set_commitment,
        trust_digest: session.trust_digest,
        revocation_digest: session.revocation_digest,
        route_digest: session.route_digest,
        process_execution_digest: session.provider_execution.process_execution_digest,
        normalized_acquire_intent: None,
        acquire_verification_floor: None,
        inventory_correlations: Some(correlations),
        request_id: [0; 16],
        request_sequence: head.next_request_sequence,
        signed_request: Vec::new(),
        signed_request_digest: [0; 32],
        owner_predecessor_revision: head.revision,
        owner_predecessor_digest: head.record_digest,
        owner_predecessor: Some(head_predecessor(&head)),
        state: ProviderAttemptStateV2::Reserved,
        record_digest: [0; 32],
    };
    inventory.attempt_id = attempt_id(&inventory);
    inventory.lineage_root_attempt_id = inventory.attempt_id;
    inventory.request_id = request_id(inventory.attempt_id);
    let request = InventorySourceRequestV1::new(
        ObjectDigest::from_bytes(session.session_binding),
        inventory.request_sequence,
        inventory.request_id,
        session.scope.holder_authority_id,
        session.root_mount_authority_generation,
        ObjectDigest::from_bytes(session.root_mount_authority_digest),
        head.inventory_floor
            .as_ref()
            .map(|floor| ObjectDigest::from_bytes(floor.inventory_digest)),
        500,
    )
    .unwrap();
    let key = SigningKey::from_bytes(&[12; 32]);
    let signed = sign_request(
        SourceProviderMethod::Inventory,
        encode_inventory_request(&request),
        fixture::signer(
            session.scope.holder_authority_id,
            [22; 16],
            SourceProviderKeyUsageV1::RootMountRecord,
            &key,
        ),
        &key,
    )
    .unwrap();
    inventory.signed_request_digest = *digest_signed_request(&signed).as_bytes();
    inventory.signed_request = signed.to_canonical_bytes();
    let inventory = sealed_attempt(inventory);
    let inventory_reference = reference(&inventory);
    let mut next_head = head;
    next_head.revision += 1;
    next_head.next_request_sequence += 1;
    next_head.pending_attempt = Some(inventory_reference);
    let next_head = sealed_head(next_head);
    table
        .provider_attempts
        .insert(inventory.attempt_id, inventory);
    table.provider_heads.insert(
        (
            next_head.scope.holder_authority_id,
            next_head.scope.provider_authority_id,
        ),
        next_head,
    );
    table
}

fn resolve_absent_inventory(mut table: SourceAcquisitionTableV2) -> SourceAcquisitionTableV2 {
    let head = table.provider_heads.values().next().unwrap().clone();
    let reserved = table.provider_attempts[&head.pending_attempt.unwrap().id].clone();
    let session = table.provider_sessions[&reserved.session_id].clone();
    let signed_request =
        SignedSourceProviderRequestV1::from_canonical_bytes(&reserved.signed_request).unwrap();
    let request = decode_inventory_request(signed_request.subject()).unwrap();
    let key = SigningKey::from_bytes(&[14; 32]);
    let signer = fixture::signer(
        session.scope.provider_authority_id,
        [24; 16],
        SourceProviderKeyUsageV1::ProviderOutcome,
        &key,
    );
    let inventory = SourceProviderInventoryV1::new(
        reserved.request_id,
        digest_inventory_request(&request),
        session.scope.holder_authority_id,
        session.root_mount_authority_generation,
        ObjectDigest::from_bytes(session.root_mount_authority_digest),
        session_provider_authority(&session).unwrap(),
        session.provider_process_instance,
        1,
        digest(62),
        1,
        Vec::new(),
    )
    .unwrap();
    let signed_inventory = sign_inventory(inventory, signer.clone(), &key).unwrap();
    let result = signed_inventory.to_canonical_bytes();
    let result_digest = response_result_digest_v1(
        SourceProviderMethod::Inventory,
        SourceProviderStatus::Complete,
        Some(&result),
    );
    let status = sign_response_status(
        SourceProviderResponseStatusV1::new(
            SourceProviderMethod::Inventory,
            reserved.request_id,
            ObjectDigest::from_bytes(reserved.signed_request_digest),
            SourceProviderStatus::Complete,
            session.provider_process_instance,
            ObjectDigest::from_bytes(session.session_binding),
            reserved.request_sequence,
            result_digest,
            empty_descriptor_set_commitment_v1(),
        )
        .unwrap(),
        signer,
        &key,
    )
    .unwrap();
    let response = encode_inventory_response(
        &InventorySourceResponseV1::new(status.clone(), Some(result.clone())).unwrap(),
    );
    let mut anchor = OutcomeVerificationAnchorV2 {
        verification_started_seconds: 110,
        verification_completed_seconds: 111,
        kernel_boot_id: session.kernel_boot_id,
        trusted_clock_evidence_digest: session.trusted_clock_evidence_digest,
        anchor_digest: [0; 32],
    };
    anchor.anchor_digest = super::super::checkpoint::outcome_verification_anchor_digest_v2(
        &anchor,
        session.session_id,
        reserved.attempt_id,
        reserved.request_sequence,
        reserved.request_sequence,
        Sha256::digest(&response).into(),
    );
    let mut complete = reserved;
    complete.revision = 2;
    complete.state = ProviderAttemptStateV2::DispositionConsumed {
        response_sequence: complete.request_sequence,
        verification_anchor: anchor,
        status: ProviderStatusV2::Complete,
        signed_status_digest: Sha256::digest(status.to_canonical_bytes()).into(),
        signed_status: status.to_canonical_bytes(),
        signed_result: result.clone(),
        signed_result_digest: *result_digest.as_bytes(),
    };
    let complete = sealed_attempt(complete);
    let inventory_reference = reference(&complete);
    table
        .provider_attempts
        .insert(complete.attempt_id, complete);
    let mut next_head = head;
    next_head.revision += 1;
    next_head.next_response_sequence += 1;
    next_head.pending_attempt = None;
    next_head.last_inventory_attempt = Some(inventory_reference);
    next_head.inventory_observation_ordinal = 1;
    next_head.inventory_floor = Some(InventoryFloorV2 {
        attempt: inventory_reference,
        provider_authority_generation: session.provider_authority_generation,
        provider_authority_digest: session.provider_authority_digest,
        provider_outcome_signer_digest: session.signers[3].public_key_fingerprint,
        inventory_generation: 1,
        inventory_digest: *digest_inventory(signed_inventory.subject()).as_bytes(),
        catalog_generation: 1,
        catalog_digest: [62; 32],
        signed_result_digest: *result_digest.as_bytes(),
    });
    next_head.recovery_barrier = None;
    next_head.last_reconciliation = Some(
        reproduce_reconciliation(&next_head, &table.provider_attempts, &table.acquisitions)
            .unwrap(),
    );
    let reconciliation = next_head.last_reconciliation.unwrap();
    let proof = RecoveryInventoryProofV2 {
        inventory_attempt: inventory_reference,
        inventory_digest: *digest_inventory(signed_inventory.subject()).as_bytes(),
        inventory_observation_ordinal: 1,
        projection_epoch: next_head.current_projection_epoch,
        projection_digest: next_head.current_projection_digest,
        reconciliation,
        reconciliation_digest: reconciliation_commitment(&reconciliation),
    };
    let mut root = original(&table).clone();
    root.revision = 3;
    let ProviderAttemptStateV2::AbandonedIndeterminate { resolution, .. } = &mut root.state else {
        panic!("fixture abandoned root");
    };
    *resolution = Some(RecoveryResolutionV2::RetryAcquireSameIntent { proof });
    let root = sealed_attempt(root);
    let root_reference = reference(&root);
    let mut row = table.acquisitions.values().next().unwrap().clone();
    row.revision += 1;
    row.acquire_lineage.root = root_reference;
    row.acquire_lineage.tail = root_reference;
    row.recovery = AcquisitionRecoveryV2::RetryPermitted {
        root_attempt: root_reference,
    };
    let row = sealed_row(row);
    let next_head = sealed_head(next_head);
    table.provider_attempts.insert(root.attempt_id, root);
    table.acquisitions.insert(row.acquisition_id, row);
    table.provider_heads.insert(
        (
            next_head.scope.holder_authority_id,
            next_head.scope.provider_authority_id,
        ),
        next_head,
    );
    table
}

fn settle_graph(mut table: SourceAcquisitionTableV2) -> SourceAcquisitionTableV2 {
    let root = original(&table).clone();
    let head = table.provider_heads.values().next().unwrap().clone();
    let session = &table.provider_sessions[&head.current_session_id];
    let mut row = table.acquisitions.values().next().unwrap().clone();
    let query = RecoveryCurrentnessQueryV1::new(
        ObjectDigest::from_bytes(session.session_binding),
        [64; 32],
        1,
        root.scope.provider_authority_id,
        root.scope.holder_authority_id,
        ObjectDigest::from_bytes(row.acquisition_id),
        ObjectDigest::from_bytes(root.signed_request_digest),
        ObjectDigest::from_bytes(root.record_digest),
    )
    .unwrap();
    let key = SigningKey::from_bytes(&[14; 32]);
    let signed = SignedNativeRecoveryUnavailableV1::sign(
        &query,
        NativeRecoveryTerminalDigestsV1 {
            reservation: digest(71),
            faulted_acquisition: digest(72),
            retired_attempt: digest(73),
            cleared_session: digest(74),
        },
        fixture::signer(
            root.scope.provider_authority_id,
            [24; 16],
            SourceProviderKeyUsageV1::ProviderOutcome,
            &key,
        ),
        &key,
    )
    .unwrap();
    let mut terminal = root.clone();
    terminal.revision += 1;
    terminal.state = ProviderAttemptStateV2::NativeNoDispatchSettled {
        prior_state: Box::new(root.state),
        canonical_query: query.to_canonical_bytes().to_vec(),
        signed_settlement: signed.to_canonical_bytes(),
        settlement_session_id: session.session_id,
    };
    let terminal = sealed_attempt(terminal);
    let terminal_reference = reference(&terminal);
    row.revision += 1;
    row.phase = SourceAcquisitionPhaseV2::Faulted;
    row.faulted_from = Some(SourceAcquisitionPhaseV2::PendingQuery);
    row.fault_digest = Some(native_recovery_settlement_digest_v2(
        &signed.to_canonical_bytes(),
    ));
    row.recovery = AcquisitionRecoveryV2::Ready;
    row.acquire_lineage.root = terminal_reference;
    row.acquire_lineage.tail = terminal_reference;
    let row = sealed_row(row);
    let mut next_head = head;
    next_head.revision += 1;
    next_head.recovery_barrier = None;
    let next_head = sealed_head(next_head);
    table
        .provider_attempts
        .insert(terminal.attempt_id, terminal);
    table.acquisitions.insert(row.acquisition_id, row);
    table.provider_heads.insert(
        (
            next_head.scope.holder_authority_id,
            next_head.scope.provider_authority_id,
        ),
        next_head,
    );
    table
}

pub(in crate::mount_source_acquisition_state) fn later_unrelated_inventory_barrier_graph()
-> SourceAcquisitionTableV2 {
    let mut table = reserve_inventory(settled_unresolved_graph(), false);
    let head = table.provider_heads.values().next().unwrap().clone();
    let inventory = table.provider_attempts[&head.pending_attempt.unwrap().id].clone();
    let old = table.provider_sessions[&inventory.session_id].clone();
    let session = successor(&old, 33);
    let inventory = abandoned(&inventory, &old, &session);
    let inventory_reference = reference(&inventory);
    let mut next_head = head;
    next_head.revision += 1;
    next_head.current_session_id = session.session_id;
    next_head.current_session_record_digest = session.record_digest;
    next_head.next_request_sequence = 1;
    next_head.next_response_sequence = 1;
    next_head.pending_attempt = None;
    next_head.last_inventory_attempt = Some(inventory_reference);
    next_head.recovery_barrier = Some(RecoveryBarrierV2 {
        root_attempt: inventory_reference,
        required_session_id: session.session_id,
        replacement_count: 1,
        baseline_inventory_ordinal: next_head.inventory_observation_ordinal,
        recovery_inventory_tail: None,
    });
    let next_head = sealed_head(next_head);
    table.provider_sessions.insert(session.session_id, session);
    table
        .provider_attempts
        .insert(inventory.attempt_id, inventory);
    table.provider_heads.insert(
        (
            next_head.scope.holder_authority_id,
            next_head.scope.provider_authority_id,
        ),
        next_head,
    );
    table
}

/// Adds a distinct signed Acquire through the existing canonical admission shape.
pub(in crate::mount_source_acquisition_state) fn reserve_later_acquire(
    mut table: SourceAcquisitionTableV2,
    native: bool,
) -> SourceAcquisitionTableV2 {
    let root = original(&table).clone();
    let mut head = table.provider_heads.values().next().unwrap().clone();
    let session = &table.provider_sessions[&head.current_session_id];
    let (mount_bytes, _) = fixture::mount_acquire_request();
    let mut mount_request =
        AcquireMountSourceRequest::decode_from_slice(mount_bytes.as_slice()).unwrap();
    mount_request.header.get_or_insert_default().request_id = vec![94; 16];
    let mount_bytes = mount_request.encode_to_vec();
    let mount = decode_historical_acquire_mount_source_request(&mount_bytes).unwrap();
    let mount = mount.request();
    let ProviderIntentV2::Acquire { value: mut intent } = root.intent.clone() else {
        panic!("fixture original Acquire");
    };
    intent.acquisition_id = *mount.acquisition_id().as_bytes();
    intent.mount_request = mount_bytes.clone();
    intent.mount_request_digest = *mount.request_digest().as_bytes();
    let intent = ProviderIntentV2::Acquire { value: intent };
    let provider_acquisition = ProviderAcquisitionIdentityV2 {
        holder_authority_id: root.scope.holder_authority_id,
        holder_authority_generation: session.root_mount_authority_generation,
        holder_authority_digest: session.root_mount_authority_digest,
        acquisition_sequence: 2,
        acquisition_id: *source_acquisition_id_v2(
            root.scope.holder_authority_id,
            session.root_mount_authority_generation,
            ObjectDigest::from_bytes(session.root_mount_authority_digest),
            2,
        )
        .as_bytes(),
    };
    let mut attempt = root.clone();
    attempt.revision = 1;
    attempt.owner = ProviderQueryOwnerV2::Acquire {
        acquisition_id: *mount.acquisition_id().as_bytes(),
    };
    attempt.intent = intent;
    attempt.immutable_intent_digest = intent_digest(&attempt.intent).unwrap();
    attempt.provider_acquisition = Some(provider_acquisition);
    attempt.lineage_root_attempt_id = [0; 32];
    attempt.previous_attempt_id = None;
    attempt.attempt_number = 1;
    attempt.session_id = session.session_id;
    attempt.session_record_digest = session.record_digest;
    attempt.request_sequence = head.next_request_sequence;
    attempt.owner_predecessor = None;
    attempt.owner_predecessor_revision = 0;
    attempt.owner_predecessor_digest = [0; 32];
    attempt.state = ProviderAttemptStateV2::Reserved;
    attempt.attempt_id = attempt_id(&attempt);
    attempt.lineage_root_attempt_id = attempt.attempt_id;
    attempt.request_id = request_id(attempt.attempt_id);
    let old_signed =
        SignedSourceProviderRequestV1::from_canonical_bytes(&root.signed_request).unwrap();
    let old_request = decode_acquire_request(old_signed.subject()).unwrap();
    let request = AcquireSourceRequestV1::new_v2(
        ObjectDigest::from_bytes(session.session_binding),
        attempt.request_sequence,
        attempt.request_id,
        2,
        mount.prospective_mount_template().to_vec(),
        mount.prospective_mount_template_digest(),
        SourceUseV1::MountCreate,
        session.node_id,
        session.kernel_boot_id,
        root.scope.holder_authority_id,
        session.root_mount_authority_generation,
        ObjectDigest::from_bytes(session.root_mount_authority_digest),
        mount.source_binding().canonical_bytes(),
        old_request.binding_digest(),
        500,
        mount.requested_lease_seconds(),
        ObjectDigest::from_bytes(session.revocation_digest),
        mount.recursive(),
        mount.requested_maximum_submounts(),
        mount.kernel_coupled(),
    )
    .unwrap();
    let request = if native {
        AcquireSourceRequestV1::new_native_v3(
            request,
            old_request.native_catalog().unwrap().clone(),
        )
        .unwrap()
    } else {
        request
    };
    let normalized = NormalizedAcquisitionIntentV2::from_original_acquire_request(
        &request,
        session_provider_authority(session).unwrap(),
        session_holder_authority(session).unwrap(),
        session.node_id,
        session.kernel_boot_id,
        session.scope.route_id,
        session.route_generation,
        ObjectDigest::from_bytes(session.route_digest),
        ObjectDigest::from_bytes(session.scope.resource_namespace_digest),
        session.revocation_generation,
        ObjectDigest::from_bytes(session.revocation_digest),
    )
    .unwrap();
    attempt.normalized_acquire_intent = Some(AttemptNormalizedAcquireV2 {
        bytes: normalized.to_canonical_bytes(),
        digest: *normalized.digest().as_bytes(),
        maximum_lease_expiry_seconds: 500,
    });
    let key = SigningKey::from_bytes(&[12; 32]);
    let signed = sign_request(
        SourceProviderMethod::Acquire,
        encode_acquire_request(&request),
        fixture::signer(
            session.scope.holder_authority_id,
            [22; 16],
            SourceProviderKeyUsageV1::RootMountRecord,
            &key,
        ),
        &key,
    )
    .unwrap();
    attempt.signed_request = signed.to_canonical_bytes();
    attempt.signed_request_digest = *digest_signed_request(&signed).as_bytes();
    let attempt = sealed_attempt(attempt);
    let attempt_reference = reference(&attempt);
    let mut row = initial_native_graph()
        .acquisitions
        .into_values()
        .next()
        .unwrap();
    row.acquisition_id = *mount.acquisition_id().as_bytes();
    row.acquire = MountOperationV2 {
        operation_id: *mount.header().request_id(),
        request_digest: *mount.request_digest().as_bytes(),
    };
    row.mount_acquire_request = mount_bytes;
    row.provider_acquisition = provider_acquisition;
    row.acquire_intent_digest = attempt.immutable_intent_digest;
    row.acquire_lineage.root = attempt_reference;
    row.acquire_lineage.tail = attempt_reference;
    let row = sealed_row(row);
    table.acquisitions.insert(row.acquisition_id, row);
    head.revision += 1;
    head.next_request_sequence += 1;
    head.pending_attempt = Some(attempt_reference);
    head.current_projection_epoch += 1;
    head.current_projection_digest = project_scope(
        head.scope,
        head.current_projection_epoch,
        &table.acquisitions,
    )
    .unwrap()
    .digest;
    head.last_reconciliation = None;
    let head = sealed_head(head);
    let mut holder = table.holder_sequences.values().next().unwrap().clone();
    holder.revision += 1;
    holder.last_allocated_acquisition_sequence = 2;
    holder.next_acquisition_sequence = 3;
    let StoredRecordV2::HolderSequence { value: holder } =
        seal_record(StoredRecordV2::HolderSequence { value: holder }).unwrap()
    else {
        panic!("later Acquire holder");
    };
    table
        .holder_sequences
        .insert(holder.holder_authority_id, holder);
    table.provider_attempts.insert(attempt.attempt_id, attempt);
    table.provider_heads.insert(
        (
            head.scope.holder_authority_id,
            head.scope.provider_authority_id,
        ),
        head,
    );
    table
}

pub(in crate::mount_source_acquisition_state) fn later_unrelated_barrier_graph()
-> SourceAcquisitionTableV2 {
    let mut table = reserve_later_acquire(settled_absent_graph(), true);
    let mut head = table.provider_heads.values().next().unwrap().clone();
    let pending = table.provider_attempts[&head.pending_attempt.unwrap().id].clone();
    let old = &table.provider_sessions[&pending.session_id];
    let session = successor(old, 33);
    let attempt = abandoned(&pending, old, &session);
    let attempt_reference = reference(&attempt);
    let mut row = table.acquisitions[&pending.owner.owner_id()].clone();
    row.revision += 1;
    row.acquire_lineage.root = attempt_reference;
    row.acquire_lineage.tail = attempt_reference;
    row.recovery = AcquisitionRecoveryV2::InventoryRequired {
        root_attempt: attempt_reference,
    };
    let row = sealed_row(row);
    head.revision += 1;
    head.current_session_id = session.session_id;
    head.current_session_record_digest = session.record_digest;
    head.next_request_sequence = 1;
    head.next_response_sequence = 1;
    head.pending_attempt = None;
    head.last_reconciliation = None;
    head.recovery_barrier = Some(RecoveryBarrierV2 {
        root_attempt: attempt_reference,
        required_session_id: session.session_id,
        replacement_count: 1,
        baseline_inventory_ordinal: head.inventory_observation_ordinal,
        recovery_inventory_tail: None,
    });
    let head = sealed_head(head);
    table.provider_sessions.insert(session.session_id, session);
    table.provider_attempts.insert(attempt.attempt_id, attempt);
    table.acquisitions.insert(row.acquisition_id, row);
    table.provider_heads.insert(
        (
            head.scope.holder_authority_id,
            head.scope.provider_authority_id,
        ),
        head,
    );
    table
}

#[test]
fn native_absent_inventory_prior3_reaches_settled4_and_preserves_exact_proof() {
    let stages = native_absence_stages();
    for table in [
        &stages.initial,
        &stages.replacement,
        &stages.inventory_reserved,
        &stages.resolved,
        &stages.settled,
    ] {
        let records = canonical_records(table);
        validate_mount_source_state_graph_v2(
            records
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
        )
        .unwrap();
    }
    let prior = original(&stages.resolved);
    let terminal = original(&stages.settled);
    assert_eq!(prior.revision, 3);
    assert_eq!(terminal.revision, 4);
    validate_native_no_dispatch_absent_resolution_v2(prior, &stages.resolved).unwrap();
    validate_native_no_dispatch_absent_resolution_v2(prior, &stages.settled).unwrap();
    assert_eq!(
        reconstruct_native_no_dispatch_prior(terminal).unwrap(),
        *prior
    );
    let prior2 = original(&stages.replacement);
    assert_eq!(
        resolve_historical_attempt(&stages.settled, reference(prior2)).unwrap(),
        *prior2
    );
    assert_eq!(
        resolve_historical_attempt(&stages.settled, reference(prior)).unwrap(),
        *prior
    );
    assert_eq!(
        canonical_records(&stages.resolved).len(),
        canonical_records(&stages.settled).len()
    );
}

#[test]
fn native_unresolved_prior2_keeps_settled3_compatibility() {
    let table = settled_unresolved_graph();
    let records = canonical_records(&table);
    validate_mount_source_state_graph_v2(
        records
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .unwrap();
    assert_eq!(original(&table).revision, 3);
    assert_eq!(
        reconstruct_native_no_dispatch_prior(original(&table))
            .unwrap()
            .revision,
        2
    );
}

#[test]
fn historical_artifact_layer_retains_exact_prior_and_refuses_unauthenticated_wrapper() {
    let stages = native_absence_stages();
    let prior = original(&stages.resolved);
    let settled = original(&stages.settled);
    assert_eq!(
        validate_native_no_dispatch_settlement_artifact(settled, &stages.settled).unwrap(),
        *prior,
    );
    let mut malformed = settled.clone();
    let ProviderAttemptStateV2::NativeNoDispatchSettled {
        signed_settlement, ..
    } = &mut malformed.state
    else {
        panic!("settlement artifact fixture");
    };
    let last = signed_settlement.len() - 1;
    signed_settlement[last] ^= 1;
    assert!(validate_native_no_dispatch_settlement_artifact(&malformed, &stages.settled).is_err());
    assert!(
        resolve_historical_attempt(
            &stages.settled,
            RecordRefV2 {
                id: prior.attempt_id,
                revision: prior.revision,
                record_digest: [99; 32],
            }
        )
        .is_err()
    );
}

#[test]
fn native_prior3_absence_requires_a_native_original_and_an_exact_complete_inventory() {
    let non_native = resolve_absent_inventory(reserve_inventory(
        unresolved_graph_from(initial_graph(false)),
        true,
    ));
    let records = canonical_records(&non_native);
    validate_mount_source_state_graph_v2(
        records
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .unwrap();
    assert!(
        validate_native_no_dispatch_absent_resolution_v2(original(&non_native), &non_native)
            .is_err()
    );

    let stages = native_absence_stages();
    assert!(
        validate_native_no_dispatch_absent_resolution_v2(
            original(&stages.replacement),
            &stages.replacement
        )
        .is_err()
    );
    let mut not_complete = stages.resolved.clone();
    let inventory = not_complete
        .provider_attempts
        .values_mut()
        .find(|attempt| attempt.method == ProviderMethodV2::Inventory)
        .unwrap();
    let ProviderAttemptStateV2::DispositionConsumed { status, .. } = &mut inventory.state else {
        panic!("fixture Inventory disposition");
    };
    *status = ProviderStatusV2::Pending;
    assert!(
        validate_native_no_dispatch_absent_resolution_v2(original(&not_complete), &not_complete)
            .is_err()
    );
    let mut retry_child = stages.resolved;
    let root = original(&retry_child).clone();
    let mut child = root.clone();
    child.attempt_id = [93; 32];
    child.previous_attempt_id = Some(root.attempt_id);
    child.attempt_number = 2;
    retry_child
        .provider_attempts
        .insert(child.attempt_id, child);
    assert!(validate_native_no_dispatch_absent_resolution_v2(&root, &retry_child).is_err());
}

#[test]
fn native_settled4_retains_multiple_idle_replacements_in_causal_order() {
    let resolved = resolved_absent_after_idle_graph();
    let settled = settle_graph(resolved.clone());
    for table in [&resolved, &settled] {
        let records = canonical_records(table);
        validate_mount_source_state_graph_v2(
            records
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
        )
        .unwrap();
        validate_native_no_dispatch_absent_resolution_v2(original(&resolved), table).unwrap();
    }
    let root = original(&resolved);
    let terminal_session = settled
        .provider_heads
        .values()
        .next()
        .unwrap()
        .current_session_id;
    assert_eq!(
        recovery_session_chain(&settled, root, terminal_session, 3).unwrap(),
        vec![Some(root.attempt_id), None, None]
    );
    assert_eq!(
        recovery_session_chain(&settled, root, terminal_session, 2),
        Err(state_error(
            "provider recovery replacement count does not reproduce"
        ))
    );

    let mut wrong_order = settled;
    for session in wrong_order.provider_sessions.values_mut() {
        if let Some(witness) = &mut session.barrier_idle_replacement {
            witness.replacement_count = if witness.replacement_count == 2 { 3 } else { 2 };
        }
    }
    assert_eq!(
        recovery_session_chain(&wrong_order, root, terminal_session, 3),
        Err(state_error("provider recovery idle root reference differs"))
    );
    assert!(validate_recovered_table(&wrong_order).is_err());
}

#[test]
fn historical_native_settlement_allows_only_a_genuine_different_current_barrier() {
    let old_terminal = later_unrelated_inventory_barrier_graph();
    let records = canonical_records(&old_terminal);
    validate_mount_source_state_graph_v2(
        records
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .unwrap();
    assert_eq!(original(&old_terminal).revision, 3);

    let table = later_unrelated_barrier_graph();
    let records = canonical_records(&table);
    validate_mount_source_state_graph_v2(
        records
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .unwrap();
    let old = original(&table);
    assert_eq!(old.revision, 4);
    let prior = resolved_absent_graph();
    validate_native_no_dispatch_absent_resolution_v2(original(&prior), &table).unwrap();
    assert_eq!(
        reconstruct_native_no_dispatch_prior(old).unwrap(),
        *original(&prior)
    );
    let mut reused = table.clone();
    let head = reused.provider_heads.values_mut().next().unwrap();
    head.recovery_barrier.as_mut().unwrap().root_attempt = reference(old);
    assert!(validate_recovered_table(&reused).is_err());
    let mut rollback = table.clone();
    let head = rollback.provider_heads.values_mut().next().unwrap();
    head.current_session_id = old.session_id;
    head.current_session_record_digest = old.session_record_digest;
    assert!(validate_recovered_table(&rollback).is_err());
}

#[test]
fn native_settled4_rejects_erased_forged_dangling_and_nested_prior_proofs() {
    let stages = native_absence_stages();
    let root_id = original(&stages.settled).attempt_id;
    for mutation in ["erased", "signature", "reference", "nested"] {
        let mut table = stages.settled.clone();
        let root = table.provider_attempts.get_mut(&root_id).unwrap();
        let ProviderAttemptStateV2::NativeNoDispatchSettled {
            prior_state,
            signed_settlement,
            ..
        } = &mut root.state
        else {
            panic!("fixture native terminal");
        };
        match mutation {
            "erased" => {
                let ProviderAttemptStateV2::AbandonedIndeterminate { resolution, .. } =
                    prior_state.as_mut()
                else {
                    panic!("fixture prior3");
                };
                *resolution = None;
            }
            "signature" => *signed_settlement.last_mut().unwrap() ^= 1,
            "reference" => {
                let ProviderAttemptStateV2::AbandonedIndeterminate {
                    resolution: Some(RecoveryResolutionV2::RetryAcquireSameIntent { proof }),
                    ..
                } = prior_state.as_mut()
                else {
                    panic!("fixture prior3 proof");
                };
                proof.inventory_attempt.record_digest[0] ^= 1;
            }
            "nested" => {
                *prior_state = Box::new(stages.settled.provider_attempts[&root_id].state.clone())
            }
            _ => unreachable!(),
        }
        assert!(validate_recovered_table(&table).is_err(), "{mutation}");
    }
    let mut missing = stages.settled;
    let inventory_id = missing
        .provider_attempts
        .values()
        .find(|attempt| attempt.method == ProviderMethodV2::Inventory)
        .unwrap()
        .attempt_id;
    missing.provider_attempts.remove(&inventory_id);
    assert!(validate_recovered_table(&missing).is_err());
}
