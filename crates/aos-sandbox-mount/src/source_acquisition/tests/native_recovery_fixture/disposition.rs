//! Actual disposition planners and protected replay reuse the signed graph.
//!
//! Test signatures and metadata exercise whole-graph structure, not installed
//! security/FD authority. No runtime owner capability is constructed here.

#[path = "disposition/export_fence.rs"]
mod export_fence;

use super::*;
use aos_sandbox_protocol::mount_source_acquisition_state::*;
use aos_sandbox_source_provider_protocol::*;
use sha2::{Digest as _, Sha256};

use crate::source_acquisition::SourceAcquisitionTableV2;

fn d(byte: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([byte; 32])
}

fn assert_same_acquisition_state(
    actual: MountSourceAcquisitionStateV2,
    expected: MountSourceAcquisitionStateV2,
) {
    let MountSourceAcquisitionStateV2 {
        acquisitions,
        holder_sequences,
        provider_heads,
        provider_sessions,
        provider_attempts,
    } = actual;

    assert_eq!(acquisitions, expected.acquisitions);
    assert_eq!(holder_sequences, expected.holder_sequences);
    assert_eq!(provider_heads, expected.provider_heads);
    assert_eq!(provider_sessions, expected.provider_sessions);
    assert_eq!(provider_attempts, expected.provider_attempts);
}

fn reference(attempt: &SourceProviderQueryAttemptV2) -> RecordRefV2 {
    RecordRefV2 {
        id: attempt.attempt_id,
        revision: attempt.revision,
        record_digest: attempt.record_digest,
    }
}

fn consumed(
    original: &SourceProviderQueryAttemptV2,
    session: &SourceProviderSessionV2,
    status: SourceProviderStatus,
    result: Option<Vec<u8>>,
    descriptor: ObjectDigest,
) -> SourceProviderQueryAttemptV2 {
    let method = match original.method {
        ProviderMethodV2::Acquire => SourceProviderMethod::Acquire,
        ProviderMethodV2::Release => SourceProviderMethod::Release,
        _ => panic!("acquisition fixture method"),
    };
    let key = SigningKey::from_bytes(&[14; 32]);
    let result_digest = response_result_digest_v1(method, status, result.as_deref());
    let status_subject = SourceProviderResponseStatusV1::new(
        method,
        original.request_id,
        ObjectDigest::from_bytes(original.signed_request_digest),
        status,
        session.provider_process_instance,
        ObjectDigest::from_bytes(session.session_binding),
        original.request_sequence,
        result_digest,
        descriptor,
    )
    .unwrap();
    let signed_status = sign_response_status(
        status_subject,
        signer(
            PROVIDER,
            [24; 16],
            SourceProviderKeyUsageV1::ProviderOutcome,
            &key,
        ),
        &key,
    )
    .unwrap();
    let response = match method {
        SourceProviderMethod::Acquire => encode_acquire_response(
            &AcquireSourceResponseV1::new(signed_status.clone(), result.clone()).unwrap(),
        ),
        SourceProviderMethod::Release => {
            ReleaseSourceResponseProfileV2::from_parts(signed_status.clone(), result.clone())
                .unwrap()
                .to_canonical_bytes()
        }
        _ => unreachable!(),
    };
    let mut anchor = OutcomeVerificationAnchorV2 {
        verification_started_seconds: 110,
        verification_completed_seconds: 111,
        kernel_boot_id: session.kernel_boot_id,
        trusted_clock_evidence_digest: session.trusted_clock_evidence_digest,
        anchor_digest: [0; 32],
    };
    anchor.anchor_digest = checkpoint::outcome_verification_anchor_digest_v2(
        &anchor,
        session.session_id,
        original.attempt_id,
        original.request_sequence,
        original.request_sequence,
        Sha256::digest(&response).into(),
    );
    let mut next = original.clone();
    next.revision = 2;
    next.state = ProviderAttemptStateV2::DispositionConsumed {
        response_sequence: original.request_sequence,
        verification_anchor: anchor,
        status: match status {
            SourceProviderStatus::Complete => ProviderStatusV2::Complete,
            SourceProviderStatus::Pending => ProviderStatusV2::Pending,
            _ => panic!("fixture disposition"),
        },
        signed_status_digest: Sha256::digest(signed_status.to_canonical_bytes()).into(),
        signed_status: signed_status.to_canonical_bytes(),
        signed_result: result.unwrap_or_default(),
        signed_result_digest: *result_digest.as_bytes(),
    };
    next.record_digest = [0; 32];
    reservation::sealed_attempt(next).unwrap()
}

fn complete_acquire(
    table: &SourceAcquisitionTableV2,
) -> (SourceProviderQueryAttemptV2, SourceRootObservationV1) {
    let original = table.provider_attempts.values().next().unwrap();
    let session = &table.provider_sessions[&original.session_id];
    let signed =
        SignedSourceProviderRequestV1::from_canonical_bytes(&original.signed_request).unwrap();
    let request = decode_acquire_request(signed.subject()).unwrap();
    let proof = SourceProviderProofV1::ImmutablePublisherTree {
        proof: ImmutablePublisherTreeProofV1::new(
            d(42),
            d(59),
            1,
            d(70),
            1,
            d(62),
            [71; 32],
            1,
            d(72),
            d(73),
            d(74),
            d(75),
            d(76),
        )
        .unwrap(),
        topology: RecursiveTopologyProofV1::new([77; 16], 1, d(78), 1, 0, 1, 0).unwrap(),
    };
    let resource = SourceResourceV1::new(
        ObjectDigest::from_bytes(session.scope.resource_namespace_digest),
        [79; 32],
        1,
        d(80),
        1,
        d(62),
        1,
        d(81),
    )
    .unwrap();
    let authority = SourceProviderAuthorityV1::new(PROVIDER, 1, d(8)).unwrap();
    let key = SigningKey::from_bytes(&[14; 32]);
    let outcome_signer = signer(
        PROVIDER,
        [24; 16],
        SourceProviderKeyUsageV1::ProviderOutcome,
        &key,
    );
    let lease = sign_export_lease(
        SourceExportLeaseV1::new(
            [82; 16],
            original.request_id,
            digest_acquire_request(&request),
            HOLDER,
            1,
            d(7),
            authority,
            resource,
            proof.clone(),
            request.binding_digest(),
            110,
            160,
            request.revocation_digest(),
        )
        .unwrap(),
        outcome_signer.clone(),
        &key,
    )
    .unwrap();
    let observation = SourceRootObservationV1::new(BOOT, 83, 84, 85, true, true, true).unwrap();
    let receipt = sign_provider_receipt(
        SourceProviderReceiptV1::new(
            original.request_id,
            digest_acquire_request(&request),
            request.acquisition_id(),
            session.provider_process_instance,
            digest_signed_export_lease(&lease),
            lease.to_canonical_bytes(),
            SourceProviderDescriptorRole::SourceRoot,
            BOOT,
            83,
            84,
            85,
            digest_provider_proof(&proof),
        )
        .unwrap(),
        outcome_signer,
        &key,
    )
    .unwrap();
    (
        consumed(
            original,
            session,
            SourceProviderStatus::Complete,
            Some(receipt.to_canonical_bytes()),
            source_root_descriptor_commitment_v1(&observation),
        ),
        observation,
    )
}

fn initial_table(journal: &mut Journal) -> SourceAcquisitionTableV2 {
    let records = initial_signed_graph();
    commit_graph_delta(journal, &[], &records, [90; 16]);
    SourceAcquisitionTableV2::recover(journal).unwrap()
}

fn prepare(
    table: &SourceAcquisitionTableV2,
    next: SourceProviderQueryAttemptV2,
    observation: Option<&SourceRootObservationV1>,
) -> (JournalTransaction, SourceAcquisitionTableV2) {
    let head = table.provider_heads[&(HOLDER, PROVIDER)].clone();
    let session = table.provider_sessions[&next.session_id].clone();
    table
        .prepare_disposition_fixture(head, session, next, observation)
        .unwrap()
}

fn reserve_release_fixture(
    table: &SourceAcquisitionTableV2,
) -> (
    JournalTransaction,
    SourceAcquisitionTableV2,
    SourceProviderQueryAttemptV2,
) {
    use crate::source_acquisition::projection::{projection_entries, projection_from_entries};
    use crate::source_acquisition::transition::{
        MutationIdentityV2, acquisition_predecessor, prepare_mutation,
    };
    use aos_proto::aos::sandbox::local::v1::ReleaseMountSourceAcquisitionRequest;
    use aos_sandbox_protocol::mount_manager_startup::{
        StartupCleanupEvidenceV1, StartupCleanupPhaseV1, StartupCleanupSourceSubjectV1,
    };

    let row = table.acquisitions.values().next().unwrap();
    let evidence = row.evidence.as_ref().unwrap();
    let head = &table.provider_heads[&(HOLDER, PROVIDER)];
    let session = &table.provider_sessions[&head.current_session_id];
    let mut body = ReleaseMountSourceAcquisitionRequest::default();
    let header = body.header.get_or_insert_default();
    header.protocol_major = 2;
    header.request_id = vec![91; 16];
    header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
    header.deadline_boottime_nanoseconds = 101;
    header.maximum_response_bytes = 4096;
    let fence = body.fence.get_or_insert_default();
    fence.sandbox_id = row.assignment.sandbox_id.to_vec();
    fence.incarnation_id = row.assignment.incarnation_id.to_vec();
    fence.assignment_epoch = row.assignment.assignment_epoch;
    fence.desired_generation = row.assignment.desired_generation;
    fence.assignment_digest = row.assignment.assignment_digest.to_vec();
    body.acquisition_id = row.acquisition_id.to_vec();
    body.expected_revision = row.revision;
    body.expected_record_digest = row.record_digest.to_vec();
    let bytes = body.encode_to_vec();
    let operation = MountOperationV2 {
        operation_id: [91; 16],
        request_digest: *aos_sandbox_protocol::mount_source_acquisition_request_digest_v1(&bytes)
            .as_bytes(),
    };
    let authority = ReleaseAuthorityV2 {
        sandbox_id: row.assignment.sandbox_id,
        incarnation_id: row.assignment.incarnation_id,
        assignment_epoch: row.assignment.assignment_epoch,
        desired_generation: row.assignment.desired_generation,
        assignment_digest: row.assignment.assignment_digest,
        expected_revision: row.revision,
        expected_record_digest: row.record_digest,
    };
    let intent = ProviderIntentV2::Release {
        value: ReleaseIntentV2 {
            scope: row.scope,
            acquisition_id: row.acquisition_id,
            provider_acquisition: row.provider_acquisition,
            mount_request: bytes.clone(),
            mount_operation: operation,
            authority,
            lease_id: evidence.lease_id,
            signed_lease_digest: evidence.signed_lease_digest,
            provider_resource_id: evidence.provider_resource_id,
            provider_resource_digest: evidence.provider_resource_digest,
            provider_proof_digest: evidence.provider_proof_digest,
            descriptor_commitment: evidence.descriptor_commitment,
        },
    };
    let mut attempt = table.provider_attempts[&evidence.acquire_attempt.id].clone();
    attempt.attempt_id = [0; 32];
    attempt.revision = 1;
    attempt.method = ProviderMethodV2::Release;
    attempt.owner = ProviderQueryOwnerV2::Release {
        acquisition_id: row.acquisition_id,
    };
    attempt.immutable_intent_digest = intent_digest(&intent).unwrap();
    attempt.intent = intent;
    attempt.lineage_root_attempt_id = [0; 32];
    attempt.previous_attempt_id = None;
    attempt.attempt_number = 1;
    attempt.normalized_acquire_intent = None;
    attempt.acquire_verification_floor = None;
    attempt.request_id = [0; 16];
    attempt.request_sequence = head.next_request_sequence;
    attempt.signed_request.clear();
    attempt.signed_request_digest = [0; 32];
    attempt.owner_predecessor_revision = row.revision;
    attempt.owner_predecessor_digest = row.record_digest;
    attempt.owner_predecessor = Some(acquisition_predecessor(row));
    attempt.state = ProviderAttemptStateV2::Reserved;
    attempt.record_digest = [0; 32];
    attempt.attempt_id = attempt_id(&attempt);
    attempt.lineage_root_attempt_id = attempt.attempt_id;
    attempt.request_id = request_id(attempt.attempt_id);
    let request = ReleaseSourceRequestV1::new(
        ObjectDigest::from_bytes(session.session_binding),
        attempt.request_sequence,
        attempt.request_id,
        ObjectDigest::from_bytes(row.provider_acquisition.acquisition_id),
        HOLDER,
        1,
        d(7),
        evidence.lease_id,
        ObjectDigest::from_bytes(evidence.signed_lease_digest),
        500,
    )
    .unwrap();
    let key = SigningKey::from_bytes(&[12; 32]);
    let signed = sign_request(
        SourceProviderMethod::Release,
        encode_release_request(&request),
        signer(
            HOLDER,
            [22; 16],
            SourceProviderKeyUsageV1::RootMountRecord,
            &key,
        ),
        &key,
    )
    .unwrap();
    attempt.signed_request_digest = *digest_signed_request(&signed).as_bytes();
    attempt.signed_request = signed.to_canonical_bytes();
    let attempt = reservation::sealed_attempt(attempt).unwrap();
    let reference = reference(&attempt);
    let mut next = row.clone();
    next.revision += 1;
    next.phase = SourceAcquisitionPhaseV2::Releasing;
    next.release = Some(operation);
    next.mount_release_request = Some(bytes);
    next.release_authority = Some(authority);
    next.release_from_phase = Some(row.phase);
    next.release_intent_digest = Some(attempt.immutable_intent_digest);
    next.release_lineage = Some(QueryLineageV2 {
        root: reference,
        tail: reference,
        next_attempt_number: 2,
    });
    // A pure persisted startup-loss observation is part of this pre-handoff
    // fixture only. It mints no negative-custody or installed release authority.
    let mut loss = ManagerCustodyLossEvidenceV2 {
        subject: StartupCleanupSourceSubjectV1 {
            acquisition_id: row.acquisition_id,
            acquisition_revision: row.revision,
            acquisition_record_digest: row.record_digest,
            phase: StartupCleanupPhaseV1::PendingQuery,
            acquire_attempt_id: evidence.acquire_attempt.id,
            acquire_attempt_revision: evidence.acquire_attempt.revision,
            acquire_attempt_record_digest: evidence.acquire_attempt.record_digest,
            evidence: Some(StartupCleanupEvidenceV1 {
                source_realization_handle: evidence.source_realization_handle,
                descriptor_commitment: evidence.descriptor_commitment,
                source_kernel_boot_id: evidence.source_kernel_boot_id,
                source_device: evidence.source_device,
                source_inode: evidence.source_inode,
                source_unique_mount_id: evidence.source_unique_mount_id,
            }),
            last_custody_owner: None,
        },
        capture_id: [92; 32],
        capture_record_digest: [93; 32],
        kind: ManagerCustodyLossKindV2::NoPriorCustody,
        death_commitment: [94; 32],
        evidence_digest: [0; 32],
    };
    loss.evidence_digest = format::manager_custody_loss_evidence_digest_v2(&loss);
    next.manager_custody_loss = Some(loss);
    let mut rows = table.acquisitions.clone();
    rows.insert(next.acquisition_id, next.clone());
    let entries = projection_entries(row.scope, &rows);
    let epoch = head.current_projection_epoch + 1;
    let projection = projection_from_entries(row.scope, epoch, &entries).unwrap();
    next.release_inventory_fence = Some(ReleaseInventoryFenceV2 {
        inventory_observation_floor: head.inventory_observation_ordinal,
        projection_epoch: epoch,
        projection_digest: projection.digest,
        projection_entries: entries,
    });
    next.record_digest = [0; 32];
    let next = reservation::sealed_row(next).unwrap();
    let mut next_head = head.clone();
    next_head.revision += 1;
    next_head.next_request_sequence += 1;
    next_head.pending_attempt = Some(reference);
    next_head.current_projection_epoch = epoch;
    next_head.current_projection_digest = projection.digest;
    next_head.last_reconciliation = None;
    next_head.record_digest = [0; 32];
    let next_head = reservation::sealed_head(next_head).unwrap();
    let (transaction, tentative) = prepare_mutation(
        table,
        MutationIdentityV2 {
            tag: format::MutationTagV2::BeginRelease,
            holder_id: HOLDER,
            provider_id: PROVIDER,
            next_holder_sequence_revision: 1,
            next_head_revision: next_head.revision,
            acquisition_id: Some(row.acquisition_id),
            next_row_revision: Some(next.revision),
            attempt_id: Some(attempt.attempt_id),
            next_attempt_revision: Some(1),
            session_id: None,
        },
        vec![
            StoredRecordV2::ProviderQueryAttempt {
                value: attempt.clone(),
            },
            StoredRecordV2::Acquisition { value: next },
            StoredRecordV2::ProviderHead { value: next_head },
        ],
    )
    .unwrap();
    (transaction, tentative, attempt)
}

fn reserve_retry_fixture(
    table: &SourceAcquisitionTableV2,
    method: ProviderMethodV2,
) -> (
    JournalTransaction,
    SourceAcquisitionTableV2,
    SourceProviderQueryAttemptV2,
) {
    use crate::source_acquisition::transition::{
        MutationIdentityV2, acquisition_predecessor, prepare_mutation,
    };

    let row = table.acquisitions.values().next().unwrap();
    let head = &table.provider_heads[&(HOLDER, PROVIDER)];
    let session = &table.provider_sessions[&head.current_session_id];
    let lineage = match method {
        ProviderMethodV2::Acquire => &row.acquire_lineage,
        ProviderMethodV2::Release => row.release_lineage.as_ref().unwrap(),
        ProviderMethodV2::Inventory => panic!("acquisition retry fixture"),
    };
    let previous = &table.provider_attempts[&lineage.tail.id];
    let mut attempt = previous.clone();
    attempt.attempt_id = [0; 32];
    attempt.revision = 1;
    attempt.previous_attempt_id = Some(previous.attempt_id);
    attempt.attempt_number = lineage.next_attempt_number;
    attempt.request_id = [0; 16];
    attempt.request_sequence = head.next_request_sequence;
    attempt.signed_request.clear();
    attempt.signed_request_digest = [0; 32];
    attempt.normalized_acquire_intent = None;
    attempt.owner_predecessor_revision = row.revision;
    attempt.owner_predecessor_digest = row.record_digest;
    attempt.owner_predecessor = Some(acquisition_predecessor(row));
    attempt.state = ProviderAttemptStateV2::Reserved;
    attempt.record_digest = [0; 32];
    attempt.attempt_id = attempt_id(&attempt);
    attempt.request_id = request_id(attempt.attempt_id);

    let (provider_method, request_bytes) = match &attempt.intent {
        ProviderIntentV2::Acquire { value } => {
            let request = AcquireSourceRequestV1::new_v2(
                ObjectDigest::from_bytes(session.session_binding),
                attempt.request_sequence,
                attempt.request_id,
                row.provider_acquisition.acquisition_sequence,
                value.prospective_mount_template.clone(),
                d_from(value.prospective_mount_template_digest),
                SourceUseV1::MountCreate,
                session.node_id,
                session.kernel_boot_id,
                HOLDER,
                session.root_mount_authority_generation,
                d_from(session.root_mount_authority_digest),
                value.source_binding.clone(),
                d_from(value.source_binding_digest),
                500,
                value.requested_lease_seconds,
                d_from(session.revocation_digest),
                value.recursive,
                value.requested_maximum_submounts,
                value.kernel_coupled,
            )
            .unwrap();
            let normalized = NormalizedAcquisitionIntentV2::from_acquire_request(
                &request,
                SourceProviderAuthorityV1::new(
                    PROVIDER,
                    session.provider_authority_generation,
                    d_from(session.provider_authority_digest),
                )
                .unwrap(),
                SourceProviderAuthorityV1::new(
                    HOLDER,
                    session.root_mount_authority_generation,
                    d_from(session.root_mount_authority_digest),
                )
                .unwrap(),
                session.node_id,
                session.kernel_boot_id,
                session.scope.route_id,
                session.route_generation,
                d_from(session.route_digest),
                d_from(session.scope.resource_namespace_digest),
                session.revocation_generation,
                d_from(session.revocation_digest),
            )
            .unwrap();
            attempt.normalized_acquire_intent = Some(AttemptNormalizedAcquireV2 {
                bytes: normalized.to_canonical_bytes(),
                digest: *normalized.digest().as_bytes(),
                maximum_lease_expiry_seconds: 500,
            });
            (
                SourceProviderMethod::Acquire,
                encode_acquire_request(&request),
            )
        }
        ProviderIntentV2::Release { value } => {
            let request = ReleaseSourceRequestV1::new(
                d_from(session.session_binding),
                attempt.request_sequence,
                attempt.request_id,
                d_from(row.provider_acquisition.acquisition_id),
                HOLDER,
                session.root_mount_authority_generation,
                d_from(session.root_mount_authority_digest),
                value.lease_id,
                d_from(value.signed_lease_digest),
                500,
            )
            .unwrap();
            (
                SourceProviderMethod::Release,
                encode_release_request(&request),
            )
        }
        _ => panic!("acquisition retry intent"),
    };
    let key = SigningKey::from_bytes(&[12; 32]);
    let signed = sign_request(
        provider_method,
        request_bytes,
        signer(
            HOLDER,
            [22; 16],
            SourceProviderKeyUsageV1::RootMountRecord,
            &key,
        ),
        &key,
    )
    .unwrap();
    attempt.signed_request_digest = *digest_signed_request(&signed).as_bytes();
    attempt.signed_request = signed.to_canonical_bytes();
    let attempt = reservation::sealed_attempt(attempt).unwrap();
    let attempt_ref = reference(&attempt);

    let mut next = row.clone();
    next.revision += 1;
    let next_lineage = match method {
        ProviderMethodV2::Acquire => &mut next.acquire_lineage,
        ProviderMethodV2::Release => next.release_lineage.as_mut().unwrap(),
        ProviderMethodV2::Inventory => unreachable!(),
    };
    next_lineage.tail = attempt_ref;
    next_lineage.next_attempt_number += 1;
    next.record_digest = [0; 32];
    let next = reservation::sealed_row(next).unwrap();
    let mut next_head = head.clone();
    next_head.revision += 1;
    next_head.next_request_sequence += 1;
    next_head.pending_attempt = Some(attempt_ref);
    next_head.record_digest = [0; 32];
    let next_head = reservation::sealed_head(next_head).unwrap();
    let (transaction, tentative) = prepare_mutation(
        table,
        MutationIdentityV2 {
            tag: format::MutationTagV2::ReserveRetry,
            holder_id: HOLDER,
            provider_id: PROVIDER,
            next_holder_sequence_revision: 1,
            next_head_revision: next_head.revision,
            acquisition_id: Some(row.acquisition_id),
            next_row_revision: Some(next.revision),
            attempt_id: Some(attempt.attempt_id),
            next_attempt_revision: Some(1),
            session_id: None,
        },
        vec![
            StoredRecordV2::ProviderQueryAttempt {
                value: attempt.clone(),
            },
            StoredRecordV2::Acquisition { value: next },
            StoredRecordV2::ProviderHead { value: next_head },
        ],
    )
    .unwrap();
    (transaction, tentative, attempt)
}

fn d_from(bytes: [u8; 32]) -> ObjectDigest {
    ObjectDigest::from_bytes(bytes)
}

#[test]
fn disposition_first_release_rebases_exact_root_and_tail_after_real_plans_and_reopen() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = directory.path().metadata().unwrap().uid();
    let (mut journal, _) = Journal::open_protected_at_uid(
        directory.path(),
        "root-release-disposition.journal",
        JournalLimits::default(),
        uid,
    )
    .unwrap();
    let table = initial_table(&mut journal);
    let (completed, observation) = complete_acquire(&table);
    let (transaction, table) = prepare(&table, completed, Some(&observation));
    journal.commit(&transaction).unwrap();
    let original_acquire = table
        .acquisitions
        .values()
        .next()
        .unwrap()
        .acquire_lineage
        .clone();
    let (admission, reserved, attempt) = reserve_release_fixture(&table);
    journal.commit(&admission).unwrap();
    let completed = consumed(
        &attempt,
        &reserved.provider_sessions[&attempt.session_id],
        SourceProviderStatus::Pending,
        None,
        empty_descriptor_set_commitment_v1(),
    );
    let expected = reference(&completed);
    let (transaction, tentative) = prepare(&reserved, completed, None);
    journal.commit(&transaction).unwrap();
    assert_eq!(
        tentative
            .acquisitions
            .values()
            .next()
            .unwrap()
            .acquire_lineage,
        original_acquire
    );
    let lineage = tentative
        .acquisitions
        .values()
        .next()
        .unwrap()
        .release_lineage
        .as_ref()
        .unwrap();
    assert_eq!(lineage.root, expected);
    assert_eq!(lineage.tail, expected);
    drop(journal);
    let (journal, _) = Journal::open_protected_at_uid(
        directory.path(),
        "root-release-disposition.journal",
        JournalLimits::default(),
        uid,
    )
    .unwrap();
    assert_eq!(
        SourceAcquisitionTableV2::recover(&journal)
            .unwrap()
            .state()
            .provider_attempts,
        tentative.state().provider_attempts
    );
}

#[test]
fn disposition_first_acquire_rebases_exact_root_and_tail_then_cold_replays() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = directory.path().metadata().unwrap().uid();
    let (mut journal, _) = Journal::open_protected_at_uid(
        directory.path(),
        "root-disposition.journal",
        JournalLimits::default(),
        uid,
    )
    .unwrap();
    let table = initial_table(&mut journal);
    let original = table.provider_attempts.values().next().unwrap();
    let next = consumed(
        original,
        &table.provider_sessions[&original.session_id],
        SourceProviderStatus::Pending,
        None,
        empty_descriptor_set_commitment_v1(),
    );
    let expected = reference(&next);
    let (transaction, tentative) = prepare(&table, next, None);
    assert_eq!(transaction.records().len(), 3);
    let row = tentative.acquisitions.values().next().unwrap();
    assert_eq!(row.acquire_lineage.root, expected);
    assert_eq!(row.acquire_lineage.tail, expected);
    assert_eq!(
        row.acquire_intent_digest,
        table
            .acquisitions
            .values()
            .next()
            .unwrap()
            .acquire_intent_digest
    );
    journal.commit(&transaction).unwrap();
    drop(journal);

    let (journal, _) = Journal::open_protected_at_uid(
        directory.path(),
        "root-disposition.journal",
        JournalLimits::default(),
        uid,
    )
    .unwrap();
    let replayed = SourceAcquisitionTableV2::recover(&journal).unwrap();
    assert_eq!(
        replayed.state().provider_attempts,
        tentative.state().provider_attempts
    );
    assert_eq!(
        replayed
            .acquisitions
            .values()
            .next()
            .unwrap()
            .acquire_lineage
            .root,
        expected
    );
}

#[test]
fn disposition_rejects_wrong_predecessor_foreign_root_and_changed_signed_intent() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = directory.path().metadata().unwrap().uid();
    let (mut journal, _) = Journal::open_protected_at_uid(
        directory.path(),
        "root-hostile-disposition.journal",
        JournalLimits::default(),
        uid,
    )
    .unwrap();
    let table = initial_table(&mut journal);
    let original = table.provider_attempts.values().next().unwrap();
    let next = consumed(
        original,
        &table.provider_sessions[&original.session_id],
        SourceProviderStatus::Pending,
        None,
        empty_descriptor_set_commitment_v1(),
    );
    for mutation in 0..4 {
        let mut hostile = table.clone();
        let mut candidate = next.clone();
        match mutation {
            0 => {
                hostile
                    .acquisitions
                    .values_mut()
                    .next()
                    .unwrap()
                    .acquire_lineage
                    .root
                    .id = [99; 32]
            }
            1 => {
                hostile
                    .acquisitions
                    .values_mut()
                    .next()
                    .unwrap()
                    .acquire_lineage
                    .tail
                    .record_digest = [99; 32]
            }
            2 => candidate.signed_request_digest = [99; 32],
            _ => candidate.immutable_intent_digest = [99; 32],
        }
        candidate.record_digest = [0; 32];
        let candidate = reservation::sealed_attempt(candidate).unwrap();
        let head = hostile.provider_heads[&(HOLDER, PROVIDER)].clone();
        let session = hostile.provider_sessions[&candidate.session_id].clone();
        assert!(
            hostile
                .prepare_disposition_fixture(head, session, candidate, None)
                .is_err()
        );
    }
    assert_eq!(
        SourceAcquisitionTableV2::recover(&journal)
            .unwrap()
            .state()
            .provider_attempts,
        table.state().provider_attempts
    );
}

#[test]
fn disposition_later_acquire_and_release_advance_only_exact_tail_then_cold_replay() {
    for method in [ProviderMethodV2::Acquire, ProviderMethodV2::Release] {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = directory.path().metadata().unwrap().uid();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "root-later-disposition.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        let initial = initial_table(&mut journal);
        let first = match method {
            ProviderMethodV2::Acquire => {
                let original = initial.provider_attempts.values().next().unwrap();
                let completed = consumed(
                    original,
                    &initial.provider_sessions[&original.session_id],
                    SourceProviderStatus::Pending,
                    None,
                    empty_descriptor_set_commitment_v1(),
                );
                let (transaction, table) = prepare(&initial, completed, None);
                journal.commit(&transaction).unwrap();
                table
            }
            ProviderMethodV2::Release => {
                let (completed, observation) = complete_acquire(&initial);
                let (transaction, table) = prepare(&initial, completed, Some(&observation));
                journal.commit(&transaction).unwrap();
                let (transaction, reserved, attempt) = reserve_release_fixture(&table);
                journal.commit(&transaction).unwrap();
                let completed = consumed(
                    &attempt,
                    &reserved.provider_sessions[&attempt.session_id],
                    SourceProviderStatus::Pending,
                    None,
                    empty_descriptor_set_commitment_v1(),
                );
                let (transaction, table) = prepare(&reserved, completed, None);
                journal.commit(&transaction).unwrap();
                table
            }
            ProviderMethodV2::Inventory => unreachable!(),
        };
        let first_row = first.acquisitions.values().next().unwrap();
        let release_fence = first_row.release_inventory_fence.clone();
        if method == ProviderMethodV2::Release {
            assert_eq!(
                first.provider_heads[&(HOLDER, PROVIDER)].inventory_observation_ordinal,
                0
            );
            assert_eq!(
                release_fence.as_ref().unwrap().inventory_observation_floor,
                0
            );
        }
        let root = match method {
            ProviderMethodV2::Acquire => first_row.acquire_lineage.root,
            ProviderMethodV2::Release => first_row.release_lineage.as_ref().unwrap().root,
            ProviderMethodV2::Inventory => unreachable!(),
        };
        let (transaction, reserved, attempt) = reserve_retry_fixture(&first, method);
        journal.commit(&transaction).unwrap();
        let completed = consumed(
            &attempt,
            &reserved.provider_sessions[&attempt.session_id],
            SourceProviderStatus::Pending,
            None,
            empty_descriptor_set_commitment_v1(),
        );
        let expected_tail = reference(&completed);

        // A foreign root, stale tail or altered immutable owner/session/request
        // never becomes valid merely because an outcome has a signature.
        for mutation in 0..7 {
            let mut hostile = reserved.clone();
            let mut candidate = completed.clone();
            let row = hostile.acquisitions.values_mut().next().unwrap();
            let lineage = match method {
                ProviderMethodV2::Acquire => &mut row.acquire_lineage,
                ProviderMethodV2::Release => row.release_lineage.as_mut().unwrap(),
                ProviderMethodV2::Inventory => unreachable!(),
            };
            match mutation {
                0 => lineage.root.id = [99; 32],
                1 => lineage.tail.record_digest = [99; 32],
                2 => candidate.signed_request_digest = [99; 32],
                3 => candidate.immutable_intent_digest = [99; 32],
                4 => candidate.session_record_digest = [99; 32],
                5 => {
                    candidate.owner = ProviderQueryOwnerV2::Acquire {
                        acquisition_id: [99; 32],
                    }
                }
                _ => candidate.owner_predecessor_digest = [99; 32],
            }
            candidate.record_digest = [0; 32];
            let candidate = reservation::sealed_attempt(candidate).unwrap();
            let head = hostile.provider_heads[&(HOLDER, PROVIDER)].clone();
            let session = hostile.provider_sessions[&attempt.session_id].clone();
            assert!(
                hostile
                    .prepare_disposition_fixture(head, session, candidate.clone(), None)
                    .is_err()
            );

            if mutation < 2 {
                let row = hostile.acquisitions.values_mut().next().unwrap();
                row.record_digest = [0; 32];
                *row = reservation::sealed_row(row.clone()).unwrap();
            } else {
                hostile
                    .provider_attempts
                    .insert(candidate.attempt_id, candidate);
            }
            assert!(validate_recovered_table(&hostile.state()).is_err());
        }

        let (transaction, tentative) = prepare(&reserved, completed, None);
        assert_eq!(transaction.records().len(), 3);
        journal.commit(&transaction).unwrap();
        let row = tentative.acquisitions.values().next().unwrap();
        let lineage = match method {
            ProviderMethodV2::Acquire => &row.acquire_lineage,
            ProviderMethodV2::Release => row.release_lineage.as_ref().unwrap(),
            ProviderMethodV2::Inventory => unreachable!(),
        };
        assert_eq!(lineage.root, root);
        assert_eq!(lineage.tail, expected_tail);
        assert_eq!(row.release_inventory_fence, release_fence);
        assert_ne!(root.id, expected_tail.id);
        assert_eq!(
            tentative.provider_attempts[&root.id],
            first.provider_attempts[&root.id]
        );
        drop(journal);

        let (journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "root-later-disposition.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        assert_same_acquisition_state(
            SourceAcquisitionTableV2::recover(&journal).unwrap().state(),
            tentative.state(),
        );
    }
}

#[test]
fn release_inventory_floor_rejects_invented_observation_after_protected_reopen() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = directory.path().metadata().unwrap().uid();
    let (mut journal, _) = Journal::open_protected_at_uid(
        directory.path(),
        "root-release-inventory-floor.journal",
        JournalLimits::default(),
        uid,
    )
    .unwrap();
    let initial = initial_table(&mut journal);
    let (completed, observation) = complete_acquire(&initial);
    let (transaction, acquired) = prepare(&initial, completed, Some(&observation));
    journal.commit(&transaction).unwrap();
    let (transaction, reserved, _) = reserve_release_fixture(&acquired);
    journal.commit(&transaction).unwrap();

    let original = reserved.acquisitions.values().next().unwrap();
    assert_eq!(
        original
            .release_inventory_fence
            .as_ref()
            .unwrap()
            .inventory_observation_floor,
        0
    );
    assert_same_acquisition_state(
        SourceAcquisitionTableV2::recover(&journal).unwrap().state(),
        reserved.state(),
    );

    // A nonzero floor is not valid merely because it looks like an ordinal.
    // Preserve the signed Release, projection, and lineage; only invent one
    // preceding Complete Inventory, then reseal the ordinary record digest.
    let mut forged = original.clone();
    // Corrupt the retained row in place. A revision advance would fail the
    // reserved-attempt causal join before reaching the observation-floor check.
    forged
        .release_inventory_fence
        .as_mut()
        .unwrap()
        .inventory_observation_floor = 1;
    forged.record_digest = [0; 32];
    let forged = reservation::sealed_row(forged).unwrap();
    let mut hostile = reserved.clone();
    hostile
        .acquisitions
        .insert(forged.acquisition_id, forged.clone());
    let error = validate_recovered_table(&hostile.state()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Release Inventory fence observation floor does not reproduce"),
        "unexpected protected-graph rejection: {error}"
    );

    // Bypass the planner only to model hostile protected-record corruption.
    // Cold whole-graph recovery must reject the same authenticated row bytes.
    commit_graph_delta(
        &mut journal,
        &[StoredRecordV2::Acquisition {
            value: original.clone(),
        }],
        &[StoredRecordV2::Acquisition { value: forged }],
        [98; 16],
    );
    drop(journal);
    let (journal, _) = Journal::open_protected_at_uid(
        directory.path(),
        "root-release-inventory-floor.journal",
        JournalLimits::default(),
        uid,
    )
    .unwrap();
    assert!(SourceAcquisitionTableV2::recover(&journal).is_err());
}
