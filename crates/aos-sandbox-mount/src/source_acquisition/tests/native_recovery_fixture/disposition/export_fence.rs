//! Dedicated Pending-native acceptance through actual Root graph transitions.
//!
//! Signed fixture claims exercise immutable retention and replay. They prove
//! neither installed live FD custody nor independently authenticated Storage.

use super::*;
use aos_sandbox_source_provider_protocol::native_export_fence::native_dispatch_backend_identity_v2;
use ed25519_dalek::Signer as _;

struct OriginalNative {
    completed: SourceProviderQueryAttemptV2,
    descriptor: SourceRootObservationV1,
    request_digest: ObjectDigest,
    signed_acceptance_digest: ObjectDigest,
    acceptance: StorageNativeAcceptanceV3,
}

fn native_catalog(
    session: &SourceProviderSessionV2,
    binding: ObjectDigest,
) -> ProviderHeldSnapshotCatalogV1 {
    let snapshot =
        ZfsHeldSnapshotProofV1::new([61; 32], 1, 62, 63, 64, [65; 16], 1, d(66), d(67), d(68))
            .unwrap();
    ProviderHeldSnapshotCatalogV1::new(
        1,
        d_from(session.scope.resource_namespace_digest),
        vec![
            ProviderHeldSnapshotRowV1::new(binding, [79; 32], 1, d(80), 1, d(81), snapshot)
                .unwrap(),
        ],
    )
    .unwrap()
}

fn initial_native_table(journal: &mut Journal) -> SourceAcquisitionTableV2 {
    let session = signed_session([19; 16], 31);
    let (_, mount) = mount_acquire_request();
    let binding = digest_logical_binding_bytes(&mount.source_binding().canonical_bytes());
    let catalog = native_catalog(&session, binding);
    let records =
        initial_signed_graph_for_session(session, 500, *catalog.digest().as_bytes(), [63; 32]);
    commit_graph_delta(journal, &[], &records, [90; 16]);
    SourceAcquisitionTableV2::recover(journal).unwrap()
}

fn original_native(table: &SourceAcquisitionTableV2) -> OriginalNative {
    let attempt = table.provider_attempts.values().next().unwrap();
    let session = &table.provider_sessions[&attempt.session_id];
    let signed_root =
        SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request).unwrap();
    let root = decode_acquire_request(signed_root.subject()).unwrap();
    let provider_key = SigningKey::from_bytes(&[14; 32]);
    let provider_signer = signer(
        PROVIDER,
        [24; 16],
        SourceProviderKeyUsageV1::ProviderOutcome,
        &provider_key,
    );
    let catalog = native_catalog(session, root.binding_digest());
    let (resource, snapshot) = catalog
        .select_under_head(
            catalog.generation(),
            catalog.digest(),
            catalog.namespace_digest(),
            root.binding_digest(),
        )
        .unwrap();
    let provider_attempt = source_provider_request_attempt_digest_v1(
        signed_root.signer(),
        SourceProviderMethod::Acquire,
        attempt.request_id,
    );
    let claims = StorageZfsHoldTransportRequestV1::new(
        1,
        [69; 32],
        provider_attempt,
        PROVIDER,
        HOLDER,
        root.session_binding(),
        root.acquisition_id(),
        root.binding_digest(),
        d(70),
        110,
        160,
        catalog,
    )
    .unwrap();
    let request = SignedStorageNativeAcquireRequestV2::sign(
        StorageNativeAcquireRequestV2::new(claims, signed_root).unwrap(),
        provider_signer.clone(),
        &provider_key,
    )
    .unwrap();
    let storage_head = StorageZfsHoldHeadV1::new(1, d(71), 1, d(72), 1, d(73), d(74)).unwrap();
    let receipt = StorageZfsHoldReceiptV1::new(
        [69; 32],
        provider_attempt,
        root.binding_digest(),
        resource.clone(),
        snapshot.clone(),
        storage_head,
        110,
        160,
    )
    .unwrap();
    let storage_signer = StorageZfsHoldSignerV1::new([75; 16], 1, d(72), [76; 16], 1).unwrap();
    let storage_key = SigningKey::from_bytes(&[77; 32]);
    let unsigned = SignedStorageZfsHoldReceiptV1::new(receipt.clone(), storage_signer, [0; 64]);
    let receipt = SignedStorageZfsHoldReceiptV1::new(
        receipt,
        storage_signer,
        storage_key.sign(&unsigned.signing_message()).to_bytes(),
    );
    let descriptor = SourceRootObservationV1::new(BOOT, 83, 84, 85, true, true, true).unwrap();
    let topology =
        storage_native_nonrecursive_topology_v1(&request, &receipt, &descriptor, 2, 55).unwrap();
    let acceptance = StorageNativeAcceptanceV3::new(
        [78; 16],
        request.digest(),
        receipt.digest(),
        descriptor.clone(),
        topology.clone(),
    )
    .unwrap();
    let signed_acceptance =
        SignedStorageNativeAcceptanceV3::sign(acceptance.clone(), storage_signer, &storage_key);
    let proof = SourceProviderProofV1::ZfsHeldSnapshot {
        proof: snapshot,
        topology,
    };
    let lease = sign_export_lease(
        SourceExportLeaseV1::new(
            [82; 16],
            attempt.request_id,
            digest_acquire_request(&root),
            HOLDER,
            1,
            d(7),
            SourceProviderAuthorityV1::new(PROVIDER, 1, d(8)).unwrap(),
            resource,
            proof.clone(),
            root.binding_digest(),
            110,
            160,
            root.revocation_digest(),
        )
        .unwrap(),
        provider_signer.clone(),
        &provider_key,
    )
    .unwrap();
    let receipt = sign_provider_receipt(
        SourceProviderReceiptV1::new(
            attempt.request_id,
            digest_acquire_request(&root),
            root.acquisition_id(),
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
        provider_signer,
        &provider_key,
    )
    .unwrap();
    OriginalNative {
        completed: consumed(
            attempt,
            session,
            SourceProviderStatus::Complete,
            Some(receipt.to_canonical_bytes()),
            source_root_descriptor_commitment_v1(&descriptor),
        ),
        descriptor,
        request_digest: request.digest(),
        signed_acceptance_digest: signed_acceptance.digest(),
        acceptance,
    }
}

fn fence_subject(
    table: &SourceAcquisitionTableV2,
    release: &SourceProviderQueryAttemptV2,
    original: &OriginalNative,
) -> SourceProviderNativeExportFenceV1 {
    let row = table.acquisitions.values().next().unwrap();
    let evidence = row.evidence.as_ref().unwrap();
    let acquire = &table.provider_attempts[&evidence.acquire_attempt.id];
    let session = &table.provider_sessions[&release.session_id];
    let signed_release =
        SignedSourceProviderRequestV1::from_canonical_bytes(&release.signed_request).unwrap();
    let request = decode_release_request(signed_release.subject()).unwrap();
    let signed_acquire =
        SignedSourceProviderRequestV1::from_canonical_bytes(&acquire.signed_request).unwrap();
    let original_attempt = source_provider_request_attempt_digest_v1(
        signed_acquire.signer(),
        SourceProviderMethod::Acquire,
        acquire.request_id,
    );
    SourceProviderNativeExportFenceV1::new(
        NativeExportFenceReleaseV1 {
            provider: SourceProviderAuthorityV1::new(PROVIDER, 1, d(8)).unwrap(),
            holder: SourceProviderAuthorityV1::new(HOLDER, 1, d(7)).unwrap(),
            request_id: release.request_id,
            signed_request_digest: d_from(release.signed_request_digest),
            typed_request_digest: digest_release_request(&request),
            attempt_digest: source_provider_request_attempt_digest_v1(
                signed_release.signer(),
                SourceProviderMethod::Release,
                release.request_id,
            ),
            session_binding: d_from(session.session_binding),
            request_sequence: release.request_sequence,
            response_sequence: release.request_sequence,
            provider_process_instance: session.provider_process_instance,
        },
        NativeExportFenceAcquireV1 {
            acquisition_id: d_from(row.provider_acquisition.acquisition_id),
            acquisition_sequence: row.provider_acquisition.acquisition_sequence,
            root_request_digest: d_from(acquire.signed_request_digest),
            attempt_digest: original_attempt,
            session_binding: decode_acquire_request(signed_acquire.subject())
                .unwrap()
                .session_binding(),
            backend_id: native_dispatch_backend_identity_v2(
                d_from(acquire.normalized_acquire_intent.as_ref().unwrap().digest),
                evidence.provider_catalog_generation,
                d_from(evidence.provider_catalog_digest),
                original_attempt,
            ),
            lease_id: evidence.lease_id,
            lease_digest: d_from(evidence.signed_lease_digest),
        },
        original.request_digest,
        original.signed_acceptance_digest,
        original.acceptance.clone(),
        NativeExportFenceCutV1 {
            sequence: 17,
            admission_transaction_id: [18; 16],
            reservation_id: [19; 32],
            fence_digest: d(20),
        },
    )
    .unwrap()
}

fn native_consumed(
    table: &SourceAcquisitionTableV2,
    release: &SourceProviderQueryAttemptV2,
    subject: SourceProviderNativeExportFenceV1,
) -> SourceProviderQueryAttemptV2 {
    let key = SigningKey::from_bytes(&[14; 32]);
    let signed = SignedSourceProviderNativeExportFenceV1::sign(
        subject,
        signer(
            PROVIDER,
            [24; 16],
            SourceProviderKeyUsageV1::ProviderOutcome,
            &key,
        ),
        &key,
    )
    .unwrap();
    consumed(
        release,
        &table.provider_sessions[&release.session_id],
        SourceProviderStatus::Pending,
        Some(signed.to_canonical_bytes()),
        empty_descriptor_set_commitment_v1(),
    )
}

#[test]
fn native_export_fence_root_consumes_exact_pending_result_and_cold_replays_without_release_proof() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = directory.path().metadata().unwrap().uid();
    let (mut journal, _) = Journal::open_protected_at_uid(
        directory.path(),
        "root-native-fence.journal",
        JournalLimits::default(),
        uid,
    )
    .unwrap();
    let table = initial_native_table(&mut journal);
    let original = original_native(&table);
    let (transaction, table) = prepare(
        &table,
        original.completed.clone(),
        Some(&original.descriptor),
    );
    journal.commit(&transaction).unwrap();
    let (transaction, reserved, release) = reserve_release_fixture(&table);
    journal.commit(&transaction).unwrap();
    let subject = fence_subject(&reserved, &release, &original);
    let next = native_consumed(&reserved, &release, subject);
    let expected = reference(&next);
    let (transaction, consumed) = prepare(&reserved, next, None);
    assert_eq!(transaction.records().len(), 3);
    journal.commit(&transaction).unwrap();
    let row = consumed.acquisitions.values().next().unwrap();
    assert_eq!(row.phase, SourceAcquisitionPhaseV2::Releasing);
    assert_eq!(row.release_lineage.as_ref().unwrap().root, expected);
    assert!(row.release_proof.is_none());
    assert!(row.negative_custody_digest.is_none());
    assert!(row.release_terminal_attempt.is_none());
    assert_eq!(
        row.evidence,
        reserved.acquisitions.values().next().unwrap().evidence
    );
    drop(journal);

    let (journal, _) = Journal::open_protected_at_uid(
        directory.path(),
        "root-native-fence.journal",
        JournalLimits::default(),
        uid,
    )
    .unwrap();
    let replayed = SourceAcquisitionTableV2::recover(&journal).unwrap();
    assert_same_acquisition_state(replayed.state(), consumed.state());
    let row = replayed.acquisitions.values().next().unwrap();
    let retained = aos_sandbox_protocol::mount_source_acquisition_state::native_export_fence::validate_native_export_fence_v1(
        row, &replayed.provider_attempts[&expected.id], &replayed.state()).unwrap().unwrap();
    assert_eq!(retained.subject().acceptance(), &original.acceptance);
}

#[test]
fn native_export_fence_root_rejects_resigned_changed_original_and_release_joins() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = directory.path().metadata().unwrap().uid();
    let (mut journal, _) = Journal::open_protected_at_uid(
        directory.path(),
        "root-native-fence-hostile.journal",
        JournalLimits::default(),
        uid,
    )
    .unwrap();
    let table = initial_native_table(&mut journal);
    let original = original_native(&table);
    let (transaction, table) = prepare(
        &table,
        original.completed.clone(),
        Some(&original.descriptor),
    );
    journal.commit(&transaction).unwrap();
    let (transaction, reserved, release) = reserve_release_fixture(&table);
    journal.commit(&transaction).unwrap();
    let subject = fence_subject(&reserved, &release, &original);
    for mutation in 0..12 {
        let mut current = subject.release().clone();
        let mut acquire = subject.acquire().clone();
        let mut acceptance = subject.acceptance().clone();
        let mut native_request = subject.native_request_digest();
        match mutation {
            0 => current.attempt_digest = d(98),
            1 => current.typed_request_digest = d(98),
            2 => acquire.acquisition_id = d(98),
            3 => current.holder = SourceProviderAuthorityV1::new(HOLDER, 2, d(98)).unwrap(),
            4 => acquire.root_request_digest = d(98),
            5 => acquire.attempt_digest = d(98),
            6 => acquire.session_binding = d(98),
            7 => acquire.lease_digest = d(98),
            8 => acquire.backend_id = [98; 32],
            9 => {
                acceptance = StorageNativeAcceptanceV3::new(
                    acceptance.issuance_id(),
                    native_request,
                    d(98),
                    acceptance.descriptor().clone(),
                    acceptance.topology().clone(),
                )
                .unwrap();
            }
            10 => {
                native_request = d(98);
                acceptance = StorageNativeAcceptanceV3::new(
                    acceptance.issuance_id(),
                    native_request,
                    acceptance.receipt_digest(),
                    acceptance.descriptor().clone(),
                    acceptance.topology().clone(),
                )
                .unwrap();
            }
            _ => {
                let descriptor =
                    SourceRootObservationV1::new(BOOT, 83, 84, 98, true, true, true).unwrap();
                acceptance = StorageNativeAcceptanceV3::new(
                    acceptance.issuance_id(),
                    native_request,
                    acceptance.receipt_digest(),
                    descriptor,
                    acceptance.topology().clone(),
                )
                .unwrap();
            }
        }
        let changed = SourceProviderNativeExportFenceV1::new(
            current,
            acquire,
            native_request,
            subject.signed_acceptance_digest(),
            acceptance,
            subject.cut(),
        )
        .unwrap();
        let next = native_consumed(&reserved, &release, changed);
        let head = reserved.provider_heads[&(HOLDER, PROVIDER)].clone();
        let session = reserved.provider_sessions[&release.session_id].clone();
        assert!(
            reserved
                .prepare_disposition_fixture(head, session, next, None)
                .is_err(),
            "mutation {mutation}"
        );
    }
    assert_same_acquisition_state(
        SourceAcquisitionTableV2::recover(&journal).unwrap().state(),
        reserved.state(),
    );
}
