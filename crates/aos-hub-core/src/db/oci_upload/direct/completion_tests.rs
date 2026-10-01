//! Direct OCI completion, duplicate logical allocation and cold receipt provenance.

use super::*;
use crate::db::{DirectSqlOwner, NewSurfacePlacementSpec, SurfaceTarget};
use crate::direct_upload::*;

async fn completion_contract(
    db: &Database,
    input: &BeginDirectOciUpload,
    index: u8,
    abort: bool,
) -> String {
    let mut input = input.clone();
    input.client_operation_id = hex::encode([index; 32]);
    let upload = db.begin_direct_oci_upload(&input).await.unwrap();
    db.reserve_direct_oci_source(&upload, input.now)
        .await
        .unwrap();
    let binding = db
        .ensure_instance_default_binding("deployment_r2", None, Some("bucket"))
        .await
        .unwrap();
    let registry = db.registry_by_id(input.registry_id).await.unwrap().unwrap();
    let rows = db
        .list_surface_placements(SurfaceTarget::Registry(input.registry_id))
        .await
        .unwrap();
    let row = if let Some(row) = rows.first() {
        row.clone()
    } else {
        db.grant_consumer_scope(
            crate::db::GrantResource::Binding {
                id: binding.id,
                stable_id: &binding.stable_id,
            },
            &registry.owner_scope_key,
            "instance_default",
            "system:test",
            "test-direct-placement",
        )
        .await
        .unwrap();
        let row = db
            .create_surface_placement(&NewSurfacePlacementSpec {
                surface: SurfaceTarget::Registry(input.registry_id),
                name: "primary".into(),
                binding_id: binding.id,
                prefix: "images".into(),
                kind: "complete".into(),
                desired_state: "active".into(),
                hash_range: None,
                desired_read_enabled: true,
                read_order: 0,
                requires_conditional_writes: false,
            })
            .await
            .unwrap();
        db.observe_surface_placement(row.id, "ready", "complete", 1)
            .await
            .unwrap();
        db.bind_surface_placement_write_capability(row.id, 1)
            .await
            .unwrap();
        db.create_surface_write_authority(
            SurfaceTarget::Registry(input.registry_id),
            "direct-writer",
            row.id,
            row.resource_version,
            row.write_spec_version,
            1,
        )
        .await
        .unwrap();
        db.surface_placement(row.id).await.unwrap().unwrap()
    };
    let credential = |purpose: &str| DirectCredentialRevision {
        purpose: purpose.into(),
        credential_id: "managed-profile".into(),
        generation: WireInteger::new(1),
        secret_version_ref: "managed-profile:1".into(),
        credential_fingerprint: "a".repeat(64),
    };
    let placement = DirectPlacement {
        placement_id: WireInteger::new(row.id as u64),
        placement_resource_version: WireInteger::new(row.resource_version as u64),
        write_spec_version: WireInteger::new(row.write_spec_version as u64),
        binding_id: WireInteger::new(binding.id as u64),
        binding_resource_version: WireInteger::new(binding.resource_version as u64),
        binding_write_revision: WireInteger::new(1),
        final_key: format!("images/{}", oci_blob_object_key(input.expected_digest)),
        staging_prefix: ".aos-direct-upload".into(),
        private_stage_policy: DirectPrivateStagePolicyRef {
            policy_id: "private".into(),
            policy_digest: "b".repeat(64),
            namespace: "bucket".into(),
        },
        protected_profile_digest: "c".repeat(64),
        checksum_algorithm: DirectChecksumAlgorithm::Md5,
        physical: DirectPhysicalContext::DeploymentR2 {
            deployment_id: input.deployment_id.clone(),
            bucket_namespace: "bucket".into(),
        },
        write_credential: credential("write"),
        read_credential: credential("read"),
        presign_credential: credential("presign"),
    };
    let mut admission = DirectUploadAdmission {
        session_id: format!("oci-final-{index}"),
        principal_id: upload.writer_id.clone(),
        actor_slot: input.actor.clone(),
        logical_fingerprint: String::new(),
        expires_at: WireInteger::new(input.expires_at as u64),
        placements: vec![placement.clone()],
        intent: DirectUploadIntent {
            version: 1,
            client_operation_id: input.client_operation_id.clone(),
            target: DirectUploadTarget::OciBlob {
                upload_id: upload.id.clone(),
            },
            expected_sha256: input.expected_digest.encoded(),
            byte_size: WireInteger::new(input.expected_size),
            part_size: WireInteger::new(MIN_DIRECT_PART_BYTES),
            dependency_phase: DirectDependencyPhase::Content,
            transfer_mode: DirectTransferMode::DirectRequired,
        },
    };
    admission.logical_fingerprint = admission.fingerprint(&input.deployment_id).unwrap();
    let mut exhausted_upload = upload.clone();
    exhausted_upload.resource_version = i64::MAX;
    assert!(Database::complete_direct_oci_upload_statements(
        &exhausted_upload,
        &admission,
        9000,
        row.id,
        input.now,
    )
    .is_err());
    let scope = db
        .registry_authorization_scope(input.registry_id)
        .await
        .unwrap();
    let record = db
        .admit_direct_upload(
            &input.deployment_id,
            &admission,
            &scope,
            &DirectSqlOwner::Oci,
            input.now,
        )
        .await
        .unwrap();
    let exact = db
        .admit_direct_upload(
            &input.deployment_id,
            &admission,
            &scope,
            &DirectSqlOwner::Oci,
            input.now,
        )
        .await
        .unwrap();
    assert_eq!(exact, record);
    let mut alternate = admission.clone();
    alternate.session_id = format!("oci-alternate-{index}");
    alternate.intent.client_operation_id = "bb".repeat(32);
    alternate.logical_fingerprint = alternate.fingerprint(&input.deployment_id).unwrap();
    assert!(db
        .admit_direct_upload(
            &input.deployment_id,
            &alternate,
            &scope,
            &DirectSqlOwner::Oci,
            input.now
        )
        .await
        .is_err());
    assert!(db
        .direct_upload_session(&input.deployment_id, &alternate.session_id)
        .await
        .unwrap()
        .is_none());
    let overdue = input.expires_at + 1;
    assert!(db.expire_oci_upload(&upload.id, overdue).await.is_err());
    assert_eq!(db.expire_due_oci_uploads(overdue, 10).await.unwrap(), 0);
    assert!(db
        .cancel_oci_upload(
            &upload.id,
            &upload.writer_id,
            &upload.token_id,
            upload.resource_version,
            input.now
        )
        .await
        .is_err());
    assert_eq!(
        db.direct_oci_upload_for_actor_recovery(&input.deployment_id, &input.actor, &upload.id)
            .await
            .unwrap()
            .state,
        "active"
    );
    if abort {
        let intent = DirectAbortRequest {
            session: DirectSessionRef {
                session_id: admission.session_id.clone(),
                logical_fingerprint: admission.logical_fingerprint.clone(),
            },
            operation_id: "f".repeat(64),
            expected_resource_version: record.resource_version,
        };
        let pending = db
            .retain_direct_abort(&input.deployment_id, &intent, input.now)
            .await
            .unwrap();
        let unknown = DirectAbortEvidence {
            session: intent.session.clone(),
            operation_id: intent.operation_id.clone(),
            outcome: DirectAbortOutcome::Unknown,
            receipt_digest: None,
        };
        db.report_direct_abort_checked(
            &input.deployment_id,
            &pending,
            &unknown,
            Vec::new(),
            input.now,
        )
        .await
        .unwrap();
        let current = db
            .direct_upload_session(&input.deployment_id, &admission.session_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.state, DirectSessionState::BlockedUnknown);
        assert!(db.expire_oci_upload(&upload.id, overdue).await.is_err());
        let evidence = DirectAbortEvidence {
            outcome: DirectAbortOutcome::Aborted,
            receipt_digest: Some("a".repeat(64)),
            ..unknown
        };
        let release = Database::abort_direct_oci_upload_statements(&upload, overdue).unwrap();
        let mut stale = current.clone();
        stale.resource_version = WireInteger::new(1);
        assert!(db
            .report_direct_abort_checked(
                &input.deployment_id,
                &stale,
                &evidence,
                release.clone(),
                overdue
            )
            .await
            .is_err());
        assert_eq!(
            db.direct_oci_upload_for_actor_recovery(&input.deployment_id, &input.actor, &upload.id)
                .await
                .unwrap()
                .state,
            "active"
        );
        db.report_direct_abort_checked(&input.deployment_id, &current, &evidence, release, overdue)
            .await
            .unwrap();
        assert_eq!(
            db.direct_oci_upload_for_actor_recovery(&input.deployment_id, &input.actor, &upload.id)
                .await
                .unwrap()
                .state,
            "cancelled"
        );
        return upload.id;
    }
    let complete = DirectCompleteRequest {
        session: DirectSessionRef {
            session_id: admission.session_id.clone(),
            logical_fingerprint: admission.logical_fingerprint.clone(),
        },
        operation_id: "d".repeat(64),
        expected_resource_version: record.resource_version,
        manifests: vec![DirectManifestCommitment {
            placement: placement.public_ref(&input.deployment_id).unwrap(),
            manifest_digest: "e".repeat(64),
            part_count: 1,
        }],
    };
    let record = db
        .retain_direct_complete(
            &input.deployment_id,
            &admission.session_id,
            &complete,
            input.now,
        )
        .await
        .unwrap();
    let incarnation = DirectObjectIncarnation::ProviderVersion {
        version: format!("source-{index}"),
    };
    let stage = DirectVerifiedStageEvidence {
        session_id: admission.session_id.clone(),
        logical_fingerprint: admission.logical_fingerprint.clone(),
        operation_id: complete.operation_id.clone(),
        part_count: 1,
        sha256: admission.intent.expected_sha256.clone(),
        byte_size: admission.intent.byte_size,
        placements: vec![DirectStagePlacementEvidence {
            placement: complete.manifests[0].placement.clone(),
            manifest: complete.manifests[0].clone(),
            verification_operation_id: "f".repeat(64),
            staging_incarnation: incarnation.clone(),
        }],
        projection: None,
    };
    db.retain_direct_verified_stage(
        &input.deployment_id,
        &record,
        &stage,
        DirectDependencyPhase::Content,
        input.now,
    )
    .await
    .unwrap();
    let record = db
        .direct_upload_session(&input.deployment_id, &admission.session_id)
        .await
        .unwrap()
        .unwrap();
    let promotion = direct_destination_promotion_operation_id(
        &complete.session,
        placement.placement_id,
        &complete.operation_id,
    )
    .unwrap();
    let evidence = DirectCompletionEvidence {
        session_id: admission.session_id.clone(),
        logical_fingerprint: admission.logical_fingerprint.clone(),
        operation_id: complete.operation_id.clone(),
        part_count: 1,
        sha256: admission.intent.expected_sha256.clone(),
        byte_size: admission.intent.byte_size,
        projection: None,
        placements: vec![DirectPlacementEvidence {
            placement_id: placement.placement_id,
            placement_resource_version: placement.placement_resource_version,
            write_spec_version: placement.write_spec_version,
            binding_id: placement.binding_id,
            binding_resource_version: placement.binding_resource_version,
            binding_write_revision: placement.binding_write_revision,
            manifest: complete.manifests[0].clone(),
            promotion_operation_id: promotion.clone(),
            staging_incarnation: incarnation.clone(),
            final_incarnation: DirectObjectIncarnation::ProviderVersion {
                version: "same-immutable-final".into(),
            },
            final_etag: "\"final-etag\"".into(),
        }],
    };
    let guard = DirectFinalGuardRecord {
        version: 1,
        reservation: DirectDestinationBaselineBinding {
            deployment_id: input.deployment_id.clone(),
            session: complete.session.clone(),
            admission_expires_at: admission.expires_at,
            complete_operation_id: complete.operation_id.clone(),
            complete_intent_digest: complete.fingerprint().unwrap(),
            placement: complete.manifests[0].placement.clone(),
            protected_profile_digest: placement.protected_profile_digest.clone(),
            final_key_digest: direct_destination_key_digest(&placement.final_key).unwrap(),
            scope: DirectDestinationReservationScope::Managed {
                bucket_namespace: "bucket".into(),
            },
            reservation_operation_id: promotion,
            reservation_nonce: hex::encode([index; 32]),
            reservation_revision: WireInteger::new(1),
        },
        selected: DirectSelectedCompleteCommitment {
            version: 1,
            session: complete.session.clone(),
            operation_id: complete.operation_id.clone(),
            expected_resource_version: complete.expected_resource_version,
            complete_intent_digest: complete.fingerprint().unwrap(),
            manifest: complete.manifests[0].clone(),
            protected_profile_digest: placement.protected_profile_digest.clone(),
        },
        sha256: stage.sha256.clone(),
        byte_size: stage.byte_size,
        source_incarnation: incarnation,
        final_incarnation: evidence.placements[0].final_incarnation.clone(),
        final_etag: "\"final-etag\"".into(),
    };
    let baseline = DirectDestinationBaselineEvidence {
        binding: guard.reservation.clone(),
        observation_operation_id: "a".repeat(64),
        issued_at: WireInteger::new(input.now as u64),
        expires_at: WireInteger::new((input.now + 30) as u64),
        state: DirectDestinationBaselineState::Missing {},
    };
    db.retain_direct_baselines(
        &input.deployment_id,
        &record,
        &[baseline],
        Vec::new(),
        Vec::new(),
        input.now,
    )
    .await
    .unwrap();
    let record = db
        .direct_upload_session(&input.deployment_id, &admission.session_id)
        .await
        .unwrap()
        .unwrap();
    let object = db
        .surface_object_named(
            SurfaceTarget::Registry(input.registry_id),
            &oci_blob_object_key(input.expected_digest),
        )
        .await
        .unwrap();
    let object_id = object.map_or(9000, |object| object.id);
    let mut plan = db
        .direct_oci_object_presence_statements(
            input.registry_id,
            row.id,
            input.expected_digest,
            input.expected_size,
            "\"final-etag\"",
            input.now,
            object_id,
        )
        .await
        .unwrap();
    plan.extend(
        Database::complete_direct_oci_upload_statements(
            &upload, &admission, object_id, row.id, input.now,
        )
        .unwrap(),
    );

    // A lost final CAS must roll back physical catalogue and all logical quota effects.
    let mut stale = record.clone();
    stale.resource_version = WireInteger::new(1);
    assert!(db
        .commit_direct_upload(
            &input.deployment_id,
            &stale,
            &evidence,
            &[guard.clone()],
            plan.clone(),
            input.now
        )
        .await
        .is_err());
    assert_eq!(
        db.direct_oci_upload_for_actor_recovery(&input.deployment_id, &input.actor, &upload.id)
            .await
            .unwrap()
            .state,
        "active"
    );
    db.commit_direct_upload(
        &input.deployment_id,
        &record,
        &evidence,
        &[guard],
        plan,
        input.now,
    )
    .await
    .unwrap();
    let complete = db
        .oci_upload(&upload.id, &upload.writer_id, &upload.token_id, input.now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(complete.state, "complete");
    assert_eq!(complete.uploaded_size, 0);
    assert_eq!(complete.sha256.total_bytes, 0);
    assert_eq!(
        complete.authenticated_source_bytes,
        Some(input.expected_size)
    );
    assert_eq!(
        complete.authenticated_source_sha256,
        Some(input.expected_digest)
    );
    upload.id
}

#[tokio::test]
async fn guarded_completion_restarts_and_deduplicates_real_logical_accounting() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("direct-completion.db");
    let (db, input) = fixture_with_database(Database::open(&path).await.unwrap()).await;
    let first = completion_contract(&db, &input, 2, false).await;
    let second = completion_contract(&db, &input, 3, false).await;
    assert_ne!(first, second);
    let org = db
        .registry_by_id(input.registry_id)
        .await
        .unwrap()
        .unwrap()
        .org_id
        .unwrap();
    let usage = db.org_usage(org).await.unwrap();
    assert_eq!(usage.used_bytes, input.expected_size as i64);
    assert_eq!(usage.object_count, 1);
    drop(db);

    let db = Database::open(&path).await.unwrap();
    for id in [first, second] {
        let upload = db
            .direct_oci_upload_for_actor_recovery(&input.deployment_id, &input.actor, &id)
            .await
            .unwrap();
        assert_eq!(upload.state, "complete");
        assert_eq!(upload.uploaded_size, 0);
        assert_eq!(upload.authenticated_source_bytes, Some(input.expected_size));
    }
}

#[tokio::test]
async fn unknown_effect_preserves_quota_and_positive_abort_releases_atomically_after_expiry() {
    let (db, input) = fixture().await;
    completion_contract(&db, &input, 4, true).await;
    let org = db
        .registry_by_id(input.registry_id)
        .await
        .unwrap()
        .unwrap()
        .org_id
        .unwrap();
    let usage = db.org_usage(org).await.unwrap();
    assert_eq!(usage.used_bytes, 0);
    assert_eq!(usage.object_count, 0);
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn postgres_direct_completion_deduplication_and_abort_accounting() {
    let Ok(url) = std::env::var("AOS_HUB_DIRECT_OCI_TEST_PG_URL") else {
        return;
    };
    let (db, input) = fixture_with_database(Database::connect(&url).await.unwrap()).await;
    let first = completion_contract(&db, &input, 2, false).await;
    let second = completion_contract(&db, &input, 3, false).await;
    completion_contract(&db, &input, 4, true).await;
    let org = db
        .registry_by_id(input.registry_id)
        .await
        .unwrap()
        .unwrap()
        .org_id
        .unwrap();
    let usage = db.org_usage(org).await.unwrap();
    assert_eq!(usage.used_bytes, input.expected_size as i64);
    assert_eq!(usage.object_count, 1);
    drop(db);

    let db = Database::connect(&url).await.unwrap();
    for id in [first, second] {
        let upload = db
            .direct_oci_upload_for_actor_recovery(&input.deployment_id, &input.actor, &id)
            .await
            .unwrap();
        assert_eq!(upload.state, "complete");
        assert_eq!(upload.uploaded_size, 0);
        assert_eq!(upload.authenticated_source_bytes, Some(input.expected_size));
    }
}
