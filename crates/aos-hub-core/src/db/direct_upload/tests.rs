//! Canonical retained originals and transactional direct lifecycle regressions.

use super::*;

#[path = "service_tests.rs"]
mod service_tests;

#[cfg(feature = "postgres")]
#[path = "../direct_target/concurrency_tests.rs"]
mod authority_lock_tests;

#[test]
fn retained_document_rejects_noncanonical_encoding() {
    let original = DirectSessionRef {
        session_id: "session".into(),
        logical_fingerprint: "a".repeat(64),
    };
    let canonical = canonical(&original).unwrap();
    assert_eq!(document::<DirectSessionRef>(&canonical).unwrap(), original);
    assert!(document::<DirectSessionRef>(&format!(" {canonical}")).is_err());
}

async fn original(db: &Database) -> DirectUploadSessionRecord {
    db.install_write_failure_test_tickets().await.unwrap();
    let user = db.create_user("direct@example.test", None).await.unwrap();
    let actor_slot = DirectActorSlot {
        kind: DirectActorKind::User,
        numeric_id: WireInteger::new(user as u64),
        incarnation: db
            .principal_incarnation(crate::domain::Principal::user(user))
            .await
            .unwrap()
            .unwrap(),
    };
    let credential = |purpose: &str| DirectCredentialRevision {
        purpose: purpose.into(),
        credential_id: "profile".into(),
        generation: WireInteger::new(1),
        secret_version_ref: "profile:1".into(),
        credential_fingerprint: "a".repeat(64),
    };
    let mut admission = DirectUploadAdmission {
        session_id: "original-session".into(),
        principal_id: actor_slot.principal_id("deployment").unwrap(),
        actor_slot,
        intent: DirectUploadIntent {
            version: 1,
            client_operation_id: "b".repeat(64),
            target: DirectUploadTarget::CacheObject {
                cache_id: "cache:00000000000000000000000000000001".into(),
                path: "single-pre".into(),
            },
            expected_sha256: "c".repeat(64),
            byte_size: WireInteger::new(1),
            part_size: WireInteger::new(8 * 1024 * 1024),
            dependency_phase: DirectDependencyPhase::Content,
            transfer_mode: DirectTransferMode::DirectRequired,
        },
        logical_fingerprint: String::new(),
        expires_at: WireInteger::new(100),
        placements: vec![DirectPlacement {
            placement_id: WireInteger::new(1),
            placement_resource_version: WireInteger::new(1),
            write_spec_version: WireInteger::new(1),
            binding_id: WireInteger::new(1),
            binding_resource_version: WireInteger::new(1),
            binding_write_revision: WireInteger::new(1),
            final_key: "cache/single-pre".into(),
            staging_prefix: ".aos-direct-upload".into(),
            private_stage_policy: DirectPrivateStagePolicyRef {
                policy_id: "private".into(),
                policy_digest: "d".repeat(64),
                namespace: "bucket".into(),
            },
            protected_profile_digest: "e".repeat(64),
            checksum_algorithm: DirectChecksumAlgorithm::Md5,
            physical: DirectPhysicalContext::DeploymentR2 {
                deployment_id: "deployment".into(),
                bucket_namespace: "bucket".into(),
            },
            write_credential: credential("write"),
            read_credential: credential("read"),
            presign_credential: credential("presign"),
        }],
    };
    admission.logical_fingerprint = admission.fingerprint("deployment").unwrap();
    db.admit_direct_upload(
        "deployment",
        &admission,
        "cache:00000000000000000000000000000001",
        &DirectSqlOwner::Cache {
            cache_id: 1,
            ticket_id: "cache-single-pre".into(),
        },
        10,
    )
    .await
    .unwrap()
}

fn complete(record: &DirectUploadSessionRecord) -> DirectCompleteRequest {
    DirectCompleteRequest {
        session: DirectSessionRef {
            session_id: record.admission.session_id.clone(),
            logical_fingerprint: record.admission.logical_fingerprint.clone(),
        },
        operation_id: "f".repeat(64),
        expected_resource_version: record.resource_version,
        manifests: vec![DirectManifestCommitment {
            placement: record.admission.placements[0]
                .public_ref("deployment")
                .unwrap(),
            manifest_digest: "1".repeat(64),
            part_count: 1,
        }],
    }
}

fn stage(
    record: &DirectUploadSessionRecord,
    intent: &DirectCompleteRequest,
) -> DirectVerifiedStageEvidence {
    DirectVerifiedStageEvidence {
        session_id: record.admission.session_id.clone(),
        logical_fingerprint: record.admission.logical_fingerprint.clone(),
        operation_id: intent.operation_id.clone(),
        part_count: 1,
        sha256: record.admission.intent.expected_sha256.clone(),
        byte_size: record.admission.intent.byte_size,
        placements: vec![DirectStagePlacementEvidence {
            placement: intent.manifests[0].placement.clone(),
            manifest: intent.manifests[0].clone(),
            verification_operation_id: "2".repeat(64),
            staging_incarnation: DirectObjectIncarnation::ProviderVersion {
                version: "stage-version".into(),
            },
        }],
        projection: None,
    }
}

#[tokio::test]
async fn original_complete_survives_stage_progress_and_changed_intents_cannot_replace_it() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("direct.sqlite");
    let db = Database::open(&path).await.unwrap();
    let admitted = original(&db).await;
    let intent = complete(&admitted);
    let retained = db
        .retain_direct_complete("deployment", &admitted.admission.session_id, &intent, 11)
        .await
        .unwrap();
    let proof = stage(&retained, &intent);

    db.retain_direct_verified_stage(
        "deployment",
        &retained,
        &proof,
        DirectDependencyPhase::Content,
        12,
    )
    .await
    .unwrap();
    // Restart after the reply is lost; the original CAS and proof survive.
    drop(db);
    let db = Database::open(&path).await.unwrap();
    let replay = db
        .retain_direct_complete("deployment", &admitted.admission.session_id, &intent, 13)
        .await
        .unwrap();
    assert_eq!(replay.resource_version, WireInteger::new(2));
    assert_eq!(replay.complete_intent, Some(intent.clone()));
    assert_eq!(replay.stage_evidence, Some(proof));

    let mut changed = intent;
    changed.expected_resource_version = replay.resource_version;
    assert!(db
        .retain_direct_complete("deployment", &admitted.admission.session_id, &changed, 14)
        .await
        .is_err());
}

#[tokio::test]
async fn abort_unknown_retains_original_cas_and_requires_positive_terminal_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("direct.sqlite");
    let db = Database::open(&path).await.unwrap();
    let admitted = original(&db).await;
    let intent = DirectAbortRequest {
        session: complete(&admitted).session,
        operation_id: "3".repeat(64),
        expected_resource_version: admitted.resource_version,
    };
    let pending = db
        .retain_direct_abort("deployment", &intent, 11)
        .await
        .unwrap();
    let mut outcome = DirectAbortEvidence {
        session: intent.session.clone(),
        operation_id: intent.operation_id.clone(),
        outcome: DirectAbortOutcome::Unknown,
        receipt_digest: None,
    };

    db.report_direct_abort("deployment", &pending, &outcome, 12)
        .await
        .unwrap();
    drop(db);
    let db = Database::open(&path).await.unwrap();
    let unknown = db
        .retain_direct_abort("deployment", &intent, 13)
        .await
        .unwrap();
    assert_eq!(unknown.state, DirectSessionState::BlockedUnknown);
    assert_eq!(unknown.abort_intent, Some(intent.clone()));
    assert_eq!(unknown.resource_version, WireInteger::new(3));

    outcome.outcome = DirectAbortOutcome::Pending;
    assert!(db
        .report_direct_abort("deployment", &unknown, &outcome, 14)
        .await
        .is_err());
    outcome.outcome = DirectAbortOutcome::Aborted;
    assert!(db
        .report_direct_abort("deployment", &unknown, &outcome, 14)
        .await
        .is_err());
    outcome.receipt_digest = Some("4".repeat(64));
    db.report_direct_abort("deployment", &unknown, &outcome, 101)
        .await
        .unwrap();
    let aborted = db
        .retain_direct_abort("deployment", &intent, 102)
        .await
        .unwrap();
    assert_eq!(aborted.state, DirectSessionState::Aborted);
    assert_eq!(aborted.abort_intent, Some(intent));
    assert!(db
        .backend
        .query_opt(
            "SELECT ticket_id FROM cache_write_tickets WHERE ticket_id = ?1
        AND active_cache_slot = 1",
            &vals!["cache-single-pre"]
        )
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn target_mutation_and_terminal_receipt_roll_back_together_on_failed_cas() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("direct.sqlite");
    let db = Database::open(&path).await.unwrap();
    let admitted = original(&db).await;
    let intent = complete(&admitted);
    let retained = db
        .retain_direct_complete("deployment", &admitted.admission.session_id, &intent, 11)
        .await
        .unwrap();
    let stage = stage(&retained, &intent);
    db.retain_direct_verified_stage(
        "deployment",
        &retained,
        &stage,
        DirectDependencyPhase::Content,
        12,
    )
    .await
    .unwrap();
    let record = db
        .direct_upload_session("deployment", &admitted.admission.session_id)
        .await
        .unwrap()
        .unwrap();
    let evidence = DirectCompletionEvidence {
        session_id: record.admission.session_id.clone(),
        logical_fingerprint: record.admission.logical_fingerprint.clone(),
        operation_id: intent.operation_id,
        part_count: 1,
        sha256: stage.sha256,
        byte_size: stage.byte_size,
        projection: None,
        placements: vec![DirectPlacementEvidence {
            placement_id: WireInteger::new(1),
            placement_resource_version: WireInteger::new(1),
            write_spec_version: WireInteger::new(1),
            binding_id: WireInteger::new(1),
            binding_resource_version: WireInteger::new(1),
            binding_write_revision: WireInteger::new(1),
            manifest: intent.manifests[0].clone(),
            promotion_operation_id: direct_destination_promotion_operation_id(
                &intent.session,
                WireInteger::new(1),
                &record.complete_intent.as_ref().unwrap().operation_id,
            )
            .unwrap(),
            staging_incarnation: stage.placements[0].staging_incarnation.clone(),
            final_incarnation: DirectObjectIncarnation::ProviderVersion {
                version: "final-version".into(),
            },
            final_etag: "\"etag\"".into(),
        }],
    };
    evidence
        .validate_against(&record.admission, "deployment")
        .unwrap();
    let placement = &record.admission.placements[0];
    let complete = record.complete_intent.as_ref().unwrap();
    let guard = DirectFinalGuardRecord {
        version: 1,
        reservation: DirectDestinationBaselineBinding {
            deployment_id: "deployment".into(),
            session: complete.session.clone(),
            admission_expires_at: record.admission.expires_at,
            complete_operation_id: complete.operation_id.clone(),
            complete_intent_digest: complete.fingerprint().unwrap(),
            placement: placement.public_ref("deployment").unwrap(),
            protected_profile_digest: placement.protected_profile_digest.clone(),
            final_key_digest: direct_destination_key_digest(&placement.final_key).unwrap(),
            scope: DirectDestinationReservationScope::Managed {
                bucket_namespace: "bucket".into(),
            },
            reservation_operation_id: evidence.placements[0].promotion_operation_id.clone(),
            reservation_nonce: "6".repeat(64),
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
        sha256: evidence.sha256.clone(),
        byte_size: evidence.byte_size,
        source_incarnation: evidence.placements[0].staging_incarnation.clone(),
        final_incarnation: evidence.placements[0].final_incarnation.clone(),
        final_etag: evidence.placements[0].final_etag.clone(),
    };
    guard
        .validate_for(&record.admission, complete, &evidence, "deployment")
        .unwrap();
    let baseline = DirectDestinationBaselineEvidence {
        binding: guard.reservation.clone(),
        observation_operation_id: "a".repeat(64),
        issued_at: WireInteger::new(12),
        expires_at: WireInteger::new(30),
        state: DirectDestinationBaselineState::Missing {},
    };
    let activation = Database::activate_cache_write_ticket_statements(
        "cache-single-pre",
        1,
        None,
        0,
        0,
        None,
        Some(&record.admission.intent.expected_sha256),
        12,
    )
    .unwrap();
    db.retain_direct_baselines(
        "deployment",
        &record,
        &[baseline],
        Vec::new(),
        activation,
        12,
    )
    .await
    .unwrap();
    let record = db
        .direct_upload_session("deployment", &record.admission.session_id)
        .await
        .unwrap()
        .unwrap();
    let mut stale = record.clone();
    stale.resource_version = WireInteger::new(1);

    assert!(db
        .commit_direct_upload(
            "deployment",
            &stale,
            &evidence,
            &[guard.clone()],
            vec![Statement::new(
                "UPDATE org_usage SET used_bytes = 99 WHERE org_id = 1",
                vec![]
            )
            .expecting(1)],
            13
        )
        .await
        .is_err());
    let usage = db
        .backend
        .query_opt("SELECT used_bytes FROM org_usage WHERE org_id = 1", &[])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(usage.get::<i64>(0).unwrap(), 0);
    let after = db
        .direct_upload_session("deployment", &record.admission.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.state, DirectSessionState::StagedVerified);
    assert!(after.completion_evidence.is_none());

    let guard_reference = DirectFinalGuardRef::from_record(&guard).unwrap();
    assert_eq!(
        guard_reference
            .expand(
                &record.admission,
                record.complete_intent.as_ref().unwrap(),
                &evidence,
                &record.baselines,
                "deployment",
            )
            .unwrap(),
        guard
    );
    let mut forged_reference = guard_reference.clone();
    forged_reference.record_digest = "f".repeat(64);
    assert!(forged_reference
        .expand(
            &record.admission,
            record.complete_intent.as_ref().unwrap(),
            &evidence,
            &record.baselines,
            "deployment",
        )
        .is_err());
    assert!(guard_reference
        .expand(
            &record.admission,
            record.complete_intent.as_ref().unwrap(),
            &evidence,
            &[],
            "deployment",
        )
        .is_err());
    let mut changed_destination = evidence.clone();
    changed_destination.placements[0].final_etag = "\"another-final-etag\"".into();
    assert!(guard_reference
        .expand(
            &record.admission,
            record.complete_intent.as_ref().unwrap(),
            &changed_destination,
            &record.baselines,
            "deployment",
        )
        .is_err());

    let settlement =
        Database::complete_cache_write_ticket_statements("cache-single-pre", 2, 14).unwrap();
    db.commit_direct_upload(
        "deployment",
        &record,
        &evidence,
        &[guard.clone()],
        settlement,
        14,
    )
    .await
    .unwrap();
    // Simulate an acknowledged final transaction whose reply was lost.
    drop(db);
    let db = Database::open(&path).await.unwrap();
    let original_complete = record.complete_intent.as_ref().unwrap();
    let committed = db
        .retain_direct_complete(
            "deployment",
            &record.admission.session_id,
            original_complete,
            101,
        )
        .await
        .unwrap();
    assert_eq!(committed.state, DirectSessionState::Committed);
    assert_eq!(committed.resource_version, WireInteger::new(3));
    assert_eq!(committed.completion_evidence, Some(evidence.clone()));
    assert_eq!(committed.final_guards, vec![guard.clone()]);
    assert_eq!(
        guard_reference
            .expand(
                &committed.admission,
                committed.complete_intent.as_ref().unwrap(),
                &evidence,
                &committed.baselines,
                "deployment",
            )
            .unwrap(),
        guard
    );
    let ticket = db
        .cache_write_ticket("cache-single-pre")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ticket.state, "completed");
}

#[tokio::test]
async fn overdue_abort_and_target_release_are_atomic_without_renewing_admission() {
    let db = Database::open_in_memory().await.unwrap();
    let admitted = original(&db).await;
    assert!(db
        .retain_direct_complete(
            "deployment",
            &admitted.admission.session_id,
            &complete(&admitted),
            101
        )
        .await
        .is_err());
    let activation = Database::activate_cache_write_ticket_statements(
        "cache-single-pre",
        1,
        None,
        0,
        0,
        None,
        Some(&admitted.admission.intent.expected_sha256),
        12,
    )
    .unwrap();
    db.backend.checked_batch(&activation).await.unwrap();
    let ticket = db
        .cache_write_ticket("cache-single-pre")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ticket.state, "active");
    assert!(!db
        .list_expired_cache_write_tickets(1, 101, i64::MIN, "", 256)
        .await
        .unwrap()
        .iter()
        .any(|item| item.ticket_id == ticket.ticket_id));
    assert!(!db
        .list_expired_cache_write_tickets_global(101, i64::MIN, "", 256)
        .await
        .unwrap()
        .iter()
        .any(|item| item.ticket_id == ticket.ticket_id));
    assert!(db
        .abort_cache_write_ticket(&ticket.ticket_id, ticket.resource_version, "aborted", 101)
        .await
        .is_err());
    assert!(db
        .recover_expired_cache_write_ticket(&ticket.ticket_id, ticket.resource_version, 101)
        .await
        .is_err());
    assert!(db
        .mark_cache_write_ticket_uncertain(&ticket.ticket_id, ticket.resource_version, 101)
        .await
        .is_err());

    let intent = DirectAbortRequest {
        session: complete(&admitted).session,
        operation_id: "3".repeat(64),
        expected_resource_version: admitted.resource_version,
    };
    let pending = db
        .retain_direct_abort("deployment", &intent, 101)
        .await
        .unwrap();
    assert_eq!(pending.admission.expires_at, admitted.admission.expires_at);
    let evidence = DirectAbortEvidence {
        session: intent.session.clone(),
        operation_id: intent.operation_id.clone(),
        outcome: DirectAbortOutcome::Aborted,
        receipt_digest: Some("4".repeat(64)),
    };
    let ticket = db
        .cache_write_ticket("cache-single-pre")
        .await
        .unwrap()
        .unwrap();
    let release = Database::abort_cache_write_ticket_statements(
        &ticket.ticket_id,
        ticket.resource_version,
        "aborted",
        102,
    )
    .unwrap();
    let mut failed = release.clone();
    failed.push(
        Statement::new(
            "UPDATE users SET created_at = created_at WHERE id = -1",
            vec![],
        )
        .expecting(1),
    );
    assert!(db
        .report_direct_abort_checked("deployment", &pending, &evidence, failed, 102)
        .await
        .is_err());
    assert_eq!(
        db.cache_write_ticket(&ticket.ticket_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ticket.state
    );
    let unchanged = db
        .direct_upload_session("deployment", &intent.session.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.state, DirectSessionState::Aborting);
    assert_eq!(unchanged.resource_version, pending.resource_version);

    db.report_direct_abort_checked("deployment", &pending, &evidence, release, 103)
        .await
        .unwrap();
    let replay = db
        .retain_direct_abort("deployment", &intent, 104)
        .await
        .unwrap();
    assert_eq!(replay.state, DirectSessionState::Aborted);
    assert_eq!(replay.admission.expires_at, admitted.admission.expires_at);
    assert_eq!(
        db.cache_write_ticket(&ticket.ticket_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        "aborted"
    );
    db.report_direct_abort_checked("deployment", &replay, &evidence, Vec::new(), 105)
        .await
        .unwrap();
    assert_eq!(
        db.cache_write_ticket(&ticket.ticket_id)
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        ticket.resource_version + 1
    );
}
