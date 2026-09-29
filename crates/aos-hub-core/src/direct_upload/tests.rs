//! Signed phases, immutable placement/source correlation and restore boundaries.

use super::*;
use crate::storage_work::StorageWorkKey;

fn intent() -> DirectUploadIntent {
    DirectUploadIntent {
        version: 1,
        client_operation_id: "11".repeat(32),
        target: DirectUploadTarget::CacheObject {
            cache_id: "cache".into(),
            path: "object".into(),
        },
        expected_sha256: "22".repeat(32),
        byte_size: WireInteger::new(1),
        part_size: WireInteger::new(8 * 1024 * 1024),
        dependency_phase: DirectDependencyPhase::Content,
        transfer_mode: DirectTransferMode::DirectRequired,
    }
}

fn credential(purpose: &str) -> DirectCredentialRevision {
    DirectCredentialRevision {
        purpose: purpose.into(),
        credential_id: "protected-profile".into(),
        generation: WireInteger::new(1),
        secret_version_ref: "worker-profile:1".into(),
        credential_fingerprint: "33".repeat(32),
    }
}

fn placement() -> DirectPlacement {
    DirectPlacement {
        placement_id: WireInteger::new(1),
        placement_resource_version: WireInteger::new(2),
        write_spec_version: WireInteger::new(3),
        binding_id: WireInteger::new(4),
        binding_resource_version: WireInteger::new(5),
        binding_write_revision: WireInteger::new(6),
        final_key: "cache/object".into(),
        staging_prefix: ".aos-direct-upload".into(),
        private_stage_policy: DirectPrivateStagePolicyRef {
            policy_id: "reviewed-policy".into(),
            policy_digest: "44".repeat(32),
            namespace: "private-bucket".into(),
        },
        checksum_algorithm: DirectChecksumAlgorithm::Md5,
        physical: DirectPhysicalContext::DeploymentR2 {
            deployment_id: "deployment".into(),
            bucket_namespace: "permanent-bucket".into(),
        },
        write_credential: credential("write"),
        read_credential: credential("read"),
        presign_credential: credential("presign"),
    }
}

fn admission() -> DirectUploadAdmission {
    let actor_slot = DirectActorSlot {
        kind: DirectActorKind::User,
        numeric_id: WireInteger::new(7),
        incarnation: "01234567-89ab-4def-8123-456789abcdef".into(),
    };
    let mut admission = DirectUploadAdmission {
        session_id: "original-session".into(),
        principal_id: actor_slot.principal_id("deployment").unwrap(),
        actor_slot,
        intent: intent(),
        logical_fingerprint: String::new(),
        expires_at: WireInteger::new(1000),
        placements: vec![placement()],
    };
    admission.logical_fingerprint = admission.fingerprint("deployment").unwrap();
    admission
}

#[test]
fn actor_incarnation_separates_recycled_slots_and_binds_protected_admission() {
    let original = admission();
    original.validate("deployment").unwrap();
    let principal = original.actor_slot.principal_id("deployment").unwrap();
    // Independently evaluated with Node's SHA-256 and explicit BE length frames.
    assert_eq!(
        principal,
        "291a378c8cf99c9aaad3ebf4a87baa24a4b7475aba4c5afcf6fc7b370d71ded1"
    );
    let mut changed = original.actor_slot.clone();
    changed.numeric_id = WireInteger::new(8);
    assert_eq!(changed.principal_id("deployment").unwrap(), principal);
    changed.incarnation = "01234567-89ab-4def-9123-456789abcdef".into();
    assert_ne!(changed.principal_id("deployment").unwrap(), principal);
    changed.kind = DirectActorKind::ServiceAccount;
    assert_ne!(changed.principal_id("deployment").unwrap(), principal);
    assert_ne!(
        original
            .actor_slot
            .principal_id("other-deployment")
            .unwrap(),
        principal
    );
    let mut admission = original.clone();
    admission.actor_slot = changed;
    assert!(admission.fingerprint("deployment").is_err());
    admission = original.clone();
    admission.actor_slot.numeric_id = WireInteger::new(8);
    assert_ne!(
        admission.fingerprint("deployment").unwrap(),
        original.logical_fingerprint
    );
    for value in [
        "01234567-89ab-1def-8123-456789abcdef",
        "01234567-89AB-4def-8123-456789abcdef",
        "01234567-89ab-4def-7123-456789abcdef",
        "0123456789ab4def8123456789abcdef",
    ] {
        let mut actor = original.actor_slot.clone();
        actor.incarnation = value.into();
        assert!(actor.validate().is_err());
    }
    for value in [0, i64::MAX as u64 + 1] {
        let mut actor = original.actor_slot.clone();
        actor.numeric_id = WireInteger::new(value);
        assert!(actor.validate().is_err());
    }
}

fn context(path: &str) -> DirectRequestContext {
    DirectRequestContext {
        deployment_id: "deployment".into(),
        executor_public_origin: "https://executor.test".into(),
        request_nonce: "55".repeat(32),
        request_body_sha256: "66".repeat(32),
        public_method: "POST".into(),
        public_path: format!("/aos.hub.v1.DirectUploadService/{path}"),
        issued_at: WireInteger::new(100),
        expires_at: WireInteger::new(130),
    }
}

#[test]
fn admission_fingerprint_pins_original_owner_source_deadline_and_all_revisions() {
    let original = admission();
    original.validate("deployment").unwrap();
    for mutation in 0..5 {
        let mut changed = original.clone();
        match mutation {
            0 => changed.intent.expected_sha256 = "77".repeat(32),
            1 => changed.expires_at = WireInteger::new(1001),
            2 => changed.placements[0].binding_write_revision = WireInteger::new(7),
            3 => changed.placements[0].read_credential.generation = WireInteger::new(2),
            _ => changed.placements[0].final_key = "cache/replacement".into(),
        }
        assert!(changed.validate("deployment").is_err());
        assert_ne!(
            changed.fingerprint("deployment").unwrap(),
            original.logical_fingerprint
        );
    }
    assert!(original.validate("another-deployment").is_err());
}

#[test]
fn shared_stage_key_is_exact_and_private_without_changing_business_identity() {
    let original = admission();
    let key = direct_staging_key(&original.session_id, &original.placements[0]).unwrap();
    assert_eq!(
        key,
        format!(
            ".aos-direct-upload/{}/1/payload",
            hex::encode(sha2::Sha256::digest(b"original-session"))
        )
    );
    let mut changed = original.clone();
    changed.session_id = "restored-new-session".into();
    assert_ne!(
        direct_staging_key(&changed.session_id, &changed.placements[0]).unwrap(),
        key
    );
    assert_eq!(
        deterministic_business_operation_id(
            "deployment",
            &original.principal_id,
            &original.intent.client_operation_id
        )
        .unwrap(),
        deterministic_business_operation_id(
            "deployment",
            &changed.principal_id,
            &changed.intent.client_operation_id
        )
        .unwrap()
    );
    changed.placements[0].staging_prefix = "public-stage".into();
    assert!(changed.fingerprint("deployment").is_err());
    changed = original;
    changed.placements[0].final_key = ".aos-direct-upload/visible".into();
    assert!(changed.fingerprint("deployment").is_err());
}

#[test]
fn protected_domains_exact_context_and_exclusive_time_are_checked_before_effects() {
    let key = StorageWorkKey::new([7; 32]).unwrap();
    let request = DirectLogicalRequestEnvelope {
        context: context("BeginBatch"),
        request: DirectUploadLogicalRequest::Admission {
            intents: vec![intent()],
        },
    };
    let signed = sign_direct_logical_request(&key, &request).unwrap();
    let verified = verify_direct_logical_request(
        &key,
        &signed.signature,
        &signed.body,
        "deployment",
        "https://executor.test",
        129,
    )
    .unwrap();
    verified
        .validate_transport("POST", &request.context.public_path, "admission")
        .unwrap();
    assert!(verified
        .validate_transport("POST", &request.context.public_path, "commit")
        .is_err());
    assert!(verify_direct_logical_request(
        &key,
        &signed.signature,
        &signed.body,
        "deployment",
        "https://executor.test",
        130
    )
    .is_err());
    assert!(verify_direct_logical_request(
        &key,
        &signed.signature,
        &signed.body,
        "deployment",
        "https://foreign.test",
        100
    )
    .is_err());
    assert!(verify_direct_logical_reply(
        &key,
        &signed.signature,
        &signed.body,
        &request.context,
        100
    )
    .is_err());
    let mut changed = signed.body.clone();
    changed.push(b' ');
    assert!(verify_direct_logical_request(
        &key,
        &signed.signature,
        &changed,
        "deployment",
        "https://executor.test",
        100
    )
    .is_err());
    let weak_domain = key.sign_body(&signed.body).unwrap();
    assert!(verify_direct_logical_request(
        &key,
        &weak_domain,
        &signed.body,
        "deployment",
        "https://executor.test",
        100
    )
    .is_err());
}

#[test]
fn changed_rpc_or_promote_step_cannot_reuse_freeze_authority() {
    let request = DirectLogicalRequestEnvelope {
        context: context("CompleteBatch"),
        request: DirectUploadLogicalRequest::Authorize {
            action: DirectLogicalAction::Complete,
            complete_step: Some(DirectCompleteStep::Freeze),
            stage_evidence: vec![],
            sessions: vec![DirectSessionAuthorization {
                session: DirectSessionRef {
                    session_id: "s".into(),
                    logical_fingerprint: "55".repeat(32),
                },
                operation_id: "77".repeat(32),
                expected_resource_version: Some(WireInteger::new(1)),
                complete_intent: Some(DirectCompleteRequest {
                    session: DirectSessionRef {
                        session_id: "s".into(),
                        logical_fingerprint: "55".repeat(32),
                    },
                    operation_id: "77".repeat(32),
                    expected_resource_version: WireInteger::new(1),
                    manifests: vec![DirectManifestCommitment {
                        placement: placement().public_ref("deployment").unwrap(),
                        manifest_digest: "88".repeat(32),
                        part_count: 1,
                    }],
                }),
            }],
        },
    };
    let key = StorageWorkKey::new([7; 32]).unwrap();
    sign_direct_logical_request(&key, &request).unwrap();
    let mut changed = request.clone();
    changed.context.public_path = context("GrantPartsBatch").public_path;
    assert!(sign_direct_logical_request(&key, &changed).is_err());
    changed = request;
    if let DirectUploadLogicalRequest::Authorize { complete_step, .. } = &mut changed.request {
        *complete_step = Some(DirectCompleteStep::Promote);
    }
    assert!(sign_direct_logical_request(&key, &changed).is_err());
}

#[test]
fn managed_profile_commitment_uses_actual_secret_coordinates_and_generation() {
    let mut profile = DirectManagedR2Profile {
        deployment_id: "deployment".into(),
        bucket_namespace: "namespace".into(),
        account_id: "account".into(),
        bucket_name: "bucket".into(),
        credential_id: "credential".into(),
        credential_generation: WireInteger::new(1),
        secret_version_ref: "worker-profile:1".into(),
        credential_fingerprint: String::new(),
        checksum_algorithm: DirectChecksumAlgorithm::Md5,
        clock_qualification: "66".repeat(32),
        clock_uncertainty_seconds: WireInteger::new(1),
    };
    let commitment = profile
        .fingerprint_with_credentials("access-canary", "secret-canary")
        .unwrap();
    profile.credential_fingerprint = commitment.clone();
    profile.validate().unwrap();
    assert!(!serde_json::to_string(&profile).unwrap().contains("canary"));
    assert!(!format!("{profile:?}").contains("canary"));
    assert_ne!(
        profile
            .fingerprint_with_credentials("access-canary", "changed-secret")
            .unwrap(),
        commitment
    );
    let mut changed = profile.clone();
    changed.clock_qualification = "77".repeat(32);
    assert_ne!(
        changed
            .fingerprint_with_credentials("access-canary", "secret-canary")
            .unwrap(),
        commitment
    );
    changed = profile.clone();
    changed.clock_uncertainty_seconds = WireInteger::new(2);
    assert_ne!(
        changed
            .fingerprint_with_credentials("access-canary", "secret-canary")
            .unwrap(),
        commitment
    );
    for uncertainty in [0, 30, u64::MAX] {
        changed.clock_uncertainty_seconds = WireInteger::new(uncertainty);
        assert!(changed.validate().is_err());
        assert!(changed
            .fingerprint_with_credentials("access-canary", "secret-canary")
            .is_err());
    }
    profile.credential_generation = WireInteger::new(2);
    assert_ne!(
        profile
            .fingerprint_with_credentials("access-canary", "secret-canary")
            .unwrap(),
        commitment
    );
}

use sha2::Digest as _;

#[test]
fn verified_stage_and_final_evidence_require_exact_original_required_destinations() {
    let original = admission();
    let reference = original.placements[0].public_ref("deployment").unwrap();
    let manifest = DirectManifestCommitment {
        placement: reference.clone(),
        manifest_digest: "88".repeat(32),
        part_count: 1,
    };
    let stage = DirectVerifiedStageEvidence {
        session_id: original.session_id.clone(),
        logical_fingerprint: original.logical_fingerprint.clone(),
        operation_id: "77".repeat(32),
        part_count: 1,
        sha256: original.intent.expected_sha256.clone(),
        byte_size: original.intent.byte_size,
        placements: vec![DirectStagePlacementEvidence {
            placement: reference,
            manifest: manifest.clone(),
            verification_operation_id: "99".repeat(32),
            staging_incarnation: DirectObjectIncarnation::ProviderVersion {
                version: "real-staging-version".into(),
            },
        }],
        projection: None,
    };
    stage.validate_against(&original, "deployment").unwrap();
    let final_evidence = DirectCompletionEvidence {
        session_id: stage.session_id.clone(),
        logical_fingerprint: stage.logical_fingerprint.clone(),
        operation_id: stage.operation_id.clone(),
        part_count: 1,
        sha256: stage.sha256.clone(),
        byte_size: stage.byte_size,
        placements: vec![DirectPlacementEvidence {
            placement_id: original.placements[0].placement_id,
            placement_resource_version: original.placements[0].placement_resource_version,
            write_spec_version: original.placements[0].write_spec_version,
            binding_id: original.placements[0].binding_id,
            binding_resource_version: original.placements[0].binding_resource_version,
            binding_write_revision: original.placements[0].binding_write_revision,
            manifest: manifest.clone(),
            promotion_operation_id: "aa".repeat(32),
            staging_incarnation: stage.placements[0].staging_incarnation.clone(),
            final_incarnation: DirectObjectIncarnation::ProviderVersion {
                version: "real-final-version".into(),
            },
            final_etag: "\"final-etag\"".into(),
        }],
        projection: None,
    };
    final_evidence
        .validate_against(&original, "deployment")
        .unwrap();
    let complete = DirectCompleteRequest {
        session: DirectSessionRef {
            session_id: stage.session_id.clone(),
            logical_fingerprint: stage.logical_fingerprint.clone(),
        },
        operation_id: stage.operation_id.clone(),
        expected_resource_version: WireInteger::new(1),
        manifests: vec![manifest],
    };
    let request = DirectLogicalRequestEnvelope {
        context: context("CompleteBatch"),
        request: DirectUploadLogicalRequest::Authorize {
            action: DirectLogicalAction::Complete,
            complete_step: Some(DirectCompleteStep::Promote),
            stage_evidence: vec![stage.clone()],
            sessions: vec![DirectSessionAuthorization {
                session: complete.session.clone(),
                expected_resource_version: Some(complete.expected_resource_version),
                operation_id: complete.operation_id.clone(),
                complete_intent: Some(complete),
            }],
        },
    };
    let key = StorageWorkKey::new([7; 32]).unwrap();
    sign_direct_logical_request(&key, &request).unwrap();
    let mut changed = request.clone();
    if let DirectUploadLogicalRequest::Authorize { stage_evidence, .. } = &mut changed.request {
        stage_evidence[0].placements[0].manifest.manifest_digest = "bb".repeat(32);
    }
    assert!(sign_direct_logical_request(&key, &changed).is_err());
    let mut changed = final_evidence;
    changed.placements[0].binding_write_revision = WireInteger::new(99);
    assert!(changed.validate_against(&original, "deployment").is_err());
    let mut changed = stage;
    changed.placements[0].placement.profile_fingerprint = "cc".repeat(32);
    changed.placements[0].manifest.placement = changed.placements[0].placement.clone();
    assert!(changed.validate_against(&original, "deployment").is_err());
}
