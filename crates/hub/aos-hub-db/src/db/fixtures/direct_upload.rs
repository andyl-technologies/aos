//! Canonical SQL-backed direct-upload originals for persistence and service tests.

use crate::db::{Database, DirectSqlOwner, DirectUploadSessionRecord};
use crate::direct_upload::*;

/// Constructs the retained original fixture.
///
/// # Panics
///
/// Panics if fixture setup or the expected fixture record is invalid.
pub async fn original(db: &Database) -> DirectUploadSessionRecord {
    db.install_write_failure_test_tickets().await.unwrap();
    let user = db.create_user("direct@example.test", None).await.unwrap();
    let actor_slot = DirectActorSlot {
        kind: DirectActorKind::User,
        numeric_id: WireInteger::new(user as u64),
        incarnation: db
            .principal_incarnation(aos_hub_model::domain::Principal::user(user))
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

/// Constructs the retained complete fixture.
///
/// # Panics
///
/// Panics if fixture setup or the expected fixture record is invalid.
pub fn complete(record: &DirectUploadSessionRecord) -> DirectCompleteRequest {
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

/// Constructs the retained stage fixture.
///
/// # Panics
///
/// Panics if fixture setup or the expected fixture record is invalid.
pub fn stage(
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
