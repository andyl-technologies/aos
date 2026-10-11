//! File-backed exact R2 cleanup receipt recovery and role separation.

use super::*;
use aos_hub_core::{
    backend::{Backend as _, SqlxBackend},
    mirror_guard::MirrorGuardIssuer,
    storage_work::StorageWorkKey,
    value::Value,
};

fn fixture() -> (ManagedOciCleanupRequest, Record) {
    let original = ManagedOciCleanupOriginal {
        upload_id: "a".repeat(32),
        upload_resource_version: 9,
        terminal_state: "complete".into(),
        finished_at: 200,
        registry_id: 1,
        repository_id: 2,
        writer_id: "retained-writer".into(),
        token_id: "retained-owner".into(),
        ordinal: 0,
        offset: 0,
        path: format!("oci/uploads/{}/chunks/0-{}", "a".repeat(32), "b".repeat(32)),
        sha256: "c".repeat(64),
        size: 12,
        placement_id: 3,
        placement_resource_version: 4,
        placement_prefix: "registry".into(),
        binding_id: 5,
        binding_resource_version: 6,
        binding_write_revision: 7,
        delete_capability_fingerprint: "independently-validated-delete".into(),
        delete_capability_resource_version: 8,
    };
    let work = ManagedOciCleanupRequest {
        deployment_id: "installed-test-deployment".into(),
        original: original.clone(),
        protected_profile_digest: "d".repeat(64),
        issuer: MirrorGuardIssuer {
            source_digest: "e".repeat(64),
            script_version: "installed-test-source".into(),
        },
        clock_uncertainty_seconds: 2,
        nonce: "f".repeat(64),
        issued_at: 300,
        expires_at: 330,
    };
    work.validate(&work.deployment_id, 302).unwrap();
    let record = Record::new(
        original.clone(),
        StorageObjectIdentity {
            key: original.key(),
            size: original.size,
            etag: "\"actual-strong-tag\"".into(),
            provider_version: Some("opaque-r2-sdk-version".into()),
        },
    )
    .unwrap();
    (work, record)
}

#[test]
fn unknown_absence_replacement_and_foreign_original_never_settle() {
    let (work, record) = fixture();
    assert!(record.reply(&work, None).is_err());
    let receipt = MutationReceipt {
        mutation: record.mutation.clone(),
        outcome: MutationOutcome::Acknowledged,
    };
    let mut foreign = work.clone();
    foreign.original.upload_resource_version += 1;
    assert!(record.reply(&foreign, Some(&receipt)).is_err());
    let mut different = receipt.clone();
    different.mutation.operation_id = "different-attempt".into();
    assert!(record.reply(&work, Some(&different)).is_err());
    let mut replacement = record.clone();
    replacement.object.provider_version = Some("later-r2-sdk-version".into());
    assert!(replacement.reply(&work, Some(&receipt)).is_err());
    let mut absent = record.object.clone();
    absent.provider_version = None;
    assert!(Record::new(record.original.clone(), absent).is_err());
    let mut wrong = work.clone();
    wrong.original.path = "oci/blobs/sha256/canonical".into();
    assert!(wrong.validate(&wrong.deployment_id, 302).is_err());
    wrong = work.clone();
    wrong.original.size = aos_hub_core::hybrid_ingress::MAX_HYBRID_OCI_CHUNK_BYTES as u64 + 1;
    assert!(wrong.validate(&wrong.deployment_id, 302).is_err());
}

#[tokio::test]
async fn cold_pending_refuses_and_exact_positive_receipt_replays_without_new_turn() {
    let (work, record) = fixture();
    let path = std::env::temp_dir().join(format!(
        "managed-oci-cleanup-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let db = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    db.execute_batch("CREATE TABLE state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        .await
        .unwrap();
    db.execute(
        "INSERT INTO state VALUES('record',?1)",
        &[Value::Text(serde_json::to_string(&record).unwrap())],
    )
    .await
    .unwrap();
    drop(db);

    let db = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    let row = db
        .query_opt("SELECT value FROM state WHERE key='record'", &[])
        .await
        .unwrap()
        .unwrap();
    let cold: Record = serde_json::from_str(&row.get::<String>(0).unwrap()).unwrap();
    assert!(cold.reply(&work, None).is_err());
    let receipt = MutationReceipt {
        mutation: cold.mutation.clone(),
        outcome: MutationOutcome::Acknowledged,
    };
    db.execute(
        "INSERT INTO state VALUES('receipt',?1)",
        &[Value::Text(serde_json::to_string(&receipt).unwrap())],
    )
    .await
    .unwrap();
    drop(db);

    let db = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    let row = db
        .query_opt("SELECT value FROM state WHERE key='receipt'", &[])
        .await
        .unwrap()
        .unwrap();
    let positive: MutationReceipt = serde_json::from_str(&row.get::<String>(0).unwrap()).unwrap();
    let mut replay = work.clone();
    replay.nonce = "1".repeat(64);
    replay.issued_at = 400;
    replay.expires_at = 430;
    replay.validate(&replay.deployment_id, 402).unwrap();
    assert_eq!(
        cold.reply(&replay, Some(&positive)).unwrap().receipt_digest,
        record.reply(&work, Some(&receipt)).unwrap().receipt_digest
    );
    assert_eq!(cold.mutation, positive.mutation);
    drop(db);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn fresh_control_and_independent_guard_mac_cannot_renew_upload_or_infer_delete() {
    let (work, record) = fixture();
    let app = StorageWorkKey::new(b"actual-test-application-authority").unwrap();
    let guard = StorageWorkKey::new(b"independent-test-physical-guard-role").unwrap();
    let (body, signature) = work.sign(&app).unwrap();
    assert!(
        ManagedOciCleanupRequest::authenticate(&app, &signature, &body, &work.deployment_id, 330)
            .is_err()
    );
    assert!(
        ManagedOciCleanupRequest::authenticate(&guard, &signature, &body, &work.deployment_id, 302)
            .is_err()
    );
    let receipt = MutationReceipt {
        mutation: record.mutation.clone(),
        outcome: MutationOutcome::Acknowledged,
    };
    let reply = record.reply(&work, Some(&receipt)).unwrap();
    let (body, signature) = reply.sign(&work, &guard).unwrap();
    assert!(ManagedOciCleanupReply::authenticate(&work, &app, &signature, &body).is_err());
    assert_eq!(
        ManagedOciCleanupReply::authenticate(&work, &guard, &signature, &body).unwrap(),
        reply
    );
    let mut next = work.clone();
    next.nonce = "1".repeat(64);
    assert!(ManagedOciCleanupReply::authenticate(&next, &guard, &signature, &body).is_err());
    assert_eq!(record.original.finished_at, 200);
}
