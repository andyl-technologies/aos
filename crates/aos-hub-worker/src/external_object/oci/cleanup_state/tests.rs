//! Real retained cleanup cells reject unknown, foreign and absence-based settlement.

use super::*;
use aos_hub_core::storage_authority::external_object::oci::OciBytes;
use aos_hub_core::{
    backend::{Backend as _, SqlxBackend},
    storage_authority::{GuardIncarnation, StorageGuardStamp},
    value::Value,
};

fn fixture() -> (OciCleanupRequest, Record) {
    let source = super::super::tests::original();
    let closed = OciClosedObject {
        bytes: OciBytes {
            sha256: "e".repeat(64),
            size: 12,
        },
        etag: "\"actual-chunk\"".into(),
        receipt_digest: "d".repeat(64),
        incarnation: OciProviderIncarnation::Versioned {
            provider_version: "actual-provider-version".into(),
            guard_stamp: StorageGuardStamp {
                physical_authority_id: source.scope.physical_authority_id.clone(),
                incarnation: GuardIncarnation::parse("1").unwrap(),
            },
        },
    };
    let work = OciCleanupRequest {
        deployment_id: source.deployment_id.clone(),
        scope: source.scope.clone(),
        issuer: aos_hub_core::mirror_guard::MirrorGuardIssuer {
            source_digest: "a".repeat(64),
            script_version: "installed-test-source".into(),
        },
        clock_uncertainty_seconds: 2,
        nonce: "b".repeat(64),
        issued_at: 300,
        expires_at: 330,
        original: OciCleanupOriginal {
            upload_id: source.upload.upload_id.clone(),
            upload_resource_version: 9,
            registry_id: 1,
            repository_id: 2,
            writer_id: source.upload.writer_id.clone(),
            token_id: source.upload.token_id.clone(),
            terminal_state: "complete".into(),
            finished_at: 280,
            ordinal: 0,
            offset: 0,
            bytes: closed.bytes.clone(),
            staging_key: format!(
                "oci/uploads/{}/chunks/0-{}",
                source.upload.upload_id,
                "d".repeat(32)
            ),
            placement_id: 3,
            placement_resource_version: 4,
            placement_prefix: "registry".into(),
            binding_id: 6,
            binding_resource_version: 7,
            binding_write_revision: 8,
            binding_spec_revision: source.binding_spec_revision.clone(),
            delete_generation: 2,
            delete_capability_fingerprint: "qualified-exact-delete".into(),
            delete_capability_resource_version: 1,
        },
    };
    work.validate(&work.deployment_id, 302).unwrap();
    let record = Record::declare(&work, source, closed, "f".repeat(64), "1".repeat(64)).unwrap();
    (work, record)
}

#[test]
fn unknown_absence_wrong_version_and_foreign_chunk_never_settle() {
    let (work, record) = fixture();
    assert!(record.reply(&work).is_err());
    for outcome in [
        Outcome::DeleteAbsent,
        Outcome::DeletePreconditionFailed,
        Outcome::DeleteAcknowledged {
            provider_version: "replacement".into(),
            etag: record.closed.etag.clone(),
        },
    ] {
        assert!(
            record
                .acknowledge(
                    &work,
                    Receipt {
                        turn: record.turn.clone(),
                        outcome
                    }
                )
                .is_err()
        );
    }
    let mut foreign = work.clone();
    foreign.original.upload_id = "c".repeat(32);
    assert!(record.reply(&foreign).is_err());
    let mut versionless = record.clone();
    let stamp = match &versionless.closed.incarnation {
        OciProviderIncarnation::Versioned { guard_stamp, .. } => guard_stamp.clone(),
        _ => unreachable!(),
    };
    versionless.closed.incarnation = OciProviderIncarnation::Guarded { guard_stamp: stamp };
    assert!(versionless.validate(&work).is_err());
    let mut rotated = work.clone();
    rotated.original.delete_generation += 1;
    assert!(record.validate(&rotated).is_err());
}

#[tokio::test]
async fn lost_reply_and_cold_positive_replay_keep_exact_receipt_without_dispatch() {
    let (work, record) = fixture();
    let path = std::env::temp_dir().join(format!(
        "oci-terminal-cleanup-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let db = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    db.execute_batch("CREATE TABLE cleanup (id INTEGER PRIMARY KEY, record TEXT NOT NULL)")
        .await
        .unwrap();
    db.execute(
        "INSERT INTO cleanup VALUES(1,?1)",
        &[Value::Text(serde_json::to_string(&record).unwrap())],
    )
    .await
    .unwrap();
    drop(db);

    let db = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    let row = db
        .query_opt("SELECT record FROM cleanup WHERE id=1", &[])
        .await
        .unwrap()
        .unwrap();
    let pending: Record = serde_json::from_str(&row.get::<String>(0).unwrap()).unwrap();
    assert!(pending.reply(&work).is_err());
    let receipt = Receipt {
        turn: pending.turn.clone(),
        outcome: Outcome::DeleteAcknowledged {
            provider_version: "actual-provider-version".into(),
            etag: pending.closed.etag.clone(),
        },
    };
    let positive = pending.acknowledge(&work, receipt).unwrap();
    db.execute(
        "UPDATE cleanup SET record=?1 WHERE id=1",
        &[Value::Text(serde_json::to_string(&positive).unwrap())],
    )
    .await
    .unwrap();
    drop(db);

    let db = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    let row = db
        .query_opt("SELECT record FROM cleanup WHERE id=1", &[])
        .await
        .unwrap()
        .unwrap();
    let cold: Record = serde_json::from_str(&row.get::<String>(0).unwrap()).unwrap();
    let mut replay = work.clone();
    replay.nonce = "2".repeat(64);
    replay.issued_at = 400;
    replay.expires_at = 430;
    // The old OCI upload and grant expired long ago. This fresh metadata
    // challenge authenticates only the retained positive Delete receipt.
    replay.validate(&replay.deployment_id, 402).unwrap();
    assert_eq!(
        cold.reply(&replay).unwrap().delete_receipt_digest,
        positive.reply(&work).unwrap().delete_receipt_digest
    );
    assert_eq!(cold.turn.dispatch_nonce, record.turn.dispatch_nonce);
    let role =
        aos_hub_core::storage_work::StorageWorkKey::new(b"independent-cleanup-physical-role")
            .unwrap();
    let app = aos_hub_core::storage_work::StorageWorkKey::new(b"separate-cleanup-application-role")
        .unwrap();
    let reply = cold.reply(&replay).unwrap();
    let (body, signature) = reply.sign(&replay, &role).unwrap();
    assert!(OciCleanupReply::authenticate(&replay, &app, &signature, &body).is_err());
    assert_eq!(
        OciCleanupReply::authenticate(&replay, &role, &signature, &body).unwrap(),
        reply
    );
    drop(db);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn fresh_cleanup_window_and_request_mac_do_not_reopen_upload() {
    let (work, record) = fixture();
    assert!(work.validate(&work.deployment_id, 330).is_err());
    let app = aos_hub_core::storage_work::StorageWorkKey::new(b"terminal-cleanup-application-key")
        .unwrap();
    let (body, signature) = work.sign(&app).unwrap();
    assert!(
        OciCleanupRequest::authenticate(&app, &signature, &body, &work.deployment_id, 330).is_err()
    );
    assert_eq!(
        OciCleanupRequest::authenticate(&app, &signature, &body, &work.deployment_id, 302).unwrap(),
        work
    );
    assert_eq!(record.source.upload.expires_at.get(), 200);
    assert_eq!(record.source.actor.expires_at.get(), 140);
}
