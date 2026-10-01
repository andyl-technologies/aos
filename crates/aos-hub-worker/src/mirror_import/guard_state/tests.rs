//! File-backed SQLite restart tests of the production held-final validator.

use super::*;
use aos_hub_core::{
    backend::{Backend, SqlxBackend},
    mirror_work::{digest, MirrorPart, MirrorVerification, MirrorVerifiedObject},
    storage_work::StorageObjectIdentity,
    value::Value,
};

fn records() -> (MirrorOriginal, MirrorProgress, MutationReceipt) {
    let mut original = MirrorOriginal {
        version: 1,
        job_id: String::new(),
        copy_operation_id: Some("11".repeat(16)),
        registry_id: 1,
        registry_resource_version: 2,
        mirror_resource_version: 3,
        upstream_base: "https://mirror.example.org/".into(),
        path: "metadata.json".into(),
        placement_id: 4,
        placement_resource_version: 5,
        write_spec_version: 6,
        binding_id: 7,
        binding_resource_version: 8,
        placement_prefix: "managed".into(),
        protected_profile_digest: "22".repeat(32),
        verification: MirrorVerification::Sha256 {
            sha256: "33".repeat(32),
            size: 8,
        },
    };
    original.job_id = original.identity().unwrap();
    let stage = StorageObjectIdentity {
        key: original.stage_key(),
        size: 8,
        etag: "\"stage\"".into(),
        provider_version: Some("stage-incarnation".into()),
    };
    let verified = MirrorVerifiedObject {
        object: stage.clone(),
        sha256: "33".repeat(32),
        nar_sha256: None,
        nar_size: None,
    };
    let mut destination = verified.clone();
    destination.object.key =
        aos_hub_core::keymap::r2_key(&original.placement_prefix, &original.path);
    destination.object.provider_version = Some("final-incarnation".into());
    let part = MirrorPart {
        part_number: 1,
        size: 8,
        sha256: "33".repeat(32),
        etag: "\"part\"".into(),
    };
    let progress = MirrorProgress {
        original_digest: digest(&original).unwrap(),
        stage_upload_id: Some("stage-upload".into()),
        stage_parts: vec![part.clone()],
        stage_object: Some(stage),
        verified: Some(verified),
        destination_upload_id: Some("final-upload".into()),
        destination_parts: vec![part],
        destination: Some(destination),
        ..Default::default()
    };
    let mutation = expected_final_mutation(
        &progress.destination.as_ref().unwrap().object.key,
        &original,
        &progress,
    )
    .unwrap();
    let receipt = MutationReceipt {
        mutation,
        outcome: MutationOutcome::Mirror {
            progress: progress.clone(),
        },
    };
    (original, progress, receipt)
}

async fn write(db: &SqlxBackend, key: &str, value: &impl serde::Serialize) {
    db.execute(
        "INSERT OR REPLACE INTO guard VALUES (?1,?2)",
        &[
            Value::Text(key.into()),
            Value::Text(serde_json::to_string(value).unwrap()),
        ],
    )
    .await
    .unwrap();
}

async fn read<T: serde::de::DeserializeOwned>(db: &SqlxBackend, key: &str) -> Option<T> {
    db.query_opt(
        "SELECT value FROM guard WHERE key=?1",
        &[Value::Text(key.into())],
    )
    .await
    .unwrap()
    .map(|row| serde_json::from_str(&row.get::<String>(0).unwrap()).unwrap())
}

#[tokio::test]
async fn sqlite_restart_preserves_unknown_and_positive_receipt_before_clear_without_writes() {
    let path = std::env::temp_dir().join(format!(
        "mirror-final-guard-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let db = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    db.execute_batch("CREATE TABLE guard (key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        .await
        .unwrap();
    let (original, progress, receipt) = records();
    let key = progress.destination.as_ref().unwrap().object.key.clone();
    let receipt_key = format!("mutation-receipt:{}", receipt.mutation.operation_id);
    write(&db, "mirror-owner", &original).await;
    write(&db, "mirror-progress", &progress).await;
    write(&db, "pending-mutation", &receipt.mutation).await;
    drop(db);

    let db = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    let owner: MirrorOriginal = read(&db, "mirror-owner").await.unwrap();
    let positive: MirrorProgress = read(&db, "mirror-progress").await.unwrap();
    let pending: Mutation = read(&db, "pending-mutation").await.unwrap();
    assert!(validate_retained_final(
        &key,
        Some(&owner),
        Some(&positive),
        None,
        Some(&pending),
        None
    )
    .is_err());
    write(&db, &receipt_key, &receipt).await;
    drop(db);

    let db = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    let retained: MutationReceipt = read(&db, &receipt_key).await.unwrap();
    let pending: Mutation = read(&db, "pending-mutation").await.unwrap();
    assert_eq!(
        validate_retained_final(
            &key,
            Some(&owner),
            Some(&positive),
            Some(&retained),
            Some(&pending),
            None
        )
        .unwrap(),
        (owner.clone(), positive.clone())
    );
    let unchanged: Mutation = read(&db, "pending-mutation").await.unwrap();
    assert_eq!(unchanged, pending);
    let mut other = pending.clone();
    other.fingerprint = "99".repeat(32);
    assert!(validate_retained_final(
        &key,
        Some(&owner),
        Some(&positive),
        Some(&retained),
        Some(&other),
        None
    )
    .is_err());
    assert!(
        validate_retained_final(&key, None, Some(&positive), Some(&retained), None, None).is_err()
    );
    assert!(validate_retained_final(
        "managed/replacement",
        Some(&owner),
        Some(&positive),
        Some(&retained),
        None,
        None
    )
    .is_err());
    let mut replacement = positive.clone();
    replacement
        .destination
        .as_mut()
        .unwrap()
        .object
        .provider_version = Some("replacement-incarnation".into());
    assert!(validate_retained_final(
        &key,
        Some(&owner),
        Some(&replacement),
        Some(&retained),
        None,
        None
    )
    .is_err());
    let mut changed = owner.clone();
    changed.protected_profile_digest = "99".repeat(32);
    changed.job_id = changed.identity().unwrap();
    assert!(validate_retained_final(
        &key,
        Some(&changed),
        Some(&positive),
        Some(&retained),
        None,
        None
    )
    .is_err());
    let delete = DeleteClaim {
        claim_id: "legacy-delete".into(),
        expected_etag: "\"stage\"".into(),
        expected_size: 8,
        expected_hash: None,
        expected_provider_version: Some("final-incarnation".into()),
    };
    assert!(validate_retained_final(
        &key,
        Some(&owner),
        Some(&positive),
        Some(&retained),
        None,
        Some(&delete)
    )
    .is_err());
    drop(db);
    std::fs::remove_file(path).unwrap();
}
