//! Real database isolation, optimistic races and atomic publication rollback.

use std::sync::Arc;

use super::*;

fn original() -> NativeDirectUploadRecord {
    let session = uuid::Uuid::new_v4().simple().to_string();
    NativeDirectUploadRecord {
        session_id: session.clone(),
        deployment_id: "native-test".into(),
        principal_id: "original-account".into(),
        client_operation_id: session,
        oci_upload_id: None,
        state: "creating".into(),
        source_sha256: "a".repeat(64),
        declared_size: 17,
        verified_sha256: None,
        verified_size: None,
        materialization_placement_id: None,
        materialization_binding_id: None,
        state_json: "{\"original\":\"test\"}".into(),
        resource_version: 1,
    }
}

async fn cases(db: Arc<Database>) {
    let initial = original();
    assert_eq!(
        db.create_native_direct_upload(&initial).await.unwrap(),
        initial
    );
    assert_eq!(
        db.create_native_direct_upload(&initial).await.unwrap(),
        initial
    );

    assert!(db
        .native_direct_upload("another-deployment", &initial.session_id)
        .await
        .unwrap()
        .is_none());
    assert!(db
        .native_direct_upload_by_operation(
            &initial.deployment_id,
            "another-account",
            &initial.client_operation_id
        )
        .await
        .unwrap()
        .is_none());

    let mut changed = initial.clone();
    changed.declared_size += 1;
    assert!(db.create_native_direct_upload(&changed).await.is_err());
    changed = initial.clone();
    changed.session_id = uuid::Uuid::new_v4().simple().to_string();
    assert!(db.create_native_direct_upload(&changed).await.is_err());

    let mut left = initial.clone();
    left.resource_version = 2;
    left.state = "uploading".into();
    left.state_json = "{\"writer\":\"left\"}".into();
    let mut right = left.clone();
    right.state_json = "{\"writer\":\"right\"}".into();

    let (a, b) = tokio::join!(
        db.replace_native_direct_upload(&left, 1, Vec::new()),
        db.replace_native_direct_upload(&right, 1, Vec::new()),
    );
    assert_ne!(a.is_ok(), b.is_ok());
    let retained = db
        .native_direct_upload(&initial.deployment_id, &initial.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retained, if a.is_ok() { left } else { right });

    let rollback = original();
    db.create_native_direct_upload(&rollback).await.unwrap();
    let mut published = rollback.clone();
    published.resource_version = 2;
    published.state = "committed".into();
    published.verified_sha256 = Some(published.source_sha256.clone());
    published.verified_size = Some(published.declared_size);
    let failed_target = Statement::new(
        "UPDATE native_direct_uploads SET resource_version = resource_version + 1
         WHERE deployment_id = ?1 AND session_id = ?2",
        vals![&rollback.deployment_id, "missing"],
    )
    .expecting(1);

    assert!(db
        .replace_native_direct_upload(&published, 1, vec![failed_target])
        .await
        .is_err());
    assert_eq!(
        db.native_direct_upload(&rollback.deployment_id, &rollback.session_id)
            .await
            .unwrap()
            .unwrap(),
        rollback
    );

    // Target statements see verified terminal scalars before transaction commit.
    let target = Statement::new(
        "UPDATE native_direct_uploads SET state_json = state_json
         WHERE deployment_id = ?1 AND session_id = ?2 AND state = 'committed'
           AND verified_sha256 = source_sha256 AND verified_size = declared_size",
        vals![&published.deployment_id, &published.session_id],
    )
    .expecting(1);
    db.replace_native_direct_upload(&published, 1, vec![target])
        .await
        .unwrap();
    assert_eq!(
        db.native_direct_upload(&published.deployment_id, &published.session_id)
            .await
            .unwrap()
            .unwrap(),
        published
    );

    let immutable = original();
    db.create_native_direct_upload(&immutable).await.unwrap();
    let mut substituted = immutable.clone();
    substituted.resource_version = 2;
    substituted.principal_id = "substituted-account".into();
    assert!(db
        .replace_native_direct_upload(&substituted, 1, Vec::new())
        .await
        .is_err());
    assert_eq!(
        db.native_direct_upload(&immutable.deployment_id, &immutable.session_id)
            .await
            .unwrap()
            .unwrap(),
        immutable
    );
}

#[tokio::test]
async fn sqlite_journal_preserves_originals_and_atomic_cas() {
    cases(Arc::new(Database::open_in_memory().await.unwrap())).await;
}

#[cfg(all(feature = "postgres", not(target_arch = "wasm32")))]
#[tokio::test]
#[ignore = "requires the dedicated disposable PostgreSQL test source"]
async fn postgres_journal_preserves_originals_and_atomic_cas() {
    let path = std::env::var("AOS_PG_SNAPSHOT_TEST_URL_FILE")
        .expect("dedicated disposable PostgreSQL URL file");
    let url = std::fs::read_to_string(path).unwrap();
    cases(Arc::new(Database::connect(url.trim()).await.unwrap())).await;
}

#[test]
fn committed_objects_require_full_matching_verification() {
    let mut record = original();
    record.state = "committed".into();
    assert!(record.validate().is_err());
    record.verified_sha256 = Some(record.source_sha256.clone());
    record.verified_size = Some(record.declared_size - 1);
    assert!(record.validate().is_err());
    record.verified_size = Some(record.declared_size);
    assert!(record.validate().is_ok());
    record.oci_upload_id = Some("oci-allocation".into());
    assert!(record.validate().is_err());
    record.materialization_placement_id = Some(1);
    assert!(record.validate().is_err());
    record.materialization_binding_id = Some(2);
    assert!(record.validate().is_ok());
}
