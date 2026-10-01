//! Actual SQLite allocation retention, quota and immutable-owner regressions.

use super::*;
use crate::db::unix_now;
use crate::direct_upload::WireInteger;
use crate::domain::{Permission, Principal};

mod completion_tests;

async fn fixture() -> (Database, BeginDirectOciUpload) {
    fixture_with_database(Database::open_in_memory().await.unwrap()).await
}

async fn fixture_with_database(db: Database) -> (Database, BeginDirectOciUpload) {
    let user = db.create_user("uploader@example.test", None).await.unwrap();
    db.grant_membership("user", user, "instance", "owner")
        .await
        .unwrap();
    let (token, _) = db
        .create_token(
            Principal::user(user),
            "instance",
            &[Permission::Publish],
            None,
            None,
        )
        .await
        .unwrap();
    let org = db.create_org("allocation", "Allocation").await.unwrap();
    let registry = db
        .create_managed_registry(org, "", "images", "private", &[], false)
        .await
        .unwrap();
    let name = RepositoryName::parse("team/image").unwrap();
    let repository = db
        .ensure_oci_repository(registry, &name, unix_now())
        .await
        .unwrap();
    let registry_record = db.registry_by_id(registry).await.unwrap().unwrap();
    let input = BeginDirectOciUpload {
        deployment_id: "deployment-one".into(),
        actor: DirectActorSlot {
            kind: DirectActorKind::User,
            numeric_id: WireInteger::new(user as u64),
            incarnation: db
                .principal_incarnation(Principal::user(user))
                .await
                .unwrap()
                .unwrap(),
        },
        client_operation_id: "1".repeat(64),
        registry_id: registry,
        registry_stable_id: registry_record.stable_id,
        repository_id: repository.id,
        repository_name: name.to_string(),
        expected_digest: Sha256Digest::digest(b"immutable source"),
        expected_size: 16,
        authorization_token_id: token,
        now: unix_now(),
        expires_at: unix_now() + 3600,
    };
    (db, input)
}

async fn count(db: &Database, table: &str) -> i64 {
    // Table names are fixed test call-site constants, never client input.
    db.backend
        .query_opt(&format!("SELECT COUNT(*) FROM {table}"), &[])
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap()
}

#[tokio::test]
async fn original_allocation_replays_after_reply_loss_and_token_rotation() {
    let (db, mut input) = fixture().await;
    let original = db.begin_direct_oci_upload(&input).await.unwrap();
    let (_, secret) = db
        .rotate_token(&input.authorization_token_id)
        .await
        .unwrap()
        .unwrap();
    input.authorization_token_id = db.validate_token(&secret).await.unwrap().unwrap().token_id;
    input.now += 1;
    input.expires_at += 100;
    let replay = db.begin_direct_oci_upload(&input).await.unwrap();

    assert_eq!(replay.id, original.id);
    assert_eq!(replay.expires_at, original.expires_at);
    assert_eq!(count(&db, "direct_oci_allocations").await, 1);
    assert_eq!(count(&db, "oci_upload_sessions").await, 1);
    assert_eq!(count(&db, "oci_quota_reservations").await, 1);
    assert_ne!(original.writer_id, input.authorization_token_id);
}

#[tokio::test]
async fn same_business_operation_rejects_changed_content_and_cross_registry_owner() {
    let (db, input) = fixture().await;
    db.begin_direct_oci_upload(&input).await.unwrap();
    let mut changed = input.clone();
    changed.expected_size += 1;
    assert!(db.begin_direct_oci_upload(&changed).await.is_err());
    changed = input.clone();
    changed.expected_digest = Sha256Digest::digest(b"different source");
    assert!(db.begin_direct_oci_upload(&changed).await.is_err());

    let org = db.create_org("second-allocation", "Second").await.unwrap();
    let registry = db
        .create_managed_registry(org, "", "images", "private", &[], false)
        .await
        .unwrap();
    let repository = db
        .ensure_oci_repository(
            registry,
            &RepositoryName::parse(&input.repository_name).unwrap(),
            input.now,
        )
        .await
        .unwrap();
    changed = input;
    changed.registry_id = registry;
    changed.registry_stable_id = db
        .registry_by_id(registry)
        .await
        .unwrap()
        .unwrap()
        .stable_id;
    changed.repository_id = repository.id;
    assert!(db.begin_direct_oci_upload(&changed).await.is_err());

    assert_eq!(count(&db, "oci_upload_sessions").await, 1);
    assert_eq!(count(&db, "direct_oci_allocations").await, 1);
}

#[tokio::test]
async fn concurrent_exact_allocations_share_one_committed_owner() {
    let (db, input) = fixture().await;
    let (left, right) = tokio::join!(
        db.begin_direct_oci_upload(&input),
        db.begin_direct_oci_upload(&input),
    );
    assert_eq!(left.unwrap().id, right.unwrap().id);
    assert_eq!(count(&db, "oci_upload_sessions").await, 1);
    assert_eq!(count(&db, "oci_quota_reservations").await, 1);
}

#[tokio::test]
async fn missing_retained_upload_never_reinitializes_the_business_slot() {
    let (db, input) = fixture().await;
    let original = db.begin_direct_oci_upload(&input).await.unwrap();
    db.backend
        .execute(
            "DELETE FROM oci_upload_sessions WHERE id = ?1",
            &vals![original.id],
        )
        .await
        .unwrap();
    assert!(db.begin_direct_oci_upload(&input).await.is_err());
    assert_eq!(count(&db, "direct_oci_allocations").await, 1);
    assert_eq!(count(&db, "oci_upload_sessions").await, 0);
}

#[tokio::test]
async fn changed_owner_incarnation_refuses_retained_allocation() {
    let (db, input) = fixture().await;
    db.begin_direct_oci_upload(&input).await.unwrap();
    db.backend
        .execute(
            "UPDATE users SET principal_incarnation = ?2 WHERE id = ?1",
            &vals![
                i64::try_from(input.actor.numeric_id.get()).unwrap(),
                Uuid::new_v4().to_string()
            ],
        )
        .await
        .unwrap();

    assert!(db.begin_direct_oci_upload(&input).await.is_err());
    assert_eq!(count(&db, "direct_oci_allocations").await, 1);
    assert_eq!(count(&db, "oci_upload_sessions").await, 1);
}

#[tokio::test]
async fn quota_failure_rolls_back_both_business_reservation_and_upload() {
    let (db, input) = fixture().await;
    let registry = db.registry_by_id(input.registry_id).await.unwrap().unwrap();
    db.set_org_quota(
        registry.org_id.unwrap(),
        &crate::db::OrgQuota {
            max_objects: Some(0),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert!(db.begin_direct_oci_upload(&input).await.is_err());
    assert_eq!(count(&db, "direct_oci_allocations").await, 0);
    assert_eq!(count(&db, "oci_upload_sessions").await, 0);
    assert_eq!(count(&db, "oci_quota_reservations").await, 0);

    db.set_org_quota(registry.org_id.unwrap(), &crate::db::OrgQuota::default())
        .await
        .unwrap();
    db.begin_direct_oci_upload(&input).await.unwrap();
    assert_eq!(count(&db, "direct_oci_allocations").await, 1);
    assert_eq!(count(&db, "oci_upload_sessions").await, 1);
}

#[tokio::test]
async fn restart_preserves_the_original_allocation_and_expiry() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("logical.db");
    let (db, mut input) = fixture_with_database(Database::open(&path).await.unwrap()).await;
    let original = db.begin_direct_oci_upload(&input).await.unwrap();
    drop(db);

    let reopened = Database::open(&path).await.unwrap();
    input.now += 10;
    input.expires_at += 10;
    let replay = reopened.begin_direct_oci_upload(&input).await.unwrap();
    assert_eq!(replay.id, original.id);
    assert_eq!(replay.expires_at, original.expires_at);
    assert_eq!(count(&reopened, "direct_oci_allocations").await, 1);
    assert_eq!(count(&reopened, "oci_upload_sessions").await, 1);
    assert_eq!(count(&reopened, "oci_quota_reservations").await, 1);
}

#[tokio::test]
async fn direct_source_reservation_is_exact_and_quota_failure_preserves_stream_state() {
    let (db, input) = fixture().await;
    let upload = db.begin_direct_oci_upload(&input).await.unwrap();
    let org = db
        .registry_by_id(input.registry_id)
        .await
        .unwrap()
        .unwrap()
        .org_id
        .unwrap();
    db.set_org_quota(
        org,
        &crate::db::OrgQuota {
            max_bytes: Some(15),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(db
        .reserve_direct_oci_source(&upload, input.now)
        .await
        .is_err());
    let reservation = db
        .backend
        .query_opt(
            "SELECT reserved_bytes FROM oci_quota_reservations WHERE id = ?1",
            &vals![upload.quota_reservation_id],
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reservation.get::<i64>(0).unwrap(), 0);
    db.set_org_quota(
        org,
        &crate::db::OrgQuota {
            max_bytes: Some(16),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    db.reserve_direct_oci_source(&upload, input.now)
        .await
        .unwrap();
    db.reserve_direct_oci_source(&upload, input.now + 1)
        .await
        .unwrap();
    let usage = db
        .backend
        .query_opt(
            "SELECT used_bytes, object_count FROM org_usage WHERE org_id = ?1",
            &vals![org],
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(usage.get::<i64>(0).unwrap(), 16);
    assert_eq!(usage.get::<i64>(1).unwrap(), 1);
    let retained = db
        .oci_upload(&upload.id, &upload.writer_id, &upload.token_id, input.now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retained.uploaded_size, 0);
    assert_eq!(retained.sha256.total_bytes, 0);
    assert!(retained.authenticated_source_sha256.is_none());
}

#[tokio::test]
async fn cold_oci_read_refuses_invented_authenticated_source_without_final_receipt() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source-provenance.db");
    let (db, input) = fixture_with_database(Database::open(&path).await.unwrap()).await;
    let upload = db.begin_direct_oci_upload(&input).await.unwrap();
    db.backend.execute("UPDATE oci_upload_sessions SET authenticated_source_sha256 = ?2, authenticated_source_bytes = ?3 WHERE id = ?1",
        &vals![upload.id, input.expected_digest.encoded(), i64::try_from(input.expected_size).unwrap()]).await.unwrap();
    drop(db);

    let db = Database::open(&path).await.unwrap();
    assert!(db
        .oci_upload(&upload.id, &upload.writer_id, &upload.token_id, input.now)
        .await
        .is_err());
    assert!(db.begin_direct_oci_upload(&input).await.is_err());
}
