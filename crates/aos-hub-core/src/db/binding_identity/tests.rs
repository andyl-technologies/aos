//! SQL history recovery and permanent reservation regression cases.

use std::sync::Arc;

use serde_json::json;

use super::*;

async fn binding(db: &Database, stable_id: &str) -> super::super::BindingRecord {
    let org_id = db.create_org(stable_id, "Binding identity").await.unwrap();
    let org = db.org_by_id(org_id).await.unwrap().unwrap();
    let id = db
        .create_topology_binding(
            Some(org_id),
            stable_id,
            &org.stable_id,
            "Binding identity",
            "s3",
            None,
            Some("identity-bucket"),
            Some("identity-prefix"),
            Some("https"),
            Some("dns"),
            Some(b"s3.example.test"),
            Some(443),
            Some("fixture-region"),
            Some("private"),
        )
        .await
        .unwrap();
    db.binding(id).await.unwrap().unwrap()
}

fn original(binding: &super::super::BindingRecord, reservation_id: Option<&str>) -> String {
    let mut document = json!({"stable_id":binding.stable_id, "owner_scope_key":binding.owner_scope_key,
        "org_id":binding.org_id, "binding_db_id":binding.id,
        "baseline_resource_version":binding.resource_version});
    if let Some(reservation_id) = reservation_id {
        document["reservation_id"] = json!(reservation_id);
    }
    serde_json::to_string(&document).unwrap()
}

async fn history(
    db: &Database,
    binding: &super::super::BindingRecord,
    original: &str,
    claimed: bool,
    positive: bool,
) {
    db.backend
        .execute(
            "INSERT INTO topology_plans
        (plan_id, plan_kind, actor_kind, actor_label, scope, input_versions_json,
         effects_json, warnings_json, created_at, expires_at, applied_at, confirmation_hash,
         apply_idempotency_key, apply_result_json)
        VALUES (?1, 'delete_binding', 'system', 'history-fixture', ?2, ?3,
                '[]', '[]', 1, 100, ?4, ?7, ?5, ?6)",
            &vals![
                uuid::Uuid::new_v4().to_string(),
                &binding.owner_scope_key,
                original,
                positive.then_some(2i64),
                claimed.then_some("original-delete-key"),
                positive.then_some("{\"deleted\":true}"),
                hex::encode(Sha256::digest(original.as_bytes()))
            ],
        )
        .await
        .unwrap();
}

async fn cases(db: Arc<Database>) {
    for positive in [false, true] {
        let stable_id = uuid::Uuid::new_v4().simple().to_string();
        let binding = binding(&db, &stable_id).await;
        let original = original(&binding, None);
        history(&db, &binding, &original, true, positive).await;
        assert!(db.validate_binding_identity_reservations().await.is_err());
        assert!(db.backfill_binding_identity_reservations().await.is_err());
        assert!(db.backfill_binding_identity_reservations().await.is_err());
        let retained: String = db
            .backend
            .query_opt(
                "SELECT input_versions_json FROM topology_plans WHERE scope = ?1",
                &vals![&binding.owner_scope_key],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(retained, original);
        db.delete_topology_binding(binding.id, binding.resource_version)
            .await
            .unwrap();
        db.backfill_binding_identity_reservations().await.unwrap();
        db.validate_binding_identity_reservations().await.unwrap();
    }

    let stable_id = uuid::Uuid::new_v4().simple().to_string();
    let live = binding(&db, &stable_id).await;
    let reservation = db
        .binding_identity_reservation(&stable_id)
        .await
        .unwrap()
        .unwrap();
    let original = original(&live, Some(&reservation.reservation_id));
    history(&db, &live, &original, true, false).await;
    db.backfill_binding_identity_reservations().await.unwrap();
    db.validate_binding_identity_reservations().await.unwrap();
    assert_eq!(
        db.binding_identity_reservation(&stable_id).await.unwrap(),
        Some(reservation.clone())
    );
    db.delete_topology_binding_checked(&live, &reservation.reservation_id, live.resource_version)
        .await
        .unwrap();
    assert_eq!(
        db.binding_identity_reservation(&stable_id).await.unwrap(),
        Some(reservation)
    );
    let org = db.org_by_id(live.org_id.unwrap()).await.unwrap().unwrap();
    assert!(db
        .create_topology_binding(
            live.org_id,
            &stable_id,
            &org.stable_id,
            "Binding identity",
            "s3",
            None,
            Some("identity-bucket"),
            Some("identity-prefix"),
            Some("https"),
            Some("dns"),
            Some(b"s3.example.test"),
            Some(443),
            Some("fixture-region"),
            Some("private")
        )
        .await
        .is_err());
    assert!(db.binding_by_stable_id(&stable_id).await.unwrap().is_none());
}

#[tokio::test]
async fn sqlite_binding_identity_claimed_history_and_retirement() {
    cases(Arc::new(Database::open_in_memory().await.unwrap())).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn postgres_binding_identity_claimed_history_and_retirement() {
    let Ok(url) = std::env::var("AOS_HUB_TEST_PG_URL") else {
        eprintln!("live PostgreSQL binding identity history was not run");
        return;
    };
    cases(Arc::new(Database::connect(&url).await.unwrap())).await;
}

#[test]
fn bounded_snapshot_history_rejects_ambiguous_and_malformed_originals() {
    let reservation = BindingIdentityReservation {
        stable_id: "binding-identity".into(),
        reservation_id: uuid::Uuid::new_v4().to_string(),
        reserved_at: 1,
    };
    let input = json!({"stable_id":reservation.stable_id,"owner_scope_key":"instance",
        "org_id":null,"binding_db_id":1,"baseline_resource_version":1});
    let original = serde_json::to_string(&input).unwrap();
    assert!(validate_binding_identity_snapshot_history(
        &original,
        None,
        Some("claimed"),
        None,
        Some(&reservation)
    )
    .is_err());
    assert!(validate_binding_identity_snapshot_history(
        &original,
        Some(2),
        Some("claimed"),
        Some("{\"deleted\":true}"),
        Some(&reservation)
    )
    .is_err());
    let mut captured = input.clone();
    captured["reservation_id"] = json!(reservation.reservation_id);
    let captured = serde_json::to_string(&captured).unwrap();
    validate_binding_identity_snapshot_history(
        &captured,
        None,
        Some("claimed"),
        None,
        Some(&reservation),
    )
    .unwrap();
    let mut unknown = input;
    unknown["unknown"] = json!(true);
    assert!(decode_binding_delete_history(
        &serde_json::to_string(&unknown).unwrap(),
        None,
        None,
        None
    )
    .is_err());
    assert!(decode_binding_delete_history(&" ".repeat(4097), None, None, None).is_err());
}

#[tokio::test]
async fn sqlite_binding_identity_history_checks_the_second_page_and_original_hash() {
    let db = Database::open_in_memory().await.unwrap();
    for _ in 0..130 {
        let stable_id = uuid::Uuid::new_v4().simple().to_string();
        let binding = binding(&db, &stable_id).await;
        let original = original(&binding, None);
        history(&db, &binding, &original, false, false).await;
        db.delete_topology_binding(binding.id, binding.resource_version)
            .await
            .unwrap();
    }
    db.backfill_binding_identity_reservations().await.unwrap();
    let last = db
        .backend
        .query_opt(
            "SELECT plan_id, input_versions_json FROM topology_plans
         WHERE plan_kind = 'delete_binding' ORDER BY plan_id DESC LIMIT 1",
            &[],
        )
        .await
        .unwrap()
        .unwrap();
    let plan_id: String = last.get(0).unwrap();
    let original: String = last.get(1).unwrap();
    db.backend
        .execute(
            "UPDATE topology_plans SET confirmation_hash = 'changed' WHERE plan_id = ?1",
            &vals![&plan_id],
        )
        .await
        .unwrap();
    assert!(db.backfill_binding_identity_reservations().await.is_err());
    assert!(db.validate_binding_identity_reservations().await.is_err());
    db.backend
        .execute(
            "UPDATE topology_plans SET confirmation_hash = ?2 WHERE plan_id = ?1",
            &vals![&plan_id, hex::encode(Sha256::digest(original.as_bytes()))],
        )
        .await
        .unwrap();
    db.backfill_binding_identity_reservations().await.unwrap();
    let count: i64 = db
        .backend
        .query_opt("SELECT COUNT(*) FROM binding_identity_reservations", &[])
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(count, 130);
}

#[tokio::test]
async fn sqlite_cold_restart_preserves_claimed_lifetime_and_missing_identity_refuses_readonly() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("binding.sqlite");
    let db = Database::open(&path).await.unwrap();
    let live = binding(&db, "cold-binding").await;
    let reservation = db
        .binding_identity_reservation(&live.stable_id)
        .await
        .unwrap()
        .unwrap();
    let original = original(&live, Some(&reservation.reservation_id));
    history(&db, &live, &original, true, false).await;
    drop(db);

    let db = Database::open(&path).await.unwrap();
    db.validate_binding_identity_reservations().await.unwrap();
    assert_eq!(
        db.binding_identity_reservation(&live.stable_id)
            .await
            .unwrap(),
        Some(reservation.clone())
    );
    assert!(db
        .delete_topology_binding_checked(&live, &reservation.reservation_id, live.resource_version)
        .await
        .unwrap());
    drop(db);

    let db = Database::open(&path).await.unwrap();
    assert!(db
        .binding_by_stable_id(&live.stable_id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        db.binding_identity_reservation(&live.stable_id)
            .await
            .unwrap(),
        Some(reservation)
    );
    let new = binding(&db, "missing-identity").await;
    db.backend
        .execute(
            "DELETE FROM binding_identity_reservations WHERE stable_id = ?1",
            &vals![&new.stable_id],
        )
        .await
        .unwrap();
    assert!(db.validate_binding_identity_reservations().await.is_err());
    assert!(db
        .binding_identity_reservation(&new.stable_id)
        .await
        .unwrap()
        .is_none());
}
