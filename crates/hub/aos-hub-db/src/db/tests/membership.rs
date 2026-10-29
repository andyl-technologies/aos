//! Reviewed service-account membership lifecycle regressions across SQL dialects.

use aos_hub_model::domain::Principal;

use super::Database;

async fn assert_reviewed_service_account_membership_lifecycle(db: &Database) {
    let org_id = db
        .create_org("reviewed-service-account", "Reviewed Service Account")
        .await
        .unwrap();
    let scope = db.org_by_id(org_id).await.unwrap().unwrap().stable_id;
    let actor_id = db
        .create_user("membership-owner@example.test", None)
        .await
        .unwrap();
    let account_id = db
        .create_service_account(org_id, "controller")
        .await
        .unwrap();
    let actor = Principal::user(actor_id);
    let target = Principal::service_account(account_id);
    db.grant_membership("user", actor_id, "instance", "owner")
        .await
        .unwrap();

    db.replace_membership_if_current(target, &scope, None, Some("owner"), actor)
        .await
        .unwrap();
    let granted = db
        .membership_snapshot("service_account", account_id, &scope)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(granted.role, "owner");
    assert!(granted.incarnation_id.is_some());

    db.replace_membership_if_current(target, &scope, Some(&granted), Some("admin"), actor)
        .await
        .unwrap();
    let updated = db
        .membership_snapshot("service_account", account_id, &scope)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.role, "admin");
    assert_eq!(updated.id, granted.id);
    assert_eq!(updated.incarnation_id, granted.incarnation_id);

    db.replace_membership_if_current(target, &scope, Some(&updated), None, actor)
        .await
        .unwrap();
    assert!(db
        .membership_snapshot("service_account", account_id, &scope)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn sqlite_reviewed_service_account_membership_lifecycle() {
    let db = Database::open_in_memory().await.unwrap();
    assert_reviewed_service_account_membership_lifecycle(&db).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn postgres_reviewed_service_account_membership_lifecycle() {
    let Ok(url) = std::env::var("AOS_HUB_MEMBERSHIP_TEST_PG_URL") else {
        eprintln!("live PostgreSQL reviewed service-account membership was not run");
        return;
    };
    let db = Database::connect(&url).await.unwrap();
    assert_reviewed_service_account_membership_lifecycle(&db).await;
}
