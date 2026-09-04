//! SQLite coverage for tenant-bound OCI administration plans and cursors.

use super::*;
use crate::db::Database;

async fn create_repository(
    db: &Database,
    registry_id: i64,
    name: &str,
    idempotency: &str,
    now: i64,
) -> OciAdminRepositoryRecord {
    let plan = db
        .plan_oci_repository_mutation(&PlanOciRepositoryMutation {
            registry_id,
            repository: RepositoryName::parse(name).unwrap(),
            operation: OciRepositoryMutationOperation::Create,
            description: Some(format!("{name} description")),
            expected_resource_version: None,
            actor_id: "test:operator".to_string(),
            idempotency_key: idempotency.to_string(),
            now,
        })
        .await
        .unwrap();
    db.apply_oci_admin_mutation(&ApplyOciAdminMutation {
        mutation_id: plan.id,
        actor_id: "test:operator".to_string(),
        idempotency_key: format!("apply-{idempotency}"),
        confirmation_hash: plan.confirmation_hash,
        now: now + 1,
    })
    .await
    .unwrap()
    .repository
    .unwrap()
}

#[tokio::test]
async fn instance_registry_plan_lookup_apply_and_expiry_are_actor_bound() {
    let db = Database::open_in_memory().await.unwrap();
    let registry_id = db.register_registry("instance", &[], false).await.unwrap();
    let plan = db
        .plan_oci_repository_mutation(&PlanOciRepositoryMutation {
            registry_id,
            repository: RepositoryName::parse("base").unwrap(),
            operation: OciRepositoryMutationOperation::Create,
            description: Some("Base container".to_string()),
            expected_resource_version: None,
            actor_id: "test:instance-operator".to_string(),
            idempotency_key: "create-base".to_string(),
            now: 1_700_000_000,
        })
        .await
        .unwrap();
    assert_eq!(plan.expires_at, 1_700_000_900);
    assert!(db
        .oci_admin_mutation_for_actor(&plan.id, "test:other")
        .await
        .unwrap()
        .is_none());

    let applied = db
        .apply_oci_admin_mutation(&ApplyOciAdminMutation {
            mutation_id: plan.id.clone(),
            actor_id: "test:instance-operator".to_string(),
            idempotency_key: "apply-base".to_string(),
            confirmation_hash: plan.confirmation_hash,
            now: plan.expires_at,
        })
        .await
        .unwrap();
    assert_eq!(applied.repository.unwrap().name.as_str(), "base");
    assert_eq!(
        db.apply_oci_admin_mutation(&ApplyOciAdminMutation {
            mutation_id: plan.id,
            actor_id: "test:instance-operator".to_string(),
            idempotency_key: "apply-base".to_string(),
            confirmation_hash: plan.confirmation_hash,
            now: plan.expires_at + 100,
        })
        .await
        .unwrap()
        .mutation
        .state,
        "applied"
    );
    let current = db
        .oci_admin_repository(registry_id, &RepositoryName::parse("base").unwrap())
        .await
        .unwrap()
        .unwrap();
    let update = db
        .plan_oci_repository_mutation(&PlanOciRepositoryMutation {
            registry_id,
            repository: current.name.clone(),
            operation: OciRepositoryMutationOperation::Update,
            description: Some("Updated base container".to_string()),
            expected_resource_version: Some(current.resource_version),
            actor_id: "test:instance-operator".to_string(),
            idempotency_key: "update-base".to_string(),
            now: 1_700_001_000,
        })
        .await
        .unwrap();
    let updated = db
        .apply_oci_admin_mutation(&ApplyOciAdminMutation {
            mutation_id: update.id,
            actor_id: "test:instance-operator".to_string(),
            idempotency_key: "apply-update-base".to_string(),
            confirmation_hash: update.confirmation_hash,
            now: 1_700_001_001,
        })
        .await
        .unwrap()
        .repository
        .unwrap();
    assert_eq!(updated.description, "Updated base container");

    let delete = db
        .plan_oci_repository_mutation(&PlanOciRepositoryMutation {
            registry_id,
            repository: updated.name.clone(),
            operation: OciRepositoryMutationOperation::Delete,
            description: None,
            expected_resource_version: Some(updated.resource_version),
            actor_id: "test:instance-operator".to_string(),
            idempotency_key: "delete-base".to_string(),
            now: 1_700_002_000,
        })
        .await
        .unwrap();
    let deleted = db
        .apply_oci_admin_mutation(&ApplyOciAdminMutation {
            mutation_id: delete.id,
            actor_id: "test:instance-operator".to_string(),
            idempotency_key: "apply-delete-base".to_string(),
            confirmation_hash: delete.confirmation_hash,
            now: 1_700_002_001,
        })
        .await
        .unwrap()
        .deletion
        .unwrap();
    assert_eq!(deleted.repository.as_str(), "base");
    assert!(deleted.tag.is_none());

    assert!(db
        .oci_admin_retention_policy(registry_id)
        .await
        .unwrap()
        .is_none());
    let retention = db
        .plan_oci_retention_policy(&PlanOciRetentionPolicy {
            registry_id,
            untagged_grace_seconds: 86_400,
            deleted_tag_history_seconds: 2_592_000,
            recent_manual_tag_revisions: 12,
            retain_referrers: true,
            expected_resource_version: None,
            actor_id: "test:instance-operator".to_string(),
            idempotency_key: "retention".to_string(),
            now: 1_700_003_000,
        })
        .await
        .unwrap();
    let policy = db
        .apply_oci_admin_mutation(&ApplyOciAdminMutation {
            mutation_id: retention.id,
            actor_id: "test:instance-operator".to_string(),
            idempotency_key: "apply-retention".to_string(),
            confirmation_hash: retention.confirmation_hash,
            now: 1_700_003_001,
        })
        .await
        .unwrap()
        .retention_policy
        .unwrap();
    assert_eq!(policy.untagged_grace_seconds, 86_400);
    assert_eq!(policy.deleted_tag_history_seconds, 2_592_000);
    assert_eq!(policy.recent_manual_tag_revisions, 12);
    assert!(policy.retain_referrers);

    let expired = db
        .plan_oci_repository_mutation(&PlanOciRepositoryMutation {
            registry_id,
            repository: RepositoryName::parse("expired").unwrap(),
            operation: OciRepositoryMutationOperation::Create,
            description: Some(String::new()),
            expected_resource_version: None,
            actor_id: "test:instance-operator".to_string(),
            idempotency_key: "create-expired".to_string(),
            now: 1_800_000_000,
        })
        .await
        .unwrap();
    assert!(db
        .apply_oci_admin_mutation(&ApplyOciAdminMutation {
            mutation_id: expired.id,
            actor_id: "test:instance-operator".to_string(),
            idempotency_key: "apply-expired".to_string(),
            confirmation_hash: expired.confirmation_hash,
            now: expired.expires_at + 1,
        })
        .await
        .is_err());
}

#[tokio::test]
async fn repository_cursor_binds_filters_and_mutation_epoch() {
    let db = Database::open_in_memory().await.unwrap();
    let registry_id = db.register_registry("cursor", &[], false).await.unwrap();
    create_repository(&db, registry_id, "a", "create-a", 1_700_000_000).await;
    create_repository(&db, registry_id, "b", "create-b", 1_700_000_010).await;

    let filter = OciRepositoryListFilter::default();
    let first = db
        .list_oci_admin_repositories(registry_id, &filter, 1, None)
        .await
        .unwrap();
    let cursor = first.next_cursor.unwrap();
    assert!(db
        .list_oci_admin_repositories(
            registry_id,
            &OciRepositoryListFilter {
                repository_prefix: Some("a".to_string()),
                lifecycle_state: None,
            },
            1,
            Some(&cursor),
        )
        .await
        .is_err());

    create_repository(&db, registry_id, "c", "create-c", 1_700_000_020).await;
    assert!(db
        .list_oci_admin_repositories(registry_id, &filter, 1, Some(&cursor))
        .await
        .is_err());
}
