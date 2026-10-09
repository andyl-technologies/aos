//! Tenancy regression cases and contract checks.

use super::*;

#[tokio::test]
async fn planned_project_create_and_delete_emit_one_atomic_history_chain() {
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    let create_id = uuid::Uuid::new_v4().to_string();
    let project_id = db
        .create_project_from_plan(
            org,
            "infra",
            "Infrastructure",
            &create_id,
            "user",
            Some(7),
            "owner@acme.test",
        )
        .await
        .unwrap();
    let project = db.project_by_path(org, "infra").await.unwrap().unwrap();
    assert_eq!(project.id, project_id);
    assert_eq!(project.resource_version, 1);
    assert_eq!(db.list_revisions(&create_id).await.unwrap().len(), 1);

    let stale_delete = uuid::Uuid::new_v4().to_string();
    assert!(!db
        .delete_project_at_version(
            org,
            project_id,
            2,
            &stale_delete,
            "user",
            Some(7),
            "owner@acme.test",
        )
        .await
        .unwrap());
    assert!(db.changeset(&stale_delete).await.unwrap().is_none());

    let delete_id = uuid::Uuid::new_v4().to_string();
    assert!(db
        .delete_project_at_version(
            org,
            project_id,
            1,
            &delete_id,
            "user",
            Some(7),
            "owner@acme.test",
        )
        .await
        .unwrap());
    assert!(db.project_by_path(org, "infra").await.unwrap().is_none());
    assert_eq!(db.list_revisions(&delete_id).await.unwrap().len(), 1);
    assert_eq!(db.materialize_topology_events().await.unwrap(), 2);
    assert_eq!(db.materialize_topology_events().await.unwrap(), 0);
    let audit = db.list_audit(&project.scope_key).await.unwrap();
    assert_eq!(audit.len(), 2);
    assert!(audit.iter().any(|entry| entry.action == "project.created"));
    assert!(audit.iter().any(|entry| entry.action == "project.deleted"));
}

#[tokio::test]
async fn concurrent_owner_revokes_preserve_one_owner() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("hub.db");
    let setup = Database::open(&path).await.unwrap();
    let org_id = setup.create_org("parallel", "Parallel").await.unwrap();
    let scope = setup.org_by_id(org_id).await.unwrap().unwrap().stable_id;
    let alice = setup
        .create_user("alice@parallel.test", None)
        .await
        .unwrap();
    let bob = setup.create_user("bob@parallel.test", None).await.unwrap();
    setup
        .grant_membership("user", alice, &scope, "owner")
        .await
        .unwrap();
    setup
        .grant_membership("user", bob, &scope, "owner")
        .await
        .unwrap();
    drop(setup);

    let left = Database::open(&path).await.unwrap();
    let right = Database::open(&path).await.unwrap();
    let (left_result, right_result) = tokio::join!(
        left.revoke_membership_owner_safe("user", alice, &scope),
        right.revoke_membership_owner_safe("user", bob, &scope),
    );
    assert_ne!(
        (left_result.is_ok(), right_result.is_ok()),
        (true, true),
        "both concurrent owner revokes succeeded"
    );
    let check = Database::open(&path).await.unwrap();
    assert_eq!(owner_count(&check, &scope).await, 1);
}

#[tokio::test]
async fn deleted_co_owner_cannot_mask_the_last_live_human_owner() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("live-owner", "Live Owner").await.unwrap();
    let scope = db.org_by_id(org_id).await.unwrap().unwrap().stable_id;
    let deleted = db.create_user("deleted@owner.test", None).await.unwrap();
    let remaining = db.create_user("remaining@owner.test", None).await.unwrap();
    db.grant_membership("user", deleted, &scope, "owner")
        .await
        .unwrap();
    db.grant_membership("user", remaining, &scope, "owner")
        .await
        .unwrap();
    db.backend
        .execute(
            "UPDATE users SET deleted_at = ?2 WHERE id = ?1",
            &vals![deleted, unix_now()],
        )
        .await
        .unwrap();

    assert!(db.delete_user(remaining).await.is_err());
    assert!(db
        .revoke_membership("user", remaining, &scope)
        .await
        .is_err());
    assert_eq!(owner_count(&db, &scope).await, 1);
}

#[tokio::test]
async fn reserve_org_usage_is_atomic_and_charges_deltas() {
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    db.set_org_quota(
        org,
        &OrgQuota {
            max_bytes: Some(100),
            max_objects: Some(2),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // First reservation of 60 bytes / 1 object fits and is recorded.
    assert!(db.reserve_org_usage(org, 60, 1).await.unwrap());
    assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 60);
    assert_eq!(db.org_usage(org).await.unwrap().object_count, 1);

    // A second reservation that would push past the byte cap (60+50 > 100)
    // is rejected and leaves usage untouched — the check-and-reserve is one
    // step, so it cannot be raced through.
    assert!(!db.reserve_org_usage(org, 50, 1).await.unwrap());
    assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 60);
    assert_eq!(db.org_usage(org).await.unwrap().object_count, 1);

    // A reservation that fits the byte cap but exceeds the object cap is
    // rejected too (object_count 1 + 2 > 2).
    assert!(!db.reserve_org_usage(org, 10, 2).await.unwrap());
    assert_eq!(db.org_usage(org).await.unwrap().object_count, 1);

    // 40 more bytes lands exactly at the cap and a 2nd object.
    assert!(db.reserve_org_usage(org, 40, 1).await.unwrap());
    assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 100);
    assert_eq!(db.org_usage(org).await.unwrap().object_count, 2);

    // A shrinking overwrite charges a negative delta and frees room; usage
    // never goes below zero.
    assert!(db.reserve_org_usage(org, -30, 0).await.unwrap());
    assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 70);
    assert!(db.reserve_org_usage(org, -1_000, -10).await.unwrap());
    assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 0);
    assert_eq!(db.org_usage(org).await.unwrap().object_count, 0);
}

#[tokio::test]
async fn purge_is_no_op_for_org_restored_in_window() {
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    db.register_owned(org, "acme/cdn").await;
    // Soft-delete with a zero grace window so the org is purgeable now.
    db.soft_delete_org(org, 0).await.unwrap();
    let purgeable = db.list_purgeable_orgs(unix_now()).await.unwrap();
    assert_eq!(purgeable.len(), 1);

    // The admin restores it before the purge job reaches the delete.
    assert!(db.restore_org(org).await.unwrap());

    // The purge delete is now a no-op: it returns `Ok(false)` and the
    // org — and everything it owns — survives.
    assert!(!db.hard_purge_org(org, unix_now()).await.unwrap());
    assert!(db.org_by_slug("acme").await.unwrap().is_some());
    assert!(db.org_is_active(org).await.unwrap());
    assert_eq!(db.list_registries().await.unwrap().len(), 1);
}

#[tokio::test]
async fn sole_owner_delete_blocked_then_transfer_succeeds() {
    use aos_hub_model::domain::{Permission, Principal, Role};
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    let org_scope = db.org_by_id(org).await.unwrap().unwrap().stable_id;
    let alice = db.create_user("alice@acme.com", None).await.unwrap();
    let bob = db.create_user("bob@acme.com", None).await.unwrap();
    db.grant_membership("user", alice, &org_scope, "owner")
        .await
        .unwrap();
    // Alice has a token + a session, to confirm they deaden on deletion.
    let (token_id, secret) = db
        .create_token(
            Principal::user(alice),
            &org_scope,
            &[Permission::Read],
            None,
            None,
        )
        .await
        .unwrap();
    let session = db.create_session(alice, 3600, 1).await.unwrap();

    // Alice is the sole owner: deletion is blocked.
    assert_eq!(
        db.sole_owned_orgs(alice).await.unwrap(),
        vec!["acme".to_string()]
    );
    assert!(db.delete_user(alice).await.is_err());
    // The token and session are untouched by the failed delete.
    assert!(db.validate_token(&secret).await.unwrap().is_some());
    assert!(db.validate_session(&session).await.unwrap().is_some());

    assert!(db
        .transfer_org_ownership(org, alice, i64::MAX)
        .await
        .is_err());
    assert_eq!(db.sole_owned_orgs(alice).await.unwrap(), vec!["acme"]);

    // Transfer ownership to Bob, then Alice is deletable.
    db.transfer_org_ownership(org, alice, bob).await.unwrap();
    assert!(db.sole_owned_orgs(alice).await.unwrap().is_empty());
    assert!(db.delete_user(alice).await.unwrap());
    // Alice's credentials deaden immediately.
    assert!(db.validate_token(&secret).await.unwrap().is_none());
    assert!(db.validate_session(&session).await.unwrap().is_none());
    assert!(db.user_email(alice).await.unwrap().is_none());
    let _ = token_id;
    // Bob now owns acme.
    let grants = db.effective_scopes(Principal::user(bob)).await.unwrap();
    assert!(grants
        .iter()
        .any(|(s, r)| s.as_str() == org_scope && *r == Role::Owner));
}

#[tokio::test]
async fn create_org_backstop_rejects_non_segment_slugs() {
    // CR-2 persistence backstop: even if a caller bypasses the RPC/console
    // validator, the db refuses to write an org slug that is not a single
    // path segment, so it can never normalize into an ancestor scope.
    let db = Database::open_in_memory().await.unwrap();
    for bad in ["/", "/victimorg", "foo/bar", "foo ", "Acme", ""] {
        assert!(
            db.create_org(bad, "Name").await.is_err(),
            "create_org should reject slug {bad:?}"
        );
        assert!(db.org_by_slug(bad).await.unwrap().is_none());
    }
    // A normal single-segment slug still succeeds.
    assert!(db.create_org("acme", "Acme").await.is_ok());
    assert_eq!(db.org_by_slug("acme").await.unwrap().unwrap().slug, "acme");
}

#[tokio::test]
async fn create_org_initializes_quota_usage() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("usage", "Usage").await.unwrap();

    let usage = db.org_usage(org_id).await.unwrap();
    assert_eq!(usage.used_bytes, 0);
    assert_eq!(usage.object_count, 0);
    assert!(
        db.reserve_org_usage(org_id, 1, 1).await.unwrap(),
        "the initialized row accepts an atomic reservation"
    );
}
