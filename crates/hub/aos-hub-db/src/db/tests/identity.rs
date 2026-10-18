//! Identity regression cases and contract checks.

use super::*;

#[tokio::test]
async fn orgs_projects_and_principals_roundtrip() {
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme, Inc.").await.unwrap();
    assert_eq!(db.org_by_slug("acme").await.unwrap().unwrap().id, org);
    assert!(db.org_by_slug("nope").await.unwrap().is_none());

    db.create_project(org, "", "Root").await.unwrap();
    db.create_project(org, "infra", "Infra").await.unwrap();
    db.create_project(org, "infra/prod", "Prod").await.unwrap();
    let projects = db.list_projects(org).await.unwrap();
    assert_eq!(projects.len(), 3);
    assert_eq!(projects[0].path, "");
    assert_eq!(projects[1].path, "infra");
    assert_eq!(projects[2].path, "infra/prod");

    let user = db.create_user("dev@acme.com", Some("Dev")).await.unwrap();
    assert_eq!(db.user_by_email("dev@acme.com").await.unwrap(), Some(user));
    assert!(db.user_by_email("ghost@acme.com").await.unwrap().is_none());

    let sa = db.create_service_account(org, "ci").await.unwrap();
    assert!(sa > 0);
}

#[tokio::test]
async fn memberships_grant_revoke_and_list() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("acme", "Acme").await.unwrap();
    let org = db.org_by_id(org_id).await.unwrap().unwrap();
    db.create_project(org_id, "infra", "Infra").await.unwrap();
    let project = db
        .list_projects(org_id)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let user = db.create_user("dev@acme.com", None).await.unwrap();
    db.grant_membership("user", user, &org.stable_id, "admin")
        .await
        .unwrap();
    db.grant_membership("user", user, &project.scope_key, "maintainer")
        .await
        .unwrap();
    // Re-granting overwrites the role at the same scope.
    db.grant_membership("user", user, &org.stable_id, "owner")
        .await
        .unwrap();

    let grants = db.list_memberships_for("user", user).await.unwrap();
    assert_eq!(
        grants,
        vec![
            (org.stable_id.clone(), "owner".to_string()),
            (project.scope_key.clone(), "maintainer".to_string()),
        ]
    );

    // effective_scopes parses into domain types.
    let scopes = db
        .effective_scopes(aos_hub_model::domain::Principal::user(user))
        .await
        .unwrap();
    assert_eq!(scopes.len(), 2);
    let project_context = db
        .authorization_context(&project.scope_key)
        .await
        .unwrap()
        .unwrap();
    assert!(aos_hub_model::domain::iam::allow(
        &scopes,
        aos_hub_model::domain::Permission::IamAdmin,
        &project_context,
    ));

    // list_members_of_scope returns exact-scope grants only (the
    // org grant, not the inherited project one).
    let members = db.list_members_of_scope(&org.stable_id).await.unwrap();
    assert_eq!(
        members,
        vec![("user".to_string(), user, "owner".to_string())]
    );

    let successor = db
        .find_or_create_user("successor@example.com")
        .await
        .unwrap();
    db.grant_membership("user", successor, &org.stable_id, "owner")
        .await
        .unwrap();
    db.revoke_membership("user", user, &org.stable_id)
        .await
        .unwrap();
    let grants = db.list_memberships_for("user", user).await.unwrap();
    assert_eq!(grants, vec![(project.scope_key, "maintainer".to_string())]);
}

#[tokio::test]
async fn invitations_create_accept_and_expire() {
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    let org_scope = db.org_by_id(org).await.unwrap().unwrap().stable_id;
    db.create_project(org, "infra", "Infra").await.unwrap();
    let project_scope = db.list_projects(org).await.unwrap()[0].scope_key.clone();
    let far_future = unix_now() + 86_400;

    db.create_invitation(
        org,
        "new@acme.com",
        &project_scope,
        "developer",
        "hash-a",
        far_future,
    )
    .await
    .unwrap();
    assert!(db.has_pending_invitation("new@acme.com").await.unwrap());
    assert!(db
        .create_invitation(
            org,
            "new@acme.com",
            &project_scope,
            "viewer",
            "hash-duplicate",
            far_future,
        )
        .await
        .is_err());
    let invitee = db.create_user("new@acme.com", None).await.unwrap();
    let accepted = db
        .accept_invitation("hash-a", org, invitee, "new@acme.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.email, "new@acme.com");
    assert_eq!(accepted.scope, project_scope);
    assert_eq!(accepted.role, "developer");
    assert_eq!(
        db.list_memberships_for("user", invitee).await.unwrap(),
        vec![(project_scope.clone(), "developer".to_string())]
    );
    assert!(!db.has_pending_invitation("new@acme.com").await.unwrap());
    // A second accept of the same hash is rejected (already accepted).
    assert!(db
        .accept_invitation("hash-a", org, invitee, "new@acme.com")
        .await
        .unwrap()
        .is_none());
    assert!(!db.has_pending_invitation("late@acme.com").await.unwrap());

    let cancelled_id = db
        .create_invitation(
            org,
            "cancelled@acme.com",
            &org_scope,
            "viewer",
            "hash-cancelled",
            far_future,
        )
        .await
        .unwrap();
    let created_at = db
        .invitation_record(org, cancelled_id)
        .await
        .unwrap()
        .unwrap()
        .created_at;
    assert!(db
        .cancel_invitation(cancelled_id, created_at)
        .await
        .unwrap());
    assert!(!db
        .has_pending_invitation("cancelled@acme.com")
        .await
        .unwrap());
    db.create_invitation(
        org,
        "cancelled@acme.com",
        &org_scope,
        "viewer",
        "hash-reinvited",
        far_future,
    )
    .await
    .unwrap();
    // Unknown hash is rejected.
    assert!(db
        .accept_invitation("hash-missing", org, invitee, "new@acme.com")
        .await
        .unwrap()
        .is_none());

    // An already-expired invitation cannot be accepted.
    let past = unix_now() - 10;
    let expired_id = db
        .create_invitation(org, "late@acme.com", &org_scope, "viewer", "hash-b", past)
        .await
        .unwrap();
    db.backend
        .execute(
            "UPDATE invitations SET secret_enc = 'sealed-expired' WHERE id = ?1",
            &vals![expired_id],
        )
        .await
        .unwrap();
    db.prune_expired_invitation_secrets(unix_now(), 100)
        .await
        .unwrap();
    let expired_secret: Option<String> = db
        .backend
        .query_opt(
            "SELECT secret_enc FROM invitations WHERE id = ?1",
            &vals![expired_id],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert!(expired_secret.is_none());
    assert!(db
        .backend
        .query_opt(
            "SELECT invitation_id FROM live_invitations WHERE invitation_id = ?1",
            &vals![expired_id],
        )
        .await
        .unwrap()
        .is_none());
    let late = db.create_user("late@acme.com", None).await.unwrap();
    assert!(db
        .accept_invitation("hash-b", org, late, "late@acme.com")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn tokens_create_validate_revoke_and_list() {
    use aos_hub_model::domain::{Permission, Principal};
    let db = Database::open_in_memory().await.unwrap();
    let owner_id = db
        .create_user("token-owner@example.test", None)
        .await
        .unwrap();
    db.grant_membership("user", owner_id, "instance", "owner")
        .await
        .unwrap();
    let owner = Principal::user(owner_id);
    let (id, secret) = db
        .create_token(
            owner,
            "instance",
            &[Permission::Read, Permission::Publish],
            Some("ci"),
            None,
        )
        .await
        .unwrap();
    assert!(secret.starts_with("aos_"));

    let auth = db.validate_token(&secret).await.unwrap().unwrap();
    assert_eq!(auth.token_id, id);
    assert_eq!(auth.owner, owner);
    assert_eq!(auth.scope.as_str(), "instance");
    assert_eq!(
        auth.permissions,
        vec![Permission::Read, Permission::Publish]
    );

    // last_used_at is bumped on validation.
    let used: Option<i64> = db
        .backend
        .query_opt("SELECT last_used_at FROM tokens WHERE id = ?1", &vals![id])
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert!(used.is_some());

    let list = db.list_tokens_for(owner).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].0, id);

    db.revoke_token(&id).await.unwrap();
    // Revoked-now is still inside grace, but a revoked token in the far
    // past would be invalid; here we just confirm the revoke ran.
    assert!(db.list_tokens_for(owner).await.unwrap().is_empty());

    // Unknown secret is rejected.
    assert!(db.validate_token("aos_deadbeef").await.unwrap().is_none());
}

#[tokio::test]
async fn tokens_expired_is_rejected() {
    use aos_hub_model::domain::{Permission, Principal};
    let db = Database::open_in_memory().await.unwrap();
    let owner_id = db.create_user("expired@example.test", None).await.unwrap();
    db.grant_membership("user", owner_id, "instance", "owner")
        .await
        .unwrap();
    let past = unix_now() - 10;
    let (_, secret) = db
        .create_token(
            Principal::user(owner_id),
            "instance",
            &[Permission::Read],
            None,
            Some(past),
        )
        .await
        .unwrap();
    assert!(db.validate_token(&secret).await.unwrap().is_none());
}

#[tokio::test]
async fn tokens_rotation_honors_grace_window() {
    use aos_hub_model::domain::{Permission, Principal};
    let db = Database::open_in_memory().await.unwrap();
    let owner_id = db.create_user("rotate@example.test", None).await.unwrap();
    db.grant_membership("user", owner_id, "instance", "owner")
        .await
        .unwrap();
    let owner = Principal::user(owner_id);
    let (old_id, old_secret) = db
        .create_token(owner, "instance", &[Permission::Read], Some("c"), None)
        .await
        .unwrap();

    let (new_id, new_secret) = db.rotate_token(&old_id).await.unwrap().unwrap();
    assert_ne!(old_id, new_id);
    assert_ne!(old_secret, new_secret);

    // New token validates and carries the same scope/perms.
    let new_auth = db.validate_token(&new_secret).await.unwrap().unwrap();
    assert_eq!(new_auth.scope.as_str(), "instance");
    assert_eq!(new_auth.permissions, vec![Permission::Read]);

    // The OLD secret still validates — it was rotated now, but within
    // the grace window.
    assert!(db.validate_token(&old_secret).await.unwrap().is_some());

    // Force the old token's rotated_at to be older than the grace
    // window: now it is invalid.
    db.backend
        .execute(
            "UPDATE tokens SET rotated_at = ?2 WHERE id = ?1",
            &vals![old_id, unix_now() - ROTATION_GRACE_SECS - 1],
        )
        .await
        .unwrap();
    assert!(db.validate_token(&old_secret).await.unwrap().is_none());

    // An already-rotated token cannot mint another replacement.
    assert!(db.rotate_token(&old_id).await.is_err());
}

#[tokio::test]
async fn revoked_token_is_denied_immediately_without_grace() {
    use aos_hub_model::domain::{Permission, Principal};
    let db = Database::open_in_memory().await.unwrap();
    let owner_id = db.create_user("revoked@example.test", None).await.unwrap();
    db.grant_membership("user", owner_id, "instance", "owner")
        .await
        .unwrap();
    let (id, secret) = db
        .create_token(
            Principal::user(owner_id),
            "instance",
            &[Permission::Read],
            None,
            None,
        )
        .await
        .unwrap();
    assert!(db.validate_token(&secret).await.unwrap().is_some());
    db.revoke_token(&id).await.unwrap();
    // A hard revocation cuts off at once — no rotation grace.
    assert!(db.validate_token(&secret).await.unwrap().is_none());
}

#[tokio::test]
async fn sessions_create_validate_expire_and_revoke() {
    let db = Database::open_in_memory().await.unwrap();
    let user = db.create_user("dev@acme.com", None).await.unwrap();
    let secret = db.create_session(user, 3600, 0).await.unwrap();
    let session = db.validate_session(&secret).await.unwrap().unwrap();
    assert_eq!(session.user_id, user);
    assert_eq!(session.auth_level, 0);

    // Elevate sets sudo.
    db.elevate_session(&secret).await.unwrap();
    assert_eq!(
        db.validate_session(&secret)
            .await
            .unwrap()
            .unwrap()
            .auth_level,
        1
    );

    // Revoke one session.
    db.revoke_session(&secret).await.unwrap();
    assert!(db.validate_session(&secret).await.unwrap().is_none());

    // An expired session is rejected.
    let expired = db.create_session(user, -10, 0).await.unwrap();
    assert!(db.validate_session(&expired).await.unwrap().is_none());

    // revoke_all clears everything.
    let s1 = db.create_session(user, 3600, 0).await.unwrap();
    let s2 = db.create_session(user, 3600, 0).await.unwrap();
    db.revoke_all_user_sessions(user).await.unwrap();
    assert!(db.validate_session(&s1).await.unwrap().is_none());
    assert!(db.validate_session(&s2).await.unwrap().is_none());
}

#[tokio::test]
async fn repeated_session_validation_preserves_liveness_without_identical_writes() {
    let db = Database::open_in_memory().await.unwrap();
    let user = db
        .create_user("session-reader@acme.com", None)
        .await
        .unwrap();
    let secret = db.create_session(user, 3600, 0).await.unwrap();
    let now = unix_now() + 1;

    assert!(db
        .validate_session_at(&secret, now)
        .await
        .unwrap()
        .is_some());
    let changes_before: i64 = db
        .backend
        .query_opt("SELECT total_changes()", &[])
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();

    for _ in 0..100 {
        assert!(db
            .validate_session_at(&secret, now)
            .await
            .unwrap()
            .is_some());
    }
    let changes_after: i64 = db
        .backend
        .query_opt("SELECT total_changes()", &[])
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(changes_after, changes_before);

    assert!(db
        .validate_session_at(&secret, now + 1)
        .await
        .unwrap()
        .is_some());
    let advanced: i64 = db
        .backend
        .query_opt(
            "SELECT last_seen_at FROM sessions WHERE id_hash = ?1",
            &vals![aos_hub_model::auth::token::sha256_hex(&secret)],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(advanced, now + 1);

    db.revoke_session(&secret).await.unwrap();
    assert!(db
        .validate_session_at(&secret, now + 1)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn session_idle_and_absolute_timeouts_enforced() {
    use aos_hub_model::auth::session::{ABSOLUTE_LIFETIME_SECS, IDLE_TIMEOUT_SECS};
    let db = Database::open_in_memory().await.unwrap();
    let user = db.create_user("dev@acme.com", None).await.unwrap();
    let now = unix_now();

    // A fresh session validates.
    let secret = db
        .create_session(user, ABSOLUTE_LIFETIME_SECS, 1)
        .await
        .unwrap();
    assert!(db.validate_session(&secret).await.unwrap().is_some());
    let hash = aos_hub_model::auth::token::sha256_hex(&secret);

    // Backdate last_seen_at past the idle timeout: the session is rejected
    // (and the dead row is deleted).
    db.backend
        .execute(
            "UPDATE sessions SET last_seen_at = ?2 WHERE id_hash = ?1",
            &vals![hash, now - IDLE_TIMEOUT_SECS - 1],
        )
        .await
        .unwrap();
    assert!(
        db.validate_session(&secret).await.unwrap().is_none(),
        "idle out"
    );

    // A fresh session whose created_at is older than the absolute cap is
    // rejected even though it was just "seen".
    let secret2 = db
        .create_session(user, ABSOLUTE_LIFETIME_SECS, 1)
        .await
        .unwrap();
    let hash2 = aos_hub_model::auth::token::sha256_hex(&secret2);
    db.backend
        .execute(
            "UPDATE sessions SET created_at = ?2, last_seen_at = ?3 WHERE id_hash = ?1",
            &vals![hash2, now - ABSOLUTE_LIFETIME_SECS - 1, now],
        )
        .await
        .unwrap();
    assert!(
        db.validate_session(&secret2).await.unwrap().is_none(),
        "absolute cap"
    );

    // Activity slides the idle window: a session seen just under the idle
    // limit validates, and validation bumps last_seen_at to now.
    let secret3 = db
        .create_session(user, ABSOLUTE_LIFETIME_SECS, 1)
        .await
        .unwrap();
    let hash3 = aos_hub_model::auth::token::sha256_hex(&secret3);
    db.backend
        .execute(
            "UPDATE sessions SET last_seen_at = ?2 WHERE id_hash = ?1",
            &vals![hash3, now - IDLE_TIMEOUT_SECS + 60],
        )
        .await
        .unwrap();
    assert!(db.validate_session(&secret3).await.unwrap().is_some());
    let seen: i64 = db
        .backend
        .query_opt(
            "SELECT last_seen_at FROM sessions WHERE id_hash = ?1",
            &vals![hash3],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert!(seen >= now, "last_seen_at slid forward to now");
}

#[tokio::test]
async fn session_is_sudo_window() {
    use aos_hub_model::auth::session::SUDO_WINDOW_SECS;
    let db = Database::open_in_memory().await.unwrap();
    let user = db.create_user("dev@acme.com", None).await.unwrap();

    // A fresh auth_level=1 session is sudo.
    let secret = db.create_session(user, 3600, 1).await.unwrap();
    let session = db.validate_session(&secret).await.unwrap().unwrap();
    let now = unix_now();
    assert!(session.is_sudo(now));
    // Past the window it is no longer sudo.
    assert!(!session.is_sudo(now + SUDO_WINDOW_SECS + 1));

    // An auth_level=0 session is never sudo.
    let weak = db.create_session(user, 3600, 0).await.unwrap();
    let weak = db.validate_session(&weak).await.unwrap().unwrap();
    assert!(!weak.is_sudo(now));
}

#[tokio::test]
async fn approve_device_is_idempotent_one_token_per_approval() {
    use aos_hub_model::domain::{Permission, Principal, Role, Scope};
    let db = Database::open_in_memory().await.unwrap();
    let approver = db.create_user("admin@acme.com", None).await.unwrap();
    let principal = Principal::user(approver);
    let grants = vec![(Scope::root(), Role::Owner)];
    db.grant_membership("user", approver, "instance", "owner")
        .await
        .unwrap();
    let (device_code, user_code, _) = db
        .start_device_authorization("instance", &[Permission::Read])
        .await
        .unwrap();

    // First approval mints exactly one token.
    assert!(db
        .approve_device(&user_code, principal, &grants)
        .await
        .unwrap());
    assert_eq!(db.list_tokens_for(principal).await.unwrap().len(), 1);
    let DevicePollResult::Approved(first_grant) = db.poll_device(&device_code).await.unwrap()
    else {
        panic!("expected Approved after first approval");
    };

    // A second approval of the same user_code is refused and mints nothing.
    assert!(!db
        .approve_device(&user_code, principal, &grants)
        .await
        .unwrap());
    assert_eq!(
        db.list_tokens_for(principal).await.unwrap().len(),
        1,
        "no second token minted on re-approval"
    );
    assert!(!first_grant.refresh_token.is_empty());
    assert!(matches!(
        db.poll_device(&device_code).await.unwrap(),
        DevicePollResult::Expired
    ));
}

#[tokio::test]
async fn revoke_membership_owner_safe_keeps_one_owner() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("acme", "Acme").await.unwrap();
    let scope = db.org_by_id(org_id).await.unwrap().unwrap().stable_id;
    let alice = db.create_user("alice@acme.com", None).await.unwrap();
    let bob = db.create_user("bob@acme.com", None).await.unwrap();
    db.grant_membership("user", alice, &scope, "owner")
        .await
        .unwrap();
    db.grant_membership("user", bob, &scope, "owner")
        .await
        .unwrap();

    // Removing one of two owners succeeds.
    db.revoke_membership_owner_safe("user", bob, &scope)
        .await
        .unwrap();
    assert_eq!(owner_count(&db, &scope).await, 1);

    // Removing the now-sole owner is refused with a LastOwnerError and the
    // grant survives.
    let err = db
        .revoke_membership_owner_safe("user", alice, &scope)
        .await
        .unwrap_err();
    assert!(is_last_owner_error(&err), "got: {err:#}");
    assert_eq!(
        owner_count(&db, &scope).await,
        1,
        "the last owner is preserved"
    );
}

#[tokio::test]
async fn set_membership_role_owner_safe_blocks_last_owner_demotion() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("acme", "Acme").await.unwrap();
    let scope = db.org_by_id(org_id).await.unwrap().unwrap().stable_id;
    let alice = db.create_user("alice@acme.com", None).await.unwrap();
    let bob = db.create_user("bob@acme.com", None).await.unwrap();
    db.grant_membership("user", alice, &scope, "owner")
        .await
        .unwrap();
    db.grant_membership("user", bob, &scope, "owner")
        .await
        .unwrap();

    // Demoting one of two owners to admin succeeds.
    db.set_membership_role_owner_safe("user", bob, &scope, "admin")
        .await
        .unwrap();
    assert_eq!(owner_count(&db, &scope).await, 1);

    // Demoting the last owner is rejected; the org keeps an owner.
    let err = db
        .set_membership_role_owner_safe("user", alice, &scope, "admin")
        .await
        .unwrap_err();
    assert!(is_last_owner_error(&err), "got: {err:#}");
    assert_eq!(
        owner_count(&db, &scope).await,
        1,
        "the last owner is preserved"
    );
}

#[tokio::test]
async fn delete_user_re_checks_sole_ownership_in_tx() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("acme", "Acme").await.unwrap();
    let scope = db.org_by_id(org_id).await.unwrap().unwrap().stable_id;
    let alice = db.create_user("alice@acme.com", None).await.unwrap();
    db.grant_membership("user", alice, &scope, "owner")
        .await
        .unwrap();

    // Sole owner: deletion is blocked.
    assert!(db.delete_user(alice).await.is_err());
    assert!(db.user_by_email("alice@acme.com").await.unwrap().is_some());

    // With a co-owner, deletion proceeds and atomically revokes Alice's
    // memberships and credentials; Bob remains the live human owner.
    let bob = db.create_user("bob@acme.com", None).await.unwrap();
    db.grant_membership("user", bob, &scope, "owner")
        .await
        .unwrap();
    assert!(db.delete_user(alice).await.unwrap());
    assert!(
        db.list_members_of_scope(&scope)
            .await
            .unwrap()
            .iter()
            .any(|(k, id, r)| k == "user" && *id == bob && r == "owner"),
        "bob remains the org owner"
    );
}

#[tokio::test]
async fn deleted_principal_deadens_unrevoked_credentials_and_grants() {
    use aos_hub_model::domain::{Permission, Principal};
    let db = Database::open_in_memory().await.unwrap();
    let user = db
        .create_user("deleted-token@example.test", None)
        .await
        .unwrap();
    db.grant_membership("user", user, "instance", "owner")
        .await
        .unwrap();
    let (_, token) = db
        .create_token(
            Principal::user(user),
            "instance",
            &[Permission::Read],
            None,
            None,
        )
        .await
        .unwrap();
    let session = db.create_session(user, 3600, 0).await.unwrap();
    db.backend
        .execute(
            "UPDATE users SET deleted_at = ?2 WHERE id = ?1",
            &vals![user, unix_now()],
        )
        .await
        .unwrap();

    assert!(db.validate_token(&token).await.unwrap().is_none());
    assert!(db.validate_session(&session).await.unwrap().is_none());
    assert!(db
        .effective_scopes(Principal::user(user))
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn magic_links_single_use_and_expiry() {
    let db = Database::open_in_memory().await.unwrap();
    let secret = db.create_magic_link("user@acme.com").await.unwrap();
    assert_eq!(
        db.consume_magic_link(&secret).await.unwrap().as_deref(),
        Some("user@acme.com")
    );
    // Second consume fails (already consumed).
    assert!(db.consume_magic_link(&secret).await.unwrap().is_none());
    // Unknown secret fails.
    assert!(db.consume_magic_link("nope").await.unwrap().is_none());

    // An expired link cannot be consumed.
    let expired = db.create_magic_link("late@acme.com").await.unwrap();
    db.backend
        .execute(
            "UPDATE magic_links SET expires_at = ?1 WHERE email = 'late@acme.com'",
            &vals![unix_now() - 1],
        )
        .await
        .unwrap();
    assert!(db.consume_magic_link(&expired).await.unwrap().is_none());
}

#[tokio::test]
async fn take_webauthn_challenge_is_scoped_by_kind() {
    let db = Database::open_in_memory().await.unwrap();
    // A registration challenge is in flight for a victim.
    db.create_webauthn_challenge("chal-abc", Some(1), "registration", 300)
        .await
        .unwrap();

    // Submitting that known challenge value through the *assertion* endpoint
    // (wrong kind) consumes nothing and leaves the row intact.
    assert!(db
        .take_webauthn_challenge("chal-abc", "assertion")
        .await
        .unwrap()
        .is_none());

    // The registration challenge is still consumable via its own kind.
    let taken = db
        .take_webauthn_challenge("chal-abc", "registration")
        .await
        .unwrap()
        .expect("registration challenge survived the cross-kind attempt");
    assert_eq!(taken.kind, "registration");

    // And it is single-use: a second take finds nothing.
    assert!(db
        .take_webauthn_challenge("chal-abc", "registration")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn registry_identity_creation_does_not_invent_storage() {
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    db.create_project(org, "team", "Team").await.unwrap();
    let id = db
        .create_managed_registry(org, "team", "cdn", "public", &[], false)
        .await
        .unwrap();
    let reg = db.registry_by_slug("acme/team/cdn").await.unwrap().unwrap();
    assert_eq!(reg.id, id);
    assert!(db
        .list_surface_placements(SurfaceTarget::Registry(id))
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn signup_policy_defaults_invite_only_and_round_trips() {
    let db = Database::open_in_memory().await.unwrap();
    assert_eq!(db.signup_policy().await.unwrap(), SignupPolicy::InviteOnly);
    db.set_signup_policy(SignupPolicy::Open).await.unwrap();
    assert_eq!(db.signup_policy().await.unwrap(), SignupPolicy::Open);
    // An unknown stored value falls closed to invite-only.
    db.instance_config_set("signup_policy", "garbage")
        .await
        .unwrap();
    assert_eq!(db.signup_policy().await.unwrap(), SignupPolicy::InviteOnly);
}

#[tokio::test]
async fn sibling_surface_scopes_are_isolated_and_slug_reuse_gets_new_identity() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("acme", "Acme").await.unwrap();
    db.create_project(org_id, "infra", "Infra").await.unwrap();
    let first_id = db
        .create_managed_registry(org_id, "infra", "packages", "private", &[], true)
        .await
        .unwrap();
    let sibling_id = db
        .create_managed_registry(org_id, "infra", "images", "private", &[], true)
        .await
        .unwrap();
    let first = db.registry_by_id(first_id).await.unwrap().unwrap();
    let sibling = db.registry_by_id(sibling_id).await.unwrap().unwrap();
    assert_eq!(first.owner_scope_key, sibling.owner_scope_key);
    assert_ne!(first.scope_key, sibling.scope_key);

    let user = db.create_user("reader@example.test", None).await.unwrap();
    db.grant_membership("user", user, &first.scope_key, "viewer")
        .await
        .unwrap();
    let grants = db
        .effective_scopes(aos_hub_model::domain::Principal::user(user))
        .await
        .unwrap();
    let first_context = db
        .authorization_context(&first.scope_key)
        .await
        .unwrap()
        .unwrap();
    let sibling_context = db
        .authorization_context(&sibling.scope_key)
        .await
        .unwrap()
        .unwrap();
    assert!(aos_hub_model::domain::iam::allow(
        &grants,
        aos_hub_model::domain::Permission::Read,
        &first_context,
    ));
    assert!(!aos_hub_model::domain::iam::allow(
        &grants,
        aos_hub_model::domain::Permission::Read,
        &sibling_context,
    ));

    let old_scope = first.scope_key;
    assert!(db.seed_delete_registry_for_test(first_id).await.unwrap());
    let grants_after_delete = db
        .effective_scopes(aos_hub_model::domain::Principal::user(user))
        .await
        .unwrap();
    assert!(grants_after_delete
        .iter()
        .all(|(scope, _)| scope.as_str() != old_scope));
    let replacement_id = db
        .create_managed_registry(org_id, "infra", "packages", "private", &[], true)
        .await
        .unwrap();
    let replacement = db.registry_by_id(replacement_id).await.unwrap().unwrap();
    assert_ne!(old_scope, replacement.scope_key);
    let replacement_context = db
        .authorization_context(&replacement.scope_key)
        .await
        .unwrap()
        .unwrap();
    assert!(!aos_hub_model::domain::iam::allow(
        &grants_after_delete,
        aos_hub_model::domain::Permission::Read,
        &replacement_context,
    ));
}

#[tokio::test]
async fn grant_membership_backstop_rejects_non_canonical_scopes() {
    // CR-2 persistence backstop: only closed, immutable scope identities
    // may reach the live grant table.
    use aos_hub_model::domain::{Principal, Role};
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("acme", "Acme").await.unwrap();
    let org_scope = db.org_by_id(org_id).await.unwrap().unwrap().stable_id;
    db.create_project(org_id, "infra", "Infra").await.unwrap();
    let project_scope = db.list_projects(org_id).await.unwrap()[0].scope_key.clone();
    let user = db.create_user("u@example.com", None).await.unwrap();
    for bad in [
        "",
        "/victimorg",
        "acme",
        "org:0000000000000000000000000000000A",
        "org:00000000000000000000000000000001/registry",
    ] {
        assert!(
            db.grant_membership("user", user, bad, Role::Owner.as_str())
                .await
                .is_err(),
            "grant_membership should reject non-canonical scope {bad:?}"
        );
    }
    // The user gained no grant from any rejected call.
    assert!(db
        .effective_scopes(Principal::user(user))
        .await
        .unwrap()
        .is_empty());

    for good in ["instance", org_scope.as_str(), project_scope.as_str()] {
        db.grant_membership("user", user, good, Role::Viewer.as_str())
            .await
            .unwrap_or_else(|e| panic!("scope {good:?} should be accepted: {e}"));
    }
    let scopes: Vec<String> = db
        .effective_scopes(Principal::user(user))
        .await
        .unwrap()
        .into_iter()
        .map(|(s, _)| s.as_str().to_string())
        .collect();
    assert!(scopes.iter().any(|s| s == "instance"));
    assert!(scopes.iter().any(|s| s == &org_scope));
    assert!(scopes.iter().any(|s| s == &project_scope));
}

#[tokio::test]
async fn registry_publication_multipart_state_retains_expired_backend_identity() {
    let db = Database::open_in_memory().await.unwrap();
    let registry_id = db
        .register_registry("multipart-state", &[], false)
        .await
        .unwrap();
    let publication_id = "multipartpublication0000000000000001";
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: publication_id.into(),
        registry_id,
        generation: "generation-1".into(),
        manifest_digest: "a".repeat(64),
        refs_digest: "b".repeat(64),
        default_commit: Some("c".repeat(40)),
        parent_publication_id: None,
    })
    .await
    .unwrap();
    let object = db
        .create_surface_object(&SetSurfaceObject {
            surface: SurfaceTarget::Registry(registry_id),
            object_key: "images/system.raw.zst".into(),
            content_hash: Some("d".repeat(64)),
            size: Some(128),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
        })
        .await
        .unwrap();
    db.set_registry_publication_object(&SetRegistryPublicationObject {
        publication_id: publication_id.into(),
        surface_object_id: object.id,
        object_kind: "immutable".into(),
        expected_hash: "d".repeat(64),
        expected_size: 128,
    })
    .await
    .unwrap();

    let created = db
        .create_registry_publication_multipart_upload(
            "multipart-upload-1",
            publication_id,
            registry_id,
            object.id,
            2,
            1,
            &[],
        )
        .await
        .unwrap();
    assert_eq!(created.expires_at, 2);
    assert_eq!(created.hashed_size, 0);

    let part_hash = "e".repeat(64);
    db.claim_registry_publication_multipart_part(
        "multipart-upload-1",
        1,
        &part_hash,
        0,
        "claim-token-1",
        100,
    )
    .await
    .unwrap();
    assert!(db
        .claim_registry_publication_multipart_part(
            "multipart-upload-1",
            1,
            &part_hash,
            0,
            "claim-token-2",
            101,
        )
        .await
        .is_err());
    assert!(db
        .claim_registry_publication_multipart_part(
            "multipart-upload-1",
            1,
            &"f".repeat(64),
            0,
            "claim-token-3",
            702,
        )
        .await
        .is_err());
    let claimed = db
        .registry_publication_multipart_upload("multipart-upload-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claimed.pending_part, Some(1));
    assert_eq!(claimed.pending_hash.as_deref(), Some(part_hash.as_str()));
    assert_eq!(claimed.pending_token.as_deref(), Some("claim-token-1"));
    assert_eq!(claimed.pending_since, Some(100));

    let active = db
        .active_registry_publication_multipart_upload(publication_id, object.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.upload_id, "multipart-upload-1");
    assert_eq!(
        db.active_registry_publication_multipart_uploads(publication_id)
            .await
            .unwrap()
            .len(),
        1
    );

    let first_completion = db
        .begin_registry_publication_multipart_completion(
            "multipart-upload-1",
            "completion-token-1",
            200,
            0,
        )
        .await
        .unwrap();
    assert_eq!(
        first_completion.completion_token.as_deref(),
        Some("completion-token-1")
    );
    let retry = db
        .begin_registry_publication_multipart_completion(
            "multipart-upload-1",
            "completion-token-1",
            201,
            0,
        )
        .await
        .unwrap();
    assert_eq!(retry.completion_since, Some(201));
    assert!(db
        .begin_registry_publication_multipart_completion(
            "multipart-upload-1",
            "completion-token-2",
            202,
            0,
        )
        .await
        .is_err());
    let stolen = db
        .begin_registry_publication_multipart_completion(
            "multipart-upload-1",
            "completion-token-2",
            900,
            300,
        )
        .await
        .unwrap();
    assert_eq!(
        stolen.completion_token.as_deref(),
        Some("completion-token-2")
    );

    db.finish_registry_publication_multipart_upload("multipart-upload-1", "aborted", 3)
        .await
        .unwrap();
    assert!(db
        .active_registry_publication_multipart_upload(publication_id, object.id)
        .await
        .unwrap()
        .is_none());
}
