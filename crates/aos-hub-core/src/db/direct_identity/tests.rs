//! Actual SQLite principal-incarnation, token and cookie provenance regressions.

use super::*;
use crate::auth::jwt::JwtKeys;
use crate::db::TokenAuth;
use crate::domain::{Permission, Scope};

#[tokio::test]
async fn malformed_retained_token_ids_cannot_authorize_secrets_or_signed_subjects() {
    for malformed in [
        "not-a-token-uuid",
        "01234567-89AB-4def-8123-456789abcdef",
        "01234567-89ab-1def-8123-456789abcdef",
        "01234567-89ab-4def-0123-456789abcdef",
        "01234567-89ab-4def-c123-456789abcdef",
        "01234567-89ab-4def-e123-456789abcdef",
    ] {
        let db = Database::open_in_memory().await.unwrap();
        let (_, original_id, secret, _) = user_authority(&db).await;
        let mut original_auth = db.validate_token(&secret).await.unwrap().unwrap();
        db.backend
            .execute(
                "UPDATE tokens SET id = ?2 WHERE id = ?1",
                &vals![original_id, malformed],
            )
            .await
            .unwrap();

        // Deliberately sign the corrupt stored subject with the real test key.
        // Cryptographic validity cannot grant a malformed credential identity.
        original_auth.token_id = malformed.into();
        let keys = JwtKeys::from_secret(b"test-only-canonical-token-id-key");
        let signed = keys.mint(&original_auth, 300).unwrap();
        let claims = keys.verify(&signed).unwrap();
        assert_eq!(claims.sub, malformed);

        assert!(db.validate_token(&secret).await.unwrap().is_none());
        assert!(db
            .current_token_authority(malformed)
            .await
            .unwrap()
            .is_none());
        assert!(db
            .current_authenticated_actor(&claims)
            .await
            .unwrap()
            .is_none());
    }
}

async fn user_authority(db: &Database) -> (Principal, String, String, Claims) {
    let user = db.create_user("owner@example.test", None).await.unwrap();
    db.grant_membership("user", user, "instance", "owner")
        .await
        .unwrap();
    let principal = Principal::user(user);
    let (id, secret) = db
        .create_token(
            principal,
            "instance",
            &[Permission::Read, Permission::Publish],
            None,
            None,
        )
        .await
        .unwrap();
    let auth = db.validate_token(&secret).await.unwrap().unwrap();
    let keys = JwtKeys::from_secret(b"test-only-principal-validation-key");
    let claims = keys.verify(&keys.mint(&auth, 300).unwrap()).unwrap();
    (principal, id, secret, claims)
}

#[tokio::test]
async fn account_creation_assigns_canonical_distinct_immutable_incarnations() {
    let db = Database::open_in_memory().await.unwrap();
    let first = db.create_user("first@example.test", None).await.unwrap();
    let second = db.find_or_create_user("second@example.test").await.unwrap();
    let org = db.create_org("test", "Test").await.unwrap();
    let service = db.create_service_account(org, "builder").await.unwrap();
    let principals = [
        Principal::user(first),
        Principal::user(second),
        Principal::service_account(service),
    ];
    let mut uuids = std::collections::BTreeSet::new();

    for principal in principals {
        let original = db.principal_incarnation(principal).await.unwrap().unwrap();
        validate_actor_incarnation(principal, &original).unwrap();
        assert_eq!(
            db.ensure_principal_incarnation(principal).await.unwrap(),
            original
        );
        assert!(uuids.insert(original));
    }
    assert_eq!(
        db.find_or_create_user("second@example.test").await.unwrap(),
        second
    );
}

#[tokio::test]
async fn concurrent_legacy_principal_cas_returns_the_same_committed_uuid() {
    let db = Database::open_in_memory().await.unwrap();
    let user = db.create_user("legacy@example.test", None).await.unwrap();
    db.backend
        .execute(
            "UPDATE users SET principal_incarnation = NULL WHERE id = ?1",
            &vals![user],
        )
        .await
        .unwrap();
    let principal = Principal::user(user);

    let (first, second) = tokio::join!(
        db.ensure_principal_incarnation(principal),
        db.ensure_principal_incarnation(principal)
    );

    assert_eq!(first.unwrap(), second.unwrap());
    assert!(db.principal_incarnation(principal).await.unwrap().is_some());
}

#[tokio::test]
async fn original_token_pin_and_stale_jwt_refuse_missing_or_restored_owner_uuid() {
    let db = Database::open_in_memory().await.unwrap();
    let (principal, id, secret, claims) = user_authority(&db).await;
    assert!(db
        .current_authenticated_actor(&claims)
        .await
        .unwrap()
        .is_some());

    for replacement in [None, Some(uuid::Uuid::new_v4().to_string())] {
        db.backend
            .execute(
                "UPDATE users SET principal_incarnation = ?2 WHERE id = ?1",
                &vals![principal.id, replacement],
            )
            .await
            .unwrap();
        assert!(db.validate_token(&secret).await.unwrap().is_none());
        assert!(db.current_token_authority(&id).await.unwrap().is_none());
        assert!(db
            .current_authenticated_actor(&claims)
            .await
            .unwrap()
            .is_none());
        assert!(db.rotate_token(&id).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn deleted_service_account_numeric_slot_cannot_reactivate_retained_token() {
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("test", "Test").await.unwrap();
    let id = db.create_service_account(org, "original").await.unwrap();
    db.grant_membership("service_account", id, "instance", "owner")
        .await
        .unwrap();
    let (token, secret) = db
        .create_token(
            Principal::service_account(id),
            "instance",
            &[Permission::Read],
            None,
            None,
        )
        .await
        .unwrap();

    db.backend
        .execute("DELETE FROM service_accounts WHERE id = ?1", &vals![id])
        .await
        .unwrap();
    db.backend.execute("INSERT INTO service_accounts (id, org_id, name, created_at, principal_incarnation) VALUES (?1, ?2, 'replacement', ?3, ?4)", &vals![id, org, unix_now(), uuid::Uuid::new_v4().to_string()]).await.unwrap();

    assert!(db.validate_token(&secret).await.unwrap().is_none());
    assert!(db.current_token_authority(&token).await.unwrap().is_none());
}

#[tokio::test]
async fn fresh_session_mint_pins_legacy_user_without_repairing_unpinned_token_authority() {
    let db = Database::open_in_memory().await.unwrap();
    let (principal, id, secret, _) = user_authority(&db).await;
    db.backend
        .execute(
            "UPDATE tokens SET owner_incarnation = NULL WHERE id = ?1",
            &vals![id],
        )
        .await
        .unwrap();
    db.backend
        .execute(
            "UPDATE users SET principal_incarnation = NULL WHERE id = ?1",
            &vals![principal.id],
        )
        .await
        .unwrap();
    let cookie = db.create_session(principal.id, 3600, 0).await.unwrap();

    let session = db.validate_session(&cookie).await.unwrap().unwrap();
    assert_eq!(
        session.session_id_hash,
        crate::auth::token::sha256_hex(&cookie)
    );
    assert_eq!(
        db.validate_session(&cookie)
            .await
            .unwrap()
            .unwrap()
            .owner_incarnation,
        session.owner_incarnation
    );
    assert!(db.validate_token(&secret).await.unwrap().is_none());
    assert!(db.rotate_token(&id).await.unwrap().is_none());
}

#[tokio::test]
async fn browser_provenance_requires_current_cookie_and_original_user_uuid() {
    let db = Database::open_in_memory().await.unwrap();
    let (principal, _, _, _) = user_authority(&db).await;
    let cookie = db.create_session(principal.id, 3600, 0).await.unwrap();
    let session = db.validate_session(&cookie).await.unwrap().unwrap();
    let auth = TokenAuth {
        token_id: format!("browser-session-{}", principal.id),
        owner: principal,
        owner_incarnation: Some(session.owner_incarnation),
        browser_session_id_hash: Some(session.session_id_hash),
        scope: Scope::parse("instance"),
        permissions: vec![Permission::Read],
    };
    let keys = JwtKeys::from_secret(b"test-only-browser-validation-key");
    let claims = keys.verify(&keys.mint(&auth, 300).unwrap()).unwrap();
    assert!(db
        .current_authenticated_actor(&claims)
        .await
        .unwrap()
        .is_some());

    let mut missing_provenance = claims.clone();
    missing_provenance.browser_session_id_hash = None;
    assert!(db
        .current_authenticated_actor(&missing_provenance)
        .await
        .unwrap()
        .is_none());
    db.revoke_session(&cookie).await.unwrap();
    assert!(db
        .current_authenticated_actor(&claims)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn token_grant_provenance_preserves_unrelated_read_after_publish_membership_loss() {
    let db = Database::open_in_memory().await.unwrap();
    let (principal, _, secret, claims) = user_authority(&db).await;
    let another_owner = db
        .create_user("remaining-owner@example.test", None)
        .await
        .unwrap();
    db.grant_membership("user", another_owner, "instance", "owner")
        .await
        .unwrap();
    db.grant_membership("user", principal.id, "instance", "viewer")
        .await
        .unwrap();

    let current = db.validate_token(&secret).await.unwrap().unwrap();
    assert_eq!(current.permissions, vec![Permission::Read]);
    assert!(db
        .current_authenticated_actor(&claims)
        .await
        .unwrap()
        .is_some());
    let mut forged_grant = claims;
    forged_grant.perms.push("admin".to_owned());
    assert!(db
        .current_authenticated_actor(&forged_grant)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn rotation_preserves_exact_owner_uuid_and_scope() {
    let db = Database::open_in_memory().await.unwrap();
    let (_, id, _, claims) = user_authority(&db).await;
    let (next, secret) = db.rotate_token(&id).await.unwrap().unwrap();
    let auth = db.validate_token(&secret).await.unwrap().unwrap();

    assert_eq!(auth.owner_incarnation, claims.owner_incarnation);
    assert_eq!(auth.scope.as_str(), claims.scope);
    assert_eq!(auth.token_id, next);
    assert!(db
        .current_token_authority("browser-session-1")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn topology_plan_retry_keeps_original_actor_uuid_and_refuses_recycled_owner() {
    let db = Database::open_in_memory().await.unwrap();
    let (principal, _, _, claims) = user_authority(&db).await;
    let mut input = crate::db::NewTopologyPlan {
        plan_id: uuid::Uuid::new_v4().to_string(),
        plan_kind: "create_registry".into(),
        actor_kind: "user".into(),
        actor_id: Some(principal.id),
        actor_incarnation: claims.owner_incarnation.clone(),
        actor_label: claims.sub,
        scope: "instance".into(),
        input_versions_json: "{}".into(),
        effects_json: "[]".into(),
        warnings_json: "[]".into(),
        confirmation_hash: None,
        request_idempotency_key: Some("original-operation".into()),
        expires_at: unix_now() + 300,
    };
    let original = db.create_topology_plan(&input).await.unwrap();
    input.plan_id = uuid::Uuid::new_v4().to_string();
    assert_eq!(
        db.create_topology_plan(&input).await.unwrap().plan_id,
        original.plan_id
    );

    let replacement = uuid::Uuid::new_v4().to_string();
    db.backend
        .execute(
            "UPDATE users SET principal_incarnation = ?2 WHERE id = ?1",
            &vals![principal.id, replacement],
        )
        .await
        .unwrap();
    input.actor_incarnation = Some(replacement);
    assert!(db.create_topology_plan(&input).await.is_err());
    assert_eq!(
        db.topology_plan(&original.plan_id)
            .await
            .unwrap()
            .unwrap()
            .actor_incarnation,
        original.actor_incarnation
    );
}
