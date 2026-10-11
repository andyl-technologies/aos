//! Genuine minted-cookie persistence, owner reuse and original-pin regressions.

use super::*;
use crate::auth::jwt::JwtKeys;
use crate::db::TokenAuth;
use crate::domain::{Permission, Scope};

#[tokio::test]
async fn genuine_session_mint_retains_the_original_uuid_across_database_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("hub.db");
    let (user, secret, original) = {
        let db = Database::open(&path).await.unwrap();
        let user = db.create_user("restart@example.test", None).await.unwrap();
        let original = db
            .principal_incarnation(Principal::user(user))
            .await
            .unwrap()
            .unwrap();
        let secret = db.create_session(user, 3600, 1).await.unwrap();
        let hash = crate::auth::token::sha256_hex(&secret);
        let retained: String = db
            .backend
            .query_opt(
                "SELECT owner_incarnation FROM sessions WHERE id_hash = ?1",
                &vals![hash],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(retained, original);
        (user, secret, original)
    };

    let reopened = Database::open(&path).await.unwrap();
    let auth = reopened.validate_session(&secret).await.unwrap().unwrap();
    assert_eq!(auth.user_id, user);
    assert_eq!(auth.owner_incarnation, original);
    assert!(reopened.session_auth_is_current(&auth).await.unwrap());
}

#[tokio::test]
async fn restored_old_cookie_cannot_adopt_a_replacement_at_the_same_numeric_slot() {
    let db = Database::open_in_memory().await.unwrap();
    let user = db.create_user("original@example.test", None).await.unwrap();
    let secret = db.create_session(user, 3600, 0).await.unwrap();
    let original = db.validate_session(&secret).await.unwrap().unwrap();
    let row = db
        .backend
        .query_opt(
            "SELECT id_hash, user_id, created_at, last_seen_at, expires_at, auth_level,
                last_authenticated_at, owner_incarnation FROM sessions WHERE id_hash = ?1",
            &vals![original.session_id_hash],
        )
        .await
        .unwrap()
        .unwrap();

    db.delete_user(user).await.unwrap();
    db.backend
        .execute("DELETE FROM users WHERE id = ?1", &vals![user])
        .await
        .unwrap();
    let replacement = db
        .create_user("replacement@example.test", None)
        .await
        .unwrap();
    assert_eq!(replacement, user);
    let replacement_uuid = db
        .principal_incarnation(Principal::user(replacement))
        .await
        .unwrap()
        .unwrap();
    assert_ne!(replacement_uuid, original.owner_incarnation);

    // Reinsert the genuinely minted historical row with all original fields.
    // This is a retained-row corruption fixture, not a snapshot auth restore.
    let values = (0..8)
        .map(|index| row.get::<crate::value::Value>(index).unwrap())
        .collect::<Vec<_>>();
    db.backend
        .execute(
            "INSERT INTO sessions(id_hash,user_id,created_at,last_seen_at,expires_at,
                              auth_level,last_authenticated_at,owner_incarnation)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            &values,
        )
        .await
        .unwrap();

    assert!(db.validate_session(&secret).await.unwrap().is_none());
    assert!(
        crate::web::session::resolve_session(&db, &secret)
            .await
            .unwrap()
            .is_none()
    );
    assert!(db.session_email(&secret).await.unwrap().is_none());
    assert!(!db.session_auth_is_current(&original).await.unwrap());
    assert_eq!(
        db.principal_incarnation(Principal::user(user))
            .await
            .unwrap()
            .unwrap(),
        replacement_uuid
    );
    let retained: String = db
        .backend
        .query_opt(
            "SELECT owner_incarnation FROM sessions WHERE id_hash = ?1",
            &vals![original.session_id_hash],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(retained, original.owner_incarnation);

    let new_secret = db.create_session(replacement, 3600, 0).await.unwrap();
    assert_eq!(
        db.validate_session(&new_secret)
            .await
            .unwrap()
            .unwrap()
            .owner_incarnation,
        replacement_uuid
    );
}

#[tokio::test]
async fn legacy_unpinned_cookie_requires_reauthentication_without_uuid_backfill() {
    let db = Database::open_in_memory().await.unwrap();
    let user = db
        .create_user("legacy-cookie@example.test", None)
        .await
        .unwrap();
    let secret = db.create_session(user, 3600, 0).await.unwrap();
    let auth = db.validate_session(&secret).await.unwrap().unwrap();
    db.backend
        .execute(
            "UPDATE sessions SET owner_incarnation = NULL WHERE id_hash = ?1",
            &vals![auth.session_id_hash],
        )
        .await
        .unwrap();

    assert!(db.validate_session(&secret).await.unwrap().is_none());
    assert!(!db.session_auth_is_current(&auth).await.unwrap());
    let retained: Option<String> = db
        .backend
        .query_opt(
            "SELECT owner_incarnation FROM sessions WHERE id_hash = ?1",
            &vals![auth.session_id_hash],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert!(retained.is_none());

    let reauthenticated = db.create_session(user, 3600, 0).await.unwrap();
    assert_eq!(
        db.validate_session(&reauthenticated)
            .await
            .unwrap()
            .unwrap()
            .owner_incarnation,
        auth.owner_incarnation
    );
    assert!(db.validate_session(&secret).await.unwrap().is_none());
}

#[tokio::test]
async fn cached_pin_check_and_cold_loader_preserve_expiry_idle_and_revocation_bounds() {
    let db = Database::open_in_memory().await.unwrap();
    let user = db.create_user("bounds@example.test", None).await.unwrap();
    let secret = db.create_session(user, 3600, 0).await.unwrap();
    let auth = db.validate_session(&secret).await.unwrap().unwrap();
    assert!(db.session_auth_is_current(&auth).await.unwrap());
    assert!(
        !db.session_auth_is_current_at(&auth, auth.expires_at)
            .await
            .unwrap()
    );

    db.backend
        .execute(
            "UPDATE sessions SET last_seen_at = ?2 WHERE id_hash = ?1",
            &vals![auth.session_id_hash, unix_now() - IDLE_TIMEOUT_SECS - 1],
        )
        .await
        .unwrap();
    assert!(!db.session_auth_is_current(&auth).await.unwrap());
    assert!(db.validate_session(&secret).await.unwrap().is_none());

    let expired = db.create_session(user, -1, 0).await.unwrap();
    assert!(db.validate_session(&expired).await.unwrap().is_none());
    let revoked = db.create_session(user, 3600, 0).await.unwrap();
    let revoked_auth = db.validate_session(&revoked).await.unwrap().unwrap();
    db.revoke_session(&revoked).await.unwrap();
    assert!(!db.session_auth_is_current(&revoked_auth).await.unwrap());
    assert!(db.validate_session(&revoked).await.unwrap().is_none());
}

#[tokio::test]
async fn signed_browser_claim_cannot_supply_an_absent_original_session_pin() {
    let db = Database::open_in_memory().await.unwrap();
    let user = db
        .create_user("browser-claim@example.test", None)
        .await
        .unwrap();
    let secret = db.create_session(user, 3600, 0).await.unwrap();
    let session = db.validate_session(&secret).await.unwrap().unwrap();
    let auth = TokenAuth {
        token_id: format!("browser-session-{user}"),
        owner: Principal::user(user),
        owner_incarnation: Some(session.owner_incarnation),
        browser_session_id_hash: Some(session.session_id_hash.clone()),
        scope: Scope::root(),
        permissions: vec![Permission::Read],
    };
    let keys = JwtKeys::from_secret(b"test-only-original-cookie-pin");
    let claims = keys.verify(&keys.mint(&auth, 300).unwrap()).unwrap();
    assert!(
        db.current_authenticated_actor(&claims)
            .await
            .unwrap()
            .is_some()
    );
    db.backend
        .execute(
            "UPDATE sessions SET owner_incarnation = NULL WHERE id_hash = ?1",
            &vals![session.session_id_hash],
        )
        .await
        .unwrap();
    assert!(
        db.current_authenticated_actor(&claims)
            .await
            .unwrap()
            .is_none()
    );
    assert!(db.validate_session(&secret).await.unwrap().is_none());
}

#[tokio::test]
async fn malformed_retained_uuid_cannot_authenticate_even_when_current_user_matches() {
    let db = Database::open_in_memory().await.unwrap();
    let user = db
        .create_user("canonical-cookie@example.test", None)
        .await
        .unwrap();
    let secret = db.create_session(user, 3600, 0).await.unwrap();
    let auth = db.validate_session(&secret).await.unwrap().unwrap();
    for bad in [
        "01234567-89AB-4def-8123-456789abcdef",
        "01234567-89ab-1def-8123-456789abcdef",
        "01234567-89ab-4def-c123-456789abcdef",
    ] {
        // These length-valid corrupt rows satisfy the portable DDL. Matching
        // recyclable SQL slots still cannot establish canonical provenance.
        db.backend
            .execute(
                "UPDATE users SET principal_incarnation = ?2 WHERE id = ?1",
                &vals![user, bad],
            )
            .await
            .unwrap();
        db.backend
            .execute(
                "UPDATE sessions SET owner_incarnation = ?2 WHERE id_hash = ?1",
                &vals![auth.session_id_hash, bad],
            )
            .await
            .unwrap();
        assert!(db.validate_session(&secret).await.unwrap().is_none());
        assert!(db.session_email(&secret).await.unwrap().is_none());
        let mut corrupt_auth = auth.clone();
        corrupt_auth.owner_incarnation = bad.into();
        assert!(!db.session_auth_is_current(&corrupt_auth).await.unwrap());
    }
}
