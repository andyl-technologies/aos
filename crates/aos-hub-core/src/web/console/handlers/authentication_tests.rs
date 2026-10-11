//! Real cookie extraction and signed browser bearer lifecycle regressions.

use super::*;
use std::sync::Arc;

use crate::auth::jwt::JwtKeys;
use crate::auth::magic::LogMailer;
use crate::auth::seal::AesGcmSealer;
use crate::coordinator::InMemoryCoordinator;
use crate::ratelimit::CoordinatorRateLimiter;
use crate::web::console::ports::HttpClient;

struct NoOutboundHttp;

#[async_trait::async_trait]
impl HttpClient for NoOutboundHttp {
    async fn post_form(&self, _: &str, _: &[(String, String)]) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("unexpected outbound HTTP")
    }

    async fn get(&self, _: &str) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("unexpected outbound HTTP")
    }
}

async fn fixture() -> (ConsoleDeps, HeaderMap, String) {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let user = db.create_user("browser@example.test", None).await.unwrap();
    db.grant_membership("user", user, "instance", Role::Owner.as_str())
        .await
        .unwrap();
    let secret = db.create_session(user, 3600, 1).await.unwrap();
    let deps = ConsoleDeps {
        db,
        jwt_keys: JwtKeys::from_secret(b"browser-provenance-fixture-key"),
        external_url: "https://hub.example.test".into(),
        dev: false,
        ratelimit: Arc::new(CoordinatorRateLimiter::new(Arc::new(
            InMemoryCoordinator::new(),
        ))),
        mailer: Arc::new(LogMailer),
        sealer: Arc::new(AesGcmSealer::new(&[7; 32]).unwrap()),
        http: Arc::new(NoOutboundHttp),
        control: None,
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("{COOKIE_NAME}={secret}").parse().unwrap(),
    );
    headers.insert(header::ORIGIN, deps.external_url.parse().unwrap());
    headers.insert("x-aos-csrf", mint_csrf_token(&secret).parse().unwrap());
    (deps, headers, secret)
}

#[tokio::test]
async fn genuine_cookie_bridge_pins_live_uuid_and_hash_then_logout_revokes_bearer() {
    let (deps, headers, secret) = fixture().await;
    let response = session_token(deps.clone(), headers.clone()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = value["accessToken"].as_str().unwrap();
    let claims = deps.jwt_keys.verify(token).unwrap();
    assert_eq!(
        claims.browser_session_id_hash.as_deref(),
        Some(crate::auth::token::sha256_hex(&secret).as_str())
    );
    assert_eq!(
        claims.owner_incarnation,
        deps.db
            .principal_incarnation(Principal::user(claims.owner_id))
            .await
            .unwrap()
    );
    assert!(!serde_json::to_string(&claims).unwrap().contains(&secret));
    assert!(deps
        .db
        .current_authenticated_actor(&claims)
        .await
        .unwrap()
        .is_some());

    // The server-side page bridge shares exactly the authenticated pin source.
    let session = require_session(&deps, &headers).await.unwrap();
    let bearer = session.api_bearer(&deps).unwrap();
    let page_claims = deps
        .jwt_keys
        .verify(bearer.strip_prefix("Bearer ").unwrap())
        .unwrap();
    assert_eq!(page_claims.owner_incarnation, claims.owner_incarnation);
    assert_eq!(
        page_claims.browser_session_id_hash,
        claims.browser_session_id_hash
    );

    deps.db.revoke_session(&secret).await.unwrap();
    assert!(deps
        .db
        .current_authenticated_actor(&claims)
        .await
        .unwrap()
        .is_none());
    assert!(deps
        .db
        .current_authenticated_actor(&page_claims)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        session_token(deps, headers).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn browser_exchange_rejects_missing_csrf_and_live_bearer_checks_session_expiry() {
    let (deps, mut headers, secret) = fixture().await;
    headers.remove("x-aos-csrf");
    assert_eq!(
        session_token(deps.clone(), headers.clone()).await.status(),
        StatusCode::FORBIDDEN
    );
    headers.insert("x-aos-csrf", mint_csrf_token(&secret).parse().unwrap());
    let session = require_session(&deps, &headers).await.unwrap();
    let token = deps.jwt_keys.mint(&session.access_auth(), 300).unwrap();
    let claims = deps.jwt_keys.verify(&token).unwrap();
    assert!(deps
        .db
        .current_authenticated_actor(&claims)
        .await
        .unwrap()
        .is_some());

    deps.db
        .backend
        .execute(
            "UPDATE sessions SET expires_at = ?2 WHERE id_hash = ?1",
            &[
                crate::value::Value::Text(crate::auth::token::sha256_hex(&secret)),
                crate::value::Value::Int(crate::clock::now_unix_secs()),
            ],
        )
        .await
        .unwrap();
    assert!(deps
        .db
        .current_authenticated_actor(&claims)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        session_token(deps, headers).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn deleted_browser_owner_slot_reuse_cannot_revive_retained_session_bearer() {
    let (deps, headers, secret) = fixture().await;
    let session = require_session(&deps, &headers).await.unwrap();
    let token = deps.jwt_keys.mint(&session.access_auth(), 300).unwrap();
    let old = deps.jwt_keys.verify(&token).unwrap();
    deps.db.delete_user(old.owner_id).await.unwrap();
    assert!(deps
        .db
        .current_authenticated_actor(&old)
        .await
        .unwrap()
        .is_none());

    deps.db
        .backend
        .execute(
            "DELETE FROM users WHERE id = ?1",
            &[crate::value::Value::Int(old.owner_id)],
        )
        .await
        .unwrap();
    let replacement = deps
        .db
        .create_user("replacement@example.test", None)
        .await
        .unwrap();
    assert_eq!(replacement, old.owner_id);
    let current_uuid = deps
        .db
        .principal_incarnation(Principal::user(replacement))
        .await
        .unwrap();
    assert!(current_uuid.is_some());
    assert_ne!(current_uuid, old.owner_incarnation);

    // Even an explicitly restored still-live session with the same hash and
    // numeric owner cannot change the account incarnation in retained claims.
    let now = crate::clock::now_unix_secs();
    deps.db.backend.execute(
        "INSERT INTO sessions (id_hash, user_id, created_at, last_seen_at, expires_at, auth_level, last_authenticated_at)
         VALUES (?1, ?2, ?3, ?3, ?4, 1, ?3)",
        &[
            crate::value::Value::Text(crate::auth::token::sha256_hex(&secret)),
            crate::value::Value::Int(replacement),
            crate::value::Value::Int(now),
            crate::value::Value::Int(now + 3600),
        ],
    ).await.unwrap();
    assert!(deps
        .db
        .current_authenticated_actor(&old)
        .await
        .unwrap()
        .is_none());
}
