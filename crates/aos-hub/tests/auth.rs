//! Integration coverage for the `POST /oauth2/token` exchange endpoint.
//!
//! Drives the `oauth2_router` fragment end to end: seed a provisioning
//! token in the hub database, present its secret in `Authorization:
//! Bearer`, and assert the response is a well-formed JWT whose claims match
//! the token's owner, scope, and permissions. Also covers the `401` paths.

use std::sync::Arc;

use aos_hub::auth::extract::{oauth2_router, AuthState};
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::db::Database;
use aos_hub::domain::{Permission, Principal};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

/// Builds an `AuthState` with deterministic JWT keys and a seeded token.
async fn seed() -> (Arc<AuthState>, String, String) {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org_id = db.create_org("acme", "Acme").await.unwrap();
    db.create_project(org_id, "infra/prod", "Production")
        .await
        .unwrap();
    let scope = db.list_projects(org_id).await.unwrap()[0].scope_key.clone();
    let (_id, secret) = db
        .create_token(
            Principal::user(42),
            &scope,
            &[Permission::Read, Permission::Publish],
            Some("ci"),
            None,
        )
        .await
        .unwrap();
    let state = Arc::new(AuthState {
        db,
        jwt_keys: JwtKeys::from_secret(b"test-secret-key-32-bytes-padding!"),
        access_token_ttl: 900,
        ratelimit: aos_hub::ratelimit::RateLimiter::new().into(),
        trusted_proxy: false,
    });
    (state, secret, scope)
}

#[tokio::test]
async fn oauth2_exchange_happy_path_decodes_to_claims() {
    let (state, secret, scope) = seed().await;
    let keys = state.jwt_keys.clone();
    let app = oauth2_router().with_state(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/token")
                .header("Authorization", format!("Bearer {secret}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["token_type"], "Bearer");
    assert_eq!(json["expires_in"], 900);

    let access_token = json["access_token"].as_str().unwrap();
    let claims = keys.verify(access_token).unwrap();
    assert_eq!(claims.owner_kind, "user");
    assert_eq!(claims.owner_id, 42);
    assert_eq!(claims.scope, scope);
    assert_eq!(claims.perms, vec!["read", "publish"]);
}

#[tokio::test]
async fn oauth2_exchange_rejects_bad_secret() {
    let (state, _secret, _scope) = seed().await;
    let app = oauth2_router().with_state(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/token")
                .header("Authorization", "Bearer aos_not_a_real_token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn oauth2_exchange_rejects_missing_header() {
    let (state, _secret, _scope) = seed().await;
    let app = oauth2_router().with_state(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
