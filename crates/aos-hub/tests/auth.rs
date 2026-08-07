//! Integration coverage for the shared OAuth grant endpoints.
//!
//! These tests drive the complete native router. The same handlers are mounted
//! by the Worker, so provisioning exchange behavior cannot drift by runtime.

use std::sync::Arc;

use aos_hub::auth::extract::AuthState;
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::db::Database;
use aos_hub::domain::{Permission, Principal};
use aos_hub::server::{router, AppState};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

const JWT_SECRET: &[u8] = b"oauth-test-secret-32-byte-key!!!!!";
const PROVISIONING_GRANT: &str = "urn:aos:params:oauth:grant-type:provisioning-token";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

async fn seed() -> (axum::Router, Arc<Database>, JwtKeys, String, String, i64) {
    seed_at("http://127.0.0.1:8420").await
}

async fn seed_at(
    external_url: &str,
) -> (axum::Router, Arc<Database>, JwtKeys, String, String, i64) {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org_id = db.create_org("acme", "Acme").await.unwrap();
    let owner_id = db
        .create_user("ci@acme.example", Some("CI publisher"))
        .await
        .unwrap();
    db.create_project(org_id, "infra/prod", "Production")
        .await
        .unwrap();
    let scope = db.list_projects(org_id).await.unwrap()[0].scope_key.clone();
    db.grant_membership("user", owner_id, &scope, "maintainer")
        .await
        .unwrap();
    let (_id, secret) = db
        .create_token(
            Principal::user(owner_id),
            &scope,
            &[Permission::Read, Permission::Publish],
            Some("ci"),
            None,
        )
        .await
        .unwrap();

    let keys = JwtKeys::from_secret(JWT_SECRET);
    let auth = Arc::new(AuthState {
        db: Arc::clone(&db),
        jwt_keys: keys.clone(),
        access_token_ttl: 3600,
        ratelimit: aos_hub::ratelimit::RateLimiter::new().into(),
        trusted_proxy: false,
    });
    let state = Arc::new(AppState {
        db: Arc::clone(&db),
        external_url: external_url.into(),
        ratelimit: auth.ratelimit.clone(),
        trusted_proxy: false,
        auth,
        leases: Arc::new(aos_hub_core::lease::InMemoryLease::new()),
        sealer: aos_hub::auth::oidc::dev_sealer(),
        secret_versions: aos_hub_core::secret_version::EmptySecretVersionResolver::shared(),
        http: aos_hub::fetch::hardened_client().await,
        image_snapshots: None,
        mailer: Arc::new(aos_hub::auth::magic::LogMailer),
        dev: true,
        delivery_attestation_verifier: None,
        domain_probe_terminator: None,
        route_reservation_keyring: None,
    });
    (router(state).await, db, keys, secret, scope, owner_id)
}

async fn post_form(
    app: &axum::Router,
    path: &str,
    secret: Option<&str>,
    body: &str,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::HOST, "127.0.0.1:8420")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(secret) = secret {
        request = request.header(header::AUTHORIZATION, format!("Bearer {secret}"));
    }
    app.clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

async fn exchange(
    app: &axum::Router,
    secret: Option<&str>,
    body: &str,
) -> axum::response::Response {
    post_form(app, "/oauth2/token", secret, body).await
}

#[tokio::test]
async fn provisioning_exchange_decodes_to_current_authority() {
    let (app, _db, keys, secret, scope, owner_id) = seed().await;
    let body = format!("grant_type={PROVISIONING_GRANT}");
    let response = exchange(&app, Some(&secret), &body).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");

    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["token_type"], "Bearer");
    assert_eq!(json["expires_in"], 3600);
    assert!(json.get("refresh_token").is_none());

    let claims = keys.verify(json["access_token"].as_str().unwrap()).unwrap();
    assert_eq!(claims.owner_kind, "user");
    assert_eq!(claims.owner_id, owner_id);
    assert_eq!(claims.scope, scope);
    assert_eq!(claims.perms, vec!["read", "publish"]);
}

#[tokio::test]
async fn provisioning_exchange_rejects_bad_or_missing_bearer() {
    let (app, _db, _keys, _secret, _scope, _owner_id) = seed().await;
    let body = format!("grant_type={PROVISIONING_GRANT}");
    for secret in [None, Some("aos_not_a_real_token")] {
        let response = exchange(&app, secret, &body).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
}

#[tokio::test]
async fn implicit_legacy_exchange_is_not_accepted() {
    let (app, _db, _keys, secret, _scope, _owner_id) = seed().await;
    let response = exchange(&app, Some(&secret), "").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn device_grant_rotates_and_revokes_refresh_credentials() {
    let (app, db, keys, _secret, scope, owner_id) = seed().await;
    let authorization_body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", "aos-cli")
        .append_pair("scope", &scope)
        .append_pair("permission", "read publish")
        .finish();
    let response = post_form(
        &app,
        "/oauth2/device_authorization",
        None,
        &authorization_body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let authorization: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let device_code = authorization["device_code"].as_str().unwrap();
    let user_code = authorization["user_code"].as_str().unwrap();
    assert_eq!(authorization["interval"], 5);
    assert!(db
        .approve_device(user_code, Principal::user(owner_id), &[])
        .await
        .unwrap());

    let device_body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", DEVICE_GRANT)
        .append_pair("client_id", "aos-cli")
        .append_pair("device_code", device_code)
        .finish();
    let response = exchange(&app, None, &device_body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let first: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let first_refresh = first["refresh_token"].as_str().unwrap();
    assert!(keys.verify(first["access_token"].as_str().unwrap()).is_ok());

    let refresh_body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "refresh_token")
        .append_pair("client_id", "aos-cli")
        .append_pair("refresh_token", first_refresh)
        .finish();
    let response = exchange(&app, None, &refresh_body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let second: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let second_refresh = second["refresh_token"].as_str().unwrap();
    assert_ne!(first_refresh, second_refresh);

    let revoke_body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", "aos-cli")
        .append_pair("token_type_hint", "refresh_token")
        .append_pair("token", second_refresh)
        .finish();
    let response = post_form(&app, "/oauth2/revoke", None, &revoke_body).await;
    assert_eq!(response.status(), StatusCode::OK);

    let revoked_refresh_body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "refresh_token")
        .append_pair("client_id", "aos-cli")
        .append_pair("refresh_token", second_refresh)
        .finish();
    let response = exchange(&app, None, &revoked_refresh_body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["error"], "invalid_grant");
}

#[tokio::test]
async fn remote_oauth_client_matches_the_live_native_http_contract() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = format!("http://{address}");
    let (app, db, _keys, _secret, scope, owner_id) = seed_at(&origin).await;
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
    });

    let authorization =
        aos_remote::start_device_authorization(&origin, Some(&scope), &["read", "publish"])
            .await
            .unwrap();
    assert!(db
        .approve_device(&authorization.user_code, Principal::user(owner_id), &[],)
        .await
        .unwrap());
    let first = match aos_remote::poll_device_token(&origin, &authorization.device_code)
        .await
        .unwrap()
    {
        aos_remote::DeviceTokenPoll::Granted(grant) => grant,
        other => panic!("expected a device grant, got {other:?}"),
    };
    let first_refresh = first.refresh_token.unwrap();
    let second = aos_remote::refresh_token(&origin, &first_refresh)
        .await
        .unwrap();
    let second_refresh = second.refresh_token.unwrap();
    assert_ne!(first_refresh, second_refresh);
    aos_remote::revoke_refresh_token(&origin, &second_refresh)
        .await
        .unwrap();
    assert!(aos_remote::refresh_token(&origin, &second_refresh)
        .await
        .is_err());

    server.abort();
}
