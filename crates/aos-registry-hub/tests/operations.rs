//! Operations-chapter integration coverage (RFC-0004 "Operations:
//! migrations, backup, quotas, observability, offboarding").
//!
//! Drives the real router and database for the operations surface:
//!
//! - the upload facade's `507 Insufficient Storage` quota gate and the running
//!   usage increment a successful upload makes;
//! - the per-endpoint rate limiter returning `429` with `Retry-After` on the
//!   magic-link issuance and device-authorization paths;
//! - the instance signup policy gating `OrgService.CreateOrg`;
//! - org export — a redacted SoR manifest plus a round-trippable surface copy;
//! - org soft-delete excluding a registry from serving, restore, and the
//!   grace-window purge job.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use aos_registry_hub::auth::extract::AuthState;
use aos_registry_hub::auth::jwt::JwtKeys;
use aos_registry_hub::db::{Database, OrgQuota, SignupPolicy, TokenAuth};
use aos_registry_hub::domain::{Permission, Principal, Scope};
use aos_registry_hub::server::{router, AppState};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

/// Deterministic HS256 key so tests can mint matching JWTs.
const TEST_JWT_SECRET: &[u8] = b"operations-test-secret-32byte!!!";

/// Build an [`AppState`] over `db` with deterministic JWT keys and a shared
/// rate limiter.
fn app_state(db: Arc<Database>) -> Arc<AppState> {
    let auth = Arc::new(AuthState {
        db: Arc::clone(&db),
        jwt_keys: JwtKeys::from_secret(TEST_JWT_SECRET),
        access_token_ttl: 900,
        ratelimit: aos_registry_hub::ratelimit::RateLimiter::new().into(),
        trusted_proxy: false,
    });
    Arc::new(AppState {
        db,
        external_url: "http://127.0.0.1:8420".into(),
        ratelimit: auth.ratelimit.clone(),
        trusted_proxy: false,
        auth,
        leases: aos_registry_hub::facade::LeaseMap::new(),
        sealer: aos_registry_hub::auth::oidc::dev_sealer(),
        http: aos_registry_hub::fetch::hardened_client(),
        mailer: std::sync::Arc::new(aos_registry_hub::auth::magic::LogMailer),
        dev: false,
    })
}

/// Mint a bearer JWT for `principal` scoped to `scope` with `perms`.
fn bearer(principal: Principal, scope: &str, perms: &[Permission]) -> String {
    JwtKeys::from_secret(TEST_JWT_SECRET)
        .mint(
            &TokenAuth {
                token_id: "test-token".into(),
                owner: principal,
                scope: Scope::parse(scope),
                permissions: perms.to_vec(),
            },
            900,
        )
        .unwrap()
}

/// Create org "acme", a `local_fs` binding over an empty dir, and a managed
/// registry at `acme/infra/prod/cdn` bound to it (prefix `cdn`). Returns
/// `(db, surface_root)`.
fn empty_managed() -> (Arc<Database>, PathBuf) {
    let root = tempfile::tempdir().unwrap().keep();
    let db = Arc::new(Database::open_in_memory().unwrap());
    let org = db.create_org("acme", "Acme, Inc.").unwrap();
    let binding = db
        .create_storage_binding(org, "primary", "local_fs", root.to_str().unwrap())
        .unwrap();
    db.create_managed_registry(
        org,
        "infra/prod",
        "cdn",
        "public",
        Some(binding),
        "cdn",
        &[],
        false,
    )
    .unwrap();
    (db, root.join("cdn"))
}

/// `PUT` one surface file, returning the `(status, retry_after)`.
async fn put(
    app: &axum::Router,
    uri: &str,
    auth: &str,
    body: Vec<u8>,
) -> (StatusCode, Option<String>) {
    let req = Request::builder()
        .method("PUT")
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {auth}"))
        .body(Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let retry = resp
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (resp.status(), retry)
}

/// POST a form body, returning `(status, retry_after)`.
async fn post_form(
    app: &axum::Router,
    uri: &str,
    body: &str,
    forwarded_for: Option<&str>,
) -> (StatusCode, Option<String>) {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(xff) = forwarded_for {
        req = req.header("x-forwarded-for", xff);
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let retry = resp
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (resp.status(), retry)
}

/// POST a Connect-JSON RPC body, returning `(status, body)`.
async fn rpc(
    app: &axum::Router,
    method: &str,
    json: serde_json::Value,
    auth: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/aos.registry.v1.{method}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("connect-protocol-version", "1");
    if let Some(auth) = auth {
        req = req.header(header::AUTHORIZATION, format!("Bearer {auth}"));
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::from(json.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

#[tokio::test]
async fn upload_over_byte_quota_returns_507_and_under_increments_usage() {
    let (db, _surface) = empty_managed();
    let org = db.org_by_slug("acme").unwrap().unwrap();
    // A tiny byte budget: 10 bytes.
    db.set_org_quota(
        org.id,
        &OrgQuota {
            max_bytes: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    let app = router(app_state(Arc::clone(&db)));
    let token = bearer(
        Principal::service_account(1),
        "acme/infra/prod/cdn",
        &[Permission::Publish],
    );

    // A 4-byte object fits and increments usage.
    let (status, _) = put(
        &app,
        "/acme/infra/prod/cdn/objects/ab/cd",
        &token,
        b"data".to_vec(),
    )
    .await;
    assert!(status.is_success(), "{status}");
    assert_eq!(db.org_usage(org.id).unwrap().used_bytes, 4);
    assert_eq!(db.org_usage(org.id).unwrap().object_count, 1);

    // A second object pushing past 10 bytes is rejected 507; usage unchanged.
    let (status, _) = put(
        &app,
        "/acme/infra/prod/cdn/objects/ef/gh",
        &token,
        b"too-many-bytes".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(db.org_usage(org.id).unwrap().used_bytes, 4);
}

#[tokio::test]
async fn overwrite_with_larger_payload_charges_the_delta() {
    let (db, _surface) = empty_managed();
    let org = db.org_by_slug("acme").unwrap().unwrap();
    let app = router(app_state(Arc::clone(&db)));
    let token = bearer(
        Principal::service_account(1),
        "acme/infra/prod/cdn",
        &[Permission::Publish],
    );

    // Initial write of a 4-byte object: usage is 4 bytes / 1 object.
    let (status, _) = put(
        &app,
        "/acme/infra/prod/cdn/objects/ab/cd",
        &token,
        b"data".to_vec(),
    )
    .await;
    assert!(status.is_success(), "{status}");
    assert_eq!(db.org_usage(org.id).unwrap().used_bytes, 4);
    assert_eq!(db.org_usage(org.id).unwrap().object_count, 1);

    // Overwrite the same path with a larger 10-byte payload: usage grows by the
    // 6-byte delta (not the full 10), and the object count is unchanged.
    let (status, _) = put(
        &app,
        "/acme/infra/prod/cdn/objects/ab/cd",
        &token,
        b"ten-bytes!".to_vec(),
    )
    .await;
    assert!(status.is_success(), "{status}");
    assert_eq!(db.org_usage(org.id).unwrap().used_bytes, 10);
    assert_eq!(db.org_usage(org.id).unwrap().object_count, 1);

    // A shrinking overwrite back to 4 bytes subtracts the delta.
    let (status, _) = put(
        &app,
        "/acme/infra/prod/cdn/objects/ab/cd",
        &token,
        b"abcd".to_vec(),
    )
    .await;
    assert!(status.is_success(), "{status}");
    assert_eq!(db.org_usage(org.id).unwrap().used_bytes, 4);
    assert_eq!(db.org_usage(org.id).unwrap().object_count, 1);
}

#[tokio::test]
async fn magic_link_issuance_is_rate_limited_per_email() {
    let db = Arc::new(Database::open_in_memory().unwrap());
    let app = router(app_state(db));
    let body = "email=victim%40acme.com";
    // The first MAGIC_LINK_PER_EMAIL requests succeed (200 "check your email").
    for _ in 0..aos_registry_hub::ratelimit::MAGIC_LINK_PER_EMAIL {
        let (status, _) = post_form(&app, "/login", body, Some("203.0.113.7")).await;
        assert_eq!(status, StatusCode::OK, "within-budget magic link");
    }
    // The next one for the same email is 429 with a Retry-After.
    let (status, retry) = post_form(&app, "/login", body, Some("203.0.113.7")).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(retry.is_some(), "Retry-After present on 429");
}

#[tokio::test]
async fn device_authorization_is_rate_limited_per_ip() {
    let db = Arc::new(Database::open_in_memory().unwrap());
    let app = router(app_state(db));
    let ip = "198.51.100.4";
    for _ in 0..aos_registry_hub::ratelimit::DEVICE_AUTH_PER_IP {
        let (status, _) = post_form(&app, "/oauth2/device_authorization", "", Some(ip)).await;
        assert_eq!(status, StatusCode::OK, "within-budget device auth");
    }
    let (status, retry) = post_form(&app, "/oauth2/device_authorization", "", Some(ip)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(retry.is_some());
}

#[tokio::test]
async fn signup_policy_gates_create_org() {
    let db = Arc::new(Database::open_in_memory().unwrap());
    // Default policy is invite-only.
    let fresh = db.create_user("nobody@acme.com", None).unwrap();
    let app = router(app_state(Arc::clone(&db)));
    let token = bearer(Principal::user(fresh), "", &[]);

    // invite_only blocks a fresh, unaffiliated user.
    let (status, _) = rpc(
        &app,
        "OrgService/CreateOrg",
        serde_json::json!({"slug": "acme", "name": "Acme"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Switch to open: the same user may now create an org.
    db.set_signup_policy(SignupPolicy::Open).unwrap();
    let (status, value) = rpc(
        &app,
        "OrgService/CreateOrg",
        serde_json::json!({"slug": "acme", "name": "Acme"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
}

#[tokio::test]
async fn invite_only_allows_existing_member() {
    let db = Arc::new(Database::open_in_memory().unwrap());
    // A user who is already a member of *some* org may create another, even
    // under invite-only.
    let member = db.create_user("dev@acme.com", None).unwrap();
    let existing = db.create_org("existing", "Existing").unwrap();
    let _ = existing;
    db.grant_membership("user", member, "existing", "developer")
        .unwrap();
    let app = router(app_state(Arc::clone(&db)));
    let token = bearer(Principal::user(member), "", &[]);
    let (status, value) = rpc(
        &app,
        "OrgService/CreateOrg",
        serde_json::json!({"slug": "second", "name": "Second"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
}

#[tokio::test]
async fn org_export_manifest_redacts_secrets_and_surface_round_trips() {
    let (db, surface) = empty_managed();
    let org = db.org_by_slug("acme").unwrap().unwrap();
    // Members and a token (its hash must never appear in the export).
    let alice = db.create_user("alice@acme.com", None).unwrap();
    db.grant_membership("user", alice, "acme", "owner").unwrap();
    let sa = db.create_service_account(org.id, "publisher").unwrap();
    let (_id, secret) = db
        .create_token(
            Principal::service_account(sa),
            "acme/infra/prod/cdn",
            &[Permission::Publish],
            Some("ci"),
            None,
        )
        .unwrap();

    // Upload a surface so the surface copy has something to round-trip.
    let app = router(app_state(Arc::clone(&db)));
    let token = bearer(
        Principal::service_account(sa),
        "acme/infra/prod/cdn",
        &[Permission::Publish],
    );
    let (status, _) = put(
        &app,
        "/acme/infra/prod/cdn/objects/ab/cd",
        &token,
        b"surface-bytes".to_vec(),
    )
    .await;
    assert!(status.is_success());
    assert!(surface.join("objects/ab/cd").exists());

    // The manifest carries the registry + members + token metadata, but no
    // hash/secret.
    let manifest = aos_registry_hub::export::export_org(&db, "acme").unwrap();
    let json = serde_json::to_string(&manifest).unwrap();
    assert!(manifest
        .registries
        .iter()
        .any(|r| r.slug == "acme/infra/prod/cdn"));
    assert!(manifest
        .memberships
        .iter()
        .any(|m| m.scope == "acme" && m.role == "owner"));
    assert_eq!(manifest.tokens.len(), 1);
    assert_eq!(manifest.tokens[0].scope, "acme/infra/prod/cdn");
    // No secret, no hash anywhere in the serialized manifest.
    let hash = aos_registry_hub::auth::token::sha256_hex(&secret);
    assert!(!json.contains(&secret), "raw secret leaked into manifest");
    assert!(!json.contains(&hash), "token hash leaked into manifest");

    // The surface copy round-trips the uploaded object byte-for-byte.
    let dest = tempfile::tempdir().unwrap();
    let registry = db.registry_by_slug("acme/infra/prod/cdn").unwrap().unwrap();
    let copied =
        aos_registry_hub::export::export_registry_surface(&db, registry.id, dest.path()).unwrap();
    assert!(copied >= 1);
    assert_eq!(
        std::fs::read(dest.path().join("objects/ab/cd")).unwrap(),
        b"surface-bytes"
    );
}

#[tokio::test]
async fn soft_deleted_org_stops_serving_and_purges_after_grace() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("cdn");
    let fixture = common::standard_registry(&surface);
    let _ = &fixture;

    let db = Arc::new(Database::open_in_memory().unwrap());
    let org = db.create_org("acme", "Acme").unwrap();
    let binding = db
        .create_storage_binding(org, "primary", "local_fs", dir.path().to_str().unwrap())
        .unwrap();
    db.create_managed_registry(org, "", "cdn", "public", Some(binding), "cdn", &[], false)
        .unwrap();
    let app = router(app_state(Arc::clone(&db)));

    // Before deletion the registry home serves.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/acme/cdn/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Soft-delete: the registry now 404s (tombstoned, non-disclosing).
    assert!(db.soft_delete_org(org, 100).unwrap());
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/acme/cdn/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Restore brings it back.
    assert!(db.restore_org(org).unwrap());
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/acme/cdn/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Re-delete and purge past the grace window.
    assert!(db.soft_delete_org(org, 100).unwrap());
    let now = unix_now();
    assert!(
        aos_registry_hub::export::purge_expired_orgs(&db, now)
            .unwrap()
            .is_empty(),
        "not purgeable inside the grace window"
    );
    let purged = aos_registry_hub::export::purge_expired_orgs(&db, now + 200).unwrap();
    assert_eq!(purged, vec!["acme".to_string()]);
    // The org (and its cascade) are gone.
    assert!(db.org_by_slug_including_deleted("acme").unwrap().is_none());
}

/// Current Unix time in seconds.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
