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

use aos_hub::auth::extract::AuthState;
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::db::{Database, OrgQuota, SignupPolicy, TokenAuth};
use aos_hub::domain::{Permission, Principal, Scope};
use aos_hub::server::{router, AppState};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

/// Deterministic HS256 key so tests can mint matching JWTs.
const TEST_JWT_SECRET: &[u8] = b"operations-test-secret-32byte!!!";

/// Build an [`AppState`] over `db` with deterministic JWT keys and a shared
/// rate limiter.
async fn app_state(db: Arc<Database>) -> Arc<AppState> {
    let auth = Arc::new(AuthState {
        db: Arc::clone(&db),
        jwt_keys: JwtKeys::from_secret(TEST_JWT_SECRET),
        access_token_ttl: 900,
        ratelimit: aos_hub::ratelimit::RateLimiter::new().into(),
        trusted_proxy: false,
    });
    Arc::new(AppState {
        db,
        external_url: "http://127.0.0.1:8420".into(),
        ratelimit: auth.ratelimit.clone(),
        trusted_proxy: false,
        auth,
        leases: std::sync::Arc::new(aos_hub::facade::LeaseMap::new()),
        sealer: aos_hub::auth::oidc::dev_sealer(),
        http: aos_hub::fetch::hardened_client().await,
        mailer: std::sync::Arc::new(aos_hub::auth::magic::LogMailer),
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
async fn empty_managed() -> (Arc<Database>, PathBuf) {
    let root = tempfile::tempdir().unwrap().keep();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme, Inc.").await.unwrap();
    let binding = db
        .create_storage_binding(org, "primary", "local_fs", root.to_str().unwrap())
        .await
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
    .await
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
    let (db, _surface) = empty_managed().await;
    let org = db.org_by_slug("acme").await.unwrap().unwrap();
    // A tiny byte budget: 10 bytes.
    db.set_org_quota(
        org.id,
        &OrgQuota {
            max_bytes: Some(10),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
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
    assert_eq!(db.org_usage(org.id).await.unwrap().used_bytes, 4);
    assert_eq!(db.org_usage(org.id).await.unwrap().object_count, 1);

    // A second object pushing past 10 bytes is rejected 507; usage unchanged.
    let (status, _) = put(
        &app,
        "/acme/infra/prod/cdn/objects/ef/gh",
        &token,
        b"too-many-bytes".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(db.org_usage(org.id).await.unwrap().used_bytes, 4);
}

#[tokio::test]
async fn overwrite_with_larger_payload_charges_the_delta() {
    let (db, _surface) = empty_managed().await;
    let org = db.org_by_slug("acme").await.unwrap().unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
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
    assert_eq!(db.org_usage(org.id).await.unwrap().used_bytes, 4);
    assert_eq!(db.org_usage(org.id).await.unwrap().object_count, 1);

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
    assert_eq!(db.org_usage(org.id).await.unwrap().used_bytes, 10);
    assert_eq!(db.org_usage(org.id).await.unwrap().object_count, 1);

    // A shrinking overwrite back to 4 bytes subtracts the delta.
    let (status, _) = put(
        &app,
        "/acme/infra/prod/cdn/objects/ab/cd",
        &token,
        b"abcd".to_vec(),
    )
    .await;
    assert!(status.is_success(), "{status}");
    assert_eq!(db.org_usage(org.id).await.unwrap().used_bytes, 4);
    assert_eq!(db.org_usage(org.id).await.unwrap().object_count, 1);
}

#[tokio::test]
async fn magic_link_issuance_is_rate_limited_per_email() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(db).await).await;
    let body = "email=victim%40acme.com";
    // The first MAGIC_LINK_PER_EMAIL requests succeed (200 "check your email").
    for _ in 0..aos_hub::ratelimit::MAGIC_LINK_PER_EMAIL {
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
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(db).await).await;
    let ip = "198.51.100.4";
    for _ in 0..aos_hub::ratelimit::DEVICE_AUTH_PER_IP {
        let (status, _) = post_form(&app, "/oauth2/device_authorization", "", Some(ip)).await;
        assert_eq!(status, StatusCode::OK, "within-budget device auth");
    }
    let (status, retry) = post_form(&app, "/oauth2/device_authorization", "", Some(ip)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(retry.is_some());
}

#[tokio::test]
async fn signup_policy_gates_create_org() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    // Default policy is invite-only.
    let fresh = db.create_user("nobody@acme.com", None).await.unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
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
    db.set_signup_policy(SignupPolicy::Open).await.unwrap();
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
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    // A user who is already a member of *some* org may create another, even
    // under invite-only.
    let member = db.create_user("dev@acme.com", None).await.unwrap();
    let existing = db.create_org("existing", "Existing").await.unwrap();
    let _ = existing;
    db.grant_membership("user", member, "existing", "developer")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
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
    let (db, surface) = empty_managed().await;
    let org = db.org_by_slug("acme").await.unwrap().unwrap();
    // A managed cache so the manifest's cache slice has something to carry.
    let binding = db
        .list_storage_bindings(org.id)
        .await
        .unwrap()
        .pop()
        .unwrap();
    db.create_cache(
        Some(org.id),
        "acme-cache",
        "Acme Cache",
        Some(binding.id),
        "cache",
        None,
        "public",
        40,
        "zstd",
        true,
    )
    .await
    .unwrap();
    // Members and a token (its hash must never appear in the export).
    let alice = db.create_user("alice@acme.com", None).await.unwrap();
    db.grant_membership("user", alice, "acme", "owner")
        .await
        .unwrap();
    let sa = db
        .create_service_account(org.id, "publisher")
        .await
        .unwrap();
    let (_id, secret) = db
        .create_token(
            Principal::service_account(sa),
            "acme/infra/prod/cdn",
            &[Permission::Publish],
            Some("ci"),
            None,
        )
        .await
        .unwrap();

    // Upload a surface so the surface copy has something to round-trip.
    let app = router(app_state(Arc::clone(&db)).await).await;
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
    let manifest = aos_hub::export::export_org(&db, "acme").await.unwrap();
    let json = serde_json::to_string(&manifest).unwrap();
    assert!(manifest
        .registries
        .iter()
        .any(|r| r.slug == "acme/infra/prod/cdn"));
    assert!(
        manifest
            .caches
            .iter()
            .any(|c| c.slug == "acme-cache" && c.compression == "zstd"),
        "managed cache missing from export manifest"
    );
    assert!(manifest
        .memberships
        .iter()
        .any(|m| m.scope == "acme" && m.role == "owner"));
    assert_eq!(manifest.tokens.len(), 1);
    assert_eq!(manifest.tokens[0].scope, "acme/infra/prod/cdn");
    // No secret, no hash anywhere in the serialized manifest.
    let hash = aos_hub::auth::token::sha256_hex(&secret);
    assert!(!json.contains(&secret), "raw secret leaked into manifest");
    assert!(!json.contains(&hash), "token hash leaked into manifest");

    // The surface copy round-trips the uploaded object byte-for-byte.
    let dest = tempfile::tempdir().unwrap();
    let registry = db
        .registry_by_slug("acme/infra/prod/cdn")
        .await
        .unwrap()
        .unwrap();
    let copied = aos_hub::export::export_registry_surface(&db, registry.id, dest.path())
        .await
        .unwrap();
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

    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    let binding = db
        .create_storage_binding(org, "primary", "local_fs", dir.path().to_str().unwrap())
        .await
        .unwrap();
    db.create_managed_registry(org, "", "cdn", "public", Some(binding), "cdn", &[], false)
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;

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
    assert!(db.soft_delete_org(org, 100).await.unwrap());
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
    assert!(db.restore_org(org).await.unwrap());
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
    assert!(db.soft_delete_org(org, 100).await.unwrap());
    let now = unix_now();
    assert!(
        aos_hub::export::purge_expired_orgs(&db, now)
            .await
            .unwrap()
            .is_empty(),
        "not purgeable inside the grace window"
    );
    let purged = aos_hub::export::purge_expired_orgs(&db, now + 200)
        .await
        .unwrap();
    assert_eq!(purged, vec!["acme".to_string()]);
    // The org (and its cascade) are gone.
    assert!(db
        .org_by_slug_including_deleted("acme")
        .await
        .unwrap()
        .is_none());
}

/// Current Unix time in seconds.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Cross-visibility safety: a public registry must not *advertise* a private
/// cache (its consumers couldn't read it), but may link it without advertising.
#[tokio::test]
async fn link_cache_rejects_advertising_a_less_visible_cache() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    let binding = db
        .create_storage_binding(org, "primary", "local_fs", "/srv")
        .await
        .unwrap();
    db.create_managed_registry(org, "", "pub", "public", Some(binding), "pub", &[], false)
        .await
        .unwrap();
    db.create_cache(
        Some(org),
        "priv-cache",
        "Priv",
        Some(binding),
        "pc",
        None,
        "private",
        40,
        "zstd",
        true,
    )
    .await
    .unwrap();
    // An owner of the org (token grant + live membership; require_permission is
    // two-sided).
    let alice = db.create_user("alice@acme.com", None).await.unwrap();
    db.grant_membership("user", alice, "acme", "owner")
        .await
        .unwrap();
    let token = bearer(
        Principal::user(alice),
        "acme",
        &[Permission::RegistryConfigure],
    );

    let app = router(app_state(Arc::clone(&db)).await).await;

    // Advertising the private cache on the public registry is rejected (400).
    let (status, _v) = rpc(
        &app,
        "CacheService/LinkCache",
        serde_json::json!({
            "cacheSlug": "priv-cache", "registrySlug": "acme/pub", "advertised": true
        }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{_v}");

    // Linking without advertising is allowed (the cache is reachable only to
    // those with cache-read authority; the registry does not point consumers at it).
    let (status, _v) = rpc(
        &app,
        "CacheService/LinkCache",
        serde_json::json!({
            "cacheSlug": "priv-cache", "registrySlug": "acme/pub",
            "advertised": false, "rootsPackages": true
        }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{_v}");
}

/// End-to-end: a key-bearing cache signs uploaded narinfo with its hosted
/// Ed25519 key, and the served narinfo carries the hub `Sig:` line.
#[tokio::test]
async fn keyed_cache_signs_uploaded_narinfo() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    let binding = db
        .create_storage_binding(org, "primary", "local_fs", dir.path().to_str().unwrap())
        .await
        .unwrap();
    // A hosted key sealed with the same dev sealer the test AppState wires.
    let sealer = aos_hub::auth::oidc::dev_sealer();
    db.create_hosted_key(sealer.as_ref(), org, "acme-cache-key")
        .await
        .unwrap();
    let key_id = db
        .hosted_key_by_name(org, "acme-cache-key")
        .await
        .unwrap()
        .unwrap()
        .id;
    db.create_cache(
        Some(org),
        "signed-cache",
        "Signed",
        Some(binding),
        "sc",
        Some(key_id),
        "public",
        40,
        "zstd",
        true,
    )
    .await
    .unwrap();
    // A cache admin (token grant + live owner membership).
    let alice = db.create_user("alice@acme.com", None).await.unwrap();
    db.grant_membership("user", alice, "acme", "owner")
        .await
        .unwrap();
    let token = bearer(
        Principal::user(alice),
        "acme",
        &[Permission::RegistryConfigure],
    );

    let app = router(app_state(Arc::clone(&db)).await).await;
    let narinfo = "StorePath: /nix/store/aaaa-foo-1.0\nURL: nar/bbbb.nar.zst\n\
                   Compression: zstd\nNarHash: sha256:1xyz\nNarSize: 100\nReferences: \n";
    let (status, _) = put(
        &app,
        "/signed-cache/aaaa.narinfo",
        &token,
        narinfo.as_bytes().to_vec(),
    )
    .await;
    assert!(status.is_success(), "upload status {status}");

    // GET the served narinfo back; it must carry the hub signature line.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/signed-cache/aaaa.narinfo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("Sig: acme-cache-key:"),
        "served narinfo must carry the hub signature: {text}"
    );
    assert!(
        text.contains("StorePath: /nix/store/aaaa-foo-1.0"),
        "{text}"
    );

    // The signed cache's home page advertises its Nix public key to pin.
    let home = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/signed-cache/")
                .header(header::ACCEPT, "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(home.status(), StatusCode::OK);
    let home_body = axum::body::to_bytes(home.into_body(), 1 << 20)
        .await
        .unwrap();
    let home_text = String::from_utf8_lossy(&home_body);
    assert!(
        home_text.contains("extra-trusted-public-keys = acme-cache-key:"),
        "cache home advertises the trusted public key: {home_text}"
    );
}

/// A cache on a private external binding serves a presigned 302 redirect to the
/// origin instead of bytes (authenticated-origin read; the client fetches S3).
#[tokio::test]
async fn private_binding_cache_serves_presigned_302() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    let binding = db
        .create_storage_binding(org, "primary", "local_fs", "/srv")
        .await
        .unwrap();
    // Seal the origin credentials with the same dev sealer the AppState wires.
    let sealer = aos_hub::auth::oidc::dev_sealer();
    let sealed = sealer.seal("AKIDEXAMPLE:secretkey:us-east-1").unwrap();
    db.set_storage_binding_access(
        binding,
        "private",
        Some("https://bucket.s3.example.com"),
        Some(&sealed),
    )
    .await
    .unwrap();
    // A *public* cache (anyone may read) on that *private* binding (bytes are
    // never served by the hub — only presigned).
    db.create_cache(
        Some(org),
        "ext-cache",
        "Ext",
        Some(binding),
        "pfx",
        None,
        "public",
        40,
        "zstd",
        true,
    )
    .await
    .unwrap();

    let app = router(app_state(Arc::clone(&db)).await).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ext-cache/aaaa.narinfo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND, "expected a 302 redirect");
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        location.starts_with("https://bucket.s3.example.com/pfx/aaaa.narinfo?"),
        "presigned origin URL: {location}"
    );
    assert!(location.contains("X-Amz-Signature="), "{location}");
    assert!(
        location.contains("X-Amz-Credential=AKIDEXAMPLE"),
        "{location}"
    );
    // The secret never appears in the redirect.
    assert!(!location.contains("secretkey"), "secret leaked: {location}");

    // A traversal path must NOT mint a presigned URL escaping the prefix — it is
    // rejected before signing (and 404s downstream), never a 302.
    let escape = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ext-cache/nar/../../other/secret.nar")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        escape.status(),
        StatusCode::FOUND,
        "traversal path must not be presigned"
    );
}

/// A cache on a private external binding whose primary frontend opts into
/// streamed proxying serves the origin's bytes *through the hub* (a `200`/`206`),
/// not a `302` — proving the shared `cache_serve` streamed-proxy branch and the
/// native `ReqwestOriginFetch` origin fetcher, range-forwarded end to end.
#[tokio::test]
async fn private_binding_cache_streams_origin_when_frontend_opts_in() {
    // A mock S3-style origin: serves a fixed object, honoring a `bytes=a-b`
    // Range with a `206` + `Content-Range` so the proxied ranged read is real.
    let object = b"NARINFO-FROM-PRIVATE-ORIGIN-streamed-through-the-hub\n".to_vec();
    let total = object.len();
    let serve_body = object.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = listener.local_addr().unwrap();
    let mock = axum::Router::new().fallback(move |headers: axum::http::HeaderMap| {
        let body = serve_body.clone();
        async move {
            // Honor a single `bytes=start-end` range; otherwise serve the whole
            // object. (The fallback ignores the request path — every signed key
            // resolves to the one fixture object.)
            if let Some((start, end)) = headers
                .get(header::RANGE)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("bytes="))
                .and_then(|v| v.split_once('-'))
                .and_then(|(s, e)| Some((s.parse::<usize>().ok()?, e.parse::<usize>().ok()?)))
            {
                let end = end.min(total - 1);
                let slice = body[start..=end].to_vec();
                axum::response::Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header(
                        header::CONTENT_RANGE,
                        format!("bytes {start}-{end}/{total}"),
                    )
                    .header(header::CONTENT_LENGTH, slice.len())
                    .body(Body::from(slice))
                    .unwrap()
            } else {
                axum::response::Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_LENGTH, body.len())
                    .body(Body::from(body))
                    .unwrap()
            }
        }
    });
    tokio::spawn(async move {
        axum::serve(listener, mock).await.unwrap();
    });

    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    let binding = db
        .create_storage_binding(org, "primary", "local_fs", "/srv")
        .await
        .unwrap();
    let sealer = aos_hub::auth::oidc::dev_sealer();
    let sealed = sealer.seal("AKIDEXAMPLE:secretkey:us-east-1").unwrap();
    db.set_storage_binding_access(
        binding,
        "private",
        Some(&format!("http://{origin_addr}")),
        Some(&sealed),
    )
    .await
    .unwrap();
    let cache = db
        .create_cache(
            Some(org),
            "ext-cache",
            "Ext",
            Some(binding),
            "pfx",
            None,
            "public",
            40,
            "zstd",
            true,
        )
        .await
        .unwrap();
    // A primary, proxied frontend that opts into streaming engages the proxy path.
    let fe = db
        .create_cache_frontend(
            cache,
            "ext-cache.example.com",
            "/",
            "proxied",
            true,
            100,
            true,
        )
        .await
        .unwrap();
    db.set_frontend_proxy(
        fe,
        Some(&aos_hub::db::ProxyConfig {
            stream: true,
            ..Default::default()
        }),
        true,
    )
    .await
    .unwrap();

    let app = router(app_state(Arc::clone(&db)).await).await;

    // Whole read: streamed through the hub as a 200 carrying the origin's bytes
    // (NOT a 302 — the client never sees the origin).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ext-cache/aaaa.narinfo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "streamed proxy serves bytes, not a redirect"
    );
    let got = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    assert_eq!(
        got.as_ref(),
        object.as_slice(),
        "proxied body matches origin"
    );

    // Ranged read: the hub forwards the Range to the origin and relays its 206.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ext-cache/aaaa.narinfo")
                .header(header::RANGE, "bytes=0-3")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::PARTIAL_CONTENT,
        "ranged proxy -> 206"
    );
    let cr = resp
        .headers()
        .get(header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert_eq!(cr, format!("bytes 0-3/{total}"), "relayed Content-Range");
    let got = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    assert_eq!(got.as_ref(), &object[0..=3], "proxied ranged body");

    // The `max_body_bytes` guard rejects an origin object larger than the cap:
    // shrink it below the object size and the proxied read must fail closed
    // (not stream an over-cap body through the hub).
    db.set_frontend_proxy(
        fe,
        Some(&aos_hub::db::ProxyConfig {
            stream: true,
            max_body_bytes: (total as u64) - 1,
            ..Default::default()
        }),
        true,
    )
    .await
    .unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ext-cache/aaaa.narinfo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "an over-cap origin object must not be proxied through the hub"
    );
}

/// MintCacheUploadCredentials returns a presigned PUT URL for a presign-mode
/// cache's object, gated on cache-write authority.
#[tokio::test]
async fn mint_cache_upload_credentials_returns_presigned_put() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    let binding = db
        .create_storage_binding(org, "primary", "local_fs", "/srv")
        .await
        .unwrap();
    let sealer = aos_hub::auth::oidc::dev_sealer();
    let sealed = sealer.seal("AKIDEXAMPLE:secretkey:us-east-1").unwrap();
    db.set_storage_binding_access(
        binding,
        "private",
        Some("https://bucket.s3.example.com"),
        Some(&sealed),
    )
    .await
    .unwrap();
    db.create_cache(
        Some(org),
        "ext-cache",
        "Ext",
        Some(binding),
        "pfx",
        None,
        "public",
        40,
        "zstd",
        true,
    )
    .await
    .unwrap();
    let alice = db.create_user("alice@acme.com", None).await.unwrap();
    db.grant_membership("user", alice, "acme", "owner")
        .await
        .unwrap();
    let token = bearer(
        Principal::user(alice),
        "acme",
        &[Permission::RegistryConfigure],
    );

    let app = router(app_state(Arc::clone(&db)).await).await;
    let (status, body) = rpc(
        &app,
        "CacheService/MintCacheUploadCredentials",
        serde_json::json!({"cacheSlug": "ext-cache", "path": "aaaa.narinfo"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let url = body
        .get("uploadUrl")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        url.starts_with("https://bucket.s3.example.com/pfx/aaaa.narinfo?"),
        "{url}"
    );
    assert!(url.contains("X-Amz-Signature="), "{url}");
    assert!(!url.contains("secretkey"), "secret leaked: {url}");

    // Without cache-write authority, the RPC is denied.
    let (status, _) = rpc(
        &app,
        "CacheService/MintCacheUploadCredentials",
        serde_json::json!({"cacheSlug": "ext-cache", "path": "aaaa.narinfo"}),
        None,
    )
    .await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "unauthenticated mint must be denied, got {status}"
    );
}

/// End-to-end GC closure-correctness through the RPC layer with a real
/// surface: a rooted (pinned) object survives a sweep; an unrooted one is
/// reclaimed (its narinfo gone). RFC-0004 "11-caches" closure-correctness.
#[tokio::test]
async fn cache_gc_keeps_rooted_and_reclaims_unrooted_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    let binding = db
        .create_storage_binding(org, "primary", "local_fs", dir.path().to_str().unwrap())
        .await
        .unwrap();
    db.create_cache(
        Some(org),
        "gc-cache",
        "GC",
        Some(binding),
        "g",
        None,
        "public",
        40,
        "zstd",
        true,
    )
    .await
    .unwrap();
    let alice = db.create_user("alice@acme.com", None).await.unwrap();
    db.grant_membership("user", alice, "acme", "owner")
        .await
        .unwrap();
    let token = bearer(
        Principal::user(alice),
        "acme",
        &[Permission::RegistryConfigure],
    );
    let app = router(app_state(Arc::clone(&db)).await).await;

    // Upload a rooted object (aaaa) and an unrooted object (dddd); each narinfo
    // is indexed via the upload write-through.
    let narinfo = |hash: &str| {
        format!(
            "StorePath: /nix/store/{hash}-pkg\nURL: nar/{hash}.nar\nCompression: none\n\
             NarHash: sha256:{hash}\nNarSize: 1\nFileHash: sha256:{hash}\nFileSize: 1\nReferences: \n"
        )
    };
    for hash in ["aaaa", "dddd"] {
        let (s, _) = put(
            &app,
            &format!("/gc-cache/{hash}.narinfo"),
            &token,
            narinfo(hash).into_bytes(),
        )
        .await;
        assert!(s.is_success(), "upload {hash}: {s}");
    }
    // Pin aaaa as a manual GC root.
    let (s, _) = rpc(
        &app,
        "CacheService/PinCachePath",
        serde_json::json!({"cacheSlug": "gc-cache", "storeHash": "aaaa"}),
        Some(&token),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // ttl=0 sweeps unrooted objects immediately (now - uploaded_at >= 0 always),
    // so reclamation is timing-independent; the rooted closure is never swept.
    let cache_id = db.cache_by_slug("gc-cache").await.unwrap().unwrap().id;
    db.set_cache_gc_policy(&aos_hub::db::CacheGcPolicy {
        cache_id,
        max_bytes: None,
        max_objects: None,
        ttl_unreferenced_secs: Some(0),
        keep_release_versions: None,
        keep_channel_frontier: true,
        schedule_secs: None,
        updated_at: 0,
    })
    .await
    .unwrap();

    // Run GC: it scans both, retains the rooted closure, reclaims the unrooted.
    let (s, body) = rpc(
        &app,
        "CacheService/RunCacheGc",
        serde_json::json!({"cacheSlug": "gc-cache"}),
        Some(&token),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["scanned"].as_i64(), Some(2), "{body}");
    assert_eq!(body["retained"].as_i64(), Some(1), "{body}");
    assert_eq!(body["deletedObjects"].as_i64(), Some(1), "{body}");

    // The rooted object survives; the unrooted one is reclaimed (GetCacheObject
    // returns 200 with a null `object` for a missing entry).
    let (s, body) = rpc(
        &app,
        "CacheService/GetCacheObject",
        serde_json::json!({"cacheSlug": "gc-cache", "storeHash": "aaaa"}),
        Some(&token),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        body.get("object").is_some_and(|o| !o.is_null()),
        "rooted object must survive: {body}"
    );
    let (s, body) = rpc(
        &app,
        "CacheService/GetCacheObject",
        serde_json::json!({"cacheSlug": "gc-cache", "storeHash": "dddd"}),
        Some(&token),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        body.get("object").is_none_or(|o| o.is_null()),
        "unrooted object must be reclaimed: {body}"
    );
}
