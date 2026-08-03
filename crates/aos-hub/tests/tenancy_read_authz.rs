//! Tenancy read-path authorization for the `aos.hub.v1` RPCs (sec H-2, H-3).
//!
//! Drives the real axum router with Connect-JSON `POST`s, with and without a
//! bearer JWT, to prove the read-path services do not disclose another tenant's
//! data to a caller who could not open the corresponding browse page:
//!
//! - **H-2** — `ListPackages`/`GetPackage`/`ListChannels`/`GetChannel`/`GetRegistry`
//!   gate non-public registries through `require_read`, so an anonymous read of a
//!   `private`/`internal` registry is denied (and its data never returned) while a
//!   `public` registry still reads anonymously. `ListRegistries` visibility-filters
//!   its page (dropping records the caller may not read, not erroring the call).
//! - **H-3** — `ListProjects`/`ListBindings`/`ListOrgs` require an authenticated
//!   member; an anonymous caller is denied/empty, a member sees their org's data,
//!   and a binding's `root` host path is redacted from a non-admin member.

mod common;

use std::sync::Arc;

use aos_hub::auth::extract::AuthState;
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::db::{ChannelSummary, Database, IndexSnapshot, TokenAuth};
use aos_hub::domain::{Permission, Principal, Scope};
use aos_hub::server::{router, AppState};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

/// Deterministic HS256 key so tests can mint matching JWTs.
const TEST_JWT_SECRET: &[u8] = b"tenancy-test-secret-32byte-key!!";

/// Build an [`AppState`] over `db` with deterministic JWT keys.
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
        mailer: Arc::new(aos_hub::auth::magic::LogMailer),
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

/// POST a Connect-JSON RPC body, returning `(status, body)`.
async fn rpc(
    app: &axum::Router,
    method: &str,
    json: serde_json::Value,
    auth: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/aos.hub.v1.{method}"))
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

/// Seed one package and one channel into `registry_id` so a successful read
/// returns observable data (and a denied read can be proven to return none).
async fn seed_inventory(db: &Database, registry_id: i64) {
    let package: aos_package::registry::parse::PackageToml = toml::from_str(
        r#"
        [package]
        name = "curl"
        description = "URL transfers"
        license = "MIT"
        maintainer = "aos"
        [[versions]]
        version = "8.5.0"
        [versions.platforms.x86_64-linux]
        store_path = "/var/lib/store/secret-curl-8.5.0"
        nar_hash = "sha256:aa"
        nar_size = 10
        closure_size = 20
        source_drv = "/var/lib/store/secret-curl-8.5.0.drv"
        source_nar_hash = "sha256:bb"
        "#,
    )
    .unwrap();
    let snapshot = IndexSnapshot {
        commit: "c".repeat(64),
        name: "secret".into(),
        description: None,
        readme: None,
        caches: Vec::new(),
        roster: Vec::new(),
        packages: vec![package],
        releases: Vec::new(),
        channels: vec![ChannelSummary {
            name: "stable".into(),
            frontier: Some("8.5.0".into()),
            partitions: vec![Some("8.5.0".into()); 256],
        }],
        refs_digest: None,
        cache_stack: None,
    };
    db.apply_snapshot(registry_id, &snapshot).await.unwrap();
}

/// Connect maps `PermissionDenied`/`Unauthenticated` to 403/401 and `NotFound`
/// to 404 — any of these is a valid "denied" outcome for a hidden registry.
fn is_denied(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::NOT_FOUND | StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED
    )
}

// -- H-2: package / channel / registry read gating --------------------------

#[tokio::test]
async fn private_registry_inventory_is_denied_to_anonymous() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("victim", "Victim").await.unwrap();
    let binding = db
        .create_storage_binding(org, "b", "local_fs", "/var/lib/aos/storage/victim")
        .await
        .unwrap();
    let id = db
        .create_managed_registry(
            org,
            "internal",
            "secret",
            "private",
            Some(binding),
            "",
            &[],
            false,
        )
        .await
        .unwrap();
    seed_inventory(&db, id).await;
    let slug = db.registry_by_id(id).await.unwrap().unwrap().slug;
    let app = router(app_state(Arc::clone(&db)).await).await;

    // Every package/channel/registry read of the private registry is denied,
    // and no inventory leaks in the body.
    for (method, extra) in [
        ("PackageService/ListPackages", serde_json::Map::new()),
        ("ChannelService/ListChannels", serde_json::Map::new()),
        ("RegistryService/GetRegistry", serde_json::Map::new()),
    ] {
        let mut body = serde_json::Map::new();
        body.insert("slug".into(), slug.clone().into());
        body.extend(extra);
        let (status, resp) = rpc(&app, method, serde_json::Value::Object(body), None).await;
        assert!(
            is_denied(status),
            "{method} anon must be denied, got {status}"
        );
        let text = resp.to_string();
        assert!(
            !text.contains("curl") && !text.contains("secret-curl"),
            "{method} must not leak inventory: {text}"
        );
    }

    let (status, resp) = rpc(
        &app,
        "PackageService/GetPackage",
        serde_json::json!({ "slug": slug, "name": "curl" }),
        None,
    )
    .await;
    assert!(is_denied(status), "GetPackage anon denied, got {status}");
    assert!(
        !resp.to_string().contains("/var/lib/store/secret"),
        "GetPackage must not leak a store path: {resp}"
    );

    let (status, _resp) = rpc(
        &app,
        "ChannelService/GetChannel",
        serde_json::json!({ "slug": slug, "name": "stable" }),
        None,
    )
    .await;
    assert!(is_denied(status), "GetChannel anon denied, got {status}");

    // A member with Read on the registry's org scope CAN read it.
    db.grant_membership("user", 7, "victim", "viewer")
        .await
        .unwrap();
    let member = bearer(Principal::user(7), "victim", &[Permission::Read]);
    let (status, resp) = rpc(
        &app,
        "PackageService/ListPackages",
        serde_json::json!({ "slug": slug }),
        Some(&member),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "member read: {resp}");
    assert_eq!(resp["packages"][0]["name"], "curl");
}

#[tokio::test]
async fn public_registry_inventory_reads_anonymously() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    let id = db
        .create_managed_registry(org, "", "cdn", "public", None, "", &[], false)
        .await
        .unwrap();
    seed_inventory(&db, id).await;
    let slug = db.registry_by_id(id).await.unwrap().unwrap().slug;
    let app = router(app_state(Arc::clone(&db)).await).await;

    // Anonymous public reads still work and return the data.
    let (status, resp) = rpc(
        &app,
        "PackageService/ListPackages",
        serde_json::json!({ "slug": slug }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "anon public ListPackages: {resp}");
    assert_eq!(resp["packages"][0]["name"], "curl");

    let (status, resp) = rpc(
        &app,
        "ChannelService/ListChannels",
        serde_json::json!({ "slug": slug }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "anon public ListChannels: {resp}");
    assert_eq!(resp["channels"][0]["name"], "stable");

    let (status, resp) = rpc(
        &app,
        "RegistryService/GetRegistry",
        serde_json::json!({ "slug": slug }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "anon public GetRegistry: {resp}");
}

#[tokio::test]
async fn list_registries_filters_private_and_soft_deleted() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    db.create_managed_registry(org, "", "cdn", "public", None, "", &[], false)
        .await
        .unwrap();
    db.create_managed_registry(org, "", "secret", "private", None, "", &[], false)
        .await
        .unwrap();
    // A second org whose registry is hidden once the org is soft-deleted.
    let gone = db.create_org("gone", "Gone").await.unwrap();
    db.create_managed_registry(gone, "", "pub", "public", None, "", &[], false)
        .await
        .unwrap();
    db.soft_delete_org(gone, 30 * 86_400).await.unwrap();

    let app = router(app_state(Arc::clone(&db)).await).await;

    // Anonymous: only the live public registry is listed.
    let (status, resp) = rpc(
        &app,
        "RegistryService/ListRegistries",
        serde_json::json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "anon ListRegistries: {resp}");
    let slugs: Vec<&str> = resp["registries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["slug"].as_str().unwrap())
        .collect();
    assert_eq!(slugs, vec!["acme/cdn"], "only the live public registry");

    // A member of acme additionally sees acme's private registry, but never the
    // soft-deleted org's registry.
    db.grant_membership("user", 1, "acme", "viewer")
        .await
        .unwrap();
    let member = bearer(Principal::user(1), "acme", &[Permission::Read]);
    let (status, resp) = rpc(
        &app,
        "RegistryService/ListRegistries",
        serde_json::json!({}),
        Some(&member),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "member ListRegistries: {resp}");
    let mut slugs: Vec<&str> = resp["registries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["slug"].as_str().unwrap())
        .collect();
    slugs.sort_unstable();
    assert_eq!(slugs, vec!["acme/cdn", "acme/secret"]);
    assert!(
        !slugs.iter().any(|s| s.starts_with("gone/")),
        "soft-deleted org's registry must never appear"
    );
}

// -- H-3: project / binding / org listing gating ----------------------------

#[tokio::test]
async fn list_orgs_requires_membership_and_filters() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    db.create_org("globex", "Globex").await.unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;

    // Anonymous enumeration is denied (was the per-slug harvest primitive).
    let (status, _resp) = rpc(
        &app,
        "OrganizationService/ListOrgs",
        serde_json::json!({}),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "anon ListOrgs must be denied"
    );

    // A member of acme sees only acme, never globex.
    db.grant_membership("user", 1, "acme", "viewer")
        .await
        .unwrap();
    let member = bearer(Principal::user(1), "acme", &[Permission::Read]);
    let (status, resp) = rpc(
        &app,
        "OrganizationService/ListOrgs",
        serde_json::json!({}),
        Some(&member),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "member ListOrgs: {resp}");
    let slugs: Vec<&str> = resp["orgs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["slug"].as_str().unwrap())
        .collect();
    assert_eq!(slugs, vec!["acme"], "only the caller's org");
}

#[tokio::test]
async fn list_projects_requires_membership() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    db.create_project(org, "team", "team").await.unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;

    // Anonymous is denied — the project tree never leaks.
    let (status, resp) = rpc(
        &app,
        "ProjectService/ListProjects",
        serde_json::json!({ "orgSlug": "acme" }),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "anon ListProjects denied: {resp}"
    );

    // A member sees the org's projects.
    db.grant_membership("user", 1, "acme", "viewer")
        .await
        .unwrap();
    let member = bearer(Principal::user(1), "acme", &[Permission::Read]);
    let (status, resp) = rpc(
        &app,
        "ProjectService/ListProjects",
        serde_json::json!({ "orgSlug": "acme" }),
        Some(&member),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "member ListProjects: {resp}");
    assert_eq!(resp["projects"][0]["path"], "team");
}

#[tokio::test]
async fn list_bindings_requires_membership_and_redacts_root_for_non_admin() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    db.create_storage_binding(org, "primary", "local_fs", "/var/lib/aos/storage/acme")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;

    // Anonymous is denied — the host path never leaks.
    let (status, resp) = rpc(
        &app,
        "StorageBindingService/ListBindings",
        serde_json::json!({ "orgSlug": "acme" }),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "anon ListBindings denied: {resp}"
    );

    // A non-admin member may list bindings (name/kind) but the host `root` is
    // redacted — proto3 JSON omits an empty string field entirely.
    db.grant_membership("user", 2, "acme", "viewer")
        .await
        .unwrap();
    let member = bearer(Principal::user(2), "acme", &[Permission::Read]);
    let (status, resp) = rpc(
        &app,
        "StorageBindingService/ListBindings",
        serde_json::json!({ "orgSlug": "acme" }),
        Some(&member),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "member ListBindings: {resp}");
    assert_eq!(resp["bindings"][0]["name"], "primary");
    let root = resp["bindings"][0]["root"].as_str().unwrap_or("");
    assert!(
        root.is_empty(),
        "a non-admin member must not see the binding root host path: {resp}"
    );
    assert!(
        !resp.to_string().contains("/var/lib/aos/storage/acme"),
        "host path must not appear anywhere for a non-admin: {resp}"
    );

    // An admin (registry.configure, plus read as every admin token carries)
    // sees the real host path.
    db.grant_membership("user", 3, "acme", "admin")
        .await
        .unwrap();
    let admin = bearer(
        Principal::user(3),
        "acme",
        &[Permission::Read, Permission::RegistryConfigure],
    );
    let (status, resp) = rpc(
        &app,
        "StorageBindingService/ListBindings",
        serde_json::json!({ "orgSlug": "acme" }),
        Some(&admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admin ListBindings: {resp}");
    assert_eq!(
        resp["bindings"][0]["root"], "/var/lib/aos/storage/acme",
        "an admin sees the binding root"
    );
}
