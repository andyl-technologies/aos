//! Phase-2c integration coverage: nested canonical URL routing, registry
//! visibility enforcement, and the tenancy ConnectRPC write path.
//!
//! Exercises the real router against a managed (org-owned, storage-bound)
//! registry served at its canonical `{org}/{project}/{registry}` path, and
//! drives the Org/Project/Storage/Registry write RPCs over Connect-JSON
//! with a bearer JWT minted from the hub's own keys.

mod common;

use std::path::Path;
use std::sync::Arc;

use aos_hub::auth::extract::AuthState;
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::db::{Database, TokenAuth};
use aos_hub::domain::{Permission, Principal, Role, Scope};
use aos_hub::fetch::LocalFsFetch;
use aos_hub::indexer::index_and_record;
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
        mailer: std::sync::Arc::new(aos_hub::auth::magic::LogMailer),
        dev: false,
    })
}

/// Mint a bearer JWT for `principal` scoped to `scope` with `perms`.
fn bearer(principal: Principal, scope: &str, perms: &[Permission]) -> String {
    let keys = JwtKeys::from_secret(TEST_JWT_SECRET);
    keys.mint(
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

/// GET a URL, optionally carrying a `Cookie` or `Authorization` header.
async fn get(
    app: &axum::Router,
    uri: &str,
    cookie: Option<&str>,
    auth: Option<&str>,
) -> (StatusCode, String) {
    let mut req = Request::builder().uri(uri);
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    if let Some(auth) = auth {
        req = req.header(header::AUTHORIZATION, format!("Bearer {auth}"));
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
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

/// Create org "acme", a `local_fs` binding over the surface's parent, and a
/// managed registry at `acme/infra/prod/cdn` whose surface is the indexed
/// fixture. Returns `(app, db)`.
async fn serve_managed(
    surface: &Path,
    fixture: &common::Fixture,
    visibility: &str,
) -> Arc<Database> {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme, Inc.").await.unwrap();
    // The binding roots at the surface's parent; prefix is the surface dir
    // name, so {root}/{prefix} == surface.
    let parent = surface.parent().unwrap().to_str().unwrap();
    let dir_name = surface.file_name().unwrap().to_str().unwrap();
    let binding = db
        .create_storage_binding(org, "primary", "local_fs", parent)
        .await
        .unwrap();
    let id = db
        .create_managed_registry(
            org,
            "infra/prod",
            "cdn",
            visibility,
            Some(binding),
            dir_name,
            std::slice::from_ref(&fixture.trust_key),
            true,
        )
        .await
        .unwrap();
    let registry = db
        .registry_by_slug("acme/infra/prod/cdn")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(registry.id, id);
    index_and_record(&db, &LocalFsFetch::new(surface), &registry)
        .await
        .unwrap();
    db
}

#[tokio::test]
async fn nested_registry_home_packages_and_machine_path_resolve() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let db = serve_managed(&surface, &fixture, "public").await;
    let app = router(app_state(db).await).await;

    // Nested registry home renders the registry page.
    let (status, body) = get(&app, "/acme/infra/prod/cdn/", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("Fixture registry"), "{body}");

    // Nested /-/packages page.
    let (status, body) = get(&app, "/acme/infra/prod/cdn/-/packages", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("curl"), "{body}");

    // Nested machine path (HEAD) served byte-faithfully from the binding.
    let (status, body) = get(&app, "/acme/infra/prod/cdn/HEAD", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains("ref:"),
        "HEAD should carry a symbolic ref: {body}"
    );

    // A canonical-prefix sibling that is not a registry is a 404 (boundary).
    let (status, _) = get(&app, "/acme/infra/prod/cdn-staging/", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn flat_phase1_slug_still_resolves() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);

    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.register_registry(
        "demo",
        surface.to_str().unwrap(),
        std::slice::from_ref(&fixture.trust_key),
        true,
    )
    .await
    .unwrap();
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    index_and_record(&db, &LocalFsFetch::new(&surface), &registry)
        .await
        .unwrap();
    let app = router(app_state(db).await).await;

    let (status, body) = get(&app, "/demo/", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("Fixture registry"), "{body}");
    let (status, _) = get(&app, "/demo/-/packages", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = get(&app, "/demo/HEAD", None, None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn static_routes_still_resolve_alongside_catch_all() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let db = serve_managed(&surface, &fixture, "public").await;
    let app = router(app_state(db).await).await;

    // healthz, assets, and the RPC method paths win over the catch-all.
    let (status, body) = get(&app, "/healthz", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("registries"), "{body}");

    let (status, _) = get(&app, "/_assets/style.css", None, None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _value) = rpc(
        &app,
        "RegistryService/ListRegistries",
        serde_json::json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The oauth2 fragment is mounted: a credential-less POST is a 401, not a
    // 404 (which would mean the route is absent).
    let resp = app
        .clone()
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

#[tokio::test]
async fn private_registry_hidden_anonymously_visible_to_member() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let db = serve_managed(&surface, &fixture, "private").await;

    // A member user with Read on the org.
    let user = db.create_user("dev@acme.com", None).await.unwrap();
    db.grant_membership("user", user, "acme", Role::Developer.as_str())
        .await
        .unwrap();
    let session = db.create_session(user, 3600, 0).await.unwrap();

    let app = router(app_state(Arc::clone(&db)).await).await;

    // Anonymous: 404 (existence is not disclosed), on home, page, and
    // machine path alike.
    for uri in [
        "/acme/infra/prod/cdn/",
        "/acme/infra/prod/cdn/-/packages",
        "/acme/infra/prod/cdn/HEAD",
    ] {
        let (status, _) = get(&app, uri, None, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "anon should not see {uri}");
    }

    // The member's session sees the registry.
    let cookie = format!("__Host-aos_session={session}");
    let (status, body) = get(&app, "/acme/infra/prod/cdn/", Some(&cookie), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("Fixture registry"), "{body}");

    // A bearer token with Read on the registry scope also sees it.
    let token = bearer(
        Principal::user(user),
        "acme/infra/prod/cdn",
        &[Permission::Read],
    );
    let (status, _) = get(&app, "/acme/infra/prod/cdn/HEAD", None, Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn internal_registry_requires_org_membership() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let db = serve_managed(&surface, &fixture, "internal").await;

    // A non-member user (no grant in acme).
    let outsider = db.create_user("ext@other.com", None).await.unwrap();
    let outsider_session = db.create_session(outsider, 3600, 0).await.unwrap();
    // A member user.
    let member = db.create_user("dev@acme.com", None).await.unwrap();
    db.grant_membership("user", member, "acme", Role::Viewer.as_str())
        .await
        .unwrap();
    let member_session = db.create_session(member, 3600, 0).await.unwrap();

    let app = router(app_state(Arc::clone(&db)).await).await;

    let (status, _) = get(&app, "/acme/infra/prod/cdn/", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "anon hidden");

    let cookie = format!("__Host-aos_session={outsider_session}");
    let (status, _) = get(&app, "/acme/infra/prod/cdn/", Some(&cookie), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "non-member hidden");

    let cookie = format!("__Host-aos_session={member_session}");
    let (status, body) = get(&app, "/acme/infra/prod/cdn/", Some(&cookie), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn instance_home_lists_only_visible_registries() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme, Inc.").await.unwrap();

    // One registry per visibility level, all under acme. No binding/surface is
    // needed: the instance home only lists records and their index state.
    let mk = |project: &str, name: &str, vis: &str| {
        let (project, name, vis) = (project.to_string(), name.to_string(), vis.to_string());
        let db = &db;
        async move {
            db.create_managed_registry(org, &project, &name, &vis, None, "", &[], false)
                .await
                .unwrap();
            format!("acme/{project}/{name}")
        }
    };
    let public = mk("p", "pub", "public").await;
    let internal = mk("i", "int", "internal").await;
    let private = mk("s", "sec", "private").await;

    let app = router(app_state(Arc::clone(&db)).await).await;

    // Anonymous: only the public registry's slug appears in the listing.
    let (status, body) = get(&app, "/", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(&public), "public must be listed: {body}");
    assert!(
        !body.contains(&internal),
        "internal must be hidden from anon: {body}"
    );
    assert!(
        !body.contains(&private),
        "private must be hidden from anon: {body}"
    );

    // The same hiding applies under the ?q= search.
    let (status, body) = get(&app, "/?q=acme", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(&public), "{body}");
    assert!(!body.contains(&internal), "{body}");
    assert!(!body.contains(&private), "{body}");

    // An outsider with no acme grant: still only the public registry, same as
    // an anonymous caller (a valid session does not by itself reveal anything).
    let outsider = db.create_user("ext@other.com", None).await.unwrap();
    let outsider_session = db.create_session(outsider, 3600, 0).await.unwrap();
    let outsider_cookie = format!("__Host-aos_session={outsider_session}");
    let (status, body) = get(&app, "/", Some(&outsider_cookie), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(&public), "{body}");
    assert!(
        !body.contains(&internal),
        "outsider hidden internal: {body}"
    );
    assert!(!body.contains(&private), "outsider hidden private: {body}");

    // A member of acme (org Viewer grant): the org-scoped Read covers internal
    // and the private registry's sub-scope alike, so all three are listed.
    let member = db.create_user("dev@acme.com", None).await.unwrap();
    db.grant_membership("user", member, "acme", Role::Viewer.as_str())
        .await
        .unwrap();
    let session = db.create_session(member, 3600, 0).await.unwrap();
    let cookie = format!("__Host-aos_session={session}");
    let (status, body) = get(&app, "/", Some(&cookie), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(&public), "{body}");
    assert!(body.contains(&internal), "member sees internal: {body}");
    assert!(body.contains(&private), "org member sees private: {body}");

    // A bearer token granting Read only on the private scope reveals exactly
    // that registry (plus the always-public one), not the internal one.
    let token = bearer(Principal::user(outsider), &private, &[Permission::Read]);
    let (status, body) = get(&app, "/", None, Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(&public), "{body}");
    assert!(body.contains(&private), "granted private is listed: {body}");
    assert!(
        !body.contains(&internal),
        "registry-scoped token does not reveal internal: {body}"
    );
}

#[tokio::test]
async fn rpc_create_org_project_binding_registry_happy_path() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    // Open signup so a fresh, unaffiliated founder may bootstrap the org.
    // (The default instance policy is invite-only; the operations test suite
    // covers the gating.)
    db.set_signup_policy(aos_hub::db::SignupPolicy::Open)
        .await
        .unwrap();
    // A user principal to act as the org bootstrapper.
    let user = db.create_user("founder@acme.com", None).await.unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;

    // CreateOrg with any authenticated principal; the caller becomes Owner.
    let token = bearer(Principal::user(user), "", &[]);
    let (status, value) = rpc(
        &app,
        "OrgService/CreateOrg",
        serde_json::json!({"slug": "acme", "name": "Acme, Inc."}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["org"]["slug"], "acme");
    // The auto-grant made the founder an Owner of acme.
    let grants = db.effective_scopes(Principal::user(user)).await.unwrap();
    assert!(grants
        .iter()
        .any(|(s, r)| s.as_str() == "acme" && *r == Role::Owner));

    // As Owner, the founder has registry.configure on acme — mint a token
    // carrying it for the subsequent mutations.
    let owner_token = bearer(
        Principal::user(user),
        "acme",
        &[Permission::RegistryConfigure],
    );

    // CreateProject.
    let (status, value) = rpc(
        &app,
        "ProjectService/CreateProject",
        serde_json::json!({"orgSlug": "acme", "path": "infra/prod", "name": "Prod"}),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["project"]["path"], "infra/prod");

    // CreateBinding.
    let (status, value) = rpc(
        &app,
        "StorageService/CreateBinding",
        serde_json::json!({"orgSlug": "acme", "name": "primary", "kind": "local_fs", "root": "/srv/aos-hub"}),
        Some(&owner_token),
    ).await
    ;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["binding"]["root"], "/srv/aos-hub");

    // CreateRegistry, bound to the new binding.
    let (status, value) = rpc(
        &app,
        "RegistryService/CreateRegistry",
        serde_json::json!({
            "orgSlug": "acme",
            "projectPath": "infra/prod",
            "name": "cdn",
            "visibility": "private",
            "bindingName": "primary",
            "prefix": "infra/prod/cdn",
            "trustKeys": ["cdn:Ed25519:AAAA"]
        }),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["registry"]["slug"], "acme/infra/prod/cdn");

    // The registry exists with the right ownership and storage binding.
    let record = db
        .registry_by_slug("acme/infra/prod/cdn")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.visibility, "private");
    assert!(record.storage_binding_id.is_some());
    assert_eq!(record.prefix, "infra/prod/cdn");
}

#[tokio::test]
async fn rpc_create_org_rejects_scope_smuggling_slugs() {
    // CR-2: a slug that `Scope::parse` would normalize into an unintended
    // ancestor scope must be rejected with InvalidArgument, creating neither
    // an org row nor any membership grant. Without the validator, "/"
    // normalizes to the all-containing ROOT scope and "/victimorg" to the
    // victim org's scope, each handing the caller Owner there.
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.set_signup_policy(aos_hub::db::SignupPolicy::Open)
        .await
        .unwrap();
    // A pre-existing victim org the attacker must not gain Owner over.
    db.create_org("victimorg", "Victim Org").await.unwrap();
    let attacker = db.create_user("attacker@evil.com", None).await.unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let token = bearer(Principal::user(attacker), "", &[]);

    for bad in [
        "/",
        "/victimorg",
        "foo/bar",
        "foo ",
        " foo",
        "Acme",
        "victimorg/",
    ] {
        let (status, value) = rpc(
            &app,
            "OrgService/CreateOrg",
            serde_json::json!({"slug": bad, "name": "Anything"}),
            Some(&token),
        )
        .await;
        // Connect maps InvalidArgument to HTTP 400.
        assert_eq!(status, StatusCode::BAD_REQUEST, "slug {bad:?}: {value}");
    }

    // No org was created for any of the smuggling attempts.
    assert!(db.org_by_slug("/").await.unwrap().is_none());
    assert!(db.org_by_slug("/victimorg").await.unwrap().is_none());
    assert!(db.org_by_slug("foo/bar").await.unwrap().is_none());

    // Crucially, the attacker holds NO grant anywhere — not at the root
    // scope, not over the victim org.
    let grants = db
        .effective_scopes(Principal::user(attacker))
        .await
        .unwrap();
    assert!(
        grants.is_empty(),
        "attacker must hold no grant after rejected creates: {grants:?}"
    );
    // And the victim org's roster gained no Owner.
    assert!(db
        .list_members_of_scope("victimorg")
        .await
        .unwrap()
        .is_empty());
    assert!(db.list_members_of_scope("").await.unwrap().is_empty());

    // Regression: a normal slug still creates the org and grants Owner at
    // exactly that org's scope.
    let (status, value) = rpc(
        &app,
        "OrgService/CreateOrg",
        serde_json::json!({"slug": "acme", "name": "Acme, Inc."}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["org"]["slug"], "acme");
    let grants = db
        .effective_scopes(Principal::user(attacker))
        .await
        .unwrap();
    assert_eq!(grants.len(), 1);
    assert!(grants
        .iter()
        .any(|(s, r)| s.as_str() == "acme" && *r == Role::Owner));
}

#[tokio::test]
async fn rpc_create_org_is_rate_limited_per_principal() {
    // L-3: an authenticated principal must not be able to loop CreateOrg to
    // mint an unbounded number of orgs. The per-principal rate limit caps the
    // burst; a fresh principal is unaffected.
    use aos_hub::ratelimit::CREATE_ORG_PER_OWNER;

    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.set_signup_policy(aos_hub::db::SignupPolicy::Open)
        .await
        .unwrap();
    let founder = db.create_user("founder@acme.com", None).await.unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let token = bearer(Principal::user(founder), "", &[]);

    // The first CREATE_ORG_PER_OWNER creations in the window succeed.
    for i in 0..CREATE_ORG_PER_OWNER {
        let (status, value) = rpc(
            &app,
            "OrgService/CreateOrg",
            serde_json::json!({"slug": format!("acme{i}"), "name": "Acme"}),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "create #{i}: {value}");
    }

    // The next one over the budget is rejected. Connect maps ResourceExhausted
    // to HTTP 429.
    let (status, value) = rpc(
        &app,
        "OrgService/CreateOrg",
        serde_json::json!({"slug": "acme-over", "name": "Acme"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{value}");
    assert!(db.org_by_slug("acme-over").await.unwrap().is_none());

    // A *different* principal is unaffected — the limit is per-caller.
    let other = db.create_user("other@acme.com", None).await.unwrap();
    let other_token = bearer(Principal::user(other), "", &[]);
    let (status, value) = rpc(
        &app,
        "OrgService/CreateOrg",
        serde_json::json!({"slug": "beta", "name": "Beta"}),
        Some(&other_token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "fresh principal unaffected: {value}"
    );
}

#[tokio::test]
async fn soft_deleted_org_registry_is_not_found_over_rpc() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    // A public registry so the read would otherwise succeed anonymously.
    let db = serve_managed(&surface, &fixture, "public").await;
    let app = router(app_state(Arc::clone(&db)).await).await;

    // While the org is live, GetRegistry/ListReleases serve.
    let (status, value) = rpc(
        &app,
        "RegistryService/GetRegistry",
        serde_json::json!({"slug": "acme/infra/prod/cdn"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let (status, _) = rpc(
        &app,
        "RegistryService/ListReleases",
        serde_json::json!({"slug": "acme/infra/prod/cdn"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Soft-delete the owning org.
    let org = db.org_by_slug("acme").await.unwrap().unwrap();
    assert!(db.soft_delete_org(org.id, 86_400).await.unwrap());

    // Both reads now report the registry as gone (NotFound -> HTTP 404).
    let (status, value) = rpc(
        &app,
        "RegistryService/GetRegistry",
        serde_json::json!({"slug": "acme/infra/prod/cdn"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{value}");
    let (status, value) = rpc(
        &app,
        "RegistryService/ListReleases",
        serde_json::json!({"slug": "acme/infra/prod/cdn"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{value}");
}

#[tokio::test]
async fn private_registry_list_releases_requires_read() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let db = serve_managed(&surface, &fixture, "private").await;
    let app = router(app_state(Arc::clone(&db)).await).await;

    // Anonymous ListReleases of a private registry is rejected (no leak).
    let (status, _) = rpc(
        &app,
        "RegistryService/ListReleases",
        serde_json::json!({"slug": "acme/infra/prod/cdn"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // GetRegistry of a private registry is likewise rejected anonymously.
    let (status, _) = rpc(
        &app,
        "RegistryService/GetRegistry",
        serde_json::json!({"slug": "acme/infra/prod/cdn"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A member with Read, carrying a bearer scoped to the registry, sees the
    // releases (the permission is intersected with the owner's live grants).
    let user = db.create_user("dev@acme.com", None).await.unwrap();
    db.grant_membership("user", user, "acme", Role::Developer.as_str())
        .await
        .unwrap();
    let token = bearer(
        Principal::user(user),
        "acme/infra/prod/cdn",
        &[Permission::Read],
    );
    let (status, value) = rpc(
        &app,
        "RegistryService/ListReleases",
        serde_json::json!({"slug": "acme/infra/prod/cdn"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
}

#[tokio::test]
async fn rpc_mutations_reject_unauthenticated_and_unauthorized() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;

    // No bearer at all: unauthenticated.
    let (status, _) = rpc(
        &app,
        "OrgService/CreateOrg",
        serde_json::json!({"slug": "globex", "name": "Globex"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Authenticated but lacking registry.configure on acme: denied.
    let weak = bearer(Principal::user(1), "acme", &[Permission::Read]);
    let (status, _) = rpc(
        &app,
        "ProjectService/CreateProject",
        serde_json::json!({"orgSlug": "acme", "path": "infra", "name": "Infra"}),
        Some(&weak),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
