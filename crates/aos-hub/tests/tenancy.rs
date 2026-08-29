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
use aos_hub::db::{Database, SurfaceTarget, TokenAuth};
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
        leases: std::sync::Arc::new(aos_hub_core::lease::InMemoryLease::new()),
        sealer: aos_hub::auth::oidc::dev_sealer(),
        secret_versions: aos_hub_core::secret_version::EmptySecretVersionResolver::shared(),
        http: aos_hub::fetch::hardened_client().await,
        image_snapshots: None,
        mailer: std::sync::Arc::new(aos_hub::auth::magic::LogMailer),
        dev: false,
        delivery_attestation_verifier: None,
        domain_probe_terminator: None,
        identity_domain_verifier: None,
        route_reservation_keyring: None,
        container_rollout: aos_hub_core::container_rollout::ContainerRollout::all_enabled(),
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
    let mut req = Request::builder()
        .uri(uri)
        .header(header::HOST, "127.0.0.1:8420");
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
        .uri(format!("/aos.hub.v1.{method}"))
        .header(header::HOST, "127.0.0.1:8420")
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

/// Executes a reviewed plan/apply pair using the returned confirmation hash.
async fn planned_rpc(
    app: &axum::Router,
    plan_method: &str,
    apply_method: &str,
    mut plan_body: serde_json::Value,
    auth: Option<&str>,
    key: &str,
) -> (StatusCode, serde_json::Value) {
    plan_body["idempotencyKey"] = serde_json::Value::String(format!("{key}-plan"));
    let (status, plan) = rpc(app, plan_method, plan_body, auth).await;
    if status != StatusCode::OK {
        return (status, plan);
    }
    rpc(
        app,
        apply_method,
        serde_json::json!({
            "planId": plan["plan"]["planId"],
            "idempotencyKey": format!("{key}-apply"),
            "confirmationHash": plan["plan"]["confirmationHash"],
        }),
        auth,
    )
    .await
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
    db.create_project(org, "infra/prod", "Production")
        .await
        .unwrap();
    // The binding roots at the surface's parent; prefix is the surface dir
    // name, so {root}/{prefix} == surface.
    let parent = surface.parent().unwrap().to_str().unwrap();
    let dir_name = surface.file_name().unwrap().to_str().unwrap();
    let binding = common::create_local_binding(&db, org, "primary", parent).await;
    let id = db
        .create_managed_registry(
            org,
            "infra/prod",
            "cdn",
            visibility,
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
    let placement = common::create_ready_placement(
        &db,
        SurfaceTarget::Registry(id),
        binding,
        "primary",
        dir_name,
    )
    .await;
    common::configure_hub_route(
        &db,
        SurfaceTarget::Registry(id),
        placement.id,
        &registry.owner_scope_key,
        "endpoint:tenancy-fixture",
        "route:tenancy-fixture",
        "/acme/infra/prod/cdn",
        "git",
    )
    .await;
    index_and_record(&db, &LocalFsFetch::new(surface), &registry)
        .await
        .unwrap();
    db
}

#[tokio::test]
async fn nested_registry_browse_resolves_and_unpublished_bytes_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let object_oid = std::fs::read_to_string(surface.join("info/refs"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    let object_path = format!("objects/{}/{}", &object_oid[..2], &object_oid[2..]);
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

    // Indexing alone does not constitute a typed publication. The route is
    // ready (asserted by the shared fixture), but bytes without exact object
    // presence evidence fail closed.
    let (status, body) = get(
        &app,
        &format!("/acme/infra/prod/cdn/{object_path}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // A canonical-prefix sibling that is not a registry is a 404 (boundary).
    let (status, _) = get(&app, "/acme/infra/prod/cdn-staging/", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn flat_explicit_route_resolves_and_unpublished_bytes_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let object_oid = std::fs::read_to_string(surface.join("info/refs"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    let object_path = format!("objects/{}/{}", &object_oid[..2], &object_oid[2..]);

    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.register_registry("demo", std::slice::from_ref(&fixture.trust_key), true)
        .await
        .unwrap();
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    let binding =
        common::create_instance_local_binding(&db, "flat-origin", surface.to_str().unwrap()).await;
    let placement = common::create_ready_placement(
        &db,
        SurfaceTarget::Registry(registry.id),
        binding,
        "primary",
        "",
    )
    .await;
    common::configure_hub_route(
        &db,
        SurfaceTarget::Registry(registry.id),
        placement.id,
        &registry.owner_scope_key,
        "endpoint:flat-fixture",
        "route:flat-fixture",
        "/demo",
        "git",
    )
    .await;
    index_and_record(&db, &LocalFsFetch::new(&surface), &registry)
        .await
        .unwrap();
    let app = router(app_state(db).await).await;

    let (status, body) = get(&app, "/demo/", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("Fixture registry"), "{body}");
    let (status, _) = get(&app, "/demo/-/packages", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = get(&app, &format!("/demo/{object_path}"), None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
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

    // The shared OAuth surface is mounted: a provisioning grant without its
    // credential is a 401, not a 404 (which would mean the route is absent).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/token")
                .header(header::HOST, "127.0.0.1:8420")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    "grant_type=urn%3Aaos%3Aparams%3Aoauth%3Agrant-type%3Aprovisioning-token",
                ))
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
    db.grant_membership(
        "user",
        user,
        &common::org_scope(&db, "acme").await,
        Role::Developer.as_str(),
    )
    .await
    .unwrap();
    let session = db.create_session(user, 3600, 0).await.unwrap();

    let app = router(app_state(Arc::clone(&db)).await).await;

    // Data delivery challenges for credentials, while the reserved browse
    // control path remains non-disclosing.
    for (uri, expected) in [
        ("/acme/infra/prod/cdn/", StatusCode::UNAUTHORIZED),
        ("/acme/infra/prod/cdn/-/packages", StatusCode::NOT_FOUND),
        ("/acme/infra/prod/cdn/HEAD", StatusCode::UNAUTHORIZED),
    ] {
        let (status, _) = get(&app, uri, None, None).await;
        assert_eq!(status, expected, "anon should not see {uri}");
    }

    // The member's session sees the registry.
    let cookie = format!("__Host-aos_session={session}");
    let (status, body) = get(&app, "/acme/infra/prod/cdn/", Some(&cookie), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("Fixture registry"), "{body}");

    // A bearer token with Read on the registry scope also sees its browse
    // surface. Successful private byte delivery after a typed publication is
    // covered by the signed-image end-to-end suite.
    let token = bearer(
        Principal::user(user),
        &common::registry_scope(&db, "acme/infra/prod/cdn").await,
        &[Permission::Read],
    );
    let (status, _) = get(&app, "/acme/infra/prod/cdn/-/packages", None, Some(&token)).await;
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
    db.grant_membership(
        "user",
        member,
        &common::org_scope(&db, "acme").await,
        Role::Viewer.as_str(),
    )
    .await
    .unwrap();
    let member_session = db.create_session(member, 3600, 0).await.unwrap();

    let app = router(app_state(Arc::clone(&db)).await).await;

    let (status, _) = get(&app, "/acme/infra/prod/cdn/", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "anon hidden");

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
    for path in ["p", "i", "s"] {
        db.create_project(org, path, path).await.unwrap();
    }

    // One registry per visibility level, all under acme. No binding/surface is
    // needed: the instance home only lists records and their index state.
    let mk = |project: &str, name: &str, vis: &str| {
        let (project, name, vis) = (project.to_string(), name.to_string(), vis.to_string());
        let db = &db;
        async move {
            db.create_managed_registry(org, &project, &name, &vis, &[], false)
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
    db.grant_membership(
        "user",
        member,
        &common::org_scope(&db, "acme").await,
        Role::Viewer.as_str(),
    )
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
    let private_scope = common::registry_scope(&db, &private).await;
    db.grant_membership("user", outsider, &private_scope, Role::Viewer.as_str())
        .await
        .unwrap();
    let token = bearer(
        Principal::user(outsider),
        &private_scope,
        &[Permission::Read],
    );
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

    // CreateOrganization with any authenticated principal; the caller becomes Owner.
    let token = bearer(Principal::user(user), "instance", &[]);
    let (status, value) = planned_rpc(
        &app,
        "OrganizationService/PlanCreateOrganization",
        "OrganizationService/CreateOrganization",
        serde_json::json!({"slug": "acme", "displayName": "Acme, Inc."}),
        Some(&token),
        "create-acme",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["organization"]["slug"], "acme");
    let org = db.org_by_slug("acme").await.unwrap().unwrap();
    let org_scope = org.stable_id.clone();
    // The auto-grant made the founder an Owner of acme.
    let grants = db.effective_scopes(Principal::user(user)).await.unwrap();
    assert!(grants
        .iter()
        .any(|(s, r)| s.as_str() == org_scope && *r == Role::Owner));

    // As Owner, the founder has registry.configure on acme — mint a token
    // carrying it for the subsequent mutations.
    let owner_token = bearer(
        Principal::user(user),
        &org_scope,
        &[Permission::RegistryConfigure, Permission::BindingManage],
    );

    // CreateProject.
    let (status, value) = planned_rpc(
        &app,
        "ProjectService/PlanCreateProject",
        "ProjectService/CreateProject",
        serde_json::json!({"orgSlug": "acme", "path": "infra/prod", "name": "Prod"}),
        Some(&owner_token),
        "create-project",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["project"]["path"], "infra/prod");

    // Create a normalized identity/spec binding.
    let (status, value) = planned_rpc(
        &app,
        "BindingService/PlanCreateBinding",
        "BindingService/CreateBinding",
        serde_json::json!({
            "stableId": "binding:acme-primary",
            "ownerScopeKey": org_scope,
            "spec": {
                "name": "primary",
                "s3": {
                    "bucket": "acme-primary",
                    "prefix": "hub",
                    "endpoint": {
                        "scheme": "https",
                        "dnsName": "objects.example.com",
                        "port": 443
                    },
                    "signingRegion": "us-east-1",
                    "accessMode": "private"
                }
            }
        }),
        Some(&owner_token),
        "create-binding",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["binding"]["spec"]["s3"]["bucket"], "acme-primary");

    // Registry creation is identity-only; placement is a separate topology step.
    let (status, value) = planned_rpc(
        &app,
        "RegistryService/PlanCreateRegistry",
        "RegistryService/CreateRegistry",
        serde_json::json!({
            "orgSlug": "acme",
            "projectPath": "infra/prod",
            "name": "cdn",
            "visibility": "private",
            "trustKeys": []
        }),
        Some(&owner_token),
        "create-registry",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["registry"]["slug"], "acme/infra/prod/cdn");

    // The registry exists with the right ownership but no implicit placement.
    let record = db
        .registry_by_slug("acme/infra/prod/cdn")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.visibility, "private");
    assert!(db
        .list_surface_placements(aos_hub::db::SurfaceTarget::Registry(record.id))
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn organization_plans_enforce_cas_replay_and_delete_grace() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.set_signup_policy(aos_hub::db::SignupPolicy::Open)
        .await
        .unwrap();
    let user = db.create_user("owner@acme.com", None).await.unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let bootstrap = bearer(Principal::user(user), "instance", &[]);

    let (status, plan) = rpc(
        &app,
        "OrganizationService/PlanCreateOrganization",
        serde_json::json!({
            "slug": "acme",
            "displayName": "Acme",
            "idempotencyKey": "org-create-plan"
        }),
        Some(&bootstrap),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{plan}");
    let apply = serde_json::json!({
        "planId": plan["plan"]["planId"],
        "idempotencyKey": "org-create-apply",
        "confirmationHash": plan["plan"]["confirmationHash"]
    });
    let (status, created) = rpc(
        &app,
        "OrganizationService/CreateOrganization",
        apply.clone(),
        Some(&bootstrap),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let org_scope = common::org_scope(&db, "acme").await;
    let (status, replayed) = rpc(
        &app,
        "OrganizationService/CreateOrganization",
        apply,
        Some(&bootstrap),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{replayed}");
    assert_eq!(created, replayed, "apply replay returns the sealed result");

    let version = created["organization"]["resourceVersion"].as_str().unwrap();
    let manager = bearer(
        Principal::user(user),
        &org_scope,
        &[Permission::MembersManage, Permission::IamAdmin],
    );
    let (status, updated) = planned_rpc(
        &app,
        "OrganizationService/PlanUpdateOrganization",
        "OrganizationService/UpdateOrganization",
        serde_json::json!({
            "slug": "acme",
            "displayName": "Acme Systems",
            "expectedResourceVersion": version
        }),
        Some(&manager),
        "org-update",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["organization"]["displayName"], "Acme Systems");

    let (status, stale) = rpc(
        &app,
        "OrganizationService/PlanUpdateOrganization",
        serde_json::json!({
            "slug": "acme",
            "displayName": "Stale",
            "expectedResourceVersion": version,
            "idempotencyKey": "org-stale"
        }),
        Some(&manager),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{stale}");

    let updated_version = updated["organization"]["resourceVersion"].as_str().unwrap();
    let (status, deleted) = planned_rpc(
        &app,
        "OrganizationService/PlanDeleteOrganization",
        "OrganizationService/DeleteOrganization",
        serde_json::json!({
            "slug": "acme",
            "expectedResourceVersion": updated_version
        }),
        Some(&manager),
        "org-delete",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    assert_eq!(deleted["deleted"], true);
    assert!(db.org_by_slug("acme").await.unwrap().is_none());
    assert!(
        db.org_by_slug_including_deleted("acme")
            .await
            .unwrap()
            .is_some(),
        "soft-deleted organization remains during purge grace"
    );
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
    let token = bearer(Principal::user(attacker), "instance", &[]);

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
            "OrganizationService/PlanCreateOrganization",
            serde_json::json!({"slug": bad, "displayName": "Anything", "idempotencyKey": format!("bad-{bad}")}),
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
        .list_members_of_scope(&common::org_scope(&db, "victimorg").await)
        .await
        .unwrap()
        .is_empty());
    assert!(db
        .list_members_of_scope("instance")
        .await
        .unwrap()
        .is_empty());

    // Regression: a normal slug still creates the org and grants Owner at
    // exactly that org's scope.
    let (status, value) = planned_rpc(
        &app,
        "OrganizationService/PlanCreateOrganization",
        "OrganizationService/CreateOrganization",
        serde_json::json!({"slug": "acme", "displayName": "Acme, Inc."}),
        Some(&token),
        "normal-acme",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["organization"]["slug"], "acme");
    let grants = db
        .effective_scopes(Principal::user(attacker))
        .await
        .unwrap();
    assert_eq!(grants.len(), 1);
    let acme_scope = common::org_scope(&db, "acme").await;
    assert!(grants
        .iter()
        .any(|(s, r)| s.as_str() == acme_scope && *r == Role::Owner));
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
    let token = bearer(Principal::user(founder), "instance", &[]);

    // The first CREATE_ORG_PER_OWNER creations in the window succeed.
    for i in 0..CREATE_ORG_PER_OWNER {
        let (status, value) = planned_rpc(
            &app,
            "OrganizationService/PlanCreateOrganization",
            "OrganizationService/CreateOrganization",
            serde_json::json!({"slug": format!("acme{i}"), "displayName": "Acme"}),
            Some(&token),
            &format!("rate-{i}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "create #{i}: {value}");
    }

    // The next one over the budget is rejected. Connect maps ResourceExhausted
    // to HTTP 429.
    let (status, value) = planned_rpc(
        &app,
        "OrganizationService/PlanCreateOrganization",
        "OrganizationService/CreateOrganization",
        serde_json::json!({"slug": "acme-over", "displayName": "Acme"}),
        Some(&token),
        "rate-over",
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{value}");
    assert!(db.org_by_slug("acme-over").await.unwrap().is_none());

    // A *different* principal is unaffected — the limit is per-caller.
    let other = db.create_user("other@acme.com", None).await.unwrap();
    let other_token = bearer(Principal::user(other), "instance", &[]);
    let (status, value) = planned_rpc(
        &app,
        "OrganizationService/PlanCreateOrganization",
        "OrganizationService/CreateOrganization",
        serde_json::json!({"slug": "beta", "displayName": "Beta"}),
        Some(&other_token),
        "rate-other",
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
    db.grant_membership(
        "user",
        user,
        &common::org_scope(&db, "acme").await,
        Role::Developer.as_str(),
    )
    .await
    .unwrap();
    let token = bearer(
        Principal::user(user),
        &common::registry_scope(&db, "acme/infra/prod/cdn").await,
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
        "OrganizationService/PlanCreateOrganization",
        serde_json::json!({"slug": "globex", "displayName": "Globex", "idempotencyKey": "unauth"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Authenticated but lacking registry.configure on acme: denied.
    let weak = bearer(
        Principal::user(1),
        &common::org_scope(&db, "acme").await,
        &[Permission::Read],
    );
    let (status, _) = rpc(
        &app,
        "ProjectService/PlanCreateProject",
        serde_json::json!({"orgSlug": "acme", "path": "infra", "name": "Infra"}),
        Some(&weak),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
