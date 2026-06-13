//! Integration coverage for the producer console's create/edit web surface
//! (RFC-0004 phase-3b management).
//!
//! Drives the real router over plain HTTP for the org → project → binding →
//! registry hierarchy *creation* and *editing* flows that previously existed
//! only over RPC/CLI: creating an organization at `/new` (auto-owner, with the
//! signup policy enforced), creating a project/binding/registry under an org
//! through the dashboard POSTs (with the authz matrix), the registry settings
//! landing page and its visibility edit (a change-set that audits), and the
//! typed-confirmation registry/org deletes.

mod common;

use std::path::Path;
use std::sync::Arc;

use aos_registry_hub::auth::extract::{mint_csrf_token, AuthState};
use aos_registry_hub::auth::jwt::JwtKeys;
use aos_registry_hub::auth::session::COOKIE_NAME;
use aos_registry_hub::db::{Database, SignupPolicy};
use aos_registry_hub::fetch::LocalFsFetch;
use aos_registry_hub::indexer::index_and_record;
use aos_registry_hub::server::{router, AppState};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

const TEST_JWT_SECRET: &[u8] = b"manage-test-secret-32-byte-key!!!";

/// Build an [`AppState`] over `db` in dev mode with deterministic JWT keys.
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
        mailer: Arc::new(aos_registry_hub::auth::magic::LogMailer),
        dev: true,
    })
}

/// A captured HTTP response: status, a `Location` redirect, and the body text.
struct Resp {
    status: StatusCode,
    set_cookie: Option<String>,
    location: Option<String>,
    body: String,
}

/// Issue a request with an optional cookie and form body.
async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    form: Option<&str>,
) -> Resp {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    let body = match form {
        Some(form) => {
            req = req.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            Body::from(form.to_string())
        }
        None => Body::empty(),
    };
    let resp = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    Resp {
        status,
        set_cookie,
        location,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

/// Extract the session cookie value from a `Set-Cookie` header.
fn cookie_value(set_cookie: &str) -> String {
    let prefix = format!("{COOKIE_NAME}=");
    let after = set_cookie.strip_prefix(&prefix).expect("session cookie");
    after.split(';').next().unwrap().to_string()
}

/// Sign in `email` by minting + consuming a magic link; returns the cookie
/// header value.
async fn login(app: &axum::Router, db: &Database, email: &str) -> String {
    let secret = db.create_magic_link(email).unwrap();
    let resp = send(
        app,
        "GET",
        &format!("/auth/magic?token={secret}"),
        None,
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    let set = resp.set_cookie.expect("magic consume sets a cookie");
    format!("{COOKIE_NAME}={}", cookie_value(&set))
}

/// The CSRF token bound to a session cookie header value.
fn csrf_for(cookie: &str) -> String {
    mint_csrf_token(cookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap())
}

#[tokio::test]
async fn create_org_open_signup_auto_owners_the_creator() {
    let db = Arc::new(Database::open_in_memory().unwrap());
    db.set_signup_policy(SignupPolicy::Open).unwrap();
    // A fresh user with no memberships.
    db.find_or_create_user("founder@acme.com").unwrap();
    let app = router(app_state(Arc::clone(&db)));
    let cookie = login(&app, &db, "founder@acme.com").await;
    let csrf = csrf_for(&cookie);

    // The /new form renders for an open-signup user.
    let resp = send(&app, "GET", "/new", Some(&cookie), None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(
        resp.body.contains("Create an organization"),
        "{}",
        resp.body
    );

    // Creating the org redirects to its dashboard, grants the creator owner,
    // and audits.
    let resp = send(
        &app,
        "POST",
        "/new",
        Some(&cookie),
        Some(&format!("csrf={csrf}&slug=acme&name=Acme%2C+Inc.")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    assert_eq!(resp.location.as_deref(), Some("/-/org/acme"));

    assert!(db.org_by_slug("acme").unwrap().is_some());
    let founder = db.user_by_email("founder@acme.com").unwrap().unwrap();
    assert!(db
        .list_members_of_scope("acme")
        .unwrap()
        .iter()
        .any(|(k, id, r)| k == "user" && *id == founder && r == "owner"));
    assert!(db
        .list_audit("acme")
        .unwrap()
        .iter()
        .any(|a| a.action == "org.create"));

    // The dashboard now renders for the creator (owner reads it).
    let resp = send(&app, "GET", "/-/org/acme", Some(&cookie), None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("Acme"), "{}", resp.body);
}

#[tokio::test]
async fn create_org_invite_only_blocks_fresh_user_and_csrf_required() {
    let db = Arc::new(Database::open_in_memory().unwrap());
    // Default policy is invite-only; a fresh, unaffiliated user.
    assert_eq!(db.signup_policy().unwrap(), SignupPolicy::InviteOnly);
    db.find_or_create_user("nobody@x.com").unwrap();
    let app = router(app_state(Arc::clone(&db)));
    let cookie = login(&app, &db, "nobody@x.com").await;
    let csrf = csrf_for(&cookie);

    // The form is forbidden for a non-member under invite-only.
    let resp = send(&app, "GET", "/new", Some(&cookie), None).await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);

    // A POST is forbidden too — and no org is created.
    let resp = send(
        &app,
        "POST",
        "/new",
        Some(&cookie),
        Some(&format!("csrf={csrf}&slug=acme&name=Acme")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    assert!(db.org_by_slug("acme").unwrap().is_none());

    // A missing CSRF token is rejected before the policy check.
    let resp = send(
        &app,
        "POST",
        "/new",
        Some(&cookie),
        Some("slug=acme&name=Acme"),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
}

#[tokio::test]
async fn admin_creates_project_binding_and_registry_then_browses() {
    let dir = tempfile::tempdir().unwrap();
    // A pre-seeded surface the new registry will be bound to and indexed from.
    let surface = dir.path().join("acme/cdn");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);

    let db = Arc::new(Database::open_in_memory().unwrap());
    db.create_org("acme", "Acme").unwrap();
    let admin = db.find_or_create_user("admin@acme.com").unwrap();
    db.grant_membership("user", admin, "acme", "admin").unwrap();
    let app = router(app_state(Arc::clone(&db)));
    let cookie = login(&app, &db, "admin@acme.com").await;
    let csrf = csrf_for(&cookie);

    // Create a project.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/projects",
        Some(&cookie),
        Some(&format!("csrf={csrf}&path=infra/prod&name=Prod")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    let org_id = db.org_by_slug("acme").unwrap().unwrap().id;
    assert!(db
        .list_projects(org_id)
        .unwrap()
        .iter()
        .any(|p| p.path == "infra/prod"));

    // Create a storage binding over the surface's parent dir.
    let parent = surface.parent().unwrap().to_str().unwrap();
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/bindings",
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&name=primary&root={}",
            url::form_urlencoded::byte_serialize(parent.as_bytes()).collect::<String>()
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    assert!(db
        .storage_binding_by_name(org_id, "primary")
        .unwrap()
        .is_some());

    // The create-registry form renders the binding select.
    let resp = send(
        &app,
        "GET",
        "/-/org/acme/registries/new",
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("primary"), "{}", resp.body);

    // Create the registry at acme/infra/prod/cdn with prefix "cdn" so its
    // surface root resolves to <parent>/cdn (the seeded fixture surface).
    let trust =
        url::form_urlencoded::byte_serialize(fixture.trust_key.as_bytes()).collect::<String>();
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/registries",
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&name=cdn&project_path=infra/prod&binding=primary\
             &visibility=public&prefix=cdn&require_signatures=1&trust_keys={trust}"
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    assert_eq!(resp.location.as_deref(), Some("/acme/infra/prod/cdn/"));
    let registry = db
        .registry_by_slug("acme/infra/prod/cdn")
        .unwrap()
        .expect("registry created");
    assert_eq!(registry.visibility, "public");
    assert!(db
        .list_audit("acme")
        .unwrap()
        .iter()
        .any(|a| a.action == "registry.create"));

    // registry_surface_root resolves to the bound surface; index it and browse.
    let root = db.registry_surface_root(registry.id).unwrap().unwrap();
    assert_eq!(root, surface);
    index_and_record(&db, &LocalFsFetch::new(&root), &registry)
        .await
        .unwrap();
    let resp = send(&app, "GET", "/acme/infra/prod/cdn/", None, None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("Registry"), "{}", resp.body);
}

#[tokio::test]
async fn create_under_org_authz_matrix() {
    let db = Arc::new(Database::open_in_memory().unwrap());
    db.create_org("acme", "Acme").unwrap();
    // A viewer member (read, but no registry.configure / storage.manage).
    let viewer = db.find_or_create_user("v@acme.com").unwrap();
    db.grant_membership("user", viewer, "acme", "viewer")
        .unwrap();
    // A complete outsider.
    db.find_or_create_user("out@x.com").unwrap();
    let app = router(app_state(Arc::clone(&db)));

    let v_cookie = login(&app, &db, "v@acme.com").await;
    let v_csrf = csrf_for(&v_cookie);
    // A viewer cannot create a project (403 — they can read the org).
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/projects",
        Some(&v_cookie),
        Some(&format!("csrf={v_csrf}&name=Nope")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    // And cannot reach the create-registry form.
    let resp = send(
        &app,
        "GET",
        "/-/org/acme/registries/new",
        Some(&v_cookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);

    // A non-member gets 404 (existence undisclosed) on every create path.
    let out_cookie = login(&app, &db, "out@x.com").await;
    let out_csrf = csrf_for(&out_cookie);
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/bindings",
        Some(&out_cookie),
        Some(&format!("csrf={out_csrf}&name=x&root=/srv/x")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND, "{}", resp.body);
    let resp = send(
        &app,
        "GET",
        "/-/org/acme/registries/new",
        Some(&out_cookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND, "{}", resp.body);
}

#[tokio::test]
async fn binding_root_must_be_absolute() {
    let db = Arc::new(Database::open_in_memory().unwrap());
    db.create_org("acme", "Acme").unwrap();
    let admin = db.find_or_create_user("admin@acme.com").unwrap();
    db.grant_membership("user", admin, "acme", "admin").unwrap();
    let app = router(app_state(Arc::clone(&db)));
    let cookie = login(&app, &db, "admin@acme.com").await;
    let csrf = csrf_for(&cookie);

    // A relative root is rejected.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/bindings",
        Some(&cookie),
        Some(&format!("csrf={csrf}&name=rel&root=relative/path")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    // A traversal root is rejected.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/bindings",
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&name=trav&root={}",
            url::form_urlencoded::byte_serialize(b"/srv/../etc").collect::<String>()
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
}

/// Seed org "acme", a binding over the fixture surface's parent, and a managed
/// registry at `acme/infra/prod/cdn` indexed from the fixture.
async fn serve_managed(
    surface: &Path,
    fixture: &common::Fixture,
    visibility: &str,
) -> Arc<Database> {
    let db = Arc::new(Database::open_in_memory().unwrap());
    let org = db.create_org("acme", "Acme, Inc.").unwrap();
    let parent = surface.parent().unwrap().to_str().unwrap();
    let dir_name = surface.file_name().unwrap().to_str().unwrap();
    let binding = db
        .create_storage_binding(org, "primary", "local_fs", parent)
        .unwrap();
    db.create_managed_registry(
        org,
        "infra/prod",
        "cdn",
        visibility,
        Some(binding),
        dir_name,
        std::slice::from_ref(&fixture.trust_key),
        true,
    )
    .unwrap();
    let registry = db.registry_by_slug("acme/infra/prod/cdn").unwrap().unwrap();
    index_and_record(&db, &LocalFsFetch::new(surface), &registry)
        .await
        .unwrap();
    db
}

#[tokio::test]
async fn settings_page_renders_links_and_visibility_edit_audits() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let db = serve_managed(&surface, &fixture, "public").await;
    let app = router(app_state(Arc::clone(&db)));

    let owner = db.find_or_create_user("owner@acme.com").unwrap();
    db.grant_membership("user", owner, "acme", "owner").unwrap();
    let cookie = login(&app, &db, "owner@acme.com").await;
    let csrf = csrf_for(&cookie);

    // The settings landing page renders the management link hub and delete form.
    let resp = send(
        &app,
        "GET",
        "/acme/infra/prod/cdn/-/settings",
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("Manage this registry"), "{}", resp.body);
    assert!(
        resp.body.contains("/acme/infra/prod/cdn/-/settings/tokens"),
        "tokens link: {}",
        resp.body
    );
    assert!(
        resp.body.contains("/acme/infra/prod/cdn/-/keys"),
        "keys link"
    );
    assert!(resp.body.contains("remove registry"), "delete form");

    // The registry home shows a manage link for this authorized session.
    let resp = send(&app, "GET", "/acme/infra/prod/cdn/", Some(&cookie), None).await;
    assert!(resp.body.contains("manage this registry"), "{}", resp.body);

    // Edit visibility public -> private: a change-set is recorded and audited.
    let resp = send(
        &app,
        "POST",
        "/acme/infra/prod/cdn/-/settings/visibility",
        Some(&cookie),
        Some(&format!("csrf={csrf}&visibility=private")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("Visibility updated"), "{}", resp.body);
    assert_eq!(
        db.registry_by_slug("acme/infra/prod/cdn")
            .unwrap()
            .unwrap()
            .visibility,
        "private"
    );
    assert!(db
        .list_audit("acme/infra/prod/cdn")
        .unwrap()
        .iter()
        .any(|a| a.action == "registry.visibility"));

    // CSRF-missing visibility edit -> 403.
    let resp = send(
        &app,
        "POST",
        "/acme/infra/prod/cdn/-/settings/visibility",
        Some(&cookie),
        Some("visibility=public"),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
}

#[tokio::test]
async fn settings_visibility_forbidden_for_developer() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let db = serve_managed(&surface, &fixture, "public").await;
    let app = router(app_state(Arc::clone(&db)));

    // A developer at the registry scope lacks registry.configure.
    let dev = db.find_or_create_user("dev@acme.com").unwrap();
    db.grant_membership("user", dev, "acme/infra/prod/cdn", "developer")
        .unwrap();
    let cookie = login(&app, &db, "dev@acme.com").await;
    let csrf = csrf_for(&cookie);

    // The settings page is forbidden (member, but no registry.configure).
    let resp = send(
        &app,
        "GET",
        "/acme/infra/prod/cdn/-/settings",
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);

    // And the visibility edit is forbidden.
    let resp = send(
        &app,
        "POST",
        "/acme/infra/prod/cdn/-/settings/visibility",
        Some(&cookie),
        Some(&format!("csrf={csrf}&visibility=private")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
}

#[tokio::test]
async fn registry_delete_requires_typed_confirmation_and_owner() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let db = serve_managed(&surface, &fixture, "public").await;
    let app = router(app_state(Arc::clone(&db)));

    // An admin holds registry.configure but NOT the owner-only iam.admin verb,
    // so delete is forbidden.
    let admin = db.find_or_create_user("admin@acme.com").unwrap();
    db.grant_membership("user", admin, "acme", "admin").unwrap();
    let a_cookie = login(&app, &db, "admin@acme.com").await;
    let a_csrf = csrf_for(&a_cookie);
    let resp = send(
        &app,
        "POST",
        "/acme/infra/prod/cdn/-/settings/delete",
        Some(&a_cookie),
        Some(&format!("csrf={a_csrf}&confirm=acme/infra/prod/cdn")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    assert!(db
        .registry_by_slug("acme/infra/prod/cdn")
        .unwrap()
        .is_some());

    // An owner with the WRONG confirmation is rejected (typed-confirm gate).
    let owner = db.find_or_create_user("owner@acme.com").unwrap();
    db.grant_membership("user", owner, "acme", "owner").unwrap();
    let cookie = login(&app, &db, "owner@acme.com").await;
    let csrf = csrf_for(&cookie);
    let resp = send(
        &app,
        "POST",
        "/acme/infra/prod/cdn/-/settings/delete",
        Some(&cookie),
        Some(&format!("csrf={csrf}&confirm=wrong")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    assert!(db
        .registry_by_slug("acme/infra/prod/cdn")
        .unwrap()
        .is_some());

    // The correct typed confirmation removes the registry and audits, then
    // redirects to the owning org dashboard.
    let resp = send(
        &app,
        "POST",
        "/acme/infra/prod/cdn/-/settings/delete",
        Some(&cookie),
        Some(&format!("csrf={csrf}&confirm=acme/infra/prod/cdn")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    assert_eq!(resp.location.as_deref(), Some("/-/org/acme"));
    assert!(db
        .registry_by_slug("acme/infra/prod/cdn")
        .unwrap()
        .is_none());
    assert!(db
        .list_audit("acme")
        .unwrap()
        .iter()
        .any(|a| a.action == "registry.delete"));
}

#[tokio::test]
async fn org_delete_requires_typed_confirmation_and_owner() {
    let db = Arc::new(Database::open_in_memory().unwrap());
    db.create_org("acme", "Acme").unwrap();
    // An admin (not owner) cannot delete the org.
    let admin = db.find_or_create_user("admin@acme.com").unwrap();
    db.grant_membership("user", admin, "acme", "admin").unwrap();
    let owner = db.find_or_create_user("owner@acme.com").unwrap();
    db.grant_membership("user", owner, "acme", "owner").unwrap();
    let app = router(app_state(Arc::clone(&db)));

    let a_cookie = login(&app, &db, "admin@acme.com").await;
    let a_csrf = csrf_for(&a_cookie);
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/delete",
        Some(&a_cookie),
        Some(&format!("csrf={a_csrf}&confirm=acme")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    assert!(db.org_by_slug("acme").unwrap().is_some());

    let cookie = login(&app, &db, "owner@acme.com").await;
    let csrf = csrf_for(&cookie);
    // Wrong confirmation -> 400.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/delete",
        Some(&cookie),
        Some(&format!("csrf={csrf}&confirm=nope")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    assert!(db.org_by_slug("acme").unwrap().is_some());

    // Correct confirmation soft-deletes (org_by_slug excludes deleted) + audits.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/delete",
        Some(&cookie),
        Some(&format!("csrf={csrf}&confirm=acme")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    assert_eq!(resp.location.as_deref(), Some("/-/orgs"));
    assert!(db.org_by_slug("acme").unwrap().is_none());
    assert!(db.org_by_slug_including_deleted("acme").unwrap().is_some());
    assert!(db
        .list_audit("acme")
        .unwrap()
        .iter()
        .any(|a| a.action == "org.delete"));
}
