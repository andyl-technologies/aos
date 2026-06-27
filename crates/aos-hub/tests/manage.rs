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

use aos_hub::auth::extract::{mint_csrf_token, AuthState};
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::auth::session::COOKIE_NAME;
use aos_hub::db::{Database, SignupPolicy};
use aos_hub::fetch::LocalFsFetch;
use aos_hub::indexer::index_and_record;
use aos_hub::server::{router, AppState};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

const TEST_JWT_SECRET: &[u8] = b"manage-test-secret-32-byte-key!!!";

/// Build an [`AppState`] over `db` in dev mode with deterministic JWT keys.
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
    let secret = db.create_magic_link(email).await.unwrap();
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

/// Serializes every test that reads or mutates the process-global
/// `AOS_HUB_ALLOW_LOCAL_REMOTES` env var (the SSRF guard's test/dev hatch).
///
/// The SSRF guard ([`aos_hub::fetch::is_safe_remote_url`]) consults
/// this variable, so a test that needs loopback *allowed* and one that needs it
/// *rejected* must not run concurrently. Each such test takes [`remote_guard`]
/// for its whole body, holding the lock across `.await` (sound on the
/// current-thread `#[tokio::test]` runtime, which never migrates the future).
static REMOTE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A held [`REMOTE_ENV_LOCK`] that restores `AOS_HUB_ALLOW_LOCAL_REMOTES` to its
/// prior value on drop, so env-sensitive tests do not leak state to each other.
struct RemoteGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    prior: Option<std::ffi::OsString>,
}

impl Drop for RemoteGuard {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(value) => std::env::set_var("AOS_HUB_ALLOW_LOCAL_REMOTES", value),
            None => std::env::remove_var("AOS_HUB_ALLOW_LOCAL_REMOTES"),
        }
    }
}

/// Take the env lock and set `AOS_HUB_ALLOW_LOCAL_REMOTES` to `allow`.
///
/// `allow = true` relaxes the SSRF guard so a test may use `127.0.0.1`/unresolvable
/// `.test` hosts; `allow = false` enforces it. The prior value is restored on drop.
fn remote_guard(allow: bool) -> RemoteGuard {
    let _lock = REMOTE_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prior = std::env::var_os("AOS_HUB_ALLOW_LOCAL_REMOTES");
    if allow {
        std::env::set_var("AOS_HUB_ALLOW_LOCAL_REMOTES", "1");
    } else {
        std::env::remove_var("AOS_HUB_ALLOW_LOCAL_REMOTES");
    }
    RemoteGuard { _lock, prior }
}

#[tokio::test]
async fn create_org_open_signup_auto_owners_the_creator() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.set_signup_policy(SignupPolicy::Open).await.unwrap();
    // A fresh user with no memberships.
    db.find_or_create_user("founder@acme.com").await.unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
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

    assert!(db.org_by_slug("acme").await.unwrap().is_some());
    let founder = db.user_by_email("founder@acme.com").await.unwrap().unwrap();
    assert!(db
        .list_members_of_scope("acme")
        .await
        .unwrap()
        .iter()
        .any(|(k, id, r)| k == "user" && *id == founder && r == "owner"));
    assert!(db
        .list_audit("acme")
        .await
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
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    // Default policy is invite-only; a fresh, unaffiliated user.
    assert_eq!(db.signup_policy().await.unwrap(), SignupPolicy::InviteOnly);
    db.find_or_create_user("nobody@x.com").await.unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
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
    assert!(db.org_by_slug("acme").await.unwrap().is_none());

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

    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    let admin = db.find_or_create_user("admin@acme.com").await.unwrap();
    db.grant_membership("user", admin, "acme", "admin")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
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
    let org_id = db.org_by_slug("acme").await.unwrap().unwrap().id;
    assert!(db
        .list_projects(org_id)
        .await
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
        .await
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
        .await
        .unwrap()
        .expect("registry created");
    assert_eq!(registry.visibility, "public");
    assert!(db
        .list_audit("acme")
        .await
        .unwrap()
        .iter()
        .any(|a| a.action == "registry.create"));

    // registry_surface_root resolves to the bound surface; index it and browse.
    let root = db
        .registry_surface_root(registry.id)
        .await
        .unwrap()
        .unwrap();
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
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    // A viewer member (read, but no registry.configure / storage.manage).
    let viewer = db.find_or_create_user("v@acme.com").await.unwrap();
    db.grant_membership("user", viewer, "acme", "viewer")
        .await
        .unwrap();
    // A complete outsider.
    db.find_or_create_user("out@x.com").await.unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;

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
async fn create_registry_with_default_storage_needs_no_binding() {
    // Regression: the new-registry form used to dead-end with "no storage
    // bindings yet" when the org had none, and the POST rejected an empty
    // binding with "Choose a storage binding". A managed registry must be
    // creatable with zero storage configuration (it roots on the deployment's
    // default storage, with a prefix auto-derived from its slug).
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    let admin = db.find_or_create_user("admin@acme.com").await.unwrap();
    db.grant_membership("user", admin, "acme", "admin")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "admin@acme.com").await;
    let csrf = csrf_for(&cookie);

    // With no bindings, the form still renders and offers the default option.
    let resp = send(
        &app,
        "GET",
        "/-/org/acme/registries/new",
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("Default storage"), "{}", resp.body);

    // POST with an empty binding and empty prefix succeeds.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/registries",
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&name=cdn&project_path=&binding=&visibility=public&prefix="
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    assert_eq!(resp.location.as_deref(), Some("/acme/cdn/"));

    let registry = db
        .registry_by_slug("acme/cdn")
        .await
        .unwrap()
        .expect("registry created");
    assert_eq!(registry.storage_binding_id, None);
    // The prefix auto-derived from the slug.
    assert_eq!(registry.prefix, "acme/cdn");
}

#[tokio::test]
async fn binding_root_must_be_absolute() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    let admin = db.find_or_create_user("admin@acme.com").await.unwrap();
    db.grant_membership("user", admin, "acme", "admin")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
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
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme, Inc.").await.unwrap();
    let parent = surface.parent().unwrap().to_str().unwrap();
    let dir_name = surface.file_name().unwrap().to_str().unwrap();
    let binding = db
        .create_storage_binding(org, "primary", "local_fs", parent)
        .await
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
    .await
    .unwrap();
    let registry = db
        .registry_by_slug("acme/infra/prod/cdn")
        .await
        .unwrap()
        .unwrap();
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
    let app = router(app_state(Arc::clone(&db)).await).await;

    let owner = db.find_or_create_user("owner@acme.com").await.unwrap();
    db.grant_membership("user", owner, "acme", "owner")
        .await
        .unwrap();
    let cookie = login(&app, &db, "owner@acme.com").await;
    let csrf = csrf_for(&cookie);

    // The settings landing page renders the management sidebar nav and delete form.
    let resp = send(
        &app,
        "GET",
        "/acme/infra/prod/cdn/-/settings",
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(
        resp.body.contains("settings-nav"),
        "settings sidebar: {}",
        resp.body
    );
    assert!(
        resp.body.contains("/acme/infra/prod/cdn/-/settings/tokens"),
        "tokens link: {}",
        resp.body
    );
    assert!(
        resp.body.contains("/acme/infra/prod/cdn/-/keys"),
        "keys link"
    );
    // The remove-registry form now lives on its own Danger tab.
    let danger = send(
        &app,
        "GET",
        "/acme/infra/prod/cdn/-/settings/danger",
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(danger.status, StatusCode::OK, "{}", danger.body);
    assert!(danger.body.contains("remove registry"), "delete form");

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
            .await
            .unwrap()
            .unwrap()
            .visibility,
        "private"
    );
    assert!(db
        .list_audit("acme/infra/prod/cdn")
        .await
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
    let app = router(app_state(Arc::clone(&db)).await).await;

    // A developer at the registry scope lacks registry.configure.
    let dev = db.find_or_create_user("dev@acme.com").await.unwrap();
    db.grant_membership("user", dev, "acme/infra/prod/cdn", "developer")
        .await
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
    let app = router(app_state(Arc::clone(&db)).await).await;

    // An admin holds registry.configure but NOT the owner-only iam.admin verb,
    // so delete is forbidden.
    let admin = db.find_or_create_user("admin@acme.com").await.unwrap();
    db.grant_membership("user", admin, "acme", "admin")
        .await
        .unwrap();
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
        .await
        .unwrap()
        .is_some());

    // An owner with the WRONG confirmation is rejected (typed-confirm gate).
    let owner = db.find_or_create_user("owner@acme.com").await.unwrap();
    db.grant_membership("user", owner, "acme", "owner")
        .await
        .unwrap();
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
        .await
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
        .await
        .unwrap()
        .is_none());
    assert!(db
        .list_audit("acme")
        .await
        .unwrap()
        .iter()
        .any(|a| a.action == "registry.delete"));
}

#[tokio::test]
async fn org_delete_requires_typed_confirmation_and_owner() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    // An admin (not owner) cannot delete the org.
    let admin = db.find_or_create_user("admin@acme.com").await.unwrap();
    db.grant_membership("user", admin, "acme", "admin")
        .await
        .unwrap();
    let owner = db.find_or_create_user("owner@acme.com").await.unwrap();
    db.grant_membership("user", owner, "acme", "owner")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;

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
    assert!(db.org_by_slug("acme").await.unwrap().is_some());

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
    assert!(db.org_by_slug("acme").await.unwrap().is_some());

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
    assert!(db.org_by_slug("acme").await.unwrap().is_none());
    assert!(db
        .org_by_slug_including_deleted("acme")
        .await
        .unwrap()
        .is_some());
    assert!(db
        .list_audit("acme")
        .await
        .unwrap()
        .iter()
        .any(|a| a.action == "org.delete"));
}

#[tokio::test]
async fn admin_creates_and_deletes_a_webhook() {
    // create_webhook runs the SSRF guard on the URL; the `.test` hosts below do
    // not resolve, so allow local/unresolvable remotes for this happy path.
    let _remotes = remote_guard(true);
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    let owner = db.find_or_create_user("owner@acme.com").await.unwrap();
    db.grant_membership("user", owner, "acme", "owner")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "owner@acme.com").await;
    let csrf = csrf_for(&cookie);
    let org_id = db.org_by_slug("acme").await.unwrap().unwrap().id;

    // Create with two events; the hub-generated secret is shown once.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/webhooks",
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&op=create&url=https%3A%2F%2Fci.test%2Fhook\
             &events=channel.advanced&events=release.published&secret="
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("Webhook created"), "{}", resp.body);
    let hooks = db.list_webhooks(org_id).await.unwrap();
    assert_eq!(hooks.len(), 1);
    assert_eq!(hooks[0].url, "https://ci.test/hook");
    assert_eq!(
        hooks[0].events,
        vec![
            "channel.advanced".to_string(),
            "release.published".to_string()
        ]
    );
    assert!(!hooks[0].secret.is_empty(), "a secret was generated");

    // An unknown event type is rejected.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/webhooks",
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&op=create&url=https%3A%2F%2Fx.test&events=bogus.event"
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);

    // Delete it; the list empties and the action is audited.
    let id = hooks[0].id;
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/webhooks",
        Some(&cookie),
        Some(&format!("csrf={csrf}&op=delete&webhook_id={id}")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(db.list_webhooks(org_id).await.unwrap().is_empty());
    assert!(db
        .list_audit("acme")
        .await
        .unwrap()
        .iter()
        .any(|a| a.action == "webhook.delete"));

    // CSRF is required.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/webhooks",
        Some(&cookie),
        Some("csrf=bad&op=create&url=https%3A%2F%2Fx.test"),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn webhook_create_rejects_ssrf_url() {
    // The SSRF guard must reject a webhook pointed at the cloud-metadata
    // (link-local) address even for an org owner: the delivery worker would POST
    // to it from inside the hub network (finding H4). Deny local remotes so the
    // guard is enforced regardless of any parallel test's env state.
    let _remotes = remote_guard(false);
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    let owner = db.find_or_create_user("owner@acme.com").await.unwrap();
    db.grant_membership("user", owner, "acme", "owner")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "owner@acme.com").await;
    let csrf = csrf_for(&cookie);
    let org_id = db.org_by_slug("acme").await.unwrap().unwrap().id;

    // The cloud-metadata link-local address is rejected without any DNS.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/webhooks",
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&op=create&url=http%3A%2F%2F169.254.169.254%2F&events=release.published"
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    assert!(resp.body.contains("rejecting webhook url"), "{}", resp.body);

    // A loopback target is likewise rejected, and nothing is stored.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/webhooks",
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&op=create&url=http%3A%2F%2F127.0.0.1%3A8500%2Fv1%2F&events=release.published"
        )),
    ).await
    ;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    assert!(db.list_webhooks(org_id).await.unwrap().is_empty());
}

#[tokio::test]
async fn non_admin_member_cannot_manage_webhooks() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    let member = db.find_or_create_user("viewer@acme.com").await.unwrap();
    db.grant_membership("user", member, "acme", "viewer")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "viewer@acme.com").await;
    let csrf = csrf_for(&cookie);

    // A reader is a member (so the org is not hidden) but lacks members.manage.
    let resp = send(&app, "GET", "/-/org/acme/webhooks", Some(&cookie), None).await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/webhooks",
        Some(&cookie),
        Some(&format!("csrf={csrf}&op=create&url=https%3A%2F%2Fx.test")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
}

#[tokio::test]
async fn owner_configures_sso_and_captures_domain() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    let owner = db.find_or_create_user("owner@acme.com").await.unwrap();
    db.grant_membership("user", owner, "acme", "owner")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "owner@acme.com").await;
    let csrf = csrf_for(&cookie);
    let org_id = db.org_by_slug("acme").await.unwrap().unwrap().id;

    // Configure the IdP with a client secret.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/sso",
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&op=set-idp&issuer=https%3A%2F%2Fidp.test&\
             auth_url=https%3A%2F%2Fidp.test%2Fa&token_url=https%3A%2F%2Fidp.test%2Ft&\
             jwks_uri=https%3A%2F%2Fidp.test%2Fj&client_id=cid&client_secret=topsecret&\
             scopes=openid+email&role_map=%7B%7D&default_role=viewer&allow_jit=1"
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    let cfg = db
        .idp_config(org_id)
        .await
        .unwrap()
        .expect("idp configured");
    assert_eq!(cfg.issuer, "https://idp.test");
    assert_eq!(cfg.client_id, "cid");
    let sealed = cfg.client_secret_enc.clone().expect("secret sealed");
    assert_ne!(sealed, "topsecret", "secret is sealed, not plaintext");

    // Editing other fields with a blank secret keeps the sealed secret.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/sso",
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&op=set-idp&issuer=https%3A%2F%2Fidp.test&\
             auth_url=https%3A%2F%2Fidp.test%2Fa&token_url=https%3A%2F%2Fidp.test%2Ft&\
             jwks_uri=https%3A%2F%2Fidp.test%2Fj&client_id=cid2&client_secret=&\
             role_map=%7B%7D&default_role=viewer"
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    let cfg = db.idp_config(org_id).await.unwrap().unwrap();
    assert_eq!(cfg.client_id, "cid2");
    assert_eq!(
        cfg.client_secret_enc.as_deref(),
        Some(sealed.as_str()),
        "kept"
    );

    // Capture a domain; it lands unverified.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/sso",
        Some(&cookie),
        Some(&format!("csrf={csrf}&op=add-domain&domain=acme.com")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(db
        .org_domain("acme.com")
        .await
        .unwrap()
        .unwrap()
        .verified_at
        .is_none());

    // An org owner (not an instance admin) cannot verify — it routes logins.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/sso",
        Some(&cookie),
        Some(&format!("csrf={csrf}&op=verify-domain&domain=acme.com")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    assert!(db
        .org_domain("acme.com")
        .await
        .unwrap()
        .unwrap()
        .verified_at
        .is_none());
}

#[tokio::test]
async fn instance_admin_verifies_a_captured_domain() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    let admin = db.find_or_create_user("root@hub").await.unwrap();
    db.grant_membership("user", admin, "acme", "owner")
        .await
        .unwrap();
    // Instance admin: owner at the root scope "".
    db.grant_membership("user", admin, "", "owner")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "root@hub").await;
    let csrf = csrf_for(&cookie);
    let org_id = db.org_by_slug("acme").await.unwrap().unwrap().id;
    db.add_org_domain(org_id, "acme.com").await.unwrap();

    let resp = send(
        &app,
        "POST",
        "/-/org/acme/sso",
        Some(&cookie),
        Some(&format!("csrf={csrf}&op=verify-domain&domain=acme.com")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(db
        .org_domain("acme.com")
        .await
        .unwrap()
        .unwrap()
        .verified_at
        .is_some());
    assert!(db
        .list_audit("acme")
        .await
        .unwrap()
        .iter()
        .any(|a| a.action == "domain.verify"));
}

/// H7: an admin of one org cannot seize a domain already claimed by another.
#[tokio::test]
async fn add_domain_rejects_cross_org_claim_theft() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    db.create_org("globex", "Globex").await.unwrap();
    let acme_id = db.org_by_slug("acme").await.unwrap().unwrap().id;

    // Acme claims and an instance admin verifies acme.com.
    db.add_org_domain(acme_id, "acme.com").await.unwrap();
    db.verify_org_domain("acme.com").await.unwrap();
    let before = db.org_domain("acme.com").await.unwrap().unwrap();
    assert_eq!(before.org_id, acme_id);
    assert!(before.verified_at.is_some());

    // An owner of Globex tries to claim acme.com through the console.
    let attacker = db.find_or_create_user("attacker@globex.com").await.unwrap();
    db.grant_membership("user", attacker, "globex", "owner")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "attacker@globex.com").await;
    let csrf = csrf_for(&cookie);
    let resp = send(
        &app,
        "POST",
        "/-/org/globex/sso",
        Some(&cookie),
        Some(&format!("csrf={csrf}&op=add-domain&domain=acme.com")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);

    // Acme's row is untouched: still owned by Acme and still verified.
    let after = db.org_domain("acme.com").await.unwrap().unwrap();
    assert_eq!(after.org_id, acme_id, "ownership unchanged");
    assert_eq!(
        after.verified_at, before.verified_at,
        "verification unchanged"
    );
    assert_eq!(
        after.txt_challenge, before.txt_challenge,
        "challenge unrotated"
    );

    // The owning org CAN re-claim its own domain (re-issues the challenge).
    let challenge = db.add_org_domain(acme_id, "acme.com").await.unwrap();
    let reclaimed = db.org_domain("acme.com").await.unwrap().unwrap();
    assert_eq!(reclaimed.org_id, acme_id);
    assert!(
        reclaimed.verified_at.is_none(),
        "re-claim resets verification"
    );
    assert_eq!(reclaimed.txt_challenge, challenge);
}

/// M-4: the transactional `add_org_domain` enforces the cross-tenant invariant
/// at the db layer — a domain owned by org A can never have its `org_id`
/// re-pointed to org B (the check + upsert share one transaction), while org A
/// can always re-claim its own domain.
#[tokio::test]
async fn add_org_domain_is_atomically_cross_org_safe() {
    let db = Database::open_in_memory().await.unwrap();
    let acme = db.create_org("acme", "Acme").await.unwrap();
    let globex = db.create_org("globex", "Globex").await.unwrap();

    // Acme claims and verifies the domain.
    db.add_org_domain(acme, "acme.com").await.unwrap();
    db.verify_org_domain("acme.com").await.unwrap();
    let before = db.org_domain("acme.com").await.unwrap().unwrap();
    assert!(before.verified_at.is_some());

    // Globex cannot re-point it: the call errors and the row is untouched.
    let err = db.add_org_domain(globex, "acme.com").await.unwrap_err();
    assert!(
        err.to_string()
            .contains("already claimed by another organization"),
        "got: {err:#}"
    );
    let after = db.org_domain("acme.com").await.unwrap().unwrap();
    assert_eq!(after.org_id, acme, "org_id unchanged");
    assert_eq!(
        after.verified_at, before.verified_at,
        "verification unwiped"
    );

    // The owning org can re-claim, rotating the challenge and resetting to
    // unverified.
    let challenge = db.add_org_domain(acme, "acme.com").await.unwrap();
    let reclaimed = db.org_domain("acme.com").await.unwrap().unwrap();
    assert_eq!(reclaimed.org_id, acme);
    assert!(reclaimed.verified_at.is_none());
    assert_eq!(reclaimed.txt_challenge, challenge);
}

#[tokio::test]
async fn project_and_binding_delete_with_in_use_guard() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    let owner = db.find_or_create_user("owner@acme.com").await.unwrap();
    db.grant_membership("user", owner, "acme", "owner")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "owner@acme.com").await;
    let csrf = csrf_for(&cookie);
    let org_id = db.org_by_slug("acme").await.unwrap().unwrap().id;

    // An unused project deletes cleanly.
    db.create_project(org_id, "infra/prod", "Prod")
        .await
        .unwrap();
    let pid = db
        .list_projects(org_id)
        .await
        .unwrap()
        .into_iter()
        .find(|p| p.path == "infra/prod")
        .unwrap()
        .id;
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/projects/delete",
        Some(&cookie),
        Some(&format!("csrf={csrf}&id={pid}")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    assert!(db
        .list_projects(org_id)
        .await
        .unwrap()
        .iter()
        .all(|p| p.id != pid));

    // A binding still referenced by a registry is guarded from deletion.
    db.create_storage_binding(org_id, "primary", "local_fs", "/srv/acme")
        .await
        .unwrap();
    let bid = db
        .storage_binding_by_name(org_id, "primary")
        .await
        .unwrap()
        .unwrap()
        .id;
    db.create_managed_registry(org_id, "", "cdn", "public", Some(bid), "cdn", &[], false)
        .await
        .unwrap();
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/bindings/delete",
        Some(&cookie),
        Some(&format!("csrf={csrf}&id={bid}")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);
    assert!(db
        .storage_binding_by_name(org_id, "primary")
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn member_role_change_and_last_owner_guard() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    let owner = db.find_or_create_user("owner@acme.com").await.unwrap();
    db.grant_membership("user", owner, "acme", "owner")
        .await
        .unwrap();
    let dev = db.find_or_create_user("dev@acme.com").await.unwrap();
    db.grant_membership("user", dev, "acme", "developer")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "owner@acme.com").await;
    let csrf = csrf_for(&cookie);

    // Promote the developer to admin.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/members/role",
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&principal_kind=user&principal_id={dev}&role=admin"
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    let members = db.list_members_of_scope("acme").await.unwrap();
    assert!(members
        .iter()
        .any(|(k, id, r)| k == "user" && *id == dev && r == "admin"));

    // Demoting the sole owner is blocked.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/members/role",
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&principal_kind=user&principal_id={owner}&role=viewer"
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);
    assert!(db
        .list_members_of_scope("acme")
        .await
        .unwrap()
        .iter()
        .any(|(k, id, r)| k == "user" && *id == owner && r == "owner"));
}

/// H1: an org admin (members.manage, NOT iam.admin) cannot grant `owner` —
/// neither to a peer nor to itself — and the rejected grant never lands.
#[tokio::test]
async fn admin_cannot_escalate_to_owner() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    let owner = db.find_or_create_user("owner@acme.com").await.unwrap();
    db.grant_membership("user", owner, "acme", "owner")
        .await
        .unwrap();
    let admin = db.find_or_create_user("admin@acme.com").await.unwrap();
    db.grant_membership("user", admin, "acme", "admin")
        .await
        .unwrap();
    let victim = db.find_or_create_user("victim@acme.com").await.unwrap();
    db.grant_membership("user", victim, "acme", "viewer")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "admin@acme.com").await;
    let csrf = csrf_for(&cookie);

    // The admin tries to promote a viewer straight to owner: forbidden.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/members/role",
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&principal_kind=user&principal_id={victim}&role=owner"
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    // The victim's role is unchanged.
    assert!(db
        .list_members_of_scope("acme")
        .await
        .unwrap()
        .iter()
        .any(|(k, id, r)| k == "user" && *id == victim && r == "viewer"));

    // The admin tries to promote ITSELF to owner: also forbidden.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/members/role",
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&principal_kind=user&principal_id={admin}&role=owner"
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    assert!(db
        .list_members_of_scope("acme")
        .await
        .unwrap()
        .iter()
        .any(|(k, id, r)| k == "user" && *id == admin && r == "admin"));

    // The admin may still make a lateral/lower grant (viewer -> developer).
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/members/role",
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&principal_kind=user&principal_id={victim}&role=developer"
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    assert!(db
        .list_members_of_scope("acme")
        .await
        .unwrap()
        .iter()
        .any(|(k, id, r)| k == "user" && *id == victim && r == "developer"));
}

#[tokio::test]
async fn instance_settings_signup_policy_admin_only() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    let member = db.find_or_create_user("member@acme.com").await.unwrap();
    db.grant_membership("user", member, "acme", "owner")
        .await
        .unwrap();
    let admin = db.find_or_create_user("root@hub").await.unwrap();
    db.grant_membership("user", admin, "", "owner")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;

    // An org owner who is not an instance admin is forbidden.
    let member_cookie = login(&app, &db, "member@acme.com").await;
    let resp = send(&app, "GET", "/-/instance", Some(&member_cookie), None).await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);

    // The instance admin can flip the signup policy.
    let admin_cookie = login(&app, &db, "root@hub").await;
    let csrf = csrf_for(&admin_cookie);
    let resp = send(
        &app,
        "POST",
        "/-/instance",
        Some(&admin_cookie),
        Some(&format!("csrf={csrf}&signup_policy=open")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(matches!(
        db.signup_policy().await.unwrap(),
        aos_hub::db::SignupPolicy::Open
    ));
}

#[tokio::test]
async fn admin_manages_frontends_and_mirror() {
    // The SSRF guard resolves the frontend/mirror host; opt into loopback so
    // the test can use 127.0.0.1 without real DNS.
    let _remotes = remote_guard(true);
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    let owner = db.find_or_create_user("owner@acme.com").await.unwrap();
    db.grant_membership("user", owner, "acme", "owner")
        .await
        .unwrap();
    let org_id = db.org_by_slug("acme").await.unwrap().unwrap().id;
    db.create_storage_binding(org_id, "primary", "local_fs", "/srv/acme")
        .await
        .unwrap();
    let bid = db
        .storage_binding_by_name(org_id, "primary")
        .await
        .unwrap()
        .unwrap()
        .id;
    let reg_id = db
        .create_managed_registry(org_id, "", "cdn", "public", Some(bid), "cdn", &[], false)
        .await
        .unwrap();
    let slug = db
        .list_registries()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.id == reg_id)
        .unwrap()
        .slug;

    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "owner@acme.com").await;
    let csrf = csrf_for(&cookie);
    let path = format!("/{slug}/-/settings/serving");

    // The page renders for a configurer.
    let resp = send(&app, "GET", &path, Some(&cookie), None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);

    // Add a frontend (loopback host).
    let resp = send(
        &app,
        "POST",
        &path,
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&op=add-frontend&domain=127.0.0.1&mode=direct&serves_web=1&consumer_priority=100"
        )),
    ).await
    ;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    let frontends = db.list_frontends(reg_id).await.unwrap();
    assert_eq!(frontends.len(), 1);
    assert_eq!(frontends[0].domain, "127.0.0.1");

    // Configure a mirror, then stop mirroring.
    let resp = send(
        &app,
        "POST",
        &path,
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&op=set-mirror&upstream_url=http%3A%2F%2F127.0.0.1%2Fup&mode=pullthrough&verify=1&schedule_secs=900"
        )),
    ).await
    ;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(db.is_mirror(reg_id).await.unwrap());

    let resp = send(
        &app,
        "POST",
        &path,
        Some(&cookie),
        Some(&format!("csrf={csrf}&op=remove-mirror")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(!db.is_mirror(reg_id).await.unwrap());

    // Delete the frontend.
    let fid = db.list_frontends(reg_id).await.unwrap()[0].id;
    let resp = send(
        &app,
        "POST",
        &path,
        Some(&cookie),
        Some(&format!("csrf={csrf}&op=delete-frontend&id={fid}")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(db.list_frontends(reg_id).await.unwrap().is_empty());

    // A non-configurer member is forbidden.
    let viewer = db.find_or_create_user("v@acme.com").await.unwrap();
    db.grant_membership("user", viewer, "acme", "viewer")
        .await
        .unwrap();
    let v_cookie = login(&app, &db, "v@acme.com").await;
    let resp = send(&app, "GET", &path, Some(&v_cookie), None).await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
}

/// Build a **non-sudo** session cookie for `user` (auth_level 0), standing in
/// for a stale, long-lived session that fell out of the sudo window.
async fn stale_cookie(db: &Database, user: i64) -> String {
    format!(
        "{COOKIE_NAME}={}",
        db.create_session(user, 30 * 24 * 60 * 60, 0).await.unwrap()
    )
}

/// M-1: the credential-minting and trust-changing org ops refuse a stale
/// (non-sudo) session with a `403`, while a fresh magic-link login (sudo)
/// performs them. Covers invite, role-change, remove-member, set-idp, and
/// hosted-key enroll.
#[tokio::test]
async fn trust_ops_require_sudo() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    let owner = db.find_or_create_user("owner@acme.com").await.unwrap();
    db.grant_membership("user", owner, "acme", "owner")
        .await
        .unwrap();
    // A second owner exists so role/remove ops are not blocked by the
    // last-owner guard (we are testing the sudo gate, not that guard).
    let co = db.find_or_create_user("co@acme.com").await.unwrap();
    db.grant_membership("user", co, "acme", "owner")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;

    // A stale (non-sudo) session for the owner.
    let stale = stale_cookie(&db, owner).await;
    let s_csrf = csrf_for(&stale);

    // invite-member: 403 stale.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/members",
        Some(&stale),
        Some(&format!("csrf={s_csrf}&email=new@acme.com&role=viewer")),
    )
    .await;
    assert_eq!(
        resp.status,
        StatusCode::FORBIDDEN,
        "invite stale: {}",
        resp.body
    );

    // role-change: 403 stale.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/members/role",
        Some(&stale),
        Some(&format!(
            "csrf={s_csrf}&principal_kind=user&principal_id={co}&role=admin"
        )),
    )
    .await;
    assert_eq!(
        resp.status,
        StatusCode::FORBIDDEN,
        "role stale: {}",
        resp.body
    );

    // remove-member: 403 stale.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/members/remove",
        Some(&stale),
        Some(&format!(
            "csrf={s_csrf}&principal_kind=user&principal_id={co}"
        )),
    )
    .await;
    assert_eq!(
        resp.status,
        StatusCode::FORBIDDEN,
        "remove stale: {}",
        resp.body
    );

    // set-idp: 403 stale.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/sso",
        Some(&stale),
        Some(&format!(
            "csrf={s_csrf}&op=set-idp&issuer=https%3A%2F%2Fidp.test&\
             auth_url=https%3A%2F%2Fidp.test%2Fa&token_url=https%3A%2F%2Fidp.test%2Ft&\
             jwks_uri=https%3A%2F%2Fidp.test%2Fj&client_id=cid&client_secret=x&\
             role_map=%7B%7D&default_role=viewer"
        )),
    )
    .await;
    assert_eq!(
        resp.status,
        StatusCode::FORBIDDEN,
        "set-idp stale: {}",
        resp.body
    );

    // hosted-key enroll: 403 stale.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/keys",
        Some(&stale),
        Some(&format!("csrf={s_csrf}&op=create&key_id=k1")),
    )
    .await;
    assert_eq!(
        resp.status,
        StatusCode::FORBIDDEN,
        "keys stale: {}",
        resp.body
    );

    // Nothing was mutated by any refused request.
    assert!(db.user_by_email("new@acme.com").await.unwrap().is_none());
    assert_eq!(
        db.list_members_of_scope("acme")
            .await
            .unwrap()
            .iter()
            .filter(|(k, _, r)| k == "user" && r == "owner")
            .count(),
        2,
        "both owners intact"
    );
    assert!(db
        .idp_config(db.org_by_slug("acme").await.unwrap().unwrap().id)
        .await
        .unwrap()
        .is_none());

    // A FRESH magic-link login (sudo) performs the same ops.
    let fresh = login(&app, &db, "owner@acme.com").await;
    let f_csrf = csrf_for(&fresh);

    let resp = send(
        &app,
        "POST",
        "/-/org/acme/members",
        Some(&fresh),
        Some(&format!("csrf={f_csrf}&email=new@acme.com&role=viewer")),
    )
    .await;
    assert_eq!(
        resp.status,
        StatusCode::SEE_OTHER,
        "invite fresh: {}",
        resp.body
    );
    assert!(db.user_by_email("new@acme.com").await.unwrap().is_some());

    let resp = send(
        &app,
        "POST",
        "/-/org/acme/sso",
        Some(&fresh),
        Some(&format!(
            "csrf={f_csrf}&op=set-idp&issuer=https%3A%2F%2Fidp.test&\
             auth_url=https%3A%2F%2Fidp.test%2Fa&token_url=https%3A%2F%2Fidp.test%2Ft&\
             jwks_uri=https%3A%2F%2Fidp.test%2Fj&client_id=cid&client_secret=x&\
             role_map=%7B%7D&default_role=viewer"
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "set-idp fresh: {}", resp.body);
    assert!(db
        .idp_config(db.org_by_slug("acme").await.unwrap().unwrap().id)
        .await
        .unwrap()
        .is_some());

    let resp = send(
        &app,
        "POST",
        "/-/org/acme/keys",
        Some(&fresh),
        Some(&format!("csrf={f_csrf}&op=create&key_id=k1")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "keys fresh: {}", resp.body);
}
