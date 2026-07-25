//! Integration coverage for the authenticated producer console (RFC-0004
//! phase-3b).
//!
//! Drives the real router over plain HTTP: the magic-link login flow,
//! device-code approval at `/activate`, CSRF enforcement on every POST,
//! per-registry token management, the channel rollout console's prepared
//! operation, member invite/remove through change-sets, and the authz
//! matrix (non-member 404, member 200, forbidden mutation 403).

mod common;

use std::path::Path;
use std::sync::Arc;

use aos_hub::auth::extract::{mint_csrf_token, AuthState};
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::auth::session::COOKIE_NAME;
use aos_hub::db::Database;
use aos_hub::domain::{Permission, Principal};
use aos_hub::fetch::LocalFsFetch;
use aos_hub::indexer::index_and_record;
use aos_hub::server::{router, AppState};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

const TEST_JWT_SECRET: &[u8] = b"console-test-secret-32-byte-key!!";

/// Build an [`AppState`] over `db` in dev mode (so the login page shows the
/// magic link inline) with deterministic JWT keys.
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

/// A captured HTTP response: status, the `Set-Cookie` value, a `Location`
/// redirect, and the body text.
struct Resp {
    status: StatusCode,
    set_cookie: Option<String>,
    location: Option<String>,
    body: String,
}

/// Issue a request with an optional cookie and form/query body.
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

/// Extract the `__Host-aos_session` cookie value from a `Set-Cookie` header.
fn cookie_value(set_cookie: &str) -> String {
    let prefix = format!("{COOKIE_NAME}=");
    let after = set_cookie.strip_prefix(&prefix).expect("session cookie");
    after.split(';').next().unwrap().to_string()
}

/// Sign in `email` by minting a magic link in the db and consuming it through
/// `/auth/magic`; returns the `__Host-aos_session` cookie header value.
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

/// Seed org "acme", a binding over the fixture surface's parent, and a
/// managed registry at `acme/infra/prod/cdn` indexed from the fixture.
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
async fn login_flow_creates_user_session_and_logout_revokes() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(Arc::clone(&db)).await).await;

    // POST /login issues a magic link (captured via the db) and shows the
    // dev link inline.
    let resp = send(&app, "POST", "/login", None, Some("email=dev@acme.com")).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("Check your email"), "{}", resp.body);
    assert!(
        resp.body.contains("dev mode:"),
        "dev link shown: {}",
        resp.body
    );

    // GET /auth/magic sets a cookie, creates the user, and redirects.
    let cookie = login(&app, &db, "dev@acme.com").await;
    assert!(db.user_by_email("dev@acme.com").await.unwrap().is_some());

    // /account renders for the session.
    let resp = send(&app, "GET", "/-/account", Some(&cookie), None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("dev@acme.com"));
    assert!(resp.body.contains("log out"), "masthead session indicator");

    // logout revokes and clears the cookie; /account then bounces to /login.
    let resp = send(&app, "GET", "/logout", Some(&cookie), None).await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    let resp = send(&app, "GET", "/-/account", Some(&cookie), None).await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert_eq!(resp.location.as_deref(), Some("/login"));
}

#[tokio::test]
async fn activate_shows_scope_and_approves_with_clamped_token() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    // The approving user is a maintainer at acme/infra.
    let user = db.find_or_create_user("maint@acme.com").await.unwrap();
    db.grant_membership("user", user, "acme/infra", "maintainer")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "maint@acme.com").await;

    // A CLI starts a device grant requesting read+publish at acme/infra/prod.
    let (device_code, user_code, _ttl) = db
        .start_device_authorization("acme/infra/prod", &[Permission::Read, Permission::Publish])
        .await
        .unwrap();

    // The activate page shows the requested scope/permissions.
    let resp = send(
        &app,
        "GET",
        &format!("/activate?user_code={user_code}"),
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("acme/infra/prod"), "{}", resp.body);
    assert!(resp.body.contains("read, publish"), "{}", resp.body);

    // Approve with a valid CSRF token.
    let csrf = mint_csrf_token(cookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap());
    let form = format!("csrf={csrf}&user_code={user_code}&decision=approve");
    let resp = send(&app, "POST", "/activate", Some(&cookie), Some(&form)).await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);

    // The CLI poll now returns Approved with a token clamped to the user's
    // grants (the maintainer holds publish at acme/infra, covering the
    // requested acme/infra/prod scope).
    let poll = db.poll_device(&device_code).await.unwrap();
    let secret = match poll {
        aos_hub::db::DevicePollResult::Approved(secret) => secret,
        other => panic!("expected approval, got {other:?}"),
    };
    let token = db
        .validate_token(&secret)
        .await
        .unwrap()
        .expect("minted token");
    assert_eq!(token.owner, Principal::user(user));
    assert!(token.permissions.contains(&Permission::Read));
    assert!(token.permissions.contains(&Permission::Publish));
}

#[tokio::test]
async fn activate_is_rate_limited_per_session_user() {
    // L-4: the /activate approve surface keys a pending grant only on its
    // user_code, with no ownership predicate, so a signed-in user must be
    // throttled to stop them enumerating the code space to discover or hijack
    // other users' in-flight device grants. A fresh session user is unaffected.
    use aos_hub::ratelimit::DEVICE_ACTIVATE;

    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.find_or_create_user("enum@acme.com").await.unwrap();
    db.find_or_create_user("other@acme.com").await.unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "enum@acme.com").await;

    // The first DEVICE_ACTIVATE GETs in the window are served (the rate-limit
    // check runs before the user_code lookup, so a missing code still counts).
    for i in 0..DEVICE_ACTIVATE {
        let resp = send(&app, "GET", "/activate", Some(&cookie), None).await;
        assert_eq!(resp.status, StatusCode::OK, "GET #{i}: {}", resp.body);
    }
    // The next over the budget is throttled with 429.
    let resp = send(&app, "GET", "/activate", Some(&cookie), None).await;
    assert_eq!(resp.status, StatusCode::TOO_MANY_REQUESTS, "{}", resp.body);

    // The POST approve path shares the same per-user budget — already exhausted
    // for this user — so a submit is throttled too (before CSRF is even read).
    let csrf = mint_csrf_token(cookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap());
    let form = format!("csrf={csrf}&user_code=ZZZ-ZZZ&decision=approve");
    let resp = send(&app, "POST", "/activate", Some(&cookie), Some(&form)).await;
    assert_eq!(resp.status, StatusCode::TOO_MANY_REQUESTS, "{}", resp.body);

    // A different session user has their own fresh budget.
    let other_cookie = login(&app, &db, "other@acme.com").await;
    let resp = send(&app, "GET", "/activate", Some(&other_cookie), None).await;
    assert_eq!(
        resp.status,
        StatusCode::OK,
        "fresh session user unaffected: {}",
        resp.body
    );
}

#[tokio::test]
async fn post_without_csrf_is_forbidden() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.find_or_create_user("dev@acme.com").await.unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "dev@acme.com").await;

    // revoke-all-sessions with no csrf field → 403.
    let resp = send(
        &app,
        "POST",
        "/-/account/sessions/revoke-all",
        Some(&cookie),
        Some(""),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);

    // A wrong csrf token is equally rejected.
    let resp = send(
        &app,
        "POST",
        "/-/account/sessions/revoke-all",
        Some(&cookie),
        Some("csrf=garbage"),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn token_management_create_list_revoke_rotate() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let db = serve_managed(&surface, &fixture, "public").await;

    // A developer at the registry scope may mint a read token.
    let user = db.find_or_create_user("dev@acme.com").await.unwrap();
    db.grant_membership("user", user, "acme/infra/prod/cdn", "developer")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "dev@acme.com").await;
    let csrf = mint_csrf_token(cookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap());

    let base = "/acme/infra/prod/cdn/-/settings/tokens";

    // Create: the secret shows exactly once.
    let resp = send(
        &app,
        "POST",
        base,
        Some(&cookie),
        Some(&format!("csrf={csrf}&perm_read=1")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("shown only once"), "{}", resp.body);
    assert!(
        resp.body.contains("aos_"),
        "the secret is rendered: {}",
        resp.body
    );

    // The token now lists for the user.
    let tokens = db.list_tokens_for(Principal::user(user)).await.unwrap();
    assert_eq!(tokens.len(), 1);
    let token_id = tokens[0].0.clone();

    // Listing page shows it.
    let resp = send(&app, "GET", base, Some(&cookie), None).await;
    assert!(resp.body.contains(&token_id), "{}", resp.body);

    // Rotate shows a new secret once and mints a fresh token id; the old
    // secret keeps validating through the rotation grace window, so it stays
    // listed (revoked_at is unset on a rotation — the v6 grace split).
    let resp = send(
        &app,
        "POST",
        &format!("{base}/rotate"),
        Some(&cookie),
        Some(&format!("csrf={csrf}&token_id={token_id}")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("Token rotated"), "{}", resp.body);
    let after_rotate = db.list_tokens_for(Principal::user(user)).await.unwrap();
    let new_id = after_rotate
        .iter()
        .map(|(id, _, _)| id.clone())
        .find(|id| id != &token_id)
        .expect("rotation mints a new token id");

    // Revoke hard-removes the new token from the live list.
    let resp = send(
        &app,
        "POST",
        &format!("{base}/revoke"),
        Some(&cookie),
        Some(&format!("csrf={csrf}&token_id={new_id}")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    assert!(db
        .list_tokens_for(Principal::user(user))
        .await
        .unwrap()
        .iter()
        .all(|(id, _, _)| id != &new_id));
}

/// M-1: minting a token and rotating a token both require a **sudo** session.
/// A stale (auth_level 0) session is refused with a `403`; a fresh magic-link
/// login (sudo) succeeds. Revocation is *not* gated (it deadens a credential
/// rather than minting one).
#[tokio::test]
async fn token_mint_and_rotate_require_sudo() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let db = serve_managed(&surface, &fixture, "public").await;

    let user = db.find_or_create_user("dev@acme.com").await.unwrap();
    db.grant_membership("user", user, "acme/infra/prod/cdn", "developer")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let base = "/acme/infra/prod/cdn/-/settings/tokens";

    // A stale (non-sudo, auth_level 0) session for the user.
    let stale_secret = db.create_session(user, 30 * 24 * 60 * 60, 0).await.unwrap();
    let stale = format!("{COOKIE_NAME}={stale_secret}");
    let s_csrf = mint_csrf_token(&stale_secret);

    // Mint refused for the stale session; no token is created.
    let resp = send(
        &app,
        "POST",
        base,
        Some(&stale),
        Some(&format!("csrf={s_csrf}&perm_read=1")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    assert!(db
        .list_tokens_for(Principal::user(user))
        .await
        .unwrap()
        .is_empty());

    // A fresh magic-link login (sudo) mints the token.
    let fresh = login(&app, &db, "dev@acme.com").await;
    let f_csrf = mint_csrf_token(fresh.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap());
    let resp = send(
        &app,
        "POST",
        base,
        Some(&fresh),
        Some(&format!("csrf={f_csrf}&perm_read=1")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    let tokens = db.list_tokens_for(Principal::user(user)).await.unwrap();
    assert_eq!(tokens.len(), 1);
    let token_id = tokens[0].0.clone();

    // Rotate is refused for the stale session...
    let resp = send(
        &app,
        "POST",
        &format!("{base}/rotate"),
        Some(&stale),
        Some(&format!("csrf={s_csrf}&token_id={token_id}")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);

    // ...but revoke is NOT gated (it only deadens a credential).
    let resp = send(
        &app,
        "POST",
        &format!("{base}/revoke"),
        Some(&stale),
        Some(&format!("csrf={s_csrf}&token_id={token_id}")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
}

#[tokio::test]
async fn channel_console_prepares_advance_and_viewer_sees_no_form() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let db = serve_managed(&surface, &fixture, "public").await;
    let app = router(app_state(Arc::clone(&db)).await).await;

    // A viewer sees the grid but no advance form.
    let viewer = db.find_or_create_user("view@acme.com").await.unwrap();
    db.grant_membership("user", viewer, "acme/infra/prod/cdn", "viewer")
        .await
        .unwrap();
    let vcookie = login(&app, &db, "view@acme.com").await;
    let resp = send(
        &app,
        "GET",
        "/acme/infra/prod/cdn/-/channels/stable/console",
        Some(&vcookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("partition-grid"), "{}", resp.body);
    assert!(
        !resp.body.contains("prepare advance"),
        "viewer sees no form"
    );
    assert!(resp.body.contains("Read-only"));

    // A maintainer prepares an advance: the apr command is rendered and a
    // change-set is recorded.
    let maint = db.find_or_create_user("maint@acme.com").await.unwrap();
    db.grant_membership("user", maint, "acme/infra/prod/cdn", "maintainer")
        .await
        .unwrap();
    let mcookie = login(&app, &db, "maint@acme.com").await;
    let csrf = mint_csrf_token(mcookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap());
    let resp = send(
        &app,
        "POST",
        "/acme/infra/prod/cdn/-/channels/stable/console",
        Some(&mcookie),
        Some(&format!("csrf={csrf}&release=1.4.2&partitions=128")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(
        resp.body.contains("apr channel advance --from-hub"),
        "{}",
        resp.body
    );
    assert!(resp.body.contains("Prepared operation"));
    // The preparation recorded a draft change-set + audited it.
    let changesets = db.list_changesets("acme/infra/prod/cdn").await.unwrap();
    assert!(changesets.iter().any(|c| c.status == "draft"));
    let audit = db.list_audit("acme/infra/prod/cdn").await.unwrap();
    assert!(audit.iter().any(|a| a.action == "channel.advance.prepared"));
}

#[tokio::test]
async fn member_invite_and_remove_audit_and_last_owner_blocked() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    let _ = org;
    // An owner who manages members.
    let owner = db.find_or_create_user("owner@acme.com").await.unwrap();
    db.grant_membership("user", owner, "acme", "owner")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "owner@acme.com").await;
    let csrf = mint_csrf_token(cookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap());

    // Invite a developer; the grant flows through a change-set (audited).
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/members",
        Some(&cookie),
        Some(&format!("csrf={csrf}&email=newdev@acme.com&role=developer")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    let audit = db.list_audit("acme").await.unwrap();
    assert!(audit.iter().any(|a| a.action == "membership.grant"));
    let invited = db.user_by_email("newdev@acme.com").await.unwrap().unwrap();

    // Remove the developer: allowed, audited.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/members/remove",
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&principal_kind=user&principal_id={invited}"
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    assert!(db
        .list_audit("acme")
        .await
        .unwrap()
        .iter()
        .any(|a| a.action == "membership.revoke"));

    // Removing the last owner is hard-blocked.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/members/remove",
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&principal_kind=user&principal_id={owner}"
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);
    // The owner grant survives.
    assert!(db
        .list_members_of_scope("acme")
        .await
        .unwrap()
        .iter()
        .any(|(k, id, r)| k == "user" && *id == owner && r == "owner"));
}

#[tokio::test]
async fn org_dashboard_authz_matrix() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    let member = db.find_or_create_user("m@acme.com").await.unwrap();
    db.grant_membership("user", member, "acme", "viewer")
        .await
        .unwrap();
    db.find_or_create_user("outsider@x.com").await.unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;

    // A non-member 404s the private org dashboard (existence undisclosed).
    let out_cookie = login(&app, &db, "outsider@x.com").await;
    let resp = send(&app, "GET", "/-/org/acme", Some(&out_cookie), None).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND, "{}", resp.body);

    // A viewer member sees it.
    let m_cookie = login(&app, &db, "m@acme.com").await;
    let resp = send(&app, "GET", "/-/org/acme", Some(&m_cookie), None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("Acme"));
    // A viewer cannot manage members: no invite form.
    assert!(!resp.body.contains("send invitation"), "{}", resp.body);

    // The viewer's member POST (invite) is forbidden (lacks members.manage).
    let csrf = mint_csrf_token(m_cookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap());
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/members",
        Some(&m_cookie),
        Some(&format!("csrf={csrf}&email=x@y.com&role=viewer")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);

    // The audit feed requires admin+: a viewer gets 403; a non-member 404.
    let resp = send(&app, "GET", "/-/org/acme/audit", Some(&m_cookie), None).await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN);
    let resp = send(&app, "GET", "/-/org/acme/audit", Some(&out_cookie), None).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);

    // A viewer sees no create affordances (those need registry.configure /
    // storage.manage) and no delete form (owner-only).
    let resp = send(&app, "GET", "/-/org/acme", Some(&m_cookie), None).await;
    assert!(!resp.body.contains("create a registry"), "{}", resp.body);
    assert!(!resp.body.contains("create project"), "{}", resp.body);
    assert!(!resp.body.contains("create binding"), "{}", resp.body);
    assert!(!resp.body.contains("delete organization"), "{}", resp.body);
}

#[tokio::test]
async fn org_dashboard_shows_create_affordances_to_admins() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    // An admin holds registry.configure + storage.manage but not iam.admin.
    let admin = db.find_or_create_user("admin@acme.com").await.unwrap();
    db.grant_membership("user", admin, "acme", "admin")
        .await
        .unwrap();
    // An owner additionally holds iam.admin (so sees the delete form).
    let owner = db.find_or_create_user("owner@acme.com").await.unwrap();
    db.grant_membership("user", owner, "acme", "owner")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;

    let a_cookie = login(&app, &db, "admin@acme.com").await;
    // The org view is split across focused tabs: registries (default) shows the
    // create-registry affordance; the create forms live on their own tabs.
    let resp = send(&app, "GET", "/-/org/acme", Some(&a_cookie), None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("create a registry"), "{}", resp.body);
    let resp = send(&app, "GET", "/-/org/acme/projects", Some(&a_cookie), None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("create project"), "{}", resp.body);
    let resp = send(&app, "GET", "/-/org/acme/storage", Some(&a_cookie), None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("create binding"), "{}", resp.body);
    // An admin is NOT an owner, so the delete form stays hidden on the danger tab.
    let resp = send(&app, "GET", "/-/org/acme/danger", Some(&a_cookie), None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(!resp.body.contains("delete organization"), "{}", resp.body);

    // An owner additionally sees the typed-confirmation delete form on the
    // danger tab.
    let o_cookie = login(&app, &db, "owner@acme.com").await;
    let resp = send(&app, "GET", "/-/org/acme/danger", Some(&o_cookie), None).await;
    assert!(resp.body.contains("delete organization"), "{}", resp.body);
}

#[tokio::test]
async fn config_edit_and_change_request_console_flow() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let db = serve_managed(&surface, &fixture, "public").await;
    let app = router(app_state(Arc::clone(&db)).await).await;

    // An Owner on the org may edit config and view change requests.
    let owner = db.find_or_create_user("owner@acme.com").await.unwrap();
    db.grant_membership("user", owner, "acme", "owner")
        .await
        .unwrap();
    let cookie = login(&app, &db, "owner@acme.com").await;

    // The config-edit page renders the current committed registry.toml.
    let resp = send(
        &app,
        "GET",
        "/acme/infra/prod/cdn/-/settings/config",
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("Fixture registry"), "{}", resp.body);
    assert!(resp.body.contains("submit change request"), "{}", resp.body);

    // A POST without CSRF is rejected.
    let resp = send(
        &app,
        "POST",
        "/acme/infra/prod/cdn/-/settings/config",
        Some(&cookie),
        Some("contents=whatever"),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);

    // A valid submission (the structured config form) creates a titled draft
    // change request and echoes the merge command.
    let csrf = mint_csrf_token(cookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap());
    let form = format!(
        "csrf={csrf}&name=demo&description=console+edit&cr_title=tighten+config\
         &cr_body=bump+the+description"
    );
    let resp = send(
        &app,
        "POST",
        "/acme/infra/prod/cdn/-/settings/config",
        Some(&cookie),
        Some(&form),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("apr change merge"), "{}", resp.body);

    // A git-backed draft change-set now exists for the registry.
    let drafts: Vec<_> = db
        .list_changesets("acme/infra/prod/cdn")
        .await
        .unwrap()
        .into_iter()
        .filter(|cs| cs.git_ref.is_some())
        .collect();
    assert_eq!(drafts.len(), 1);
    assert_eq!(drafts[0].status, "draft");

    // The change-requests list page shows the draft as an Open row that links
    // to its detail page.
    let change_id = drafts[0].change_id.clone();
    let detail_url = format!("/acme/infra/prod/cdn/-/changes/{change_id}");
    let resp = send(
        &app,
        "GET",
        "/acme/infra/prod/cdn/-/changes",
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("Change requests"), "{}", resp.body);
    assert!(
        resp.body.contains("badge-open"),
        "open badge: {}",
        resp.body
    );
    assert!(
        resp.body.contains(&format!("href=\"{detail_url}\"")),
        "list links to detail: {}",
        resp.body
    );

    // The Diff view renders the syntax-highlighted change.
    let resp = send(
        &app,
        "GET",
        &format!("{detail_url}?view=diff"),
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("class=\"diff\""), "{}", resp.body);
    assert!(resp.body.contains("console edit"), "{}", resp.body);

    // The Conversation view carries the (CLI-only) merge command + copy button.
    let resp = send(&app, "GET", &detail_url, Some(&cookie), None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("apr change merge"), "{}", resp.body);
    assert!(resp.body.contains("data-copy-target"), "{}", resp.body);

    // The Checks view recomputes validation and never claims a roster signature.
    let resp = send(
        &app,
        "GET",
        &format!("{detail_url}?view=checks"),
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("schema valid"), "{}", resp.body);
    assert!(
        resp.body.contains("not in the roster"),
        "honest draft-key note: {}",
        resp.body
    );

    // A change action without a valid CSRF token is rejected.
    let resp = send(
        &app,
        "POST",
        &format!("{detail_url}/comment"),
        Some(&cookie),
        Some("body=nope"),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);

    // Posting a comment appends it to the conversation timeline.
    let resp = send(
        &app,
        "POST",
        &format!("{detail_url}/comment"),
        Some(&cookie),
        Some(&format!("csrf={csrf}&body=lgtm-from-owner")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    let resp = send(&app, "GET", &detail_url, Some(&cookie), None).await;
    assert!(resp.body.contains("lgtm-from-owner"), "{}", resp.body);

    // Closing withdraws the draft (status stays draft; closed badge shows).
    let resp = send(
        &app,
        "POST",
        &format!("{detail_url}/close"),
        Some(&cookie),
        Some(&format!("csrf={csrf}")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    let closed = db.changeset(&change_id).await.unwrap().unwrap();
    assert_eq!(closed.status, "draft", "close must not touch status");
    assert!(closed.closed_at.is_some(), "close stamps closed_at");
    let resp = send(&app, "GET", &detail_url, Some(&cookie), None).await;
    assert!(resp.body.contains("badge-closed"), "{}", resp.body);

    // Reopening clears closed_at, re-arming auto-merge detection.
    let resp = send(
        &app,
        "POST",
        &format!("{detail_url}/reopen"),
        Some(&cookie),
        Some(&format!("csrf={csrf}")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    let reopened = db.changeset(&change_id).await.unwrap().unwrap();
    assert!(reopened.closed_at.is_none(), "reopen clears closed_at");

    // A developer (no registry.configure) cannot submit a change request.
    let dev = db.find_or_create_user("dev@acme.com").await.unwrap();
    db.grant_membership("user", dev, "acme/infra/prod/cdn", "developer")
        .await
        .unwrap();
    let dcookie = login(&app, &db, "dev@acme.com").await;
    let dcsrf = mint_csrf_token(dcookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap());
    let resp = send(
        &app,
        "POST",
        "/acme/infra/prod/cdn/-/settings/config",
        Some(&dcookie),
        Some(&format!("csrf={dcsrf}&contents=x")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    // And cannot view the change-request list (needs audit.read).
    let resp = send(
        &app,
        "GET",
        "/acme/infra/prod/cdn/-/changes",
        Some(&dcookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
}
