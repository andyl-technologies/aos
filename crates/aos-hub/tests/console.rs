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
use aos_hub_core::web::console::{route_manifest, ConsoleRouteMatched, RouteMethods, RouteSpec};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

const TEST_JWT_SECRET: &[u8] = b"console-test-secret-32-byte-key!!";

/// Historical paths are test-only negative fixtures, never runtime metadata.
const REMOVED_ROUTES: &[RouteSpec] = &[
    RouteSpec {
        path: "/-/org/{org}/caches/{cache}/integrations",
        methods: RouteMethods::Get,
    },
    RouteSpec {
        path: "/-/org/{org}/caches/{cache}/retention",
        methods: RouteMethods::Get,
    },
    RouteSpec {
        path: "/-/org/{org}/caches/{cache}/delivery",
        methods: RouteMethods::Get,
    },
    RouteSpec {
        path: "/-/org/{org}/storage",
        methods: RouteMethods::Get,
    },
    RouteSpec {
        path: "/-/org/{org}/bindings/{id}",
        methods: RouteMethods::GetAndPost,
    },
    RouteSpec {
        path: "/-/org/{org}/storage-bindings/{id}/grants/plan-grant",
        methods: RouteMethods::Post,
    },
    RouteSpec {
        path: "/-/org/{org}/storage-bindings/{id}/grants/grant",
        methods: RouteMethods::Post,
    },
    RouteSpec {
        path: "/-/org/{org}/storage-bindings/{id}/grants/plan-revoke",
        methods: RouteMethods::Post,
    },
    RouteSpec {
        path: "/-/org/{org}/storage-bindings/{id}/grants/revoke",
        methods: RouteMethods::Post,
    },
    RouteSpec {
        path: "/{registry}/-/settings/caches",
        methods: RouteMethods::Get,
    },
    RouteSpec {
        path: "/{registry}/-/settings/caches/consumer-stack",
        methods: RouteMethods::Get,
    },
    RouteSpec {
        path: "/{registry}/-/settings/delivery",
        methods: RouteMethods::Get,
    },
    RouteSpec {
        path: "/{registry}/-/settings/storage",
        methods: RouteMethods::GetAndPost,
    },
    RouteSpec {
        path: "/{registry}/-/settings/serving",
        methods: RouteMethods::GetAndPost,
    },
    RouteSpec {
        path: "/-/instance/storage",
        methods: RouteMethods::GetAndPost,
    },
    RouteSpec {
        path: "/-/instance/serving",
        methods: RouteMethods::GetAndPost,
    },
];

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
        leases: std::sync::Arc::new(aos_hub_core::lease::InMemoryLease::new()),
        sealer: aos_hub::auth::oidc::dev_sealer(),
        secret_versions: aos_hub_core::secret_version::EmptySecretVersionResolver::shared(),
        http: aos_hub::fetch::hardened_client().await,
        image_snapshots: None,
        mailer: Arc::new(aos_hub::auth::magic::LogMailer),
        dev: true,
        delivery_attestation_verifier: None,
        domain_probe_terminator: None,
        route_reservation_keyring: None,
    })
}

/// A captured HTTP response: status, the `Set-Cookie` value, a `Location`
/// redirect, and the body text.
struct Resp {
    status: StatusCode,
    matched_console_route: bool,
    allow: Option<String>,
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
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "127.0.0.1:8420");
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
    let matched_console_route = resp.extensions().get::<ConsoleRouteMatched>().is_some();
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let allow = resp
        .headers()
        .get(header::ALLOW)
        .and_then(|value| value.to_str().ok())
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
        matched_console_route,
        allow,
        set_cookie,
        location,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

#[tokio::test]
async fn declared_console_manifest_is_reachable_with_strict_path_parity() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(db).await).await;

    for route in route_manifest() {
        let flat_path = route.sample_path("missing");
        assert_declared_route(&app, route.methods, &flat_path).await;
        assert_trailing_slash_absent(&app, &flat_path).await;

        if route.is_registry() {
            let nested_path = route.sample_path("acme/infra/missing");
            assert_declared_route(&app, route.methods, &nested_path).await;
            assert_trailing_slash_absent(&app, &nested_path).await;
        }
    }
}

async fn assert_declared_route(app: &axum::Router, methods: RouteMethods, path: &str) {
    for method in ["GET", "POST"] {
        let declared = (method == "GET" && methods.allows_get())
            || (method == "POST" && methods.allows_post());
        let response = send(app, method, path, None, None).await;
        assert!(
            response.matched_console_route,
            "manifest path did not match the console router for {method} {path}: {} {}",
            response.status, response.body,
        );
        if declared {
            assert_ne!(
                response.status,
                StatusCode::METHOD_NOT_ALLOWED,
                "declared {method} did not reach its handler: {path}",
            );
        } else {
            assert_eq!(
                response.status,
                StatusCode::METHOD_NOT_ALLOWED,
                "undeclared {method} is accepted at {path}: {}",
                response.body,
            );
            assert_eq!(
                response.allow.as_deref(),
                Some(methods.allow_header()),
                "wrong Allow header for {method} {path}",
            );
        }
    }

    for method in [
        "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
    ] {
        let response = send(app, method, path, None, None).await;
        assert!(
            response.matched_console_route,
            "{method} bypassed the declared route at {path}",
        );
        assert_eq!(
            response.status,
            StatusCode::METHOD_NOT_ALLOWED,
            "undeclared {method} is accepted at {path}: {}",
            response.body,
        );
        assert_eq!(
            response.allow.as_deref(),
            Some(methods.allow_header()),
            "wrong Allow header for {method} {path}",
        );
    }
}

async fn assert_trailing_slash_absent(app: &axum::Router, path: &str) {
    let path = format!("{path}/");
    let response = send(app, "GET", &path, None, None).await;
    assert_eq!(
        response.status,
        StatusCode::NOT_FOUND,
        "trailing-slash alias is mounted: {path}",
    );
    assert!(
        !response.matched_console_route,
        "trailing-slash alias matched a console route: {path}",
    );
}

#[tokio::test]
async fn every_removed_method_path_pair_is_unreachable() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "removed-route-check@example.com").await;

    for route in REMOVED_ROUTES {
        for registry in ["missing", "acme/infra/missing"] {
            if registry.contains('/') && !route.is_registry() {
                continue;
            }
            let path = route.sample_path(registry);
            for method in [
                "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
            ] {
                let response = send(&app, method, &path, Some(&cookie), None).await;
                assert!(
                    matches!(
                        response.status,
                        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
                    ),
                    "removed path is reachable with {method} at {path}: {}",
                    response.body,
                );
                assert!(
                    !response.matched_console_route,
                    "removed path matched a console route with {method} at {path}: {} {}",
                    response.status, response.body,
                );
            }
        }
    }
}

/// Extract the `__Host-aos_session` cookie value from a `Set-Cookie` header.
fn cookie_value(set_cookie: &str) -> String {
    let prefix = format!("{COOKIE_NAME}=");
    let after = set_cookie.strip_prefix(&prefix).expect("session cookie");
    after.split(';').next().unwrap().to_string()
}

/// Extracts one escaped-free hidden form value from a rendered plan page.
fn hidden_value(body: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    body.split_once(&marker)
        .and_then(|(_, rest)| rest.split_once('\"'))
        .map(|(value, _)| value.to_string())
        .unwrap_or_else(|| panic!("missing hidden field {name}: {body}"))
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
    db.create_project(org, "infra/prod", "Production")
        .await
        .unwrap();
    let parent = surface.parent().unwrap().to_str().unwrap();
    let dir_name = surface.file_name().unwrap().to_str().unwrap();
    let binding = common::create_local_binding(&db, org, "primary", parent).await;
    db.create_managed_registry(
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
    let placement = common::create_ready_placement(
        &db,
        aos_hub::db::SurfaceTarget::Registry(registry.id),
        binding,
        "primary",
        dir_name,
    )
    .await;
    common::configure_write_authority(
        &db,
        aos_hub::db::SurfaceTarget::Registry(registry.id),
        binding,
        &placement,
        "console-fixture-writer",
    )
    .await;
    index_and_record(&db, &LocalFsFetch::new(surface), &registry)
        .await
        .unwrap();
    db
}

#[tokio::test]
async fn removed_nested_settings_path_is_absent_for_every_method() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let db = serve_managed(&surface, &fixture, "public").await;
    let app = router(app_state(db).await).await;

    for method in ["GET", "POST", "PUT", "HEAD", "DELETE", "PATCH"] {
        let resp = send(
            &app,
            method,
            "/acme/infra/prod/cdn/-/settings/storage",
            None,
            None,
        )
        .await;
        assert_eq!(
            resp.status,
            StatusCode::NOT_FOUND,
            "removed path unexpectedly handled {method}: {}",
            resp.body
        );
    }

    // The final placement route still rejects undeclared methods instead of
    // falling through to the machine delivery surface.
    let resp = send(
        &app,
        "HEAD",
        "/acme/infra/prod/cdn/-/settings/placements",
        None,
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);
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

    // GET is a non-mutating confirmation; POST requires the session CSRF token.
    let resp = send(&app, "GET", "/logout", Some(&cookie), None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("method=\"post\" action=\"/logout\""));
    let resp = send(&app, "POST", "/logout", Some(&cookie), Some("")).await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN);
    let secret = cookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap();
    let csrf = mint_csrf_token(secret);
    let resp = send(
        &app,
        "POST",
        "/logout",
        Some(&cookie),
        Some(&format!("csrf={csrf}")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    let resp = send(&app, "GET", "/-/account", Some(&cookie), None).await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert_eq!(resp.location.as_deref(), Some("/login"));
}

#[tokio::test]
async fn browser_session_exchange_requires_origin_and_csrf_and_returns_no_store_bearer() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "browser@acme.com").await;
    let secret = cookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap();
    let csrf = mint_csrf_token(secret);

    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/-/auth/session-token")
                .header(header::HOST, "127.0.0.1:8420")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert!(unauthorized.headers().get(header::LOCATION).is_none());

    for (origin, proof) in [
        (None, Some(csrf.as_str())),
        (Some("http://attacker.invalid"), Some(csrf.as_str())),
        (Some("http://127.0.0.1:8420"), None),
    ] {
        let mut request = Request::builder()
            .method("POST")
            .uri("/-/auth/session-token")
            .header(header::HOST, "127.0.0.1:8420")
            .header(header::COOKIE, &cookie);
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        if let Some(proof) = proof {
            request = request.header("x-aos-csrf", proof);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/-/auth/session-token")
                .header(header::HOST, "127.0.0.1:8420")
                .header(header::COOKIE, cookie)
                .header(header::ORIGIN, "http://127.0.0.1:8420")
                .header("x-aos-csrf", csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["token_type"], "Bearer");
    assert_eq!(value["expires_in"], 300);
    assert_eq!(value["principal"]["email"], "browser@acme.com");
    let token = value["access_token"].as_str().unwrap();
    let claims = JwtKeys::from_secret(TEST_JWT_SECRET).verify(token).unwrap();
    assert_eq!(
        claims.owner_id,
        db.user_by_email("browser@acme.com").await.unwrap().unwrap()
    );
    assert!(claims.exp - claims.iat <= 300);
}

#[tokio::test]
async fn public_cache_inventory_does_not_link_outsiders_to_management() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    db.create_binary_cache(
        Some(org),
        "public-build",
        "Public build cache",
        "public",
        40,
        "zstd",
        false,
    )
    .await
    .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let outsider = login(&app, &db, "outside@example.com").await;

    let response = send(&app, "GET", "/-/caches", Some(&outsider), None).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    assert!(response.body.contains("Public build cache"));
    assert!(!response
        .body
        .contains("href=\"/-/org/acme/caches/public-build\""));
    assert!(!response.body.contains("href=\"/-/org/acme\""));

    let response = send(
        &app,
        "GET",
        "/-/org/acme/caches/public-build",
        Some(&outsider),
        None,
    )
    .await;
    assert_eq!(response.status, StatusCode::NOT_FOUND, "{}", response.body);
}

#[tokio::test]
async fn activate_shows_scope_and_approves_with_clamped_token() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    db.create_project(org, "infra", "Infrastructure")
        .await
        .unwrap();
    db.create_project(org, "infra/prod", "Production")
        .await
        .unwrap();
    // The approving user is a maintainer at the organization, covering the
    // requested project scope.
    let user = db.find_or_create_user("maint@acme.com").await.unwrap();
    db.grant_membership(
        "user",
        user,
        &common::org_scope(&db, "acme").await,
        "maintainer",
    )
    .await
    .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "maint@acme.com").await;

    // A CLI starts a device grant requesting read+publish at acme/infra/prod.
    let (device_code, user_code, _ttl) = db
        .start_device_authorization(
            &common::project_scope(&db, "acme", "infra/prod").await,
            &[Permission::Read, Permission::Publish],
        )
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

    // The CLI poll now returns Approved with authority clamped to the user's
    // grants (the maintainer holds publish at acme, covering the
    // requested acme/infra/prod scope).
    let poll = db.poll_device(&device_code).await.unwrap();
    let grant = match poll {
        aos_hub::db::DevicePollResult::Approved(grant) => grant,
        other => panic!("expected approval, got {other:?}"),
    };
    assert_eq!(grant.auth.owner, Principal::user(user));
    assert!(grant.auth.permissions.contains(&Permission::Read));
    assert!(grant.auth.permissions.contains(&Permission::Publish));
    assert!(!grant.refresh_token.is_empty());
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
async fn token_management_uses_reviewed_issue_and_retirement() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let db = serve_managed(&surface, &fixture, "public").await;

    // Token issuance and retirement are IAM-admin retained-control actions.
    let user = db.find_or_create_user("dev@acme.com").await.unwrap();
    db.grant_membership(
        "user",
        user,
        &common::registry_scope(&db, "acme/infra/prod/cdn").await,
        "owner",
    )
    .await
    .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "dev@acme.com").await;
    let csrf = mint_csrf_token(cookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap());

    let base = "/acme/infra/prod/cdn/-/settings/tokens";

    // Plan issuance, then apply the exact reviewed plan. The secret appears
    // only in the apply response.
    let plan = send(
        &app,
        "POST",
        base,
        Some(&cookie),
        Some(&format!("csrf={csrf}&perm_read=1")),
    )
    .await;
    assert_eq!(plan.status, StatusCode::OK, "{}", plan.body);
    let plan_id = hidden_value(&plan.body, "plan_id");
    let confirmation_hash = hidden_value(&plan.body, "confirmation_hash");
    let resp = send(
        &app,
        "POST",
        base,
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&plan_id={plan_id}&confirmation_hash={confirmation_hash}"
        )),
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

    // Retirement is also a plan/apply operation on the exact token identity.
    let retirement = send(
        &app,
        "POST",
        &format!("{base}/{token_id}/revoke"),
        Some(&cookie),
        Some(&format!("csrf={csrf}")),
    )
    .await;
    assert_eq!(retirement.status, StatusCode::OK, "{}", retirement.body);
    let plan_id = hidden_value(&retirement.body, "plan_id");
    let confirmation_hash = hidden_value(&retirement.body, "confirmation_hash");
    let resp = send(
        &app,
        "POST",
        &format!("{base}/{token_id}/revoke"),
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&plan_id={plan_id}&confirmation_hash={confirmation_hash}"
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    assert!(db
        .list_tokens_for(Principal::user(user))
        .await
        .unwrap()
        .iter()
        .all(|(id, _, _)| id != &token_id));
}

/// Issuing or retiring a token requires a sudo IAM-admin session.
#[tokio::test]
async fn token_issue_and_retirement_require_sudo() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let db = serve_managed(&surface, &fixture, "public").await;

    let user = db.find_or_create_user("dev@acme.com").await.unwrap();
    db.grant_membership(
        "user",
        user,
        &common::registry_scope(&db, "acme/infra/prod/cdn").await,
        "owner",
    )
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

    // A fresh magic-link login may plan and apply issuance.
    let fresh = login(&app, &db, "dev@acme.com").await;
    let f_csrf = mint_csrf_token(fresh.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap());
    let plan = send(
        &app,
        "POST",
        base,
        Some(&fresh),
        Some(&format!("csrf={f_csrf}&perm_read=1")),
    )
    .await;
    assert_eq!(plan.status, StatusCode::OK, "{}", plan.body);
    let plan_id = hidden_value(&plan.body, "plan_id");
    let confirmation_hash = hidden_value(&plan.body, "confirmation_hash");
    let resp = send(
        &app,
        "POST",
        base,
        Some(&fresh),
        Some(&format!(
            "csrf={f_csrf}&plan_id={plan_id}&confirmation_hash={confirmation_hash}"
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    let tokens = db.list_tokens_for(Principal::user(user)).await.unwrap();
    assert_eq!(tokens.len(), 1);
    let token_id = tokens[0].0.clone();

    // The stale session cannot even prepare a retirement plan.
    let resp = send(
        &app,
        "POST",
        &format!("{base}/{token_id}/revoke"),
        Some(&stale),
        Some(&format!("csrf={s_csrf}")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);

    // The sudo session can prepare the reviewed retirement.
    let resp = send(
        &app,
        "POST",
        &format!("{base}/{token_id}/revoke"),
        Some(&fresh),
        Some(&format!("csrf={f_csrf}")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
}

#[tokio::test]
async fn channel_console_is_read_only_until_normalized_plan_apply_exists() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let db = serve_managed(&surface, &fixture, "public").await;
    let app = router(app_state(Arc::clone(&db)).await).await;

    // Public consumer visibility never grants access to producer settings or
    // publish/audit actor metadata.
    let outsider = login(&app, &db, "outside@example.com").await;
    for path in [
        "/acme/infra/prod/cdn/-/settings/channels",
        "/acme/infra/prod/cdn/-/settings/channels/stable",
        "/acme/infra/prod/cdn/-/settings/publish-history",
    ] {
        let response = send(&app, "GET", path, Some(&outsider), None).await;
        assert_eq!(
            response.status,
            StatusCode::NOT_FOUND,
            "public registry exposed producer settings at {path}: {}",
            response.body,
        );
        assert!(!response.body.contains("opened by"), "{}", response.body);
    }

    // A viewer sees the grid but no advance form.
    let viewer = db.find_or_create_user("view@acme.com").await.unwrap();
    db.grant_membership(
        "user",
        viewer,
        &common::registry_scope(&db, "acme/infra/prod/cdn").await,
        "viewer",
    )
    .await
    .unwrap();
    let vcookie = login(&app, &db, "view@acme.com").await;
    let resp = send(
        &app,
        "GET",
        "/acme/infra/prod/cdn/-/settings/channels/stable",
        Some(&vcookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("partition-grid"), "{}", resp.body);
    assert_eq!(resp.body.matches("aria-current=\"page\"").count(), 1);
    assert!(
        resp.body.contains(
            "href=\"/acme/infra/prod/cdn/-/settings/channels\" class=\"active\" aria-current=\"page\""
        ),
        "{}",
        resp.body,
    );
    assert!(!resp.body.contains("/-/channels"), "{}", resp.body);
    assert!(
        !resp.body.contains("prepare advance"),
        "viewer sees no form"
    );
    assert!(resp.body.contains("read-only"));

    // Maintainer authority does not revive the removed direct mutation path.
    let maint = db.find_or_create_user("maint@acme.com").await.unwrap();
    db.grant_membership(
        "user",
        maint,
        &common::registry_scope(&db, "acme/infra/prod/cdn").await,
        "maintainer",
    )
    .await
    .unwrap();
    let mcookie = login(&app, &db, "maint@acme.com").await;
    let resp = send(
        &app,
        "POST",
        "/acme/infra/prod/cdn/-/settings/channels/stable",
        Some(&mcookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED, "{}", resp.body);
    assert_eq!(resp.allow.as_deref(), Some("GET"));
}

#[tokio::test]
async fn member_invite_and_remove_audit_and_last_owner_blocked() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    let _ = org;
    // An owner who manages members.
    let owner = db.find_or_create_user("owner@acme.com").await.unwrap();
    db.grant_membership(
        "user",
        owner,
        &common::org_scope(&db, "acme").await,
        "owner",
    )
    .await
    .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "owner@acme.com").await;
    let csrf = mint_csrf_token(cookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap());

    // Invite a developer through a reviewed plan; the apply is audited.
    let invite_plan = send(
        &app,
        "POST",
        "/-/org/acme/members/invitations",
        Some(&cookie),
        Some(&format!("csrf={csrf}&email=newdev@acme.com&role=developer")),
    )
    .await;
    assert_eq!(invite_plan.status, StatusCode::OK, "{}", invite_plan.body);
    let plan_id = hidden_value(&invite_plan.body, "plan_id");
    let confirmation_hash = hidden_value(&invite_plan.body, "confirmation_hash");
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/members/invitations",
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&plan_id={plan_id}&confirmation_hash={confirmation_hash}"
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    let audit = db
        .list_audit(&common::org_scope(&db, "acme").await)
        .await
        .unwrap();
    assert!(audit.iter().any(|a| a.action == "membership.grant"));
    let invited = db.user_by_email("newdev@acme.com").await.unwrap().unwrap();

    // Remove the developer: allowed, audited.
    let removal_plan = send(
        &app,
        "POST",
        &format!("/-/org/acme/members/user:{invited}/remove"),
        Some(&cookie),
        Some(&format!("csrf={csrf}")),
    )
    .await;
    assert_eq!(removal_plan.status, StatusCode::OK, "{}", removal_plan.body);
    let plan_id = hidden_value(&removal_plan.body, "plan_id");
    let confirmation_hash = hidden_value(&removal_plan.body, "confirmation_hash");
    let resp = send(
        &app,
        "POST",
        &format!("/-/org/acme/members/user:{invited}/remove"),
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&plan_id={plan_id}&confirmation_hash={confirmation_hash}"
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    assert!(db
        .list_audit(&common::org_scope(&db, "acme").await)
        .await
        .unwrap()
        .iter()
        .any(|a| a.action == "membership.revoke"));

    // Removing the last owner is hard-blocked.
    let resp = send(
        &app,
        "POST",
        &format!("/-/org/acme/members/user:{owner}/remove"),
        Some(&cookie),
        Some(&format!("csrf={csrf}")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);
    // The owner grant survives.
    assert!(db
        .list_members_of_scope(&common::org_scope(&db, "acme").await)
        .await
        .unwrap()
        .iter()
        .any(|(k, id, r)| k == "user" && *id == owner && r == "owner"));
}

#[tokio::test]
async fn org_dashboard_authz_matrix() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    let org_scope = common::org_scope(&db, "acme").await;
    let binding_stable_id = "binding-viewer-redaction";
    let binding_id = db
        .create_topology_storage_binding(
            Some(org),
            binding_stable_id,
            &org_scope,
            "Private artifacts",
            "s3",
            None,
            Some("private-bucket"),
            Some("tenant-prefix"),
            Some("https"),
            Some("dns"),
            Some(b"origin.internal.example"),
            Some(443),
            Some("us-secret-1"),
            Some("private"),
        )
        .await
        .unwrap();
    let credential_fingerprint = "a".repeat(64);
    db.set_storage_binding_credential_revision(
        binding_id,
        "read",
        "secret://private/reader/v1",
        0,
        &credential_fingerprint,
        "test",
    )
    .await
    .unwrap();
    let member = db.find_or_create_user("m@acme.com").await.unwrap();
    db.grant_membership(
        "user",
        member,
        &common::org_scope(&db, "acme").await,
        "viewer",
    )
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
    for readable in [
        "/storage-bindings",
        "/domains",
        "/network-boundaries",
        "/delivery-endpoints",
        "/storage-gateways",
    ] {
        assert!(
            resp.body
                .contains(&format!("href=\"/-/org/acme{readable}\"")),
            "viewer navigation omits readable {readable}: {}",
            resp.body,
        );
        let page = send(
            &app,
            "GET",
            &format!("/-/org/acme{readable}"),
            Some(&m_cookie),
            None,
        )
        .await;
        assert_eq!(page.status, StatusCode::OK, "{readable}: {}", page.body);
    }
    for restricted in [
        "/topology-defaults",
        "/sso",
        "/signing-keys",
        "/webhooks",
        "/audit-log",
        "/danger",
    ] {
        assert!(
            !resp
                .body
                .contains(&format!("href=\"/-/org/acme{restricted}\"")),
            "viewer navigation exposes {restricted}: {}",
            resp.body,
        );
    }

    // The viewer's member POST (invite) is forbidden (lacks members.manage).
    let csrf = mint_csrf_token(m_cookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap());
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/members/invitations",
        Some(&m_cookie),
        Some(&format!("csrf={csrf}&email=x@y.com&role=viewer")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);

    // The audit feed requires admin+: a viewer gets 403; a non-member 404.
    let resp = send(&app, "GET", "/-/org/acme/audit-log", Some(&m_cookie), None).await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN);
    let resp = send(
        &app,
        "GET",
        "/-/org/acme/audit-log",
        Some(&out_cookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);

    // StorageBindingRead exposes identity and topology links, not provider or
    // credential material. The credentials subsection is rejected before its
    // rows can be loaded because the viewer lacks StorageBindingManage.
    let binding_url = format!("/-/org/acme/storage-bindings/{binding_stable_id}");
    let response = send(&app, "GET", &binding_url, Some(&m_cookie), None).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    assert!(response.body.contains("provider configuration"));
    for hidden_field in [
        "<dt>location</dt>",
        "<dt>object prefix</dt>",
        "<dt>signing region</dt>",
        "<dt>access</dt>",
    ] {
        assert!(!response.body.contains(hidden_field), "{}", response.body);
    }
    for secret in [
        "private-bucket",
        "tenant-prefix",
        "origin.internal.example",
        "us-secret-1",
        "secret://private/reader/v1",
        credential_fingerprint.as_str(),
    ] {
        assert!(
            !response.body.contains(secret),
            "read-only binding overview leaked {secret}: {}",
            response.body,
        );
    }
    for subsection in ["credentials", "write-revisions"] {
        let response = send(
            &app,
            "GET",
            &format!("{binding_url}/{subsection}"),
            Some(&m_cookie),
            None,
        )
        .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN, "{}", response.body);
        assert!(!response.body.contains("secret://private/reader/v1"));
    }

    // A viewer sees no create affordances (those need registry.configure /
    // storage.manage) and no delete form (owner-only).
    let resp = send(&app, "GET", "/-/org/acme", Some(&m_cookie), None).await;
    assert!(!resp.body.contains("Create a registry"), "{}", resp.body);
    assert!(
        !resp.body.contains("aos hub registry create"),
        "{}",
        resp.body
    );
    assert!(!resp.body.contains("Create a project"), "{}", resp.body);
    assert!(
        !resp.body.contains("aos hub org project create"),
        "{}",
        resp.body
    );
    assert!(!resp.body.contains("create binding"), "{}", resp.body);
    assert!(!resp.body.contains("delete organization"), "{}", resp.body);
}

#[tokio::test]
async fn org_resource_sections_point_admins_to_reviewed_creation_flows() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    let binding_stable_id = "binding-placement-redaction";
    db.create_topology_storage_binding(
        Some(org),
        binding_stable_id,
        &common::org_scope(&db, "acme").await,
        "Private placement storage",
        "s3",
        None,
        Some("placement-private-bucket"),
        Some("placement-private-prefix"),
        Some("https"),
        Some("dns"),
        Some(b"placement-origin.internal.example"),
        Some(443),
        Some("placement-secret-region"),
        Some("private"),
    )
    .await
    .unwrap();
    db.create_binary_cache(
        Some(org),
        "build",
        "Build cache",
        "private",
        40,
        "zstd",
        false,
    )
    .await
    .unwrap();
    db.create_managed_registry(org, "", "release", "private", &[], false)
        .await
        .unwrap();
    // An admin holds registry.configure + storage.manage but not iam.admin.
    let admin = db.find_or_create_user("admin@acme.com").await.unwrap();
    db.grant_membership(
        "user",
        admin,
        &common::org_scope(&db, "acme").await,
        "admin",
    )
    .await
    .unwrap();
    // An owner additionally holds iam.admin (so sees the delete form).
    let owner = db.find_or_create_user("owner@acme.com").await.unwrap();
    db.grant_membership(
        "user",
        owner,
        &common::org_scope(&db, "acme").await,
        "owner",
    )
    .await
    .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;

    // Cache-scoped administration is sufficient even without an org grant.
    let cache_admin = db
        .find_or_create_user("cache-admin@acme.com")
        .await
        .unwrap();
    let cache = db.binary_cache_by_slug("build").await.unwrap().unwrap();
    db.grant_membership("user", cache_admin, &cache.scope_key, "admin")
        .await
        .unwrap();
    let registry_configurer = db
        .find_or_create_user("registry-configurer@acme.com")
        .await
        .unwrap();
    db.grant_membership(
        "user",
        registry_configurer,
        &common::registry_scope(&db, "acme/release").await,
        "admin",
    )
    .await
    .unwrap();
    let cache_cookie = login(&app, &db, "cache-admin@acme.com").await;
    let response = send(
        &app,
        "GET",
        "/-/org/acme/caches/build/placements",
        Some(&cache_cookie),
        None,
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    let response = send(&app, "GET", "/-/org/acme", Some(&cache_cookie), None).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND, "{}", response.body);

    // Placement-only/cache-admin and registry-configure authority may select a
    // binding by its redacted identity. Neither authority can load or render
    // the full provider record merely by opening the creation form.
    let registry_cookie = login(&app, &db, "registry-configurer@acme.com").await;
    for (cookie, path) in [
        (&cache_cookie, "/-/org/acme/caches/build/placements/new"),
        (&registry_cookie, "/acme/release/-/settings/placements/new"),
    ] {
        let response = send(&app, "GET", path, Some(cookie), None).await;
        assert_eq!(response.status, StatusCode::OK, "{path}: {}", response.body);
        assert!(
            response.body.contains(binding_stable_id),
            "{path}: {}",
            response.body
        );
        assert!(
            response.body.contains("Private placement storage · s3"),
            "{path}: {}",
            response.body,
        );
        for provider_material in [
            "placement-private-bucket",
            "placement-private-prefix",
            "placement-origin.internal.example",
            "placement-secret-region",
        ] {
            assert!(
                !response.body.contains(provider_material),
                "placement form {path} leaked {provider_material}: {}",
                response.body,
            );
        }
    }

    let a_cookie = login(&app, &db, "admin@acme.com").await;
    let new_binding = send(
        &app,
        "GET",
        "/-/org/acme/storage-bindings/new",
        Some(&a_cookie),
        None,
    )
    .await;
    assert_eq!(new_binding.status, StatusCode::OK, "{}", new_binding.body);
    assert!(new_binding
        .body
        .contains("action=\"/-/org/acme/storage-bindings/plan-create\""));
    let collection_post = send(
        &app,
        "POST",
        "/-/org/acme/storage-bindings",
        Some(&a_cookie),
        None,
    )
    .await;
    assert_eq!(
        collection_post.status,
        StatusCode::METHOD_NOT_ALLOWED,
        "{}",
        collection_post.body,
    );
    assert_eq!(collection_post.allow.as_deref(), Some("GET"));
    let plan_create = send(
        &app,
        "POST",
        "/-/org/acme/storage-bindings/plan-create",
        Some(&a_cookie),
        None,
    )
    .await;
    assert_ne!(plan_create.status, StatusCode::METHOD_NOT_ALLOWED);
    let numeric_binding = send(
        &app,
        "GET",
        "/-/org/acme/storage-bindings/1",
        Some(&a_cookie),
        None,
    )
    .await;
    assert_eq!(
        numeric_binding.status,
        StatusCode::NOT_FOUND,
        "legacy numeric binding identity resolved: {}",
        numeric_binding.body,
    );
    let csrf = mint_csrf_token(a_cookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap());
    for (path, form) in [
        (
            "/-/org/acme/storage-bindings/1/credentials/plan-set",
            format!("csrf={csrf}&purpose=write&secret_version_ref=secret&credential_fingerprint=fingerprint"),
        ),
        (
            "/-/org/acme/storage-bindings/1/credentials/set",
            format!("csrf={csrf}&plan_id=plan&confirmation_hash=hash"),
        ),
        (
            "/-/org/acme/storage-bindings/1/credentials/plan-rotate",
            format!("csrf={csrf}&purpose=write&secret_version_ref=secret&credential_fingerprint=fingerprint"),
        ),
        (
            "/-/org/acme/storage-bindings/1/credentials/rotate",
            format!("csrf={csrf}&plan_id=plan&confirmation_hash=hash"),
        ),
    ] {
        let response = send(&app, "POST", path, Some(&a_cookie), Some(&form)).await;
        assert_eq!(
            response.status,
            StatusCode::NOT_FOUND,
            "legacy numeric binding identity resolved: {path} {}",
            response.body,
        );
    }
    for path in [
        "/-/org/acme/storage-bindings/1/grants/plan-grant",
        "/-/org/acme/storage-bindings/1/grants/grant",
        "/-/org/acme/storage-bindings/1/grants/plan-revoke",
        "/-/org/acme/storage-bindings/1/grants/revoke",
    ] {
        let response = send(&app, "POST", path, Some(&a_cookie), None).await;
        assert_eq!(
            response.status,
            StatusCode::NOT_FOUND,
            "removed binding-grant path is reachable: {path} {}",
            response.body,
        );
    }
    // The organization default is a read-only topology overview. Registry
    // creation lives on the focused Registries section instead.
    let resp = send(&app, "GET", "/-/org/acme", Some(&a_cookie), None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(!resp.body.contains("Create a registry"), "{}", resp.body);
    let resp = send(&app, "GET", "/-/org/acme/registries", Some(&a_cookie), None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("Create a registry"), "{}", resp.body);
    assert!(
        resp.body
            .contains("aos hub registry create --org acme --name NAME"),
        "{}",
        resp.body
    );
    let resp = send(&app, "GET", "/-/org/acme/projects", Some(&a_cookie), None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("Create a project"), "{}", resp.body);
    assert!(
        resp.body
            .contains("aos hub org project create acme --name NAME"),
        "{}",
        resp.body
    );
    let resp = send(&app, "GET", "/-/org/acme/caches", Some(&a_cookie), None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("Create a binary cache"), "{}", resp.body);
    assert!(
        resp.body
            .contains("aos hub cache create acme/CACHE --name NAME"),
        "{}",
        resp.body
    );
    let resp = send(
        &app,
        "GET",
        "/-/org/acme/caches/build/danger",
        Some(&a_cookie),
        None,
    )
    .await;
    assert_eq!(
        resp.status,
        StatusCode::NOT_FOUND,
        "registry configuration authority exposed cache deletion: {}",
        resp.body,
    );
    let resp = send(
        &app,
        "GET",
        "/-/org/acme/storage-bindings",
        Some(&a_cookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("Add a storage binding"), "{}", resp.body);
    let resp = send(&app, "GET", "/-/org/acme/storage", Some(&a_cookie), None).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND, "{}", resp.body);
    // An admin is not an owner, so the owner-only danger tab is cloaked.
    let resp = send(&app, "GET", "/-/org/acme/danger", Some(&a_cookie), None).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND, "{}", resp.body);

    // An owner additionally sees the typed-confirmation delete form on the
    // danger tab.
    let o_cookie = login(&app, &db, "owner@acme.com").await;
    let resp = send(&app, "GET", "/-/org/acme/danger", Some(&o_cookie), None).await;
    assert!(resp.body.contains("delete organization"), "{}", resp.body);
    let resp = send(
        &app,
        "GET",
        "/-/org/acme/caches/build/danger",
        Some(&o_cookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(
        resp.body.contains("/caches/build/danger/plan-delete"),
        "{}",
        resp.body,
    );
    assert!(!resp.body.contains("soft delete"), "{}", resp.body);
}

#[tokio::test]
async fn config_edit_and_change_request_console_flow() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let db = serve_managed(&surface, &fixture, "private").await;
    let app = router(app_state(Arc::clone(&db)).await).await;

    // An Owner on the org may edit config and view change requests.
    let owner = db.find_or_create_user("owner@acme.com").await.unwrap();
    db.grant_membership(
        "user",
        owner,
        &common::org_scope(&db, "acme").await,
        "owner",
    )
    .await
    .unwrap();
    let cookie = login(&app, &db, "owner@acme.com").await;

    // The config-edit page renders the current committed registry.toml.
    let resp = send(
        &app,
        "GET",
        "/acme/infra/prod/cdn/-/settings/configuration",
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
        "/acme/infra/prod/cdn/-/settings/configuration",
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
        "/acme/infra/prod/cdn/-/settings/configuration",
        Some(&cookie),
        Some(&form),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("apr change merge"), "{}", resp.body);

    // A git-backed draft change-set now exists for the registry.
    let drafts: Vec<_> = db
        .list_changesets(&common::registry_scope(&db, "acme/infra/prod/cdn").await)
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
    let detail_url = format!("/acme/infra/prod/cdn/-/settings/change-requests/{change_id}");

    // A private registry stays undisclosed to a nonmember across the list,
    // detail, and every change action. Valid CSRF proves the 404 comes from the
    // shared registry read gate rather than the form gate.
    let outsider_cookie = login(&app, &db, "outsider@example.com").await;
    let outsider_csrf = mint_csrf_token(
        outsider_cookie
            .strip_prefix(&format!("{COOKIE_NAME}="))
            .unwrap(),
    );
    for path in [
        "/acme/infra/prod/cdn/-/settings/change-requests".to_string(),
        detail_url.clone(),
    ] {
        let response = send(&app, "GET", &path, Some(&outsider_cookie), None).await;
        assert_eq!(
            response.status,
            StatusCode::NOT_FOUND,
            "{path}: {}",
            response.body
        );
    }
    for (suffix, form) in [
        ("comment", format!("csrf={outsider_csrf}&body=hidden")),
        (
            "review",
            format!("csrf={outsider_csrf}&verdict=approve&body=hidden"),
        ),
        ("close", format!("csrf={outsider_csrf}")),
        ("reopen", format!("csrf={outsider_csrf}")),
    ] {
        let path = format!("{detail_url}/{suffix}");
        let response = send(&app, "POST", &path, Some(&outsider_cookie), Some(&form)).await;
        assert_eq!(
            response.status,
            StatusCode::NOT_FOUND,
            "{path}: {}",
            response.body
        );
    }

    let resp = send(
        &app,
        "GET",
        "/acme/infra/prod/cdn/-/settings/change-requests",
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
    db.grant_membership(
        "user",
        dev,
        &common::registry_scope(&db, "acme/infra/prod/cdn").await,
        "developer",
    )
    .await
    .unwrap();
    let dcookie = login(&app, &db, "dev@acme.com").await;
    let dcsrf = mint_csrf_token(dcookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap());
    let resp = send(
        &app,
        "POST",
        "/acme/infra/prod/cdn/-/settings/configuration",
        Some(&dcookie),
        Some(&format!("csrf={dcsrf}&contents=x")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    // And cannot view the change-request list (needs audit.read).
    let resp = send(
        &app,
        "GET",
        "/acme/infra/prod/cdn/-/settings/change-requests",
        Some(&dcookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    let resp = send(&app, "GET", &detail_url, Some(&dcookie), None).await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    for (suffix, form) in [
        ("comment", format!("csrf={dcsrf}&body=readable")),
        (
            "review",
            format!("csrf={dcsrf}&verdict=approve&body=readable"),
        ),
        ("close", format!("csrf={dcsrf}")),
        ("reopen", format!("csrf={dcsrf}")),
    ] {
        let path = format!("{detail_url}/{suffix}");
        let response = send(&app, "POST", &path, Some(&dcookie), Some(&form)).await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "{path}: {}",
            response.body
        );
    }
}
