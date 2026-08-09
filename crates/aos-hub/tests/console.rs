//! Integration coverage for the shared Hub browser boundary.
//!
//! These tests drive the native router and prove that both runtimes can share
//! one closed management deep-link manifest. Management GETs return the
//! authenticated application shell, mutations exist only in Connect, and the
//! retained identity ceremonies remain ordinary server-rendered routes.

use std::sync::Arc;

use aos_hub::auth::extract::{mint_csrf_token, AuthState};
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::auth::session::COOKIE_NAME;
use aos_hub::db::Database;
use aos_hub::server::{router, AppState};
use aos_hub_core::web::assets::{
    console_bootstrap_name, console_css_name, console_js_name, console_wasm_name,
};
use aos_hub_core::web::console::{route_manifest, ConsoleRouteMatched};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt as _;

const TEST_JWT_SECRET: &[u8] = b"console-test-secret-32-byte-key!!";

fn removed_management_paths() -> Vec<String> {
    serde_json::from_str(include_str!("fixtures/removed-management-paths-v1.json"))
        .expect("removed management path fixture")
}

fn removed_management_posts() -> Vec<String> {
    serde_json::from_str(include_str!("fixtures/removed-management-posts-v1.json"))
        .expect("removed management POST fixture")
}

struct ResponseParts {
    status: StatusCode,
    matched_console_route: bool,
    allow: Option<String>,
    set_cookie: Option<String>,
    location: Option<String>,
    cache_control: Option<String>,
    content_type: Option<String>,
    content_security_policy: Option<String>,
    body: Vec<u8>,
}

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
        ratelimit: Arc::clone(&auth.ratelimit),
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
        identity_domain_verifier: None,
        route_reservation_keyring: None,
    })
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    form: Option<&str>,
) -> ResponseParts {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "127.0.0.1:8420");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    let body = if let Some(form) = form {
        request = request.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        Body::from(form.to_string())
    } else {
        Body::empty()
    };
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let matched_console_route = response.extensions().get::<ConsoleRouteMatched>().is_some();
    let header = |name: header::HeaderName| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    };
    let allow = header(header::ALLOW);
    let set_cookie = header(header::SET_COOKIE);
    let location = header(header::LOCATION);
    let cache_control = header(header::CACHE_CONTROL);
    let content_type = header(header::CONTENT_TYPE);
    let content_security_policy = header(header::CONTENT_SECURITY_POLICY);
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap()
        .to_vec();
    ResponseParts {
        status,
        matched_console_route,
        allow,
        set_cookie,
        location,
        cache_control,
        content_type,
        content_security_policy,
        body,
    }
}

async fn login(app: &axum::Router, db: &Database, email: &str) -> String {
    let secret = db.create_magic_link(email).await.unwrap();
    let response = send(
        app,
        "GET",
        &format!("/auth/magic?token={secret}"),
        None,
        None,
    )
    .await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    let set_cookie = response.set_cookie.expect("magic login sets a cookie");
    let value = set_cookie
        .strip_prefix(&format!("{COOKIE_NAME}="))
        .and_then(|value| value.split(';').next())
        .expect("session cookie has a value");
    format!("{COOKIE_NAME}={value}")
}

#[tokio::test]
async fn declared_console_manifest_is_reachable_with_strict_method_parity() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(db).await).await;

    for route in route_manifest() {
        for registry in ["missing", "acme/infra/missing"] {
            if registry.contains('/') && !route.is_registry() {
                continue;
            }
            let path = route.sample_path(registry);
            for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] {
                let declared = (method == "GET" && route.methods.allows_get())
                    || (method == "POST" && route.methods.allows_post());
                let response = send(&app, method, &path, None, None).await;
                assert!(
                    response.matched_console_route,
                    "manifest route was not claimed for {method} {path}"
                );
                if declared {
                    assert_ne!(response.status, StatusCode::METHOD_NOT_ALLOWED);
                } else {
                    assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);
                    assert_eq!(
                        response.allow.as_deref(),
                        Some(route.methods.allow_header())
                    );
                }
            }
            let alias = format!("{path}/");
            let response = send(&app, "GET", &alias, None, None).await;
            assert_eq!(response.status, StatusCode::NOT_FOUND, "alias: {alias}");
            assert!(!response.matched_console_route, "alias: {alias}");
        }
    }
}

#[tokio::test]
async fn removed_management_routes_are_absent_for_every_method() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "removed@example.com").await;

    for path in removed_management_paths() {
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] {
            let response = send(&app, method, &path, Some(&cookie), None).await;
            if matches!(method, "GET" | "HEAD") {
                assert_eq!(response.status, StatusCode::NOT_FOUND, "{method} {path}");
            } else {
                assert!(
                    matches!(
                        response.status,
                        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
                    ),
                    "{method} {path}: {}",
                    response.status
                );
            }
            assert!(!response.matched_console_route, "{method} {path}");
        }
    }
}

#[tokio::test]
async fn every_removed_management_post_is_absent() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "removed-posts@example.com").await;
    for path in removed_management_posts() {
        let response = send(&app, "POST", &path, Some(&cookie), None).await;
        assert!(
            matches!(
                response.status,
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
            ),
            "removed management POST remained mounted: {path} ({})",
            response.status
        );
        // A canonical GET deep link can legitimately match the closed console
        // route registry before its method guard returns 405. The invariant is
        // that no historical management POST reaches a handler.
    }
}

#[tokio::test]
async fn canonical_management_links_serve_one_authenticated_shell() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(Arc::clone(&db)).await).await;

    let anonymous = send(&app, "GET", "/-/instance", None, None).await;
    assert_eq!(anonymous.status, StatusCode::SEE_OTHER);
    assert_eq!(anonymous.location.as_deref(), Some("/login"));

    let cookie = login(&app, &db, "console@example.com").await;
    for path in [
        "/-/instance",
        "/-/instance/storage-bindings",
        "/-/caches",
        "/-/orgs",
        "/-/org/acme/projects",
        "/-/org/acme/caches/build/garbage-collection",
        "/acme/main/-/settings",
        "/acme/infra/prod/cdn/-/settings/images",
    ] {
        let response = send(&app, "GET", path, Some(&cookie), None).await;
        assert_eq!(response.status, StatusCode::OK, "{path}");
        assert_eq!(response.cache_control.as_deref(), Some("no-store"));
        assert!(
            response
                .content_security_policy
                .as_deref()
                .is_some_and(|value| value.contains("'wasm-unsafe-eval'")),
            "{path}"
        );
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains("name=\"aos-session-csrf\""), "{path}");
        assert!(body.contains("name=\"aos-site-brand\""), "{path}");
        for chrome_field in [
            "aos-site-tagline",
            "aos-site-announcement",
            "aos-site-tos-url",
            "aos-site-privacy-url",
            "aos-site-support-url",
        ] {
            assert!(body.contains(&format!("name=\"{chrome_field}\"")), "{path}");
        }
        assert!(body.contains("/_assets/style.css?v="), "{path}");
        assert!(body.contains("/_assets/app.js?v="), "{path}");
        assert!(body.contains(&console_bootstrap_name()), "{path}");
        assert!(
            !body.contains("<form"),
            "management shell contains a legacy form: {path}"
        );
    }

    let post = send(&app, "POST", "/-/org/acme/projects", Some(&cookie), None).await;
    assert_eq!(post.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(post.allow.as_deref(), Some("GET"));

    let unknown = send(&app, "GET", "/-/org/acme/not-a-page", Some(&cookie), None).await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert!(!unknown.matched_console_route);
}

#[tokio::test]
async fn browser_console_assets_have_explicit_types_and_cache_identity() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(db).await).await;
    for (name, media_type) in [
        (console_js_name(), "text/javascript"),
        (console_bootstrap_name(), "text/javascript"),
        (console_wasm_name(), "application/wasm"),
        (console_css_name(), "text/css"),
    ] {
        let path = format!("/_assets/{name}");
        let response = send(&app, "GET", &path, None, None).await;
        assert_eq!(response.status, StatusCode::OK, "{path}");
        assert!(
            response
                .content_type
                .as_deref()
                .is_some_and(|value| value.starts_with(media_type)),
            "{path}"
        );
        assert!(
            response
                .cache_control
                .as_deref()
                .is_some_and(|value| value.contains("immutable")),
            "{path}"
        );
        if name.starts_with("hub-console-bootstrap-") {
            let source = String::from_utf8(response.body).unwrap();
            assert!(source.contains(&console_js_name()));
            assert!(source.contains(&console_wasm_name()));
            assert!(source.contains("import init, { mount }"));
            assert!(source.contains("mount();"));
        }
    }
    for legacy in [
        "/_assets/hub-console.js",
        "/_assets/hub-console-bootstrap.js",
        "/_assets/hub-console_bg.wasm",
        "/_assets/hub-console.css",
    ] {
        assert_eq!(
            send(&app, "GET", legacy, None, None).await.status,
            StatusCode::NOT_FOUND,
            "legacy asset path remained mounted: {legacy}"
        );
    }
}

#[tokio::test]
async fn login_session_exchange_and_logout_preserve_identity_boundary() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "browser@example.com").await;
    let secret = cookie
        .strip_prefix(&format!("{COOKIE_NAME}="))
        .expect("session cookie value");
    let csrf = mint_csrf_token(secret);
    let user_id = db
        .user_by_email("browser@example.com")
        .await
        .unwrap()
        .expect("magic login creates a user");
    assert!(!db.user_has_any_membership(user_id).await.unwrap());

    let bootstrap_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/-/auth/session-token")
                .header(header::HOST, "127.0.0.1:8420")
                .header(header::COOKIE, &cookie)
                .header(header::ORIGIN, "http://127.0.0.1:8420")
                .header("x-aos-csrf", &csrf)
                .header("x-aos-console-route", "/-/orgs/new")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bootstrap_response.status(), StatusCode::OK);
    let bootstrap_body = axum::body::to_bytes(bootstrap_response.into_body(), 1 << 20)
        .await
        .unwrap();
    let bootstrap: serde_json::Value = serde_json::from_slice(&bootstrap_body).unwrap();
    assert_eq!(bootstrap["routePermissions"], serde_json::json!(["read"]));

    db.grant_membership("user", user_id, "instance", "owner")
        .await
        .unwrap();

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
                .header(header::COOKIE, &cookie)
                .header(header::ORIGIN, "http://127.0.0.1:8420")
                .header("x-aos-csrf", csrf)
                .header("x-aos-console-route", "/-/instance")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["tokenType"], "Bearer");
    assert_eq!(value["expiresIn"], "300");
    assert!(value["accessToken"].as_str().is_some());
    let permissions = value["routePermissions"]
        .as_array()
        .expect("route permissions are an array");
    assert!(permissions.iter().any(|permission| permission == "read"));
    assert!(permissions
        .iter()
        .any(|permission| permission == "iam.admin"));

    let logout = send(&app, "POST", "/logout", Some(&cookie), Some("")).await;
    assert_eq!(logout.status, StatusCode::FORBIDDEN);
    let logout = send(
        &app,
        "POST",
        "/logout",
        Some(&cookie),
        Some(&format!("csrf={}", mint_csrf_token(secret))),
    )
    .await;
    assert_eq!(logout.status, StatusCode::SEE_OTHER);
    let account = send(&app, "GET", "/-/account", Some(&cookie), None).await;
    assert_eq!(account.status, StatusCode::SEE_OTHER);
}
