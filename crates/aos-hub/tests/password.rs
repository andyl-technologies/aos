//! Integration coverage for the email + password login path (RFC-0004, the
//! operator-requested reversal of the original "no passwords" stance).
//!
//! Exercises the Argon2id hash/verify primitives, the pre-auth
//! `POST /login/password` route (success creates a session; failure re-renders
//! generically without leaking whether an email exists; repeated attempts are
//! rate-limited), the session-authed `POST /account/password` set/change flow,
//! and the "no password set" account behavior.

use std::sync::Arc;

use aos_hub::auth::extract::{mint_csrf_token, AuthState};
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::auth::password::{hash_password, verify_password};
use aos_hub::auth::session::COOKIE_NAME;
use aos_hub::db::{Database, IdpConfigRecord};
use aos_hub::server::{router, AppState};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

const TEST_JWT_SECRET: &[u8] = b"password-test-secret-32-byte-key";

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
        dev: true,
    })
}

/// A captured HTTP response.
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

// -- KDF unit-level round-trips ---------------------------------------------

#[test]
fn hash_verify_roundtrip_and_tamper() {
    let phc = hash_password("s3cr3t-passphrase").unwrap();
    assert!(verify_password("s3cr3t-passphrase", &phc));
    assert!(!verify_password("wrong", &phc));

    // Tamper the digest's last char; must not verify and must not panic.
    let mut chars: Vec<char> = phc.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();
    assert!(!verify_password("s3cr3t-passphrase", &tampered));
    assert!(!verify_password("anything", "not-a-phc"));
}

// -- HTTP login + session ----------------------------------------------------

#[tokio::test]
async fn set_password_then_login_creates_session() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(Arc::clone(&db)).await).await;

    // Provision a user with a password directly.
    let user = db.create_user("dev@acme.com", None).await.unwrap();
    db.set_user_password(user, &hash_password("hunter2").unwrap())
        .await
        .unwrap();
    assert!(db.user_has_password(user).await.unwrap());

    // Correct password logs in: 303 redirect to / with a session cookie.
    let resp = send(
        &app,
        "POST",
        "/login/password",
        None,
        Some("email=dev@acme.com&password=hunter2"),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    assert_eq!(resp.location.as_deref(), Some("/"));
    let cookie = format!(
        "{COOKIE_NAME}={}",
        cookie_value(&resp.set_cookie.expect("login sets a cookie"))
    );

    // The session works: /account renders.
    let resp = send(&app, "GET", "/-/account", Some(&cookie), None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(resp.body.contains("dev@acme.com"));
}

#[tokio::test]
async fn wrong_password_re_renders_without_leaking_existence() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(Arc::clone(&db)).await).await;

    let user = db.create_user("real@acme.com", None).await.unwrap();
    db.set_user_password(user, &hash_password("correct").unwrap())
        .await
        .unwrap();

    // Wrong password for a real account.
    let wrong = send(
        &app,
        "POST",
        "/login/password",
        None,
        Some("email=real@acme.com&password=nope"),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::OK, "re-renders, not a redirect");
    assert!(wrong.set_cookie.is_none(), "no session on failure");
    assert!(wrong.body.contains("Invalid email or password"));

    // Unknown account returns the identical generic page (no oracle).
    let unknown = send(
        &app,
        "POST",
        "/login/password",
        None,
        Some("email=ghost@acme.com&password=nope"),
    )
    .await;
    assert_eq!(unknown.status, StatusCode::OK);
    assert!(unknown.set_cookie.is_none());
    assert!(unknown.body.contains("Invalid email or password"));
    // The two failure bodies are indistinguishable (modulo the timed footer).
    assert_eq!(
        wrong.body.contains("Invalid email or password"),
        unknown.body.contains("Invalid email or password"),
    );
}

#[tokio::test]
async fn user_without_password_cannot_log_in_by_password() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(Arc::clone(&db)).await).await;

    // A user exists but never set a password.
    let user = db.create_user("nopass@acme.com", None).await.unwrap();
    assert!(!db.user_has_password(user).await.unwrap());
    assert!(db
        .user_for_password("nopass@acme.com")
        .await
        .unwrap()
        .is_none());

    let resp = send(
        &app,
        "POST",
        "/login/password",
        None,
        Some("email=nopass@acme.com&password=anything"),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(
        resp.set_cookie.is_none(),
        "no session for password-less user"
    );
    assert!(resp.body.contains("Invalid email or password"));
}

#[tokio::test]
async fn repeated_password_attempts_are_rate_limited() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(Arc::clone(&db)).await).await;

    let user = db.create_user("victim@acme.com", None).await.unwrap();
    db.set_user_password(user, &hash_password("secret").unwrap())
        .await
        .unwrap();

    // PASSWORD_PER_EMAIL is 5 per window; the 6th wrong attempt is throttled.
    let mut throttled = false;
    for _ in 0..(aos_hub::ratelimit::PASSWORD_PER_EMAIL + 1) {
        let resp = send(
            &app,
            "POST",
            "/login/password",
            None,
            Some("email=victim@acme.com&password=wrong"),
        )
        .await;
        if resp.status == StatusCode::TOO_MANY_REQUESTS {
            throttled = true;
            break;
        }
    }
    assert!(throttled, "repeated password attempts must be rate-limited");
}

// -- Account set/change password --------------------------------------------

#[tokio::test]
async fn account_set_password_flow() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(Arc::clone(&db)).await).await;

    // Log the user in via a magic link (no password yet).
    let secret = db.create_magic_link("dev@acme.com").await.unwrap();
    let resp = send(
        &app,
        "GET",
        &format!("/auth/magic?token={secret}"),
        None,
        None,
    )
    .await;
    let cookie = format!(
        "{COOKIE_NAME}={}",
        cookie_value(&resp.set_cookie.expect("magic sets cookie"))
    );
    let user = db.user_by_email("dev@acme.com").await.unwrap().unwrap();
    assert!(
        !db.user_has_password(user).await.unwrap(),
        "no password yet"
    );

    // The account page shows the "set password" affordance.
    let page = send(&app, "GET", "/-/account", Some(&cookie), None).await;
    assert!(page.body.contains("set password"), "{}", page.body);

    // Set a password (CSRF-protected). The magic-link session is fresh, so it
    // is within the sudo window and the change is allowed.
    let csrf = mint_csrf_token(cookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap());
    let resp = send(
        &app,
        "POST",
        "/-/account/password",
        Some(&cookie),
        Some(&format!("csrf={csrf}&password=brand-new-pass")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    assert_eq!(resp.location.as_deref(), Some("/-/account"));
    assert!(
        db.user_has_password(user).await.unwrap(),
        "password now set"
    );

    // The new password actually authenticates.
    assert!(verify_password(
        "brand-new-pass",
        &db.user_for_password("dev@acme.com")
            .await
            .unwrap()
            .unwrap()
            .1
    ));

    // The change revokes every session and re-issues a fresh cookie for this
    // browser: the OLD cookie no longer validates, the NEW one does.
    let new_cookie = format!(
        "{COOKIE_NAME}={}",
        cookie_value(&resp.set_cookie.expect("password change re-issues a cookie"))
    );
    assert_ne!(new_cookie, cookie, "a fresh cookie is minted");
    let old = send(&app, "GET", "/-/account", Some(&cookie), None).await;
    assert_eq!(
        old.status,
        StatusCode::SEE_OTHER,
        "old session is revoked, bounced to /login"
    );
    let fresh = send(&app, "GET", "/-/account", Some(&new_cookie), None).await;
    assert_eq!(fresh.status, StatusCode::OK, "new session is live");

    // A bad CSRF token is rejected (using the live, re-issued cookie).
    let resp = send(
        &app,
        "POST",
        "/-/account/password",
        Some(&new_cookie),
        Some("csrf=bogus&password=whatever"),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN);
}

/// Changing the password evicts every *other* session (M4b): a user with two
/// live sessions who changes their password from one browser locks the other
/// (e.g. a stolen) session out, while the changing browser stays signed in via
/// a freshly minted cookie.
#[tokio::test]
async fn password_change_evicts_sibling_sessions() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(Arc::clone(&db)).await).await;
    let user = db.create_user("dev@acme.com", None).await.unwrap();

    // Two live sudo sessions (as if signed in from two browsers).
    let a = format!(
        "{COOKIE_NAME}={}",
        db.create_session(user, 30 * 24 * 60 * 60, 1).await.unwrap()
    );
    let b = format!(
        "{COOKIE_NAME}={}",
        db.create_session(user, 30 * 24 * 60 * 60, 1).await.unwrap()
    );
    assert_eq!(
        send(&app, "GET", "/-/account", Some(&b), None).await.status,
        StatusCode::OK,
        "sibling session starts live"
    );

    // Change the password from browser A.
    let csrf = mint_csrf_token(a.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap());
    let resp = send(
        &app,
        "POST",
        "/-/account/password",
        Some(&a),
        Some(&format!("csrf={csrf}&password=fresh-secret-pass")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    let a_new = format!(
        "{COOKIE_NAME}={}",
        cookie_value(&resp.set_cookie.expect("change re-issues a cookie"))
    );

    // Browser B (the sibling) is now evicted.
    assert_eq!(
        send(&app, "GET", "/-/account", Some(&b), None).await.status,
        StatusCode::SEE_OTHER,
        "sibling session evicted"
    );
    // The original A cookie is dead too; the re-issued one is live.
    assert_eq!(
        send(&app, "GET", "/-/account", Some(&a), None).await.status,
        StatusCode::SEE_OTHER,
        "old A cookie evicted"
    );
    assert_eq!(
        send(&app, "GET", "/-/account", Some(&a_new), None)
            .await
            .status,
        StatusCode::OK,
        "re-issued cookie live"
    );
}

/// A non-sudo session (one that is not recently re-authenticated) cannot change
/// the password (M4): the sudo gate refuses it with a `403`. An `auth_level=0`
/// session is never sudo, so it stands in for a stale, long-lived session.
#[tokio::test]
async fn password_change_requires_sudo() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(Arc::clone(&db)).await).await;
    let user = db.create_user("dev@acme.com", None).await.unwrap();

    // A live but non-sudo session (auth_level 0).
    let cookie = format!(
        "{COOKIE_NAME}={}",
        db.create_session(user, 30 * 24 * 60 * 60, 0).await.unwrap()
    );
    // It is authenticated enough to view the account page...
    assert_eq!(
        send(&app, "GET", "/-/account", Some(&cookie), None)
            .await
            .status,
        StatusCode::OK,
    );
    // ...but not to change the password.
    let csrf = mint_csrf_token(cookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap());
    let resp = send(
        &app,
        "POST",
        "/-/account/password",
        Some(&cookie),
        Some(&format!("csrf={csrf}&password=should-be-refused")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    assert!(
        !db.user_has_password(user).await.unwrap(),
        "password unchanged by refused request"
    );
}

// -- enforce_sso closes the local-credential bypass (H-4) -------------------

/// Seed an org `slug` with an OIDC IdP config and `enforce_sso`, returning its
/// id. The config is otherwise a minimal dev stub (it is never actually called
/// in these tests — the redirect target is what we assert on).
async fn seed_sso_org(db: &Database, slug: &str, enforce_sso: bool) -> i64 {
    let org_id = db.create_org(slug, slug).await.unwrap();
    db.upsert_idp_config(&IdpConfigRecord {
        org_id,
        issuer: "https://idp.example".into(),
        authorization_endpoint: "https://idp.example/authorize".into(),
        token_endpoint: "https://idp.example/token".into(),
        jwks_uri: "https://idp.example/jwks".into(),
        client_id: "hub-client".into(),
        client_secret_enc: None,
        scopes: "openid email profile".into(),
        groups_claim: None,
        role_map_json: "{}".into(),
        allow_jit: false,
        enforce_sso,
        default_role: "viewer".into(),
    })
    .await
    .unwrap();
    org_id
}

/// A user whose **verified email domain** is captured by an SSO-enforcing org
/// cannot log in with a password — the attempt redirects into the org's OIDC
/// flow instead of minting a local session, even though the password is valid.
#[tokio::test]
async fn enforced_user_password_login_redirects_to_sso() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(Arc::clone(&db)).await).await;

    let org_id = seed_sso_org(&db, "acme", true).await;
    db.add_org_domain(org_id, "acme.com").await.unwrap();
    db.verify_org_domain("acme.com").await.unwrap();

    // The user has a real, working password (set before enforcement, say).
    let user = db.create_user("dev@acme.com", None).await.unwrap();
    db.set_user_password(user, &hash_password("hunter2").unwrap())
        .await
        .unwrap();

    let resp = send(
        &app,
        "POST",
        "/login/password",
        None,
        Some("email=dev@acme.com&password=hunter2"),
    )
    .await;
    // Redirected to SSO, no local session cookie issued.
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    assert_eq!(
        resp.location.as_deref(),
        Some("/auth/oidc/start?org=acme"),
        "valid password is steered to the IdP, not a local session"
    );
    assert!(
        resp.set_cookie.is_none(),
        "no local session for an SSO-enforced user"
    );
}

/// SSO enforcement also follows **membership**: a user whose email domain is
/// *not* captured, but who is a member of an SSO-enforcing org, is likewise
/// blocked from password login and redirected to that org's IdP.
#[tokio::test]
async fn enforced_via_membership_password_login_redirects_to_sso() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(Arc::clone(&db)).await).await;

    seed_sso_org(&db, "acme", true).await;
    // The user's email domain (other.example) is NOT captured by acme; the bind
    // is purely the membership grant under the `acme` scope.
    let user = db
        .create_user("contractor@other.example", None)
        .await
        .unwrap();
    db.set_user_password(user, &hash_password("hunter2").unwrap())
        .await
        .unwrap();
    db.grant_membership("user", user, "acme/cdn", "viewer")
        .await
        .unwrap();

    let resp = send(
        &app,
        "POST",
        "/login/password",
        None,
        Some("email=contractor@other.example&password=hunter2"),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    assert_eq!(resp.location.as_deref(), Some("/auth/oidc/start?org=acme"));
    assert!(resp.set_cookie.is_none());
}

/// An org with an IdP but `enforce_sso = false` does **not** block local
/// credentials: password login still mints a session (regression — the fix
/// must not break non-enforced users).
#[tokio::test]
async fn unenforced_user_password_login_still_works() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(Arc::clone(&db)).await).await;

    let org_id = seed_sso_org(&db, "acme", false).await;
    db.add_org_domain(org_id, "acme.com").await.unwrap();
    db.verify_org_domain("acme.com").await.unwrap();

    let user = db.create_user("dev@acme.com", None).await.unwrap();
    db.set_user_password(user, &hash_password("hunter2").unwrap())
        .await
        .unwrap();

    let resp = send(
        &app,
        "POST",
        "/login/password",
        None,
        Some("email=dev@acme.com&password=hunter2"),
    )
    .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    assert_eq!(resp.location.as_deref(), Some("/"), "{}", resp.body);
    assert!(
        resp.set_cookie.is_some(),
        "non-enforced user still gets a local session"
    );
}

/// A member of an SSO-enforced org cannot set a local password: the
/// `POST /account/password` handler refuses with a `403`, leaving the account
/// password-less (no standing bypass of IdP deprovisioning).
#[tokio::test]
async fn enforced_user_cannot_set_password() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(Arc::clone(&db)).await).await;

    let org_id = seed_sso_org(&db, "acme", true).await;
    db.add_org_domain(org_id, "acme.com").await.unwrap();
    db.verify_org_domain("acme.com").await.unwrap();

    // Sign in via magic link (fresh = sudo-capable, satisfying the sudo gate).
    let secret = db.create_magic_link("dev@acme.com").await.unwrap();
    let resp = send(
        &app,
        "GET",
        &format!("/auth/magic?token={secret}"),
        None,
        None,
    )
    .await;
    let cookie = format!(
        "{COOKIE_NAME}={}",
        cookie_value(&resp.set_cookie.expect("magic sets cookie"))
    );
    let user = db.user_by_email("dev@acme.com").await.unwrap().unwrap();

    let csrf = mint_csrf_token(cookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap());
    let resp = send(
        &app,
        "POST",
        "/-/account/password",
        Some(&cookie),
        Some(&format!("csrf={csrf}&password=brand-new-pass")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    assert!(
        !db.user_has_password(user).await.unwrap(),
        "SSO-enforced user cannot set a local password"
    );
}

/// A member of an SSO-enforced org cannot enroll a passkey: the
/// `POST /account/passkeys/finish` handler refuses with a `403` before any
/// credential is persisted.
#[tokio::test]
async fn enforced_user_cannot_enroll_passkey() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(Arc::clone(&db)).await).await;

    let org_id = seed_sso_org(&db, "acme", true).await;
    db.add_org_domain(org_id, "acme.com").await.unwrap();
    db.verify_org_domain("acme.com").await.unwrap();

    let secret = db.create_magic_link("dev@acme.com").await.unwrap();
    let resp = send(
        &app,
        "GET",
        &format!("/auth/magic?token={secret}"),
        None,
        None,
    )
    .await;
    let cookie = format!(
        "{COOKIE_NAME}={}",
        cookie_value(&resp.set_cookie.expect("magic sets cookie"))
    );
    let user = db.user_by_email("dev@acme.com").await.unwrap().unwrap();

    // The finish handler refuses before parsing the WebAuthn payload, so a
    // minimal JSON body (just a valid CSRF) suffices to prove the gate.
    let csrf = mint_csrf_token(cookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap());
    let body = serde_json::json!({
        "csrf": csrf,
        "client_data_json": "",
        "attestation_object": "",
    })
    .to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/-/account/passkeys/finish")
        .header(header::COOKIE, &cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        db.list_user_credentials(user).await.unwrap().is_empty(),
        "no passkey persisted for an SSO-enforced user"
    );
}
