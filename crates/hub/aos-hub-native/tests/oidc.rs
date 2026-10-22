//! Per-org OIDC SSO e2e: drive the authorization-code + PKCE flow against a
//! fake in-test identity provider.
//!
//! A tiny axum IdP stands up on an ephemeral port with three endpoints — an
//! authorize endpoint, a token endpoint that returns a signed id_token, and a
//! JWKS endpoint exposing the RSA public key — using a baked 2048-bit RSA test
//! keypair (`TEST_RSA_PEM` / `TEST_JWK_N`). The tests drive `begin_login` →
//! fake authorize → callback → `complete_login` and assert the identity is
//! created, linked (JIT keyed on verifier and subject), and mapped to roles, plus the
//! negative cases (bad nonce/state, expired flow, aud/iss mismatch, tampered
//! signature, JIT disabled).

use std::sync::Arc;
use std::sync::Mutex;

use aos_hub_native::auth::oidc::{
    self, begin_login, code_challenge_s256, complete_login, dev_sealer, CallbackParams, IdpConfig,
};
use aos_hub_native::coreports::HubHttpClient;
use aos_hub_native::db::{Database, IdentityLink, IdpConfigRecord};
use aos_hub_native::domain::{Principal, Role, Scope};
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;

const TEST_BROWSER_BINDING: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// A baked 2048-bit RSA private key (PKCS#8 PEM) for signing test id_tokens.
const TEST_RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDkpZkwExMNISz1
ccixwArA+F9CL7PZQAVQIRK3q3VVDPKHOgqcszlhY13qLnI0YVaeN+eHptmmrkdO
tpwfu4SJzJuyrFKsa+/WLr/NE31RbQ9Z/Ac8gLfvJe3DDzoXaWWbqdGNALkNaSwd
rQKpJP96T9l2H+XQI4kzw1RGNwW9LDUMuEh6wtG4v1oHX1aYAC7tgRAnd1d8j9ga
vz0QJb68YI+4XczL6k23eu0FN5tzwFT3dKOC9w2xshgKKwDBskfT6KLW1NNiWXIZ
B7udhb+PUvP76YCbtvYisfItAekH9696FFDvtP9Cs1Rh1B5yBeZoWMg2KiilSsxQ
93dP/mI5AgMBAAECggEAEbmDo04rO9PpTg/3cKNpl1V5tEy0irVzjqdjBybNFkjb
aTUMOw21YkcSHJ65SYsNLFU68dFdoytJ9FW5dcfzKZKECbO28fj+aJJgWdJhCdr5
kG52P3qz/N+UwPpbyhJTJzV2J5HZhpWzWYvpU6Q+WM86qp/6Ov/HjvdyqkHG2bKf
hEjUVDQCc+iX8uDMIPIx9ZxjGd/3Q46c0tz6bH67mhkrUdJkx1sXzXB3cy1s4aK6
FrX2t0TZNKNBRKJWmfK+tGKiYMv4NjRDGYF84KRoEQU1eLosut1wt5pXTN+sUiqI
xAM1LCBx975X1Ia8Vi3bxY1p0CqinQrTewE06UIRzQKBgQDzjuzTsOkyYKkLeqtr
CfB8Kskl/vEry5M71wSjpt/eY09TtwxSCNRv0FyPWCeeH6BP1gHKV9QGZKwXEW+M
EdmGxr1oG0jt3tB8VGrddHkPABio8ImTngrBgv0f8zdV5RmMFqwBdcwFCAQgpakW
nd5LXPfFweGe/KecpLf5KApDnQKBgQDwU6wxMYSZVtmqfbMTZYgjaGpavZcBosqh
RWoSF2UFR4W0o2K1LAc1Q5uSoeUVhm8Atk0MF5yg03PD8nDXmYthsfnfRloqckYQ
rvyuWdRDi5tV4JDLDkR4ZUj752W10Qee5R2h15QO0QOvVJbJhJaQ4gIYUs970nJx
CnRY6Eh8TQKBgClrL9kcJ7wadgTuuoH8cbob6JMelNLWztYJTc+qzD1cdBwPb/fv
ankNXQA/hJU+WZvaD/niD7t6mU1e+LJAQtbJq2It6awSDTBnhrjcWs3zPT5VkX/a
C4g3B2bMjKd9y2doX53r82MTpugKZAPlmu0EBVrLCtxnqPVZibPEXGJ9AoGBAJlA
wk2chjJCcAuInOmBlY7+xtOWkvU4Gn89BKcExCbZtSm8BvYBXZdZxZt8IdnYIHET
z44mgHsOXIRX1h2mjHuAQxdehaELviJldDy6i+GG5UeeLLdQIdmkvSXmKbYH1hQ9
huft0TyhjPgBuSZIprs9ZJieNjF/wfrT793CQncBAoGBAKUAH+I+4aZjeTgFNyX1
O1ARgVKq01zuxB4ZqLF9hu5VXMVfCu6xcvarsg00L25nKwkNnKBzqRwREAw6iAEn
XVENEPWUVraadDB1WoLnBvKraDBgWHupTYO3m6LPz+SkKpD/lksBO/J4zfPkudOF
ZVjOi7o378jYXc5CptxoZcbM
-----END PRIVATE KEY-----";

/// The base64url RSA modulus (`n`) matching [`TEST_RSA_PEM`], for the JWKS.
const TEST_JWK_N: &str = "5KWZMBMTDSEs9XHIscAKwPhfQi-z2UAFUCESt6t1VQzyhzoKnLM5YWNd6i5yNGFWnjfnh6bZpq5HTracH7uEicybsqxSrGvv1i6_zRN9UW0PWfwHPIC37yXtww86F2llm6nRjQC5DWksHa0CqST_ek_Zdh_l0COJM8NURjcFvSw1DLhIesLRuL9aB19WmAAu7YEQJ3dXfI_YGr89ECW-vGCPuF3My-pNt3rtBTebc8BU93SjgvcNsbIYCisAwbJH0-ii1tTTYllyGQe7nYW_j1Lz--mAm7b2IrHyLQHpB_evehRQ77T_QrNUYdQecgXmaFjINioopUrMUPd3T_5iOQ";

/// The base64url RSA exponent (`e` = 65537) for the JWKS.
const TEST_JWK_E: &str = "AQAB";

/// The test IdP's key id.
const TEST_KID: &str = "test-key-1";
const TEST_VERIFIER_ID: &str = "test-verifier";

/// Claims the fake IdP mints into the id_token, controllable per test.
#[derive(Clone, Serialize)]
struct IdToken {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    groups: Vec<String>,
}

/// Shared state of the fake IdP: how to mint the next id_token and whether to
/// tamper its signature.
#[derive(Clone)]
struct IdpState {
    issuer: String,
    /// `(sub, email, email_verified, groups)` plus aud override for the next
    /// token; the nonce is taken from the authorize redirect.
    sub: Arc<Mutex<String>>,
    email: Arc<Mutex<Option<String>>>,
    email_verified: Arc<Mutex<Option<bool>>>,
    groups: Arc<Mutex<Vec<String>>>,
    aud_override: Arc<Mutex<Option<String>>>,
    iss_override: Arc<Mutex<Option<String>>>,
    tamper: Arc<Mutex<bool>>,
    /// The nonce captured from the most recent authorize request.
    last_nonce: Arc<Mutex<String>>,
}

impl IdpState {
    fn new(issuer: &str) -> IdpState {
        IdpState {
            issuer: issuer.to_string(),
            sub: Arc::new(Mutex::new("idp-subject-1".into())),
            email: Arc::new(Mutex::new(Some("alice@acme.com".into()))),
            email_verified: Arc::new(Mutex::new(Some(true))),
            groups: Arc::new(Mutex::new(Vec::new())),
            aud_override: Arc::new(Mutex::new(None)),
            iss_override: Arc::new(Mutex::new(None)),
            tamper: Arc::new(Mutex::new(false)),
            last_nonce: Arc::new(Mutex::new(String::new())),
        }
    }
}

#[derive(serde::Deserialize)]
struct AuthorizeQuery {
    redirect_uri: String,
    state: String,
    nonce: String,
}

/// `GET /authorize` — record the nonce and 302 back to the hub callback with a
/// fixed code and the echoed state.
async fn authorize(State(idp): State<IdpState>, Query(q): Query<AuthorizeQuery>) -> Response {
    *idp.last_nonce.lock().unwrap() = q.nonce.clone();
    let location = format!("{}?code=test-code&state={}", q.redirect_uri, q.state);
    axum::response::Redirect::to(&location).into_response()
}

/// `POST /token` — return a signed id_token using the staged claims.
async fn token(State(idp): State<IdpState>) -> Response {
    let now = jsonwebtoken_now();
    let claims = IdToken {
        iss: idp
            .iss_override
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| idp.issuer.clone()),
        sub: idp.sub.lock().unwrap().clone(),
        aud: idp
            .aud_override
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| "hub-client".into()),
        exp: now + 300,
        iat: now,
        nonce: idp.last_nonce.lock().unwrap().clone(),
        email: idp.email.lock().unwrap().clone(),
        email_verified: *idp.email_verified.lock().unwrap(),
        groups: idp.groups.lock().unwrap().clone(),
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.into());
    let key = EncodingKey::from_rsa_pem(TEST_RSA_PEM.as_bytes()).unwrap();
    let mut id_token = jsonwebtoken::encode(&header, &claims, &key).unwrap();
    if *idp.tamper.lock().unwrap() {
        // Flip the last char of the signature to break verification.
        let last = id_token.pop().unwrap();
        id_token.push(if last == 'A' { 'B' } else { 'A' });
    }
    Json(serde_json::json!({
        "access_token": "test-access",
        "token_type": "Bearer",
        "id_token": id_token,
    }))
    .into_response()
}

/// `GET /jwks` — the RSA public key.
async fn jwks() -> Response {
    Json(serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": TEST_KID,
            "n": TEST_JWK_N,
            "e": TEST_JWK_E,
        }]
    }))
    .into_response()
}

fn jsonwebtoken_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Stand up the fake IdP on an ephemeral port; returns `(base_url, state)`.
async fn spawn_idp() -> (String, IdpState) {
    // The persisted OIDC contract is HTTPS-only. Debug builds expose the same
    // explicit loopback escape hatch as the outbound URL guard so this in-test
    // cleartext listener can exercise the real flow without weakening release
    // builds or accepting non-loopback HTTP issuers.
    std::env::set_var("AOS_HUB_ALLOW_LOCAL_REMOTES", "1");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let idp = IdpState::new(&base);
    let app = axum::Router::new()
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/jwks", get(jwks))
        .with_state(idp.clone());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (base, idp)
}

/// Seed an org with an IdP config pointing at `idp_base`, returning `org_id`.
async fn seed_org(
    db: &Database,
    idp_base: &str,
    enforce_sso: bool,
    allow_jit: bool,
    role_map: &str,
) {
    let org_id = db.create_org("acme", "Acme").await.unwrap();
    db.upsert_idp_config(&IdpConfigRecord {
        org_id,
        issuer: idp_base.to_string(),
        authorization_endpoint: format!("{idp_base}/authorize"),
        token_endpoint: format!("{idp_base}/token"),
        jwks_uri: format!("{idp_base}/jwks"),
        client_id: "hub-client".into(),
        client_secret_enc: Some(dev_sealer().seal("super-secret").unwrap()),
        scopes: "openid email profile".into(),
        groups_claim: Some("groups".into()),
        role_map_json: role_map.to_string(),
        allow_jit,
        enforce_sso,
        default_role: "viewer".into(),
        resource_version: 1,
        incarnation_id: None,
        mutation_plan_id: None,
    })
    .await
    .unwrap();
}

/// A `HubHttpClient` over a plain (non-SSRF-resolving) reqwest client, so the
/// `127.0.0.1` fake IdP is reachable in tests.
///
/// `complete_login` now takes the `HttpClient` port instead of a bare
/// `reqwest::Client` (RFC-0004 Phase 5, console-dedup stage F); the hub's
/// [`HubHttpClient`] is that port. It wraps whatever client it is given, so a
/// plain client here keeps the loopback IdP reachable while still exercising the
/// real `post_form`/`get` (error-for-status + body-cap) path the production code
/// runs.
fn test_http() -> HubHttpClient {
    HubHttpClient::new(reqwest::Client::new())
}

/// Run the full flow: begin_login → fake authorize → callback → complete_login.
async fn run_flow(
    db: &Database,
    http: &HubHttpClient,
    external_url: &str,
    org_id: i64,
) -> anyhow::Result<aos_hub_native::auth::oidc::OidcLogin> {
    let redirect = begin_login(db, external_url, org_id, Some("/account")).await?;
    let params = authorize_redirect(&redirect).await?;

    complete_login(
        db,
        dev_sealer().as_ref(),
        http,
        external_url,
        &params,
        &redirect.browser_binding,
    )
    .await
}

async fn authorize_redirect(redirect: &oidc::AuthRedirect) -> anyhow::Result<CallbackParams> {
    // Hit the IdP authorize endpoint *without following redirects*: it 302s
    // back to the hub callback (which is not a real server here), so we read
    // the Location to recover the code + state the hub would have received.
    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let resp = no_redirect.get(&redirect.url).send().await?;
    let location = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let parsed = url::Url::parse(&location)?;
    let mut code = String::new();
    let mut state = String::new();
    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "code" => code = v.into_owned(),
            "state" => state = v.into_owned(),
            _ => {}
        }
    }

    Ok(CallbackParams { code, state })
}

#[tokio::test]
async fn jit_creates_user_and_identity_keyed_on_iss_sub() {
    let (idp_base, _idp) = spawn_idp().await;
    let db = Database::open_in_memory().await.unwrap();
    seed_org(&db, &idp_base, false, true, "{}").await;
    let org = db.org_by_slug("acme").await.unwrap().unwrap();
    let org_id = org.id;
    let http = test_http();

    let login = run_flow(&db, &http, "http://hub.example.com", org_id)
        .await
        .unwrap();
    assert!(login.provisioned, "first login should provision a user");
    assert_eq!(login.email.as_deref(), Some("alice@acme.com"));

    let config = db.idp_config(org_id).await.unwrap().unwrap();
    let verifier_id = aos_hub_model::identity::oidc_verifier_id(&config);
    let user = db
        .identity_user(&verifier_id, "idp-subject-1")
        .await
        .unwrap();
    assert_eq!(user, Some(login.user_id));
}

#[tokio::test]
async fn second_login_same_iss_sub_does_not_create_new_user() {
    let (idp_base, idp) = spawn_idp().await;
    let db = Database::open_in_memory().await.unwrap();
    seed_org(&db, &idp_base, false, true, "{}").await;
    let org = db.org_by_slug("acme").await.unwrap().unwrap();
    let org_id = org.id;
    let http = test_http();

    let first = run_flow(&db, &http, "http://hub.example.com", org_id)
        .await
        .unwrap();

    // Same verifier and subject but a different email: resolve to the
    // same user, not a fresh one.
    *idp.email.lock().unwrap() = Some("alice-new@acme.com".into());
    let second = run_flow(&db, &http, "http://hub.example.com", org_id)
        .await
        .unwrap();

    assert_eq!(first.user_id, second.user_id);
    assert!(
        !second.provisioned,
        "a known identity is not re-provisioned"
    );
}

#[tokio::test]
async fn group_claim_maps_to_role_at_org_scope() {
    let (idp_base, idp) = spawn_idp().await;
    let db = Database::open_in_memory().await.unwrap();
    seed_org(&db, &idp_base, false, true, r#"{"acme-admins":"admin"}"#).await;
    let org = db.org_by_slug("acme").await.unwrap().unwrap();
    let org_id = org.id;
    *idp.groups.lock().unwrap() = vec!["acme-admins".into()];
    let http = test_http();

    let login = run_flow(&db, &http, "http://hub.example.com", org_id)
        .await
        .unwrap();

    let grants = db
        .effective_scopes(Principal::user(login.user_id))
        .await
        .unwrap();
    assert!(
        grants
            .iter()
            .any(|(scope, role)| *scope == Scope::parse(&org.stable_id) && *role == Role::Admin),
        "the acme-admins group should grant admin at the org scope: {grants:?}"
    );
}

#[tokio::test]
async fn default_role_granted_when_no_group_maps() {
    let (idp_base, _idp) = spawn_idp().await;
    let db = Database::open_in_memory().await.unwrap();
    seed_org(&db, &idp_base, false, true, r#"{"acme-admins":"admin"}"#).await;
    let org = db.org_by_slug("acme").await.unwrap().unwrap();
    let org_id = org.id;
    let http = test_http();

    let login = run_flow(&db, &http, "http://hub.example.com", org_id)
        .await
        .unwrap();
    let grants = db
        .effective_scopes(Principal::user(login.user_id))
        .await
        .unwrap();
    assert!(grants
        .iter()
        .any(|(scope, role)| *scope == Scope::parse(&org.stable_id) && *role == Role::Viewer));
}

#[tokio::test]
async fn forged_or_replayed_state_is_rejected() {
    let (idp_base, _idp) = spawn_idp().await;
    let db = Database::open_in_memory().await.unwrap();
    seed_org(&db, &idp_base, false, true, "{}").await;
    let org_id = db.org_by_slug("acme").await.unwrap().unwrap().id;
    let http = test_http();

    // A callback with a state that was never staged.
    let err = complete_login(
        &db,
        dev_sealer().as_ref(),
        &http,
        "http://hub.example.com",
        &CallbackParams {
            code: "test-code".into(),
            state: "forged-state".into(),
        },
        TEST_BROWSER_BINDING,
    )
    .await;
    assert!(err.is_err());

    // A staged-then-consumed state cannot be replayed.
    let redirect = begin_login(&db, "http://hub.example.com", org_id, None)
        .await
        .unwrap();
    let parsed = url::Url::parse(&redirect.url).unwrap();
    let state = parsed
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    // First consumption succeeds (drives the real IdP).
    let _ = run_flow(&db, &http, "http://hub.example.com", org_id).await;
    // Replaying the original state now finds nothing.
    let replay = complete_login(
        &db,
        dev_sealer().as_ref(),
        &http,
        "http://hub.example.com",
        &CallbackParams {
            code: "test-code".into(),
            state,
        },
        &redirect.browser_binding,
    )
    .await;
    assert!(replay.is_err());
}

#[tokio::test]
async fn callback_requires_the_browser_that_started_the_flow() {
    let (idp_base, _idp) = spawn_idp().await;
    let db = Database::open_in_memory().await.unwrap();
    seed_org(&db, &idp_base, false, true, "{}").await;
    let org_id = db.org_by_slug("acme").await.unwrap().unwrap().id;
    let http = test_http();

    let redirect = begin_login(&db, "http://hub.example.com", org_id, None)
        .await
        .unwrap();
    let params = authorize_redirect(&redirect).await.unwrap();
    assert_ne!(redirect.browser_binding, TEST_BROWSER_BINDING);

    let transferred = complete_login(
        &db,
        dev_sealer().as_ref(),
        &http,
        "http://hub.example.com",
        &params,
        TEST_BROWSER_BINDING,
    )
    .await;
    assert!(transferred.is_err());

    let login = complete_login(
        &db,
        dev_sealer().as_ref(),
        &http,
        "http://hub.example.com",
        &params,
        &redirect.browser_binding,
    )
    .await
    .unwrap();
    assert_eq!(login.email.as_deref(), Some("alice@acme.com"));
}

#[tokio::test]
async fn concurrent_login_tabs_keep_independent_flows() {
    let (idp_base, _idp) = spawn_idp().await;
    let db = Database::open_in_memory().await.unwrap();
    seed_org(&db, &idp_base, false, true, "{}").await;
    let org_id = db.org_by_slug("acme").await.unwrap().unwrap().id;

    let first = begin_login(&db, "http://hub.example.com", org_id, None)
        .await
        .unwrap();
    let second = begin_login(&db, "http://hub.example.com", org_id, None)
        .await
        .unwrap();
    assert_ne!(first.state, second.state);
    assert_ne!(first.browser_binding, second.browser_binding);
    assert_ne!(
        oidc::browser_binding_cookie_name(&first.state).unwrap(),
        oidc::browser_binding_cookie_name(&second.state).unwrap()
    );

    let second_hash = oidc::browser_binding_digest(&second.browser_binding).unwrap();
    let first_hash = oidc::browser_binding_digest(&first.browser_binding).unwrap();
    assert!(db
        .take_oidc_flow(&second.state, &second_hash)
        .await
        .unwrap()
        .is_some());
    assert!(db
        .take_oidc_flow(&first.state, &first_hash)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn expired_flow_is_rejected() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("acme", "Acme").await.unwrap();
    // Stage a flow that is already expired (negative TTL).
    let binding_hash = "0".repeat(64);
    db.create_oidc_flow(
        "st",
        org_id,
        TEST_VERIFIER_ID,
        "nn",
        "verifier",
        &binding_hash,
        None,
        -1,
    )
        .await
        .unwrap();
    assert!(db
        .take_oidc_flow("st", &binding_hash)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn bad_nonce_is_rejected() {
    let (idp_base, idp) = spawn_idp().await;
    let db = Database::open_in_memory().await.unwrap();
    seed_org(&db, &idp_base, false, true, "{}").await;
    let org_id = db.org_by_slug("acme").await.unwrap().unwrap().id;
    let http = test_http();

    // Begin a real flow to capture a valid state, but force the IdP to mint a
    // token with a nonce that does not match the staged one.
    let redirect = begin_login(&db, "http://hub.example.com", org_id, None)
        .await
        .unwrap();
    let parsed = url::Url::parse(&redirect.url).unwrap();
    let state = parsed
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    // The IdP will set last_nonce to whatever it sees; pre-set a wrong nonce
    // and never call authorize, so the token carries the wrong nonce.
    *idp.last_nonce.lock().unwrap() = "wrong-nonce".into();
    let err = complete_login(
        &db,
        dev_sealer().as_ref(),
        &http,
        "http://hub.example.com",
        &CallbackParams {
            code: "test-code".into(),
            state,
        },
        &redirect.browser_binding,
    )
    .await;
    assert!(err.is_err(), "a mismatched nonce must be rejected");
}

#[tokio::test]
async fn aud_mismatch_is_rejected() {
    let (idp_base, idp) = spawn_idp().await;
    let db = Database::open_in_memory().await.unwrap();
    seed_org(&db, &idp_base, false, true, "{}").await;
    let org_id = db.org_by_slug("acme").await.unwrap().unwrap().id;
    *idp.aud_override.lock().unwrap() = Some("someone-else".into());
    let http = test_http();
    let err = run_flow(&db, &http, "http://hub.example.com", org_id).await;
    assert!(err.is_err(), "an aud mismatch must be rejected");
}

#[tokio::test]
async fn iss_mismatch_is_rejected() {
    let (idp_base, idp) = spawn_idp().await;
    let db = Database::open_in_memory().await.unwrap();
    seed_org(&db, &idp_base, false, true, "{}").await;
    let org_id = db.org_by_slug("acme").await.unwrap().unwrap().id;
    *idp.iss_override.lock().unwrap() = Some("https://evil.example".into());
    let http = test_http();
    let err = run_flow(&db, &http, "http://hub.example.com", org_id).await;
    assert!(err.is_err(), "an iss mismatch must be rejected");
}

#[tokio::test]
async fn tampered_signature_is_rejected() {
    let (idp_base, idp) = spawn_idp().await;
    let db = Database::open_in_memory().await.unwrap();
    seed_org(&db, &idp_base, false, true, "{}").await;
    let org_id = db.org_by_slug("acme").await.unwrap().unwrap().id;
    *idp.tamper.lock().unwrap() = true;
    let http = test_http();
    let err = run_flow(&db, &http, "http://hub.example.com", org_id).await;
    assert!(
        err.is_err(),
        "a tampered id_token signature must be rejected"
    );
}

#[tokio::test]
async fn jit_disabled_rejects_unknown_identity() {
    let (idp_base, _idp) = spawn_idp().await;
    let db = Database::open_in_memory().await.unwrap();
    seed_org(&db, &idp_base, false, false, "{}").await; // allow_jit = false
    let org_id = db.org_by_slug("acme").await.unwrap().unwrap().id;
    let http = test_http();
    let err = run_flow(&db, &http, "http://hub.example.com", org_id).await;
    assert!(
        err.is_err(),
        "an unknown identity must be rejected when JIT is disabled"
    );
}

#[tokio::test]
async fn domain_capture_routes_only_verified_domains() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("acme", "Acme").await.unwrap();
    let _challenge = db.add_org_domain(org_id, "acme.com").await.unwrap();
    // Unverified: org_for_domain returns nothing.
    assert_eq!(db.org_for_domain("acme.com").await.unwrap(), None);
    // After verification it routes.
    assert!(db.verify_org_domain("acme.com").await.unwrap());
    assert_eq!(db.org_for_domain("acme.com").await.unwrap(), Some(org_id));
    // Verification matches the published challenge value.
    let record = db.org_domain("acme.com").await.unwrap().unwrap();
    assert!(record.txt_challenge.starts_with("aos-domain-verify="));
}

#[tokio::test]
async fn begin_login_sets_pkce_s256_and_records_flow() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("acme", "Acme").await.unwrap();
    db.upsert_idp_config(&IdpConfigRecord {
        org_id,
        issuer: "https://idp.example".into(),
        authorization_endpoint: "https://idp.example/authorize".into(),
        token_endpoint: "https://idp.example/token".into(),
        jwks_uri: "https://idp.example/jwks".into(),
        client_id: "hub-client".into(),
        client_secret_enc: None,
        scopes: "openid email".into(),
        groups_claim: None,
        role_map_json: "{}".into(),
        allow_jit: true,
        enforce_sso: false,
        default_role: "viewer".into(),
        resource_version: 1,
        incarnation_id: None,
        mutation_plan_id: None,
    })
    .await
    .unwrap();

    let redirect = begin_login(&db, "http://hub.example.com", org_id, None)
        .await
        .unwrap();
    let parsed = url::Url::parse(&redirect.url).unwrap();
    let q: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
    assert_eq!(q.get("response_type").map(String::as_str), Some("code"));
    assert_eq!(
        q.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    let state = q.get("state").unwrap();
    // The recorded flow's verifier hashes to the sent challenge.
    let binding_hash = oidc::browser_binding_digest(&redirect.browser_binding).unwrap();
    let flow = db
        .take_oidc_flow(state, &binding_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        &code_challenge_s256(&flow.code_verifier),
        q.get("code_challenge").unwrap()
    );
    assert_eq!(&flow.nonce, q.get("nonce").unwrap());
}

#[test]
fn idp_config_from_record_parses_role_map() {
    let record = IdpConfigRecord {
        org_id: 1,
        issuer: "https://idp".into(),
        authorization_endpoint: "https://idp/a".into(),
        token_endpoint: "https://idp/t".into(),
        jwks_uri: "https://idp/j".into(),
        client_id: "c".into(),
        client_secret_enc: None,
        scopes: "openid".into(),
        groups_claim: Some("groups".into()),
        role_map_json: r#"{"g":"maintainer"}"#.into(),
        allow_jit: true,
        enforce_sso: true,
        default_role: "developer".into(),
        resource_version: 1,
        incarnation_id: None,
        mutation_plan_id: None,
    };
    let config = IdpConfig::from_record(record);
    assert_eq!(config.role_map.get("g"), Some(&Role::Maintainer));
    assert_eq!(config.default_role, Role::Developer);
    assert!(config.enforce_sso);
}

#[tokio::test]
async fn identity_link_existing_then_link_paths() {
    // Verifier-subject keying: existing identity wins; verified email on a captured
    // domain links to an existing user; otherwise JIT.
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("acme", "Acme").await.unwrap();
    db.add_org_domain(org_id, "acme.com").await.unwrap();
    db.verify_org_domain("acme.com").await.unwrap();

    // Pre-existing user with the captured email but no identity.
    let existing = db.create_user("bob@acme.com", None).await.unwrap();
    let link = db
        .link_or_create_identity(
            TEST_VERIFIER_ID,
            "https://idp",
            "sub-bob",
            Some("bob@acme.com"),
            true,
            org_id,
            true,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(link, IdentityLink::Linked(existing));

    // Same identity again resolves as Existing.
    let again = db
        .link_or_create_identity(
            TEST_VERIFIER_ID,
            "https://idp",
            "sub-bob",
            Some("bob@acme.com"),
            true,
            org_id,
            true,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again, IdentityLink::Existing(existing));

    // An unverified email on the captured domain does NOT auto-link; JIT off
    // returns None for a new identity.
    let none = db
        .link_or_create_identity(
            TEST_VERIFIER_ID,
            "https://idp",
            "sub-new",
            Some("carol@acme.com"),
            false,
            org_id,
            false,
        )
        .await
        .unwrap();
    assert_eq!(none, None);

    // Sanity: oidc module re-exported types are usable.
    let _ = oidc::FLOW_TTL_SECS;
}

#[tokio::test]
async fn provider_profile_does_not_replace_an_existing_mailbox_owner() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("external", "External").await.unwrap();

    let mailbox_owner = db.create_user("owner@othercorp.com", None).await.unwrap();

    let link = db
        .link_or_create_identity(
            TEST_VERIFIER_ID,
            "https://external-idp",
            "external-subject",
            Some("owner@othercorp.com"),
            true,
            org_id,
            true,
        )
        .await
        .unwrap()
        .unwrap();
    let provider_user = link.user_id();

    assert_ne!(provider_user, mailbox_owner);
    assert_eq!(
        db.identity_user(TEST_VERIFIER_ID, "external-subject")
            .await
            .unwrap(),
        Some(provider_user)
    );
    assert_eq!(
        db.user_by_email("owner@othercorp.com").await.unwrap(),
        Some(mailbox_owner)
    );
    db.set_user_password(provider_user, "profile-hash")
        .await
        .unwrap();
    assert_eq!(
        db.user_for_password("owner@othercorp.com").await.unwrap(),
        None
    );

    let org = db.org_by_id(org_id).await.unwrap().unwrap();
    db.create_invitation(
        org_id,
        "owner@othercorp.com",
        &org.stable_id,
        "viewer",
        "mailbox-invitation",
        i64::MAX,
    )
    .await
    .unwrap();
    assert!(db
        .accept_invitation(
            "mailbox-invitation",
            org_id,
            provider_user,
            "owner@othercorp.com",
        )
        .await
        .unwrap()
        .is_none());
    assert!(db
        .accept_invitation(
            "mailbox-invitation",
            org_id,
            mailbox_owner,
            "owner@othercorp.com",
        )
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn unverified_email_remains_profile_metadata() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("acme", "Acme").await.unwrap();

    assert_eq!(db.user_by_email("dana@newcomer.com").await.unwrap(), None);
    let link = db
        .link_or_create_identity(
            TEST_VERIFIER_ID,
            "https://idp",
            "sub-dana",
            Some("dana@newcomer.com"),
            false,
            org_id,
            true,
        )
        .await
        .unwrap()
        .unwrap();
    let new_user = match link {
        IdentityLink::Created(id) => id,
        other => panic!("expected a freshly created user, got {other:?}"),
    };
    // The provider profile exists without claiming the supplied mailbox.
    assert_eq!(db.user_by_email("dana@newcomer.com").await.unwrap(), None);
    assert_eq!(
        db.identity_user(TEST_VERIFIER_ID, "sub-dana")
            .await
            .unwrap(),
        Some(new_user)
    );

    let mailbox_owner = db.find_or_create_user("dana@newcomer.com").await.unwrap();
    assert_ne!(mailbox_owner, new_user);
    assert_eq!(
        db.identity_user(TEST_VERIFIER_ID, "sub-dana")
            .await
            .unwrap(),
        Some(new_user)
    );
}

#[tokio::test]
async fn captured_verified_email_creates_a_mailbox_owner() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("captured", "Captured").await.unwrap();
    db.add_org_domain(org_id, "captured.example").await.unwrap();
    db.verify_org_domain("captured.example").await.unwrap();

    let link = db
        .link_or_create_identity(
            TEST_VERIFIER_ID,
            "https://idp.example",
            "captured-subject",
            Some("user@captured.example"),
            true,
            org_id,
            true,
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        db.user_by_email("user@captured.example").await.unwrap(),
        Some(link.user_id())
    );
}

#[tokio::test]
async fn missing_email_verification_remains_profile_metadata() {
    let (idp_base, idp) = spawn_idp().await;
    *idp.email_verified.lock().unwrap() = None;
    let db = Database::open_in_memory().await.unwrap();
    seed_org(&db, &idp_base, false, true, "{}").await;
    let org_id = db.org_by_slug("acme").await.unwrap().unwrap().id;

    let login = run_flow(&db, &test_http(), "http://hub.example.com", org_id)
        .await
        .unwrap();

    assert!(login.provisioned);
    assert_eq!(db.user_by_email("alice@acme.com").await.unwrap(), None);
}

#[tokio::test]
async fn identical_issuers_remain_bound_to_their_verifiers() {
    let db = Database::open_in_memory().await.unwrap();
    let first_org = db.create_org("first", "First").await.unwrap();
    let second_org = db.create_org("second", "Second").await.unwrap();

    let mut first_config = verifier_config(first_org, "https://idp.example/keys-one");
    let second_config = verifier_config(second_org, "https://idp.example/keys-two");
    db.upsert_idp_config(&first_config).await.unwrap();
    db.upsert_idp_config(&second_config).await.unwrap();

    let first_verifier = aos_hub_model::identity::oidc_verifier_id(&first_config);
    let second_verifier = aos_hub_model::identity::oidc_verifier_id(&second_config);
    assert_ne!(first_verifier, second_verifier);

    let first_user = db
        .link_or_create_identity(
            &first_verifier,
            &first_config.issuer,
            "shared-subject",
            Some("first@example.test"),
            true,
            first_org,
            true,
        )
        .await
        .unwrap()
        .unwrap()
        .user_id();

    let disabled = db
        .link_or_create_identity(
            &second_verifier,
            &second_config.issuer,
            "shared-subject",
            Some("second@example.test"),
            true,
            second_org,
            false,
        )
        .await
        .unwrap();
    assert_eq!(disabled, None);
    assert_eq!(
        db.identity_user(&second_verifier, "shared-subject")
            .await
            .unwrap(),
        None
    );

    first_config.org_id = second_org;
    assert_eq!(
        aos_hub_model::identity::oidc_verifier_id(&first_config),
        first_verifier
    );
    assert_eq!(
        db.identity_user(&first_verifier, "shared-subject")
            .await
            .unwrap(),
        Some(first_user)
    );
}

#[tokio::test]
async fn login_flow_rejects_a_changed_verifier() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("flow-change", "Flow Change").await.unwrap();
    let initial = verifier_config(org_id, "https://idp.example/keys-one");
    db.upsert_idp_config(&initial).await.unwrap();

    let redirect = begin_login(&db, "https://hub.example", org_id, None)
        .await
        .unwrap();
    let state = url::Url::parse(&redirect.url)
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap();

    let changed = verifier_config(org_id, "https://idp.example/keys-two");
    db.upsert_idp_config(&changed).await.unwrap();

    let result = complete_login(
        &db,
        dev_sealer().as_ref(),
        &test_http(),
        "https://hub.example",
        &CallbackParams {
            code: "unused-code".into(),
            state,
        },
    )
    .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn legacy_identity_adoption_requires_one_verifier() {
    let db = Database::open_in_memory().await.unwrap();
    let first_org = db.create_org("legacy-first", "Legacy First").await.unwrap();
    let first_config = verifier_config(first_org, "https://idp.example/keys-one");
    db.upsert_idp_config(&first_config).await.unwrap();
    let first_verifier = aos_hub_model::identity::oidc_verifier_id(&first_config);

    let adopted_user = db.create_user("adopted@example.test", None).await.unwrap();
    db.seed_legacy_oidc_identity(adopted_user, &first_config.issuer, "legacy-one")
        .await
        .unwrap();
    let adopted = db
        .link_or_create_identity(
            &first_verifier,
            &first_config.issuer,
            "legacy-one",
            None,
            false,
            first_org,
            false,
        )
        .await
        .unwrap();
    assert_eq!(adopted, Some(IdentityLink::Existing(adopted_user)));

    let second_org = db
        .create_org("legacy-second", "Legacy Second")
        .await
        .unwrap();
    let second_config = verifier_config(second_org, "https://idp.example/keys-two");
    db.upsert_idp_config(&second_config).await.unwrap();

    let ambiguous_user = db
        .create_user("ambiguous@example.test", None)
        .await
        .unwrap();
    db.seed_legacy_oidc_identity(ambiguous_user, &first_config.issuer, "legacy-ambiguous")
        .await
        .unwrap();
    let ambiguous = db
        .link_or_create_identity(
            &first_verifier,
            &first_config.issuer,
            "legacy-ambiguous",
            None,
            false,
            first_org,
            false,
        )
        .await
        .unwrap();
    assert_eq!(ambiguous, None);
}

fn verifier_config(org_id: i64, jwks_uri: &str) -> IdpConfigRecord {
    IdpConfigRecord {
        org_id,
        issuer: "https://idp.example".into(),
        authorization_endpoint: "https://idp.example/authorize".into(),
        token_endpoint: "https://idp.example/token".into(),
        jwks_uri: jwks_uri.into(),
        client_id: "hub-client".into(),
        client_secret_enc: None,
        scopes: "openid email".into(),
        groups_claim: None,
        role_map_json: "{}".into(),
        allow_jit: true,
        enforce_sso: false,
        default_role: "viewer".into(),
        resource_version: 1,
        incarnation_id: None,
        mutation_plan_id: None,
    }
}
