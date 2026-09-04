//! End-to-end coverage for the in-house WebAuthn relying-party verifier
//! (RFC-0004 passkeys, `attestation: none`).
//!
//! A tiny in-process *software authenticator* (Ed25519 and P-256) plays the
//! browser: it mints a keypair, builds `authenticatorData`/`clientDataJSON`,
//! signs as a real authenticator would, and posts the base64url-encoded result
//! through the **real router** to the `/-/account/passkeys/{begin,finish}` and
//! `/auth/passkey/{begin,finish}` endpoints — so a passkey registered over HTTP
//! can sign a fresh session in over HTTP, exactly as the inline browser script
//! drives it. Negative cases (wrong origin, replayed/forged challenge, bad
//! signature, non-`none` attestation, sign-count rollback) are exercised both
//! directly and, where applicable, through the router.

use std::sync::Arc;

use aos_hub::auth::extract::{mint_csrf_token, AuthState};
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::auth::session::COOKIE_NAME;
use aos_hub::auth::webauthn::{
    self, AssertionResponse, RegistrationResponse, KIND_ASSERTION, TYPE_CREATE, TYPE_GET,
};
use aos_hub::db::{Database, IdpConfigRecord};
use aos_hub::server::{router, AppState};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const TEST_JWT_SECRET: &[u8] = b"webauthn-test-secret-32-byte-key!";
const EXTERNAL_URL: &str = "http://127.0.0.1:8420";
const RP_ID: &str = "127.0.0.1";
const ORIGIN: &str = "http://127.0.0.1:8420";

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
        external_url: EXTERNAL_URL.into(),
        deployment_id: None,
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
        identity_domain_verifier: None,
        route_reservation_keyring: None,
        container_rollout: aos_hub_core::container_rollout::ContainerRollout::all_enabled(),
        release_evidence: None,
    })
}

// -- software authenticator -------------------------------------------------

enum SoftAuthenticator {
    Ed25519 {
        signing: ed25519_dalek::SigningKey,
        cred_id: Vec<u8>,
    },
    P256 {
        signing: p256::ecdsa::SigningKey,
        cred_id: Vec<u8>,
    },
}

impl SoftAuthenticator {
    fn ed25519(cred_id: &[u8]) -> Self {
        SoftAuthenticator::Ed25519 {
            signing: ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]),
            cred_id: cred_id.to_vec(),
        }
    }

    fn p256(cred_id: &[u8]) -> Self {
        let scalar = [
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
            0x2F, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
            0x3E, 0x3F, 0x41, 0x42,
        ];
        SoftAuthenticator::P256 {
            signing: p256::ecdsa::SigningKey::from_bytes((&scalar).into()).unwrap(),
            cred_id: cred_id.to_vec(),
        }
    }

    fn cred_id(&self) -> &[u8] {
        match self {
            SoftAuthenticator::Ed25519 { cred_id, .. }
            | SoftAuthenticator::P256 { cred_id, .. } => cred_id,
        }
    }

    fn cose_public_key(&self) -> Vec<u8> {
        use ciborium::value::{Integer, Value};
        let map = match self {
            SoftAuthenticator::Ed25519 { signing, .. } => {
                let vk = signing.verifying_key();
                vec![
                    (i(1), i(1)),
                    (i(3), i(-8)),
                    (i(-1), i(6)),
                    (
                        Value::Integer(Integer::from(-2)),
                        Value::Bytes(vk.to_bytes().to_vec()),
                    ),
                ]
            }
            SoftAuthenticator::P256 { signing, .. } => {
                let vk = signing.verifying_key();
                let point = vk.to_encoded_point(false);
                vec![
                    (i(1), i(2)),
                    (i(3), i(-7)),
                    (i(-1), i(1)),
                    (
                        Value::Integer(Integer::from(-2)),
                        Value::Bytes(point.x().unwrap().to_vec()),
                    ),
                    (
                        Value::Integer(Integer::from(-3)),
                        Value::Bytes(point.y().unwrap().to_vec()),
                    ),
                ]
            }
        };
        let mut out = Vec::new();
        ciborium::ser::into_writer(&Value::Map(map), &mut out).unwrap();
        out
    }

    fn authenticator_data(&self, sign_count: u32, attested: bool) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(Sha256::digest(RP_ID.as_bytes()).as_slice());
        data.push(if attested { 0x41 } else { 0x01 }); // UP | AT, or UP
        data.extend_from_slice(&sign_count.to_be_bytes());
        if attested {
            data.extend_from_slice(&[0u8; 16]);
            let cid = self.cred_id();
            data.extend_from_slice(&(cid.len() as u16).to_be_bytes());
            data.extend_from_slice(cid);
            data.extend_from_slice(&self.cose_public_key());
        }
        data
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            SoftAuthenticator::Ed25519 { signing, .. } => {
                use ed25519_dalek::Signer as _;
                signing.sign(message).to_bytes().to_vec()
            }
            SoftAuthenticator::P256 { signing, .. } => {
                use p256::ecdsa::signature::Signer as _;
                let sig: p256::ecdsa::Signature = signing.sign(message);
                sig.to_der().as_bytes().to_vec()
            }
        }
    }
}

fn i(n: i64) -> ciborium::value::Value {
    ciborium::value::Value::Integer(ciborium::value::Integer::from(n))
}

fn client_data_json(ty: &str, challenge: &str, origin: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"{ty}","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
    )
    .into_bytes()
}

fn attestation_object(auth_data: &[u8], fmt: &str) -> Vec<u8> {
    use ciborium::value::Value;
    let map = vec![
        (Value::Text("fmt".into()), Value::Text(fmt.into())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (
            Value::Text("authData".into()),
            Value::Bytes(auth_data.to_vec()),
        ),
    ];
    let mut out = Vec::new();
    ciborium::ser::into_writer(&Value::Map(map), &mut out).unwrap();
    out
}

// -- direct verifier round-trips (in-process) -------------------------------

async fn register_direct(
    db: &Database,
    user: i64,
    auth: &SoftAuthenticator,
) -> anyhow::Result<String> {
    let challenge = webauthn::begin_registration(db, user, "u@x.com", RP_ID, "Hub")
        .await?
        .challenge;
    let response = RegistrationResponse {
        client_data_json: client_data_json(TYPE_CREATE, &challenge, ORIGIN),
        attestation_object: attestation_object(&auth.authenticator_data(0, true), "none"),
    };
    webauthn::finish_registration(db, user, RP_ID, ORIGIN, &response, Some("test")).await
}

async fn assert_direct(
    db: &Database,
    auth: &SoftAuthenticator,
    sign_count: u32,
) -> anyhow::Result<i64> {
    let challenge = webauthn::begin_assertion(db, RP_ID).await?.challenge;
    let ad = auth.authenticator_data(sign_count, false);
    let cdj = client_data_json(TYPE_GET, &challenge, ORIGIN);
    let signature = auth.sign(&webauthn::signed_message(&ad, &cdj));
    let response = AssertionResponse {
        credential_id: B64URL.encode(auth.cred_id()),
        client_data_json: cdj,
        authenticator_data: ad,
        signature,
    };
    webauthn::finish_assertion(db, RP_ID, ORIGIN, &response).await
}

#[tokio::test]
async fn ed25519_register_then_assert_direct() {
    let db = Database::open_in_memory().await.unwrap();
    let user = db.create_user("u@x.com", None).await.unwrap();
    let auth = SoftAuthenticator::ed25519(b"ed-1");
    register_direct(&db, user, &auth).await.unwrap();
    assert_eq!(assert_direct(&db, &auth, 1).await.unwrap(), user);
}

#[tokio::test]
async fn es256_register_then_assert_direct() {
    let db = Database::open_in_memory().await.unwrap();
    let user = db.create_user("u@x.com", None).await.unwrap();
    let auth = SoftAuthenticator::p256(b"p-1");
    register_direct(&db, user, &auth).await.unwrap();
    assert_eq!(assert_direct(&db, &auth, 1).await.unwrap(), user);
}

// -- HTTP ceremony round-trip (through the router) --------------------------

struct Resp {
    status: StatusCode,
    set_cookie: Option<String>,
    body: String,
}

async fn send_json(
    app: &axum::Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    json: Option<String>,
    form: Option<String>,
) -> Resp {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "127.0.0.1:8420");
    if let Some(c) = cookie {
        req = req.header(header::COOKIE, c);
    }
    let body = if let Some(j) = json {
        req = req.header(header::CONTENT_TYPE, "application/json");
        Body::from(j)
    } else if let Some(f) = form {
        req = req.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        Body::from(f)
    } else {
        Body::empty()
    };
    let resp = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    Resp {
        status,
        set_cookie,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

async fn login_session(app: &axum::Router, db: &Database, email: &str) -> String {
    let secret = db.create_magic_link(email).await.unwrap();
    let resp = send_json(
        app,
        "GET",
        &format!("/auth/magic?token={secret}"),
        None,
        None,
        None,
    )
    .await;
    let set = resp.set_cookie.expect("magic consume sets a cookie");
    let value = set
        .strip_prefix(&format!("{COOKIE_NAME}="))
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    format!("{COOKIE_NAME}={value}")
}

#[tokio::test]
async fn http_register_then_login_ed25519() {
    http_register_then_login(SoftAuthenticator::ed25519(b"http-ed")).await;
}

#[tokio::test]
async fn http_register_then_login_es256() {
    http_register_then_login(SoftAuthenticator::p256(b"http-p256")).await;
}

/// Register a passkey through the session-authed HTTP endpoints, then sign a
/// fresh, cookie-less session in through the pre-auth assertion endpoints.
async fn http_register_then_login(auth: SoftAuthenticator) {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let user = db.create_user("u@x.com", None).await.unwrap();
    let state = app_state(Arc::clone(&db)).await;
    let app = router(state).await;

    let cookie = login_session(&app, &db, "u@x.com").await;
    let session_secret = cookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap();
    let csrf = mint_csrf_token(session_secret);

    // 1. Registration: begin (session + CSRF), run the authenticator, finish.
    let begin = send_json(
        &app,
        "POST",
        "/-/account/passkeys/begin",
        Some(&cookie),
        None,
        Some(format!("csrf={csrf}")),
    )
    .await;
    assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
    let opts: serde_json::Value = serde_json::from_str(&begin.body).unwrap();
    let challenge = opts["challenge"].as_str().unwrap();

    let ad = auth.authenticator_data(0, true);
    let cdj = client_data_json(TYPE_CREATE, challenge, ORIGIN);
    let finish_body = serde_json::json!({
        "csrf": csrf,
        "label": "laptop",
        "client_data_json": B64URL.encode(&cdj),
        "attestation_object": B64URL.encode(attestation_object(&ad, "none")),
    });
    let finish = send_json(
        &app,
        "POST",
        "/-/account/passkeys/finish",
        Some(&cookie),
        Some(finish_body.to_string()),
        None,
    )
    .await;
    assert_eq!(finish.status, StatusCode::OK, "{}", finish.body);

    assert_eq!(db.list_user_credentials(user).await.unwrap().len(), 1);

    // 2. Login with the passkey (no cookie — usernameless assertion).
    let lbegin = send_json(&app, "POST", "/auth/passkey/begin", None, None, None).await;
    assert_eq!(lbegin.status, StatusCode::OK, "{}", lbegin.body);
    let lopts: serde_json::Value = serde_json::from_str(&lbegin.body).unwrap();
    let lchallenge = lopts["challenge"].as_str().unwrap();

    let lad = auth.authenticator_data(1, false);
    let lcdj = client_data_json(TYPE_GET, lchallenge, ORIGIN);
    let signature = auth.sign(&webauthn::signed_message(&lad, &lcdj));
    let login_body = serde_json::json!({
        "credential_id": B64URL.encode(auth.cred_id()),
        "client_data_json": B64URL.encode(&lcdj),
        "authenticator_data": B64URL.encode(&lad),
        "signature": B64URL.encode(&signature),
    });
    let lfinish = send_json(
        &app,
        "POST",
        "/auth/passkey/finish",
        None,
        Some(login_body.to_string()),
        None,
    )
    .await;
    assert_eq!(lfinish.status, StatusCode::OK, "{}", lfinish.body);
    let set = lfinish.set_cookie.expect("assertion sets a session cookie");
    assert!(set.starts_with(&format!("{COOKIE_NAME}=")), "{set}");

    // The minted cookie authenticates as the registered user.
    let value = set
        .strip_prefix(&format!("{COOKIE_NAME}="))
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let resolved = db.validate_session(value).await.unwrap().unwrap();
    assert_eq!(resolved.user_id, user);
}

/// A passkey is a local credential, so it must not bypass `enforce_sso` (H-4).
/// When the asserting user belongs to an SSO-enforced org, the HTTP login finish
/// refuses to mint a session: it answers `403` with a `{ "redirect": … }` body
/// steering the script to the org's IdP, and sets no cookie — even though the
/// assertion itself is cryptographically valid.
#[tokio::test]
async fn enforced_user_passkey_login_refused_to_sso() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let user = db.create_user("dev@acme.com", None).await.unwrap();
    let auth = SoftAuthenticator::ed25519(b"enforced");
    register_direct(&db, user, &auth).await.unwrap();

    // Turn on SSO enforcement for the user's verified email domain.
    let org_id = db.create_org("acme", "Acme").await.unwrap();
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
        enforce_sso: true,
        default_role: "viewer".into(),
        resource_version: 1,
        incarnation_id: None,
        mutation_plan_id: None,
    })
    .await
    .unwrap();
    db.add_org_domain(org_id, "acme.com").await.unwrap();
    db.verify_org_domain("acme.com").await.unwrap();

    let app = router(app_state(Arc::clone(&db)).await).await;

    // A genuine, valid assertion still gets refused.
    let lbegin = send_json(&app, "POST", "/auth/passkey/begin", None, None, None).await;
    let lopts: serde_json::Value = serde_json::from_str(&lbegin.body).unwrap();
    let lchallenge = lopts["challenge"].as_str().unwrap();
    let lad = auth.authenticator_data(1, false);
    let lcdj = client_data_json(TYPE_GET, lchallenge, ORIGIN);
    let signature = auth.sign(&webauthn::signed_message(&lad, &lcdj));
    let login_body = serde_json::json!({
        "credential_id": B64URL.encode(auth.cred_id()),
        "client_data_json": B64URL.encode(&lcdj),
        "authenticator_data": B64URL.encode(&lad),
        "signature": B64URL.encode(&signature),
    });
    let lfinish = send_json(
        &app,
        "POST",
        "/auth/passkey/finish",
        None,
        Some(login_body.to_string()),
        None,
    )
    .await;
    assert_eq!(lfinish.status, StatusCode::FORBIDDEN, "{}", lfinish.body);
    assert!(
        lfinish.set_cookie.is_none(),
        "no local session for an SSO-enforced user"
    );
    let body: serde_json::Value = serde_json::from_str(&lfinish.body).unwrap();
    assert_eq!(
        body["redirect"].as_str(),
        Some("/auth/oidc/start?org=acme"),
        "the script is steered to the org's IdP"
    );
}

// -- negative cases ---------------------------------------------------------

#[tokio::test]
async fn wrong_origin_rejected() {
    let db = Database::open_in_memory().await.unwrap();
    let user = db.create_user("u@x.com", None).await.unwrap();
    let auth = SoftAuthenticator::ed25519(b"neg-origin");
    register_direct(&db, user, &auth).await.unwrap();
    let challenge = webauthn::begin_assertion(&db, RP_ID)
        .await
        .unwrap()
        .challenge;
    let ad = auth.authenticator_data(1, false);
    let cdj = client_data_json(TYPE_GET, &challenge, "http://evil.example.com");
    let signature = auth.sign(&webauthn::signed_message(&ad, &cdj));
    let response = AssertionResponse {
        credential_id: B64URL.encode(auth.cred_id()),
        client_data_json: cdj,
        authenticator_data: ad,
        signature,
    };
    assert!(webauthn::finish_assertion(&db, RP_ID, ORIGIN, &response)
        .await
        .is_err());
}

#[tokio::test]
async fn forged_challenge_rejected() {
    let db = Database::open_in_memory().await.unwrap();
    let user = db.create_user("u@x.com", None).await.unwrap();
    let auth = SoftAuthenticator::ed25519(b"neg-chal");
    register_direct(&db, user, &auth).await.unwrap();
    // Stage a real challenge, but present one that was never staged.
    let _ = webauthn::begin_assertion(&db, RP_ID).await.unwrap();
    let ad = auth.authenticator_data(1, false);
    let cdj = client_data_json(TYPE_GET, "forged-never-staged", ORIGIN);
    let signature = auth.sign(&webauthn::signed_message(&ad, &cdj));
    let response = AssertionResponse {
        credential_id: B64URL.encode(auth.cred_id()),
        client_data_json: cdj,
        authenticator_data: ad,
        signature,
    };
    assert!(webauthn::finish_assertion(&db, RP_ID, ORIGIN, &response)
        .await
        .is_err());
}

#[tokio::test]
async fn bad_signature_rejected() {
    let db = Database::open_in_memory().await.unwrap();
    let user = db.create_user("u@x.com", None).await.unwrap();
    let auth = SoftAuthenticator::p256(b"neg-sig");
    register_direct(&db, user, &auth).await.unwrap();
    let challenge = webauthn::begin_assertion(&db, RP_ID)
        .await
        .unwrap()
        .challenge;
    let ad = auth.authenticator_data(1, false);
    let cdj = client_data_json(TYPE_GET, &challenge, ORIGIN);
    let mut signature = auth.sign(&webauthn::signed_message(&ad, &cdj));
    signature[0] ^= 0xFF;
    let response = AssertionResponse {
        credential_id: B64URL.encode(auth.cred_id()),
        client_data_json: cdj,
        authenticator_data: ad,
        signature,
    };
    assert!(webauthn::finish_assertion(&db, RP_ID, ORIGIN, &response)
        .await
        .is_err());
}

#[tokio::test]
async fn non_none_attestation_rejected() {
    let db = Database::open_in_memory().await.unwrap();
    let user = db.create_user("u@x.com", None).await.unwrap();
    let auth = SoftAuthenticator::ed25519(b"neg-att");
    let challenge = webauthn::begin_registration(&db, user, "u@x.com", RP_ID, "Hub")
        .await
        .unwrap()
        .challenge;
    let response = RegistrationResponse {
        client_data_json: client_data_json(TYPE_CREATE, &challenge, ORIGIN),
        attestation_object: attestation_object(&auth.authenticator_data(0, true), "packed"),
    };
    assert!(
        webauthn::finish_registration(&db, user, RP_ID, ORIGIN, &response, None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn sign_count_rollback_rejected() {
    let db = Database::open_in_memory().await.unwrap();
    let user = db.create_user("u@x.com", None).await.unwrap();
    let auth = SoftAuthenticator::ed25519(b"neg-count");
    register_direct(&db, user, &auth).await.unwrap();
    assert_direct(&db, &auth, 9).await.unwrap();
    assert!(assert_direct(&db, &auth, 4).await.is_err());
}

#[tokio::test]
async fn challenge_single_use_consumed() {
    let db = Database::open_in_memory().await.unwrap();
    db.create_webauthn_challenge("xyz", None, KIND_ASSERTION, 300)
        .await
        .unwrap();
    assert!(db
        .take_webauthn_challenge("xyz", KIND_ASSERTION)
        .await
        .unwrap()
        .is_some());
    assert!(db
        .take_webauthn_challenge("xyz", KIND_ASSERTION)
        .await
        .unwrap()
        .is_none());
}
