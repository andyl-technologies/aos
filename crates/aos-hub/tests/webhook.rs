//! Phase-4 integration coverage: outbound webhooks.
//!
//! Exercises the delivery path against a real in-test receiver (2xx →
//! delivered, 500 → retry scheduled with the attempt incremented), the
//! dispatch fan-out (only subscribed, active hooks enqueue), the
//! `WebhookService` ConnectRPC create/list/delete authz, and the Prometheus
//! `/metrics` rendering.

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use aos_hub::auth::extract::AuthState;
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::db::{Database, DueDelivery, TokenAuth};
use aos_hub::domain::{Permission, Principal, Scope};
use aos_hub::server::{router, AppState};
use aos_hub::webhook::{self, WebhookEvent};
use aos_hub_core::secret_version::{ResolvedSecretVersion, SecretVersionResolver};
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::routing::post;
use sha2::{Digest as _, Sha256};
use tower::ServiceExt;

/// Deterministic HS256 key so tests can mint matching JWTs.
const TEST_JWT_SECRET: &[u8] = b"webhook-test-secret-32byte-key!!";
const RPC_SECRET_REF: &str = "vault://acme/webhooks/ci/v1";
const RPC_SECRET_VALUE: &str = "must-never-enter-hub-persistence";

/// Serializes tests that read or mutate `AOS_HUB_ALLOW_LOCAL_REMOTES`.
///
/// `create_webhook` and `deliver_one` now run the SSRF guard
/// ([`aos_hub::fetch::is_safe_remote_url`]), which consults this
/// process-global env var. A test needing loopback *allowed* and one needing it
/// *rejected* must not interleave, so each takes [`remote_guard`] for its body.
static REMOTE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
const TEST_FINGERPRINT: &str = "043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89";

struct TestSecretResolver(std::collections::BTreeMap<String, Vec<u8>>);

#[async_trait::async_trait]
impl SecretVersionResolver for TestSecretResolver {
    async fn resolve(&self, version_ref: &str) -> anyhow::Result<ResolvedSecretVersion> {
        self.0
            .get(version_ref)
            .cloned()
            .map(ResolvedSecretVersion::from_bytes)
            .ok_or_else(|| anyhow::anyhow!("missing test secret"))
    }
}

fn test_resolver(entries: impl IntoIterator<Item = (String, String)>) -> TestSecretResolver {
    TestSecretResolver(
        entries
            .into_iter()
            .map(|(version_ref, value)| (version_ref, value.into_bytes()))
            .collect(),
    )
}

fn test_credential(secret: &str) -> (Arc<dyn SecretVersionResolver>, String, String) {
    let secret_version_ref = "native://acme/webhook/v1".to_string();
    let resolver: Arc<dyn SecretVersionResolver> = Arc::new(test_resolver([(
        secret_version_ref.clone(),
        secret.to_string(),
    )]));
    let fingerprint = hex::encode(Sha256::digest(secret.as_bytes()));
    (resolver, secret_version_ref, fingerprint)
}

/// A held [`REMOTE_ENV_LOCK`] restoring the prior env value on drop.
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

/// Take the env lock and set `AOS_HUB_ALLOW_LOCAL_REMOTES` to `allow`; the prior
/// value is restored on drop. `allow = true` lets a test use loopback receivers
/// and single-label hosts; `allow = false` enforces the SSRF guard.
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

/// A request captured by the in-test webhook receiver.
#[derive(Clone)]
struct Captured {
    event: String,
    signature: String,
    delivery_id: String,
    body: Vec<u8>,
}

/// Shared receiver state: captured requests plus a configurable status code.
#[derive(Clone)]
struct Receiver {
    captured: Arc<Mutex<Vec<Captured>>>,
    status: Arc<AtomicU32>,
}

async fn receive(
    State(rx): State<Receiver>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> StatusCode {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    rx.captured.lock().unwrap().push(Captured {
        event: header("X-AOS-Event"),
        signature: header("X-AOS-Signature"),
        delivery_id: header("X-AOS-Delivery-ID"),
        body: body.to_vec(),
    });
    StatusCode::from_u16(rx.status.load(Ordering::SeqCst) as u16).unwrap()
}

/// Spawn a receiver on an ephemeral port; returns its URL and shared state.
async fn spawn_receiver(initial_status: u16) -> (String, Receiver) {
    let rx = Receiver {
        captured: Arc::new(Mutex::new(Vec::new())),
        status: Arc::new(AtomicU32::new(initial_status as u32)),
    };
    let app = axum::Router::new()
        .route("/hook", post(receive))
        .with_state(rx.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, rx)
}

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
        deployment_id: None,
        ratelimit: auth.ratelimit.clone(),
        trusted_proxy: false,
        auth,
        leases: std::sync::Arc::new(aos_hub_core::lease::InMemoryLease::new()),
        sealer: aos_hub::auth::oidc::dev_sealer(),
        secret_versions: Arc::new(test_resolver([(
            RPC_SECRET_REF.to_string(),
            RPC_SECRET_VALUE.to_string(),
        )])),
        http: aos_hub::fetch::hardened_client().await,
        image_snapshots: None,
        mailer: Arc::new(aos_hub::auth::magic::LogMailer),
        dev: false,
        delivery_attestation_verifier: None,
        domain_probe_terminator: None,
        identity_domain_verifier: None,
        route_reservation_keyring: None,
        container_rollout: aos_hub_core::container_rollout::ContainerRollout::all_enabled(),
        release_evidence: None,
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

async fn planned_rpc(
    app: &axum::Router,
    plan_method: &str,
    apply_method: &str,
    mut request: serde_json::Value,
    auth: Option<&str>,
    key: &str,
) -> (StatusCode, serde_json::Value) {
    request["idempotencyKey"] = serde_json::Value::String(format!("{key}-plan"));
    let (status, plan) = rpc(app, plan_method, request, auth).await;
    if status != StatusCode::OK {
        return (status, plan);
    }
    rpc(
        app,
        apply_method,
        serde_json::json!({
            "planId": plan["plan"]["planId"],
            "confirmationHash": plan["plan"]["confirmationHash"],
            "idempotencyKey": format!("{key}-apply"),
        }),
        auth,
    )
    .await
}

// -- dispatch ---------------------------------------------------------------

#[tokio::test]
async fn dispatch_enqueues_only_for_subscribed_active_hooks() {
    let _remotes = remote_guard(true);
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    db.create_managed_registry(org, "", "cdn", "public", &[], false)
        .await
        .unwrap();

    // A hook subscribed to index.completed, one to channel.advanced, one to
    // all events, and a disabled one.
    let h_index = db
        .seed_webhook_for_test(
            org,
            "http://a/",
            "native://acme/a/v1",
            TEST_FINGERPRINT,
            &["index.completed".into()],
        )
        .await
        .unwrap();
    let _h_channel = db
        .seed_webhook_for_test(
            org,
            "http://b/",
            "native://acme/b/v1",
            TEST_FINGERPRINT,
            &["channel.advanced".into()],
        )
        .await
        .unwrap();
    let h_all = db
        .seed_webhook_for_test(
            org,
            "http://c/",
            "native://acme/c/v1",
            TEST_FINGERPRINT,
            &[],
        )
        .await
        .unwrap();
    let h_disabled = db
        .seed_webhook_for_test(
            org,
            "http://d/",
            "native://acme/d/v1",
            TEST_FINGERPRINT,
            &["index.completed".into()],
        )
        .await
        .unwrap();
    db.seed_set_webhook_active_for_test(h_disabled, false)
        .await
        .unwrap();

    let event = WebhookEvent::IndexCompleted {
        registry: "acme/cdn".into(),
        commit: "ab".repeat(32),
        packages: 1,
        releases: 0,
        channels: 0,
        incremental: false,
        at: 1,
    };
    let enqueued = webhook::dispatch(&db, org, &event).await.unwrap();
    assert_eq!(enqueued, 1, "one semantic event entered the outbox");
    assert_eq!(
        webhook::dispatch(&db, org, &event).await.unwrap(),
        0,
        "a producer retry converges on the same outbox identity"
    );

    // Materialization fans out to h_index (subscribed) + h_all (all events),
    // but not the channel-only or disabled hooks.

    let due = db.claim_due_deliveries(i64::MAX, 100, 30).await.unwrap();
    let hook_ids: Vec<i64> = due.iter().map(|d| d.webhook_id).collect();
    assert!(hook_ids.contains(&h_index));
    assert!(hook_ids.contains(&h_all));
    assert_eq!(due.len(), 2);
}

// -- delivery ---------------------------------------------------------------

#[tokio::test]
async fn deliver_one_marks_delivered_and_signs_body_on_2xx() {
    let _remotes = remote_guard(true);
    let (url, rx) = spawn_receiver(200).await;
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    let secret = "shhh";
    let (secrets, secret_version_ref, fingerprint) = test_credential(secret);
    let hook = db
        .seed_webhook_for_test(
            org,
            &url,
            &secret_version_ref,
            &fingerprint,
            &["index.completed".into()],
        )
        .await
        .unwrap();
    let payload = r#"{"type":"index.completed","registry":"acme/cdn"}"#;
    db.seed_delivery_for_test(hook, "index.completed", payload)
        .await
        .unwrap();

    let due = db.claim_due_deliveries(i64::MAX, 100, 30).await.unwrap();
    assert_eq!(due.len(), 1);
    let http = aos_hub::fetch::hardened_client().await;
    let ok = webhook::deliver_one(&http, &db, secrets.as_ref(), &due[0])
        .await
        .unwrap();
    assert!(ok, "2xx should mark delivered");

    // The receiver saw the event header and a valid signature over the body.
    let captured = rx.captured.lock().unwrap().clone();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].event, "index.completed");
    assert_eq!(captured[0].delivery_id, due[0].delivery_id);
    assert_eq!(captured[0].body, payload.as_bytes());
    assert_eq!(
        captured[0].signature,
        webhook::sign_body(secret, payload.as_bytes()),
        "X-AOS-Signature is HMAC-SHA256 of the raw body under the secret"
    );

    // The delivery is now delivered and no longer due.
    let (pending, delivered, failed) = db.delivery_status_counts().await.unwrap();
    assert_eq!((pending, delivered, failed), (0, 1, 0));
    assert!(db
        .claim_due_deliveries(i64::MAX, 100, 30)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn deliver_one_fails_closed_before_post_when_provider_value_drifts() {
    let _remotes = remote_guard(true);
    let (url, rx) = spawn_receiver(200).await;
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    let (secrets, secret_version_ref, _) = test_credential("changed-value");
    let hook = db
        .seed_webhook_for_test(org, &url, &secret_version_ref, TEST_FINGERPRINT, &[])
        .await
        .unwrap();
    db.seed_delivery_for_test(hook, "index.completed", "{}")
        .await
        .unwrap();

    let due = db.claim_due_deliveries(i64::MAX, 100, 30).await.unwrap();
    let http = aos_hub::fetch::hardened_client().await;
    let ok = webhook::deliver_one(&http, &db, secrets.as_ref(), &due[0])
        .await
        .unwrap();
    assert!(!ok);
    assert!(rx.captured.lock().unwrap().is_empty());
    assert_eq!(db.delivery_status_counts().await.unwrap(), (0, 0, 1));
}

#[tokio::test]
async fn unavailable_secret_provider_consumes_retry_budget_without_posting() {
    let _remotes = remote_guard(true);
    let (url, rx) = spawn_receiver(200).await;
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    let (_, secret_version_ref, fingerprint) = test_credential("expected-value");
    let hook = db
        .seed_webhook_for_test(org, &url, &secret_version_ref, &fingerprint, &[])
        .await
        .unwrap();
    db.seed_delivery_for_test(hook, "index.completed", "{}")
        .await
        .unwrap();

    let due = db.claim_due_deliveries(i64::MAX, 100, 30).await.unwrap();
    let unavailable = test_resolver(std::iter::empty::<(String, String)>());
    let http = aos_hub::fetch::hardened_client().await;
    assert!(!webhook::deliver_one(&http, &db, &unavailable, &due[0])
        .await
        .unwrap());
    assert!(rx.captured.lock().unwrap().is_empty());
    assert_eq!(db.delivery_status_counts().await.unwrap(), (1, 0, 0));
    let retry = db
        .claim_delivery_by_stable_id(&due[0].delivery_id, i64::MAX - 100, 30)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retry.attempts, 1);
}

#[tokio::test]
async fn deliver_one_schedules_retry_with_incremented_attempts_on_500() {
    let _remotes = remote_guard(true);
    let (url, rx) = spawn_receiver(500).await;
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    let (secrets, secret_version_ref, fingerprint) = test_credential("s");
    let hook = db
        .seed_webhook_for_test(org, &url, &secret_version_ref, &fingerprint, &[])
        .await
        .unwrap();
    db.seed_delivery_for_test(hook, "index.completed", "{}")
        .await
        .unwrap();

    let due = db.claim_due_deliveries(i64::MAX, 100, 30).await.unwrap();
    let http = aos_hub::fetch::hardened_client().await;
    let ok = webhook::deliver_one(&http, &db, secrets.as_ref(), &due[0])
        .await
        .unwrap();
    assert!(!ok, "500 must not mark delivered");
    assert_eq!(rx.captured.lock().unwrap().len(), 1);

    // Still pending (not failed yet), attempts incremented, and scheduled into
    // the future so it is not immediately due again.
    let (pending, delivered, failed) = db.delivery_status_counts().await.unwrap();
    assert_eq!((pending, delivered, failed), (1, 0, 0));
    assert!(
        db.claim_due_deliveries(now(), 100, 30)
            .await
            .unwrap()
            .is_empty(),
        "a backed-off retry is not due now"
    );
    assert!(
        db.claim_delivery_by_stable_id(&due[0].delivery_id, now(), 30)
            .await
            .unwrap()
            .is_none(),
        "a queued stable-id job cannot bypass retry backoff"
    );
    // Far in the future it is due again, with attempts == 1.
    let later: Vec<DueDelivery> = db
        .claim_due_deliveries(now() + 100_000, 100, 30)
        .await
        .unwrap();
    assert_eq!(later.len(), 1);
    assert_eq!(later[0].attempts, 1);
    assert_eq!(later[0].delivery_id, due[0].delivery_id);
}

#[tokio::test]
async fn deliveries_fail_after_the_attempt_cap() {
    let _remotes = remote_guard(true);
    let (url, _rx) = spawn_receiver(500).await;
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    let (secrets, secret_version_ref, fingerprint) = test_credential("s");
    let hook = db
        .seed_webhook_for_test(org, &url, &secret_version_ref, &fingerprint, &[])
        .await
        .unwrap();
    db.seed_delivery_for_test(hook, "index.completed", "{}")
        .await
        .unwrap();
    let http = aos_hub::fetch::hardened_client().await;

    // Hammer the delivery past the attempt cap (querying with a far-future
    // `now` so the backoff never hides it).
    for _ in 0..(webhook::MAX_ATTEMPTS + 1) {
        let due = db.claim_due_deliveries(i64::MAX, 100, 30).await.unwrap();
        if due.is_empty() {
            break;
        }
        webhook::deliver_one(&http, &db, secrets.as_ref(), &due[0])
            .await
            .unwrap();
    }
    let (pending, _delivered, failed) = db.delivery_status_counts().await.unwrap();
    assert_eq!(pending, 0, "no longer pending after the cap");
    assert_eq!(failed, 1, "marked failed after the attempt cap");
}

#[tokio::test]
async fn deliver_one_rejects_ssrf_url_without_posting() {
    // Defense in depth: a delivery whose URL fails the SSRF guard (e.g. a row
    // written before the guard existed, or a host that now resolves internally)
    // must be marked failed and never POSTed (finding H4).
    //
    // Stand up a real receiver and enqueue a real delivery row under the local
    // hatch, then construct a DueDelivery pointing at the cloud-metadata address
    // with the guard enforced and confirm deliver_one refuses to POST.
    let (url, rx) = spawn_receiver(200).await;
    let (delivery, db) = {
        let _remotes = remote_guard(true);
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        let (_secrets, secret_version_ref, fingerprint) = test_credential("s");
        let hook = db
            .seed_webhook_for_test(org, &url, &secret_version_ref, &fingerprint, &[])
            .await
            .unwrap();
        db.seed_delivery_for_test(hook, "index.completed", "{}")
            .await
            .unwrap();
        let mut due = db.claim_due_deliveries(i64::MAX, 100, 30).await.unwrap();
        assert_eq!(due.len(), 1);
        // Repoint the queued row at an internal address, as a stale/poisoned row
        // would be; the row id stays valid so mark_delivery can update it.
        let mut delivery = due.remove(0);
        delivery.url = "http://169.254.169.254/latest/meta-data/".to_string();
        (delivery, db)
    };

    let _remotes = remote_guard(false);
    let http = aos_hub::fetch::hardened_client().await;
    let (secrets, _, _) = test_credential("s");
    let ok = webhook::deliver_one(&http, &db, secrets.as_ref(), &delivery)
        .await
        .unwrap();
    assert!(
        !ok,
        "an SSRF-guarded delivery must not be reported delivered"
    );
    // No POST reached the receiver.
    assert!(
        rx.captured.lock().unwrap().is_empty(),
        "deliver_one must not POST to a guard-rejected URL"
    );
    // It is marked failed (not retried): the rejection is structural, so retries
    // would never pass the guard.
    let (pending, delivered, failed) = db.delivery_status_counts().await.unwrap();
    assert_eq!((pending, delivered, failed), (0, 0, 1));
}

#[tokio::test]
async fn delivery_claims_fence_duplicates_and_recover_after_crash() {
    let _remotes = remote_guard(true);
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("claim-test", "Claim Test").await.unwrap();
    let (secrets, secret_ref, fingerprint) = test_credential("claim-secret");
    drop(secrets);
    let hook = db
        .seed_webhook_for_test(
            org,
            "https://hooks.example.test/aos",
            &secret_ref,
            &fingerprint,
            &[],
        )
        .await
        .unwrap();
    db.seed_delivery_for_test(hook, "index.completed", "{}")
        .await
        .unwrap();

    let claim_at = i64::MAX - 100;
    let first = db.claim_due_deliveries(claim_at, 1, 30).await.unwrap();
    assert_eq!(first.len(), 1);
    assert!(db
        .claim_due_deliveries(claim_at + 1, 1, 30)
        .await
        .unwrap()
        .is_empty());

    let recovered = db.claim_due_deliveries(claim_at + 31, 1, 30).await.unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].delivery_id, first[0].delivery_id);
    assert_ne!(recovered[0].claim_token, first[0].claim_token);
    assert!(db
        .mark_delivery(
            first[0].id,
            &first[0].claim_token,
            "delivered",
            Some(200),
            1,
            None,
        )
        .await
        .is_err());
    db.mark_delivery(
        recovered[0].id,
        &recovered[0].claim_token,
        "delivered",
        Some(200),
        1,
        None,
    )
    .await
    .unwrap();
    assert!(db
        .claim_delivery_by_stable_id(&recovered[0].delivery_id, 2_000_000, 30)
        .await
        .unwrap()
        .is_none());
}

// -- RPC create/list/delete authz -------------------------------------------

#[tokio::test]
async fn webhook_rpc_create_list_delete_with_authz() {
    let _remotes = remote_guard(true);
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;

    // An admin (members.manage on acme) may create.
    let org_scope = common::org_scope(&db, "acme").await;
    let admin_id = db
        .create_user("webhook-admin@acme.test", None)
        .await
        .unwrap();
    let admin = bearer(
        Principal::user(admin_id),
        &org_scope,
        &[Permission::MembersManage],
    );
    db.grant_membership("user", admin_id, &org_scope, "admin")
        .await
        .unwrap();

    for (secret_version_ref, credential_fingerprint) in [
        (
            "vault://acme/webhooks/missing/v1",
            "2117783d3b65799d40a3a830a3342bfd88658a71d70b2af30324b73cfc9f6335",
        ),
        (
            RPC_SECRET_REF,
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
    ] {
        let (status, body) = rpc(
            &app,
            "WebhookService/PlanCreateWebhook",
            serde_json::json!({
                "orgSlug": "acme",
                "url": "https://ci.acme/hook",
                "events": ["index.completed"],
                "secretVersionRef": secret_version_ref,
                "credentialFingerprint": credential_fingerprint,
                "idempotencyKey": format!("rejected-{secret_version_ref}"),
            }),
            Some(&admin),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["code"], "failed_precondition");
    }

    let (status, plan_body) = rpc(
        &app,
        "WebhookService/PlanCreateWebhook",
        serde_json::json!({
            "orgSlug": "acme",
            "url": "https://ci.acme/hook",
            "events": ["index.completed"],
            "secretVersionRef": RPC_SECRET_REF,
            "credentialFingerprint": "2117783d3b65799d40a3a830a3342bfd88658a71d70b2af30324b73cfc9f6335",
            "idempotencyKey": "create-hook-plan",
        }),
        Some(&admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admin plan: {plan_body}");
    let plan_id = plan_body["plan"]["planId"].as_str().unwrap().to_string();
    let persisted_plan = db.topology_plan(&plan_id).await.unwrap().unwrap();
    for persisted in [
        persisted_plan.input_versions_json.as_str(),
        persisted_plan.effects_json.as_str(),
        persisted_plan.warnings_json.as_str(),
    ] {
        assert!(!persisted.contains(RPC_SECRET_VALUE));
    }
    let (status, body) = rpc(
        &app,
        "WebhookService/CreateWebhook",
        serde_json::json!({
            "planId": plan_id,
            "confirmationHash": plan_body["plan"]["confirmationHash"],
            "idempotencyKey": "create-hook-apply",
        }),
        Some(&admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admin create: {body}");
    assert!(
        body.get("secret").is_none(),
        "plaintext secret leaked: {body}"
    );
    // The Connect-JSON body shape encodes int64 as a native JSON number
    // (camelCase names, native scalars — not canonical proto3 int64-as-string).
    let id = json_i64(&body["webhook"]["id"]);

    // List shows the hook but never its secret.
    let (status, body) = rpc(
        &app,
        "WebhookService/ListWebhooks",
        serde_json::json!({ "orgSlug": "acme" }),
        Some(&admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let hooks = body["webhooks"].as_array().unwrap();
    assert_eq!(hooks.len(), 1);
    assert!(hooks[0].get("secret").is_none() || hooks[0]["secret"].is_null());
    assert_eq!(hooks[0]["secretVersionRef"], RPC_SECRET_REF);
    let persisted_plan = db.topology_plan(&plan_id).await.unwrap().unwrap();
    assert!(!persisted_plan
        .apply_result_json
        .unwrap()
        .contains(RPC_SECRET_VALUE));
    for revision in db.list_revisions(&plan_id).await.unwrap() {
        assert!(!revision
            .old_json
            .as_deref()
            .unwrap_or_default()
            .contains(RPC_SECRET_VALUE));
        assert!(!revision
            .new_json
            .as_deref()
            .unwrap_or_default()
            .contains(RPC_SECRET_VALUE));
    }
    for audit in db.list_audit(&org_scope).await.unwrap() {
        assert!(!audit
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains(RPC_SECRET_VALUE));
    }

    // A non-admin (only read) is denied create.
    let viewer_id = db
        .create_user("webhook-viewer@acme.test", None)
        .await
        .unwrap();
    let viewer = bearer(Principal::user(viewer_id), &org_scope, &[Permission::Read]);
    db.grant_membership("user", viewer_id, &org_scope, "viewer")
        .await
        .unwrap();
    let (status, _body) = rpc(
        &app,
        "WebhookService/PlanCreateWebhook",
        serde_json::json!({
            "orgSlug": "acme",
            "url": "https://x/",
            "secretVersionRef": "vault://acme/webhooks/x/v1"
        }),
        Some(&viewer),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer cannot create webhooks"
    );

    // The admin deletes it.
    let version = body["webhooks"][0]["resourceVersion"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = planned_rpc(
        &app,
        "WebhookService/PlanDeleteWebhook",
        "WebhookService/DeleteWebhook",
        serde_json::json!({ "id": id, "expectedResourceVersion": version }),
        Some(&admin),
        "delete-hook",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["deleted"], true);
    assert!(db.list_webhooks(1).await.unwrap().is_empty());
}

// -- metrics ----------------------------------------------------------------

#[tokio::test]
async fn metrics_renders_counters() {
    let _remotes = remote_guard(true);
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    // A queued (pending) delivery so the gauge is non-zero.
    let hook = db
        .seed_webhook_for_test(
            org,
            "http://x/",
            "native://acme/x/v1",
            TEST_FINGERPRINT,
            &[],
        )
        .await
        .unwrap();
    db.seed_delivery_for_test(hook, "index.completed", "{}")
        .await
        .unwrap();
    // A managed cache exists, but a loose logical surface object is not part of
    // the normalized, published cache inventory counted by usage metrics.
    db.create_binary_cache(Some(org), "acme-cache", "Acme", "public", 40, "zstd", true)
        .await
        .unwrap();
    let app = router(app_state(db).await).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .header(header::HOST, "127.0.0.1:8420")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();

    assert!(text.contains("# TYPE aos_hub_registries_total gauge"));
    assert!(text.contains("aos_hub_registries_total 0"));
    assert!(text.contains("aos_hub_registries_by_state{state=\"fresh\"} 0"));
    assert!(text.contains("aos_hub_webhook_deliveries{status=\"pending\"} 1"));
    assert!(text.contains("aos_hub_caches_total 1"));
    assert!(text.contains("aos_hub_cache_objects_total 0"));
    assert!(text.contains("aos_hub_cache_bytes_total 0"));
    assert!(text.contains("aos_hub_cache_gc_runs{status=\"ok\"} 0"));
    assert!(text.contains("aos_hub_cache_gc_freed_bytes 0"));
    assert!(text.contains("aos_hub_oci_rollout_enabled{capability=\"pull\"} 1"));
    assert!(text.contains("aos_hub_oci_gc_runs{state=\"planned\"} 0"));
    assert!(text.contains("aos_hub_oci_gc_bytes{state=\"finalized\"} 0"));
    assert!(text.contains("aos_hub_oci_gc_failed_actions 0"));
    assert!(text.contains("aos_hub_oci_gc_stale_inventories 0"));
    assert!(text.contains("aos_hub_oci_catalog_bytes{kind=\"logical\"} 0"));
    assert!(text.contains("aos_hub_oci_catalog_bytes{kind=\"reused\"} 0"));
    assert!(text.contains("aos_hub_oci_reuse_ratio 0.000000"));
    assert!(text.contains("aos_hub_oci_provider_inventory_bytes 0"));
    assert!(text.contains("aos_hub_oci_uploads{state=\"expired_nonterminal\"} 0"));
    assert!(text.contains("aos_hub_oci_publications{state=\"stuck\"} 0"));
    assert!(text.contains("aos_hub_oci_publication_ready_latency_seconds_count 0"));
    assert!(text.contains("aos_hub_oci_placements{health=\"unhealthy\"} 0"));
    assert!(text.contains("aos_hub_oci_inventory_age_seconds{stat=\"max\"} 0"));
    assert!(text.contains("aos_hub_oci_inventory_events{kind=\"takeover\"} 0"));
    assert!(text.contains("aos_hub_oci_gc_recoveries{kind=\"action_requeue\"} 0"));
    assert!(text.contains("aos_hub_oci_digest_mismatches 0"));
    assert!(text.contains("aos_hub_build_info{version="));
}

/// Read a proto3-JSON int64, which may be encoded as a string or a number.
fn json_i64(value: &serde_json::Value) -> i64 {
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
        .unwrap_or_else(|| panic!("expected an int64, got {value}"))
}

/// Current Unix time in seconds.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
