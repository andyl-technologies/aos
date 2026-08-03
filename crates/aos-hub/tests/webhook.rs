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
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::routing::post;
use tower::ServiceExt;

/// Deterministic HS256 key so tests can mint matching JWTs.
const TEST_JWT_SECRET: &[u8] = b"webhook-test-secret-32byte-key!!";

/// Serializes tests that read or mutate `AOS_HUB_ALLOW_LOCAL_REMOTES`.
///
/// `create_webhook` and `deliver_one` now run the SSRF guard
/// ([`aos_hub::fetch::is_safe_remote_url`]), which consults this
/// process-global env var. A test needing loopback *allowed* and one needing it
/// *rejected* must not interleave, so each takes [`remote_guard`] for its body.
static REMOTE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
        ratelimit: auth.ratelimit.clone(),
        trusted_proxy: false,
        auth,
        leases: std::sync::Arc::new(aos_hub::facade::LeaseMap::new()),
        sealer: aos_hub::auth::oidc::dev_sealer(),
        http: aos_hub::fetch::hardened_client().await,
        mailer: Arc::new(aos_hub::auth::magic::LogMailer),
        dev: false,
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

// -- dispatch ---------------------------------------------------------------

#[tokio::test]
async fn dispatch_enqueues_only_for_subscribed_active_hooks() {
    let _remotes = remote_guard(true);
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();

    // A hook subscribed to index.completed, one to channel.advanced, one to
    // all events, and a disabled one.
    let h_index = db
        .create_webhook(org, "http://a/", "s", &["index.completed".into()])
        .await
        .unwrap();
    let _h_channel = db
        .create_webhook(org, "http://b/", "s", &["channel.advanced".into()])
        .await
        .unwrap();
    let h_all = db.create_webhook(org, "http://c/", "s", &[]).await.unwrap();
    let h_disabled = db
        .create_webhook(org, "http://d/", "s", &["index.completed".into()])
        .await
        .unwrap();
    db.set_webhook_active(h_disabled, false).await.unwrap();

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
    // h_index (subscribed) + h_all (all events); NOT the channel-only hook,
    // NOT the disabled one.
    assert_eq!(enqueued, 2);

    let due = db.due_deliveries(i64::MAX).await.unwrap();
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
    let hook = db
        .create_webhook(org, &url, secret, &["index.completed".into()])
        .await
        .unwrap();
    let payload = r#"{"type":"index.completed","registry":"acme/cdn"}"#;
    db.enqueue_delivery(hook, "index.completed", payload)
        .await
        .unwrap();

    let due = db.due_deliveries(i64::MAX).await.unwrap();
    assert_eq!(due.len(), 1);
    let http = aos_hub::fetch::hardened_client().await;
    let ok = webhook::deliver_one(&http, &db, &due[0]).await.unwrap();
    assert!(ok, "2xx should mark delivered");

    // The receiver saw the event header and a valid signature over the body.
    let captured = rx.captured.lock().unwrap().clone();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].event, "index.completed");
    assert_eq!(captured[0].body, payload.as_bytes());
    assert_eq!(
        captured[0].signature,
        webhook::sign_body(secret, payload.as_bytes()),
        "X-AOS-Signature is HMAC-SHA256 of the raw body under the secret"
    );

    // The delivery is now delivered and no longer due.
    let (pending, delivered, failed) = db.delivery_status_counts().await.unwrap();
    assert_eq!((pending, delivered, failed), (0, 1, 0));
    assert!(db.due_deliveries(i64::MAX).await.unwrap().is_empty());
}

#[tokio::test]
async fn deliver_one_schedules_retry_with_incremented_attempts_on_500() {
    let _remotes = remote_guard(true);
    let (url, rx) = spawn_receiver(500).await;
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    let hook = db.create_webhook(org, &url, "s", &[]).await.unwrap();
    db.enqueue_delivery(hook, "index.completed", "{}")
        .await
        .unwrap();

    let due = db.due_deliveries(i64::MAX).await.unwrap();
    let http = aos_hub::fetch::hardened_client().await;
    let ok = webhook::deliver_one(&http, &db, &due[0]).await.unwrap();
    assert!(!ok, "500 must not mark delivered");
    assert_eq!(rx.captured.lock().unwrap().len(), 1);

    // Still pending (not failed yet), attempts incremented, and scheduled into
    // the future so it is not immediately due again.
    let (pending, delivered, failed) = db.delivery_status_counts().await.unwrap();
    assert_eq!((pending, delivered, failed), (1, 0, 0));
    assert!(
        db.due_deliveries(now()).await.unwrap().is_empty(),
        "a backed-off retry is not due now"
    );
    // Far in the future it is due again, with attempts == 1.
    let later: Vec<DueDelivery> = db.due_deliveries(now() + 100_000).await.unwrap();
    assert_eq!(later.len(), 1);
    assert_eq!(later[0].attempts, 1);
}

#[tokio::test]
async fn deliveries_fail_after_the_attempt_cap() {
    let _remotes = remote_guard(true);
    let (url, _rx) = spawn_receiver(500).await;
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    let hook = db.create_webhook(org, &url, "s", &[]).await.unwrap();
    db.enqueue_delivery(hook, "index.completed", "{}")
        .await
        .unwrap();
    let http = aos_hub::fetch::hardened_client().await;

    // Hammer the delivery past the attempt cap (querying with a far-future
    // `now` so the backoff never hides it).
    for _ in 0..(webhook::MAX_ATTEMPTS + 1) {
        let due = db.due_deliveries(i64::MAX).await.unwrap();
        if due.is_empty() {
            break;
        }
        webhook::deliver_one(&http, &db, &due[0]).await.unwrap();
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
        let hook = db.create_webhook(org, &url, "s", &[]).await.unwrap();
        db.enqueue_delivery(hook, "index.completed", "{}")
            .await
            .unwrap();
        let mut due = db.due_deliveries(i64::MAX).await.unwrap();
        assert_eq!(due.len(), 1);
        // Repoint the queued row at an internal address, as a stale/poisoned row
        // would be; the row id stays valid so mark_delivery can update it.
        let mut delivery = due.remove(0);
        delivery.url = "http://169.254.169.254/latest/meta-data/".to_string();
        (delivery, db)
    };

    let _remotes = remote_guard(false);
    let http = aos_hub::fetch::hardened_client().await;
    let ok = webhook::deliver_one(&http, &db, &delivery).await.unwrap();
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

// -- RPC create/list/delete authz -------------------------------------------

#[tokio::test]
async fn webhook_rpc_create_list_delete_with_authz() {
    let _remotes = remote_guard(true);
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;

    // An admin (members.manage on acme) may create.
    let admin = bearer(Principal::user(1), "acme", &[Permission::MembersManage]);
    db.grant_membership("user", 1, "acme", "admin")
        .await
        .unwrap();

    let (status, body) = rpc(
        &app,
        "WebhookService/CreateWebhook",
        serde_json::json!({
            "orgSlug": "acme",
            "url": "https://ci.acme/hook",
            "events": ["index.completed"],
        }),
        Some(&admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admin create: {body}");
    assert!(
        body["secret"].as_str().is_some_and(|s| !s.is_empty()),
        "secret returned once on create: {body}"
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

    // A non-admin (only read) is denied create.
    let viewer = bearer(Principal::user(2), "acme", &[Permission::Read]);
    db.grant_membership("user", 2, "acme", "viewer")
        .await
        .unwrap();
    let (status, _body) = rpc(
        &app,
        "WebhookService/CreateWebhook",
        serde_json::json!({ "orgSlug": "acme", "url": "https://x/" }),
        Some(&viewer),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer cannot create webhooks"
    );

    // The admin deletes it.
    let (status, body) = rpc(
        &app,
        "WebhookService/DeleteWebhook",
        serde_json::json!({ "id": id }),
        Some(&admin),
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
    let hook = db.create_webhook(org, "http://x/", "s", &[]).await.unwrap();
    db.enqueue_delivery(hook, "index.completed", "{}")
        .await
        .unwrap();
    // A managed cache with one indexed object so the cache gauges are non-zero.
    let binding = db
        .create_storage_binding(org, "primary", "local_fs", "/srv/aos-hub")
        .await
        .unwrap();
    let cache = db
        .create_cache(
            Some(org),
            "acme-cache",
            "Acme",
            Some(binding),
            "p",
            None,
            "public",
            40,
            "zstd",
            true,
        )
        .await
        .unwrap();
    db.upsert_cache_object(&aos_hub_core::db::CacheObject {
        cache_id: cache,
        store_hash: "aaaa".into(),
        store_name: "aaaa-foo-1.0".into(),
        nar_url: "nar/ff.nar.zst".into(),
        nar_hash: "sha256:dd".into(),
        nar_size: 100,
        file_hash: "ff".into(),
        file_size: 50,
        compression: "zstd".into(),
        deriver: None,
        refs: vec![],
        sig: None,
        ca: None,
        uploaded_at: now(),
        last_accessed_at: None,
    })
    .await
    .unwrap();
    db.refresh_cache_usage(cache).await.unwrap();
    let run = db.start_cache_gc_run(cache).await.unwrap();
    db.finish_cache_gc_run(run, "ok", None, 5, 4, 1, 4096)
        .await
        .unwrap();

    let app = router(app_state(db).await).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
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
    assert!(text.contains("aos_hub_cache_objects_total 1"));
    assert!(text.contains("aos_hub_cache_bytes_total 50"));
    assert!(text.contains("aos_hub_cache_gc_runs{status=\"ok\"} 1"));
    assert!(text.contains("aos_hub_cache_gc_freed_bytes 4096"));
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
