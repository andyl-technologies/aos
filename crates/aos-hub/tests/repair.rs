//! RFC-0004 deferred validation-and-repair coverage: `MintUploadCredentials`
//! (the `PublishService` write-credential path) and HTTP-cache repair
//! (fetch-verify-PUT through the registry facade).
//!
//! Two scenarios run against the *real* hub router:
//!
//! - **MintUploadCredentials** — a Publish-authorized caller mints an upload
//!   credential over Connect-JSON; the returned token validates and is scoped
//!   to exactly that registry with only `publish` and a near expiry, and an
//!   unauthorized caller is rejected.
//! - **HTTP-cache repair** — a managed registry's facade is the repair
//!   *target*; a `file://` cache holding the narinfo + NAR is the *source*.
//!   [`run_repairs`](aos_hub::validation::run_repairs) fetches the
//!   object from the source, verifies its content hash, and PUTs it to the
//!   target facade with an internally minted bearer JWT. The target binding
//!   ends up holding the narinfo + NAR and the repair job is recorded `done`.

use std::path::Path;
use std::sync::Arc;

use aos_hub::auth::extract::AuthState;
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::db::{Database, IndexSnapshot};
use aos_hub::domain::{Permission, Principal};
use aos_hub::fetch::hardened_client;
use aos_hub::server::{router, AppState, HubRepairAuthorizer};
use aos_hub::validation;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

/// Deterministic HS256 key so the authorizer's minted JWTs verify against the
/// running hub.
const TEST_JWT_SECRET: &[u8] = b"repair-test-secret-32-byte-key!!!";

/// Build an [`AppState`] over `db` with deterministic JWT keys and the given
/// external URL (the facade base the repair PUTs land on).
async fn app_state(db: Arc<Database>, external_url: &str) -> Arc<AppState> {
    let auth = Arc::new(AuthState {
        db: Arc::clone(&db),
        jwt_keys: JwtKeys::from_secret(TEST_JWT_SECRET),
        access_token_ttl: 900,
        ratelimit: aos_hub::ratelimit::RateLimiter::new().into(),
        trusted_proxy: false,
    });
    Arc::new(AppState {
        db,
        external_url: external_url.to_string(),
        ratelimit: auth.ratelimit.clone(),
        trusted_proxy: false,
        auth,
        leases: std::sync::Arc::new(aos_hub::facade::LeaseMap::new()),
        sealer: aos_hub::auth::oidc::dev_sealer(),
        http: hardened_client().await,
        mailer: Arc::new(aos_hub::auth::magic::LogMailer),
        dev: false,
    })
}

/// Mint a bearer JWT for `principal` scoped to `scope` with `perms`.
fn bearer(principal: Principal, scope: &str, perms: &[Permission]) -> String {
    let keys = JwtKeys::from_secret(TEST_JWT_SECRET);
    keys.mint(
        &aos_hub::db::TokenAuth {
            token_id: "test-token".into(),
            owner: principal,
            scope: aos_hub::domain::Scope::parse(scope),
            permissions: perms.to_vec(),
        },
        900,
    )
    .unwrap()
}

/// POST a Connect-JSON RPC, returning `(status, body)`.
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

/// Create org "acme", a `local_fs` binding rooted at `binding_root`, and a
/// managed registry at `acme/infra/prod/cdn` with surface prefix `cdn` and the
/// given visibility. Returns the registry id.
async fn create_managed_with_visibility(
    db: &Database,
    binding_root: &Path,
    visibility: &str,
) -> i64 {
    create_managed_with_keys(db, binding_root, visibility, &[]).await
}

/// As [`create_managed_with_visibility`], but enrolls a narinfo trust roster so
/// the repair path's mandatory signature gate can be exercised against a signed
/// source object.
async fn create_managed_with_keys(
    db: &Database,
    binding_root: &Path,
    visibility: &str,
    trust_keys: &[String],
) -> i64 {
    let org = db.create_org("acme", "Acme, Inc.").await.unwrap();
    let binding = db
        .create_storage_binding(org, "primary", "local_fs", binding_root.to_str().unwrap())
        .await
        .unwrap();
    db.create_managed_registry(
        org,
        "infra/prod",
        "cdn",
        visibility,
        Some(binding),
        "cdn",
        trust_keys,
        false,
    )
    .await
    .unwrap()
}

/// [`create_managed_with_visibility`] with `private` visibility.
async fn create_managed(db: &Database, binding_root: &Path) -> i64 {
    create_managed_with_visibility(db, binding_root, "private").await
}

/// Build a *signed* `abc.narinfo` (store hash `abc`, NAR at `nar/abc.nar`)
/// whose Ed25519 `Sig:` verifies against the returned trust-roster line.
///
/// The repair path now mandates that a source narinfo carry a valid signature
/// from the registry's trust roster before its bytes may be propagated onto the
/// hub facade, so repair tests must source a signed object rather than a raw
/// hash-consistent one.
fn signed_abc_narinfo(nar_bytes: &[u8]) -> (String, String) {
    use base64::Engine as _;

    let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let trust_key = aos_hub::surface::sshsig::trusted_key_line("demo", &key.verifying_key());

    let mut secret = Vec::with_capacity(64);
    secret.extend_from_slice(&key.to_bytes());
    secret.extend_from_slice(key.verifying_key().as_bytes());
    let secret_b64 = base64::engine::general_purpose::STANDARD.encode(&secret);
    let signer =
        aos_core::nar::cache::NarInfoSigner::from_key_content(&format!("demo:{secret_b64}"))
            .unwrap();

    let store_path = "/var/lib/store/abc-curl-8.5.0";
    let hash = format!("sha256:{}", hex::encode(Sha256::digest(nar_bytes)));
    let size = nar_bytes.len() as i64;
    let fingerprint =
        aos_core::nar::cache::NarInfoSigner::fingerprint(store_path, &hash, size, &[]);
    let sig = signer.sign(&fingerprint).unwrap();
    let narinfo = format!(
        "StorePath: {store_path}\nURL: nar/abc.nar\nCompression: none\n\
         FileHash: {hash}\nFileSize: {size}\nNarHash: {hash}\nNarSize: {size}\nSig: {sig}\n",
    );
    (narinfo, trust_key)
}

/// A package referencing a single store hash `abc`, for an index snapshot.
fn one_hash_package() -> aos_package::registry::parse::PackageToml {
    toml::from_str(
        r#"
        [package]
        name = "curl"
        description = "URL transfers"
        license = "MIT"
        maintainer = "aos"
        [[versions]]
        version = "8.5.0"
        [versions.platforms.x86_64-linux]
        store_path = "/var/lib/store/abc-curl-8.5.0"
        nar_hash = "sha256:aa"
        nar_size = 10
        closure_size = 20
        source_drv = "/var/lib/store/abc.drv"
        source_nar_hash = "sha256:bb"
        "#,
    )
    .unwrap()
}

#[tokio::test]
async fn mint_upload_credentials_authz_scope_and_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    create_managed(&db, dir.path()).await;
    let app = router(app_state(Arc::clone(&db), "http://hub.test").await).await;

    // The RPC checks the principal's *current* grants too, so the publisher
    // service account holds a real maintainer (publish-capable) membership.
    let publisher_sa = db
        .create_service_account(db.org_by_slug("acme").await.unwrap().unwrap().id, "ci")
        .await
        .unwrap();
    db.grant_membership(
        "service_account",
        publisher_sa,
        "acme/infra/prod/cdn",
        "maintainer",
    )
    .await
    .unwrap();

    // An authorized Publish caller mints a credential.
    let publisher = bearer(
        Principal::service_account(publisher_sa),
        "acme/infra/prod/cdn",
        &[Permission::Publish],
    );
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (status, body) = rpc(
        &app,
        "PublishService/MintUploadCredentials",
        serde_json::json!({ "slug": "acme/infra/prod/cdn" }),
        Some(&publisher),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let token = body["token"].as_str().unwrap();
    assert!(token.starts_with("aos_"), "got {token}");
    assert_eq!(
        body["uploadUrl"].as_str().unwrap(),
        "http://hub.test/acme/infra/prod/cdn"
    );
    // Connect-JSON here uses canonical camelCase field names with native JSON
    // scalars (int64 as a JSON number, not the proto3-canonical string form) —
    // both ends share the `aos-proto-types` structs, so this stays consistent.
    let expires_at = body["expiresAt"].as_i64().unwrap();
    // Near expiry: within the documented 1-hour TTL window.
    assert!(expires_at > before, "expiry is in the future");
    assert!(
        expires_at <= before + 3600 + 5,
        "expiry within the 1h credential TTL (got {expires_at}, before {before})"
    );

    // The minted token validates and is scoped Publish to exactly this registry.
    let auth = db
        .validate_token(token)
        .await
        .unwrap()
        .expect("token validates");
    assert_eq!(auth.scope.as_str(), "acme/infra/prod/cdn");
    assert_eq!(auth.permissions, vec![Permission::Publish]);

    // An unauthorized caller (only Read) is rejected.
    let reader = bearer(
        Principal::service_account(2),
        "acme/infra/prod/cdn",
        &[Permission::Read],
    );
    let (status, _) = rpc(
        &app,
        "PublishService/MintUploadCredentials",
        serde_json::json!({ "slug": "acme/infra/prod/cdn" }),
        Some(&reader),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // An anonymous caller is rejected.
    let (status, _) = rpc(
        &app,
        "PublishService/MintUploadCredentials",
        serde_json::json!({ "slug": "acme/infra/prod/cdn" }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn http_repair_fetches_verifies_and_puts_to_facade() {
    // The repair *source*: a file:// cache holding a *signed* abc.narinfo + its
    // NAR. The repair path verifies the source narinfo's `Sig:` against the
    // registry trust roster before propagating it onto the hub facade, so an
    // unsigned source would (correctly) be refused.
    let source_dir = tempfile::tempdir().unwrap();
    let nar_bytes = b"the-real-nar-bytes";
    let (narinfo, trust_key) = signed_abc_narinfo(nar_bytes);
    std::fs::create_dir_all(source_dir.path().join("nar")).unwrap();
    std::fs::write(source_dir.path().join("nar/abc.nar"), nar_bytes).unwrap();
    std::fs::write(source_dir.path().join("abc.narinfo"), &narinfo).unwrap();
    let source_url = format!("file://{}", source_dir.path().display());

    // The repair *target*: a managed registry served by a real hub, enrolling
    // the source's trust key so the signature gate passes. Its binding root
    // (the cdn prefix under it) is initially empty.
    let binding_dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    // Public so the validation HEAD probe (anonymous) can read the facade.
    let reg_id = create_managed_with_keys(
        &db,
        binding_dir.path(),
        "public",
        std::slice::from_ref(&trust_key),
    )
    .await;

    // Bring up the real hub so the facade accepts PUTs.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let external_url = format!("http://{}", listener.local_addr().unwrap());
    let target_url = format!("{external_url}/acme/infra/prod/cdn");
    let app = router(app_state(Arc::clone(&db), &external_url).await).await;
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Index a snapshot referencing hash `abc` with two caches: the file://
    // source (which has it) and the hub facade target (which does not yet).
    db.apply_snapshot(
        reg_id,
        &IndexSnapshot {
            commit: "c".repeat(64),
            name: "demo".into(),
            caches: vec![(source_url.clone(), 100), (target_url.clone(), 50)],
            packages: vec![one_hash_package()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let registry = db
        .registry_by_slug("acme/infra/prod/cdn")
        .await
        .unwrap()
        .unwrap();

    // Record the validation state directly: the source holds `abc`, the hub
    // facade target is missing it. (The hub's *own* facade serves reads over
    // GET but reserves HEAD for the Publish-only upload-existence probe, so a
    // live presence HEAD against the facade target is not anonymous; recording
    // the state directly keeps the test focused on the repair round-trip.)
    db.record_validation_run(registry.id, &source_url, "presence", 1, &[], true, 0, 1)
        .await
        .unwrap();
    db.record_validation_run(
        registry.id,
        &target_url,
        "presence",
        1,
        &["abc".to_string()],
        true,
        0,
        1,
    )
    .await
    .unwrap();

    // Run repairs with a real hub authorizer (matching keys + external_url).
    let authorizer = HubRepairAuthorizer::new(
        Arc::clone(&db),
        JwtKeys::from_secret(TEST_JWT_SECRET),
        external_url.clone(),
    );
    let client = hardened_client().await;
    let summary = validation::run_repairs(&db, &client, &registry, &authorizer)
        .await
        .unwrap();
    assert_eq!(summary.done, 1, "one http repair completed");
    assert_eq!(summary.plan_only, 0);
    assert_eq!(summary.failed, 0);

    // The facade binding now holds the narinfo + NAR the source provided.
    let target_root = binding_dir.path().join("cdn");
    assert_eq!(
        std::fs::read(target_root.join("nar/abc.nar")).unwrap(),
        nar_bytes,
        "NAR landed in the target binding"
    );
    let written_narinfo = std::fs::read_to_string(target_root.join("abc.narinfo")).unwrap();
    assert!(written_narinfo.contains("URL: nar/abc.nar"));

    // The repair job is recorded `done`.
    let jobs = db.list_repair_jobs(reg_id, 10).await.unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].status, "done");
    assert_eq!(jobs[0].store_hash, "abc");
    assert_eq!(jobs[0].cache_url, target_url);
    assert_eq!(jobs[0].source_cache_url, source_url);

    // The repaired narinfo is now fetchable over the public read facade (a
    // plain GET, the path a consumer or Nix would use).
    let resp = client
        .get(format!("{target_url}/abc.narinfo"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert!(resp.text().await.unwrap().contains("URL: nar/abc.nar"));
}

#[tokio::test]
async fn http_repair_to_unauthorized_target_is_plan_only() {
    // A file:// source holding the object.
    let source_dir = tempfile::tempdir().unwrap();
    std::fs::write(
        source_dir.path().join("abc.narinfo"),
        b"StorePath: /var/lib/store/abc-curl-8.5.0\n",
    )
    .unwrap();
    let source_url = format!("file://{}", source_dir.path().display());

    // An *external* http target the hub does not serve (no facade match).
    let target_url = "https://external.example.com/cache".to_string();

    let binding_dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let reg_id = create_managed(&db, binding_dir.path()).await;
    let registry = db
        .registry_by_slug("acme/infra/prod/cdn")
        .await
        .unwrap()
        .unwrap();

    // Record validation runs directly so the repair plan targets the external
    // cache: the source holds `abc`, the external target is missing it. (We
    // bypass live probing — the external URL is not really reachable.)
    db.record_validation_run(reg_id, &source_url, "presence", 1, &[], true, 0, 1)
        .await
        .unwrap();
    db.record_validation_run(
        reg_id,
        &target_url,
        "presence",
        1,
        &["abc".to_string()],
        true,
        0,
        1,
    )
    .await
    .unwrap();

    // The authorizer's external_url does not match the external target, so the
    // hub has no credential for it: run_repairs leaves it plan-only.
    let authorizer = HubRepairAuthorizer::new(
        Arc::clone(&db),
        JwtKeys::from_secret(TEST_JWT_SECRET),
        "http://hub.test".to_string(),
    );
    let client = hardened_client().await;
    let summary = validation::run_repairs(&db, &client, &registry, &authorizer)
        .await
        .unwrap();
    assert_eq!(summary.done, 0);
    assert_eq!(summary.failed, 0);
    assert_eq!(summary.plan_only, 1, "external target left as a plan");

    let jobs = db.list_repair_jobs(reg_id, 10).await.unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].status, "plan_only");
    assert_eq!(jobs[0].cache_url, target_url);
}
