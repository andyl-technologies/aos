//! Real-client to hub integration coverage: the `aos-cache` HTTP backend
//! driven against a running hub server over real TCP.
//!
//! The existing `upload.rs` e2e hand-rolls `PUT`/`GET` requests with axum's
//! `oneshot`, which exercises the hub router but *not* the client code that
//! `apr`/`apm` actually run. This test closes that gap: it stands up the
//! real hub on a [`tokio::net::TcpListener`] with [`axum::serve`] (like
//! `http_source.rs`) and drives the genuine
//! [`aos_cache::backend::http::HttpBackend`] — constructed through the same
//! [`aos_cache::backend::from_url`] entry point the producer uses — to
//! publish and then read back a registry surface over HTTP.
//!
//! # What this covers — and what it does not
//!
//! This is the **real client *library* to hub** loop (RFC-0004 testing
//! tier 2): the actual `CacheBackend` implementation issues the real HTTP
//! requests against the real router, facade, auth, and indexer. It does
//! *not* shell out to the `apr`/`apm` *binaries* over a real Nix store —
//! that full binary-plus-Nix-store loop is the VM/fleet harness tier
//! (RFC-0004 testing tier 3, `tests/fleet/*.nix`) and is deliberately out
//! of scope here (no Nix is built or run).
//!
//! # The client surface exercised
//!
//! `apr origin upload` to an HTTP(S) destination runs in the backend's
//! **generic mode** (`is_aos == false`): no `--token` is supplied, and the
//! Bearer JWT travels in `AuthOptions::headers` as
//! `"Authorization: Bearer <jwt>"`. In that mode the backend issues one
//! `PUT {base_url}/{relative_path}` per surface file via
//! [`CacheBackend::put_static_file`] — which is exactly the wire protocol
//! the hub's [`facade`](aos_hub::facade) documents and answers.
//! The read side uses the backend's real
//! [`CacheBackend::get_narinfo`] / [`CacheBackend::get_nar`] /
//! [`CacheBackend::ensure_cache_info`] methods.
//!
//! The JWT itself is obtained by the real `/oauth2/token` exchange (the
//! same request bytes [`HttpBackend::authenticate`] sends), so provisioning
//! token to JWT to authenticated upload is end to end.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aos_cache::backend::{self, AuthOptions};
use aos_hub::auth::extract::AuthState;
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::db::Database;
use aos_hub::domain::{Permission, Principal};
use aos_hub::server::{router, AppState};

/// Deterministic HS256 key so the hub mints JWTs the same keys verify.
const TEST_JWT_SECRET: &[u8] = b"client-e2e-secret-32-byte-key!!!!";

/// A hub running on a real loopback TCP socket, with a managed registry
/// already created and a provisioning token minted for it.
struct RunningHub {
    /// `http://127.0.0.1:<port>` origin of the live server.
    origin: String,
    /// The managed registry's canonical slug (`acme/infra/prod/cdn`).
    slug: String,
    /// On-disk surface root the hub writes uploaded files to.
    binding_root: PathBuf,
    /// Shared database handle, for asserting on the index directly.
    db: Arc<Database>,
}

impl RunningHub {
    /// The base URL a client points the cache backend at: the live origin
    /// joined with the registry's canonical path.
    fn base_url(&self) -> String {
        format!("{}/{}", self.origin, self.slug)
    }
}

/// Build an [`AppState`] over `db` with the deterministic test JWT keys.
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
        secret_versions: aos_hub_core::secret_version::EmptySecretVersionResolver::shared(),
        http: aos_hub::fetch::hardened_client().await,
        image_snapshots: None,
        mailer: std::sync::Arc::new(aos_hub::auth::magic::LogMailer),
        dev: false,
        delivery_attestation_verifier: None,
        domain_probe_terminator: None,
        route_reservation_keyring: None,
    })
}

/// Create org `acme`, a `local_fs` binding over an empty dir, and a managed
/// registry `acme/infra/prod/cdn` bound to it, then serve the hub on a real
/// ephemeral TCP port. Returns the [`RunningHub`] handle.
async fn spawn_hub(visibility: &str) -> RunningHub {
    let root = tempfile::tempdir().unwrap().keep();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme, Inc.").await.unwrap();
    let binding = common::create_local_binding(&db, org, "primary", root.to_str().unwrap()).await;
    db.create_managed_registry(
        org,
        "infra/prod",
        "cdn",
        visibility,
        &[],
        false, // fixture is signed, but trust keys are not pinned for this test
    )
    .await
    .unwrap();

    let app = router(app_state(Arc::clone(&db)).await).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    RunningHub {
        origin,
        slug: "acme/infra/prod/cdn".into(),
        binding_root: root.join("cdn"),
        db,
    }
}

/// Mint a Publish-scoped provisioning token and exchange it for a JWT at
/// the hub's real `/oauth2/token` endpoint, returning the access token.
///
/// This is the exact request [`HttpBackend::authenticate`] performs in AOS
/// mode; running it over reqwest here yields the same JWT the generic-mode
/// upload then carries in its `Authorization` header.
async fn mint_jwt(hub: &RunningHub, perms: &[Permission]) -> String {
    let (_id, secret) = hub
        .db
        .create_token(
            Principal::service_account(1),
            &common::registry_scope(&hub.db, &hub.slug).await,
            perms,
            Some("client-e2e"),
            None,
        )
        .await
        .unwrap();

    let resp = reqwest::Client::new()
        .post(format!("{}/oauth2/token", hub.origin))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Authorization", format!("Bearer {secret}"))
        .body("grant_type=client_credentials")
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "oauth2 exchange: {}",
        resp.status()
    );
    let json: serde_json::Value = resp.json().await.unwrap();
    json["access_token"].as_str().unwrap().to_string()
}

/// Generic-mode [`AuthOptions`] carrying a Bearer JWT exactly as
/// `apr origin upload` does (no `--token`; the JWT rides in `--header`).
fn generic_auth(jwt: &str) -> AuthOptions {
    AuthOptions {
        headers: vec![format!("Authorization: Bearer {jwt}")],
        ..Default::default()
    }
}

/// Recursively collect a surface directory into `(relative_path, bytes)`
/// pairs, sorted immutable-first then by path — the producer's phase-major
/// upload order (objects/NARs before the pointers that name them).
fn collect_surface(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    walk(root, root, &mut files);
    files.sort_by(|a, b| {
        is_pointer(&a.0)
            .cmp(&is_pointer(&b.0))
            .then_with(|| a.0.cmp(&b.0))
    });
    files
}

/// Whether a relative path is a mutable pointer (uploaded last).
fn is_pointer(path: &str) -> bool {
    path == "HEAD"
        || path == "info/refs"
        || path == "nix-cache-info"
        || path.starts_with("objects/info/")
        || path.starts_with("channels/")
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            walk(root, &path, out);
        } else {
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, std::fs::read(&path).unwrap()));
        }
    }
}

/// Pick a `Content-Type` for a surface file the same way the producer's
/// `static_upload` does — enough fidelity for the round-trip assertions.
fn content_type(rel: &str) -> &'static str {
    if rel.ends_with(".narinfo") {
        "text/x-nix-narinfo"
    } else if rel.ends_with(".zst") {
        "application/zstd"
    } else if rel == "HEAD" || rel == "info/refs" || rel == "nix-cache-info" {
        "text/plain"
    } else {
        "application/octet-stream"
    }
}

/// Drive the real generic-mode backend to publish every surface file, then
/// read the nix-cache files back through the same backend and assert a
/// byte-exact round-trip; confirm the hub indexed the package.
#[tokio::test]
async fn real_backend_publishes_and_reads_back() {
    // A real signed surface in a scratch dir (not the binding root).
    let scratch = tempfile::tempdir().unwrap();
    let surface = scratch.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    common::standard_registry(&surface);
    let files = collect_surface(&surface);
    assert!(files.len() >= 8, "fixture should have many files");

    let hub = spawn_hub("public").await;
    let jwt = mint_jwt(&hub, &[Permission::Publish, Permission::Read]).await;

    // The REAL client backend, constructed through the same `from_url`
    // dispatch the producer uses. Generic mode: the JWT rides in a header.
    let auth = generic_auth(&jwt);
    let backend = backend::from_url(&hub.base_url(), &auth).await.unwrap();
    assert!(
        !backend.supports_pack(),
        "an http(s) destination without an AOS provisioning token is generic mode"
    );

    // Upload every file through the real `put_static_file`, immutable-first
    // (the `collect_surface` order). The pointer flips trigger the hub's
    // inline re-index.
    for (rel, _bytes) in &files {
        let source = surface.join(rel);
        backend
            .put_static_file(rel, &source, Some(content_type(rel)), None, None, None)
            .await
            .unwrap_or_else(|e| panic!("put_static_file {rel}: {e:#}"));
    }

    // The bytes landed in the hub's binding root.
    assert_eq!(
        std::fs::read(hub.binding_root.join("HEAD")).unwrap(),
        std::fs::read(surface.join("HEAD")).unwrap(),
        "HEAD bytes reached the binding root",
    );

    // The hub indexed the registry: the package is queryable in its DB.
    let registry = hub.db.registry_by_slug(&hub.slug).await.unwrap().unwrap();
    let packages = hub.db.list_packages(registry.id).await.unwrap();
    assert!(
        packages.iter().any(|p| p.name == "curl"),
        "hub should have indexed the `curl` package, got {:?}",
        packages.iter().map(|p| &p.name).collect::<Vec<_>>()
    );

    // --- Download round-trip through the REAL backend ----------------------

    // `ensure_cache_info` is a no-op for HTTP caches but is part of the real
    // pull path; call it to exercise the method.
    backend.ensure_cache_info("/var/lib/store").await.unwrap();

    // The narinfo round-trips byte-for-byte (modulo a trailing newline the
    // HTTP layer does not add): assert the body the hub serves equals the
    // uploaded narinfo.
    let store_hash = "h7j3k8l2m9n4";
    let got_narinfo = backend.get_narinfo(store_hash).await.unwrap();
    let want_narinfo =
        String::from_utf8(std::fs::read(surface.join(format!("{store_hash}.narinfo"))).unwrap())
            .unwrap();
    assert_eq!(
        got_narinfo, want_narinfo,
        "narinfo round-trips through the real backend",
    );

    // The NAR round-trips byte-for-byte via the URL the narinfo records.
    let nar_rel = want_narinfo
        .lines()
        .find_map(|l| l.strip_prefix("URL:"))
        .map(str::trim)
        .expect("narinfo has a URL field");
    let got_nar = backend.get_nar(nar_rel).await.unwrap();
    let want_nar = std::fs::read(surface.join(nar_rel)).unwrap();
    assert_eq!(
        got_nar, want_nar,
        "NAR round-trips through the real backend"
    );

    // A git machine path (a loose object) also round-trips. The backend has
    // no git-object primitive, so read it as a static surface fetch — the
    // facade serves it the same way regardless of client method. Use the
    // backend's own engine path shape via a plain GET to the same URL.
    let any_object = files
        .iter()
        .find(|(rel, _)| rel.starts_with("objects/") && !rel.starts_with("objects/info/"))
        .expect("fixture has a loose git object");
    let object_url = format!("{}/{}", hub.base_url(), any_object.0);
    let got_object = reqwest::get(&object_url)
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(
        got_object.as_ref(),
        any_object.1.as_slice(),
        "git loose object {} round-trips byte-for-byte",
        any_object.0,
    );
}

/// A backend with no credential is rejected by the hub's publish gate: the
/// real `put_static_file` surfaces the `401` as an error.
#[tokio::test]
async fn unauthenticated_backend_upload_is_rejected() {
    let scratch = tempfile::tempdir().unwrap();
    let surface = scratch.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    common::standard_registry(&surface);

    let hub = spawn_hub("public").await;

    // No Authorization header at all.
    let backend = backend::from_url(&hub.base_url(), &AuthOptions::default())
        .await
        .unwrap();
    let source = surface.join("HEAD");
    let err = backend
        .put_static_file("HEAD", &source, Some("text/plain"), None, None, None)
        .await
        .expect_err("an unauthenticated PUT must be rejected by the hub");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("401"),
        "error should report the 401 the hub returned, got: {msg}"
    );
}

/// A Read-only token cannot publish: the real backend surfaces the hub's
/// `403` as an error from `put_static_file`.
#[tokio::test]
async fn read_only_token_cannot_publish() {
    let scratch = tempfile::tempdir().unwrap();
    let surface = scratch.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    common::standard_registry(&surface);

    let hub = spawn_hub("public").await;
    let jwt = mint_jwt(&hub, &[Permission::Read]).await;

    let backend = backend::from_url(&hub.base_url(), &generic_auth(&jwt))
        .await
        .unwrap();
    let source = surface.join("HEAD");
    let err = backend
        .put_static_file("HEAD", &source, Some("text/plain"), None, None, None)
        .await
        .expect_err("a Read-only token must not be allowed to publish");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("403"),
        "error should report the 403 the hub returned, got: {msg}"
    );
}
