//! Phase-2d integration coverage: the authenticated upload facade.
//!
//! Drives the real router's `PUT`/`HEAD` machine-path facade exactly as
//! `apr origin upload` (generic mode) would: generate a registry surface
//! with [`common::standard_registry`], `PUT` every relative file of that
//! surface to the managed registry's canonical path under a Publish-scoped
//! Bearer JWT, then `GET` the machine paths back and assert byte-equality
//! plus that the registry indexed (the browse page shows the package). This
//! is the end-to-end "publish through the hub -> index -> consume" loop.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aos_hub::auth::extract::AuthState;
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::db::{Database, TokenAuth};
use aos_hub::domain::{Permission, Principal, Scope};
use aos_hub::server::{router, AppState};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde::Deserialize;
use tower::ServiceExt;

/// Deterministic HS256 key so tests can mint matching JWTs.
const TEST_JWT_SECRET: &[u8] = b"upload-test-secret-32-byte-key!!!";

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

/// Mint a bearer JWT for `principal` scoped to `scope` with `perms`.
fn bearer(token_id: &str, principal: Principal, scope: &str, perms: &[Permission]) -> String {
    JwtKeys::from_secret(TEST_JWT_SECRET)
        .mint(
            &TokenAuth {
                token_id: token_id.into(),
                owner: principal,
                scope: Scope::parse(scope),
                permissions: perms.to_vec(),
            },
            900,
        )
        .unwrap()
}

/// Create org "acme", a `local_fs` binding rooted at an *empty* directory,
/// and a managed registry at `acme/infra/prod/cdn` bound to it (prefix
/// `cdn`). The surface starts empty — it is populated by uploads. Returns
/// `(db, binding_root)`.
async fn empty_managed(visibility: &str) -> (Arc<Database>, PathBuf) {
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
        false, // no signature requirement: fixture is signed but trust keys are not pinned
    )
    .await
    .unwrap();
    (db, root.join("cdn"))
}

/// Collect a surface directory into `(relative_path, bytes)` pairs, sorted
/// immutable-first then by path — the producer's phase-major upload order.
fn collect_surface(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    walk(root, root, &mut files);
    files.sort_by(|a, b| {
        let a_mut = is_pointer(&a.0);
        let b_mut = is_pointer(&b.0);
        a_mut.cmp(&b_mut).then_with(|| a.0.cmp(&b.0))
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

/// `PUT` one surface file, returning the status.
async fn put(app: &axum::Router, uri: &str, auth: Option<&str>, body: Vec<u8>) -> StatusCode {
    let mut req = Request::builder().method("PUT").uri(uri);
    if let Some(auth) = auth {
        req = req.header(header::AUTHORIZATION, format!("Bearer {auth}"));
    }
    app.clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap()
        .status()
}

/// `GET` a URL, returning `(status, body bytes)`.
async fn get(app: &axum::Router, uri: &str, auth: Option<&str>) -> (StatusCode, Vec<u8>) {
    let mut req = Request::builder().uri(uri);
    if let Some(auth) = auth {
        req = req.header(header::AUTHORIZATION, format!("Bearer {auth}"));
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1 << 24)
        .await
        .unwrap();
    (status, body.to_vec())
}

#[derive(Deserialize)]
struct MultipartInitiateResponse {
    upload_id: String,
}

#[derive(Deserialize)]
struct MultipartPartResponse {
    part_number: u32,
    etag: String,
}

async fn multipart_request(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: &str,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, body.to_vec())
}

#[tokio::test]
async fn publish_through_hub_indexes_and_serves() {
    // Build a real surface in a scratch dir (not the binding root).
    let scratch = tempfile::tempdir().unwrap();
    let surface = scratch.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    common::standard_registry(&surface);
    let files = collect_surface(&surface);
    assert!(files.len() >= 8, "fixture should have many files");

    let (db, binding_root) = empty_managed("public").await;
    let app = router(app_state(Arc::clone(&db)).await).await;
    let token = bearer(
        "pub",
        Principal::service_account(1),
        "acme/infra/prod/cdn",
        &[Permission::Publish],
    );

    // Upload every file in phase-major order to the canonical path.
    for (rel, bytes) in &files {
        let status = put(
            &app,
            &format!("/acme/infra/prod/cdn/{rel}"),
            Some(&token),
            bytes.clone(),
        )
        .await;
        assert!(
            status == StatusCode::CREATED || status == StatusCode::OK,
            "PUT {rel} -> {status}"
        );
    }

    // The bytes landed in the binding root.
    assert_eq!(
        std::fs::read(binding_root.join("HEAD")).unwrap(),
        std::fs::read(surface.join("HEAD")).unwrap()
    );

    // GET every uploaded machine path back: byte-equal to the source.
    for (rel, bytes) in &files {
        let (status, got) = get(&app, &format!("/acme/infra/prod/cdn/{rel}"), None).await;
        assert_eq!(status, StatusCode::OK, "GET {rel}");
        assert_eq!(&got, bytes, "GET {rel} byte-equality");
    }

    // The registry indexed: the browse page shows the package.
    let (status, body) = get(&app, "/acme/infra/prod/cdn/-/packages", None).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("curl"), "package should be indexed: {html}");
}

#[tokio::test]
async fn nested_registry_multipart_parts_are_concurrency_safe_through_native_router() {
    let (db, binding_root) = empty_managed("public").await;
    let app = router(app_state(Arc::clone(&db)).await).await;
    let token = bearer(
        "multipart-publisher",
        Principal::service_account(1),
        "acme/infra/prod/cdn",
        &[Permission::Publish],
    );
    let path = "/acme/infra/prod/cdn/nar/concurrent.nar";
    let (status, body) = multipart_request(
        &app,
        "POST",
        &format!("{path}?uploads&size=8"),
        &token,
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let initiated: MultipartInitiateResponse = serde_json::from_slice(&body).unwrap();

    let first_uri = format!("{path}?uploadId={}&partNumber=1", initiated.upload_id);
    let second_uri = format!("{path}?partNumber=2&uploadId={}", initiated.upload_id);
    let (first, second) = tokio::join!(
        multipart_request(&app, "PUT", &first_uri, &token, b"abcd".to_vec()),
        multipart_request(&app, "PUT", &second_uri, &token, b"efgh".to_vec()),
    );
    assert_eq!(first.0, StatusCode::OK);
    assert_eq!(second.0, StatusCode::OK);
    let first: MultipartPartResponse = serde_json::from_slice(&first.1).unwrap();
    let second: MultipartPartResponse = serde_json::from_slice(&second.1).unwrap();
    assert_eq!((first.part_number, second.part_number), (1, 2));

    let complete = serde_json::to_vec(&serde_json::json!({
        "parts": [
            {"part_number": first.part_number, "etag": first.etag},
            {"part_number": second.part_number, "etag": second.etag},
        ]
    }))
    .unwrap();
    let (status, _) = multipart_request(
        &app,
        "POST",
        &format!("{path}?uploadId={}", initiated.upload_id),
        &token,
        complete,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        std::fs::read(binding_root.join("nar/concurrent.nar")).unwrap(),
        b"abcdefgh"
    );
}

#[tokio::test]
async fn put_requires_publish_permission() {
    let scratch = tempfile::tempdir().unwrap();
    let surface = scratch.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    common::standard_registry(&surface);
    let object = std::fs::read(surface.join("HEAD")).unwrap();

    let (db, _root) = empty_managed("public").await;
    let app = router(app_state(Arc::clone(&db)).await).await;

    // No token -> 401.
    let status = put(&app, "/acme/infra/prod/cdn/HEAD", None, object.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Read-only token -> 403.
    let read_only = bearer(
        "ro",
        Principal::service_account(1),
        "acme/infra/prod/cdn",
        &[Permission::Read],
    );
    let status = put(
        &app,
        "/acme/infra/prod/cdn/HEAD",
        Some(&read_only),
        object.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Publish token -> ok.
    let publish = bearer(
        "pub",
        Principal::service_account(1),
        "acme/infra/prod/cdn",
        &[Permission::Publish],
    );
    let status = put(&app, "/acme/infra/prod/cdn/HEAD", Some(&publish), object).await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "{status}"
    );
}

#[tokio::test]
async fn upload_to_soft_deleted_org_registry_is_not_found() {
    let (db, _root) = empty_managed("public").await;
    let app = router(app_state(Arc::clone(&db)).await).await;
    let token = bearer(
        "pub",
        Principal::service_account(1),
        "acme/infra/prod/cdn",
        &[Permission::Publish],
    );

    // While the org is live, a Publish-scoped PUT is accepted.
    let status = put(
        &app,
        "/acme/infra/prod/cdn/HEAD",
        Some(&token),
        b"ref: refs/heads/stable\n".to_vec(),
    )
    .await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "{status}"
    );

    // Soft-delete the owning org: its registry stops accepting uploads (404),
    // before any auth or quota work — the resource is gone.
    let org = db.org_by_slug("acme").await.unwrap().unwrap();
    assert!(db.soft_delete_org(org.id, 86_400).await.unwrap());

    let status = put(
        &app,
        "/acme/infra/prod/cdn/objects/ab/cdef",
        Some(&token),
        b"payload".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // HEAD probe likewise reports the registry as gone.
    let req = Request::builder()
        .method("HEAD")
        .uri("/acme/infra/prod/cdn/HEAD")
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    let status = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status();
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn publish_lease_blocks_a_second_pointer_writer() {
    let (db, _root) = empty_managed("public").await;
    let app = router(app_state(Arc::clone(&db)).await).await;

    let token_a = bearer(
        "token-a",
        Principal::service_account(1),
        "acme/infra/prod/cdn",
        &[Permission::Publish],
    );
    let token_b = bearer(
        "token-b",
        Principal::service_account(2),
        "acme/infra/prod/cdn",
        &[Permission::Publish],
    );

    // Token A acquires the lease on a mutable-pointer write.
    let status = put(
        &app,
        "/acme/infra/prod/cdn/HEAD",
        Some(&token_a),
        b"ref: refs/heads/stable\n".to_vec(),
    )
    .await;
    assert!(status == StatusCode::CREATED || status == StatusCode::OK);

    // Token B's mutable-pointer write is rejected while A holds the lease.
    let status = put(
        &app,
        "/acme/infra/prod/cdn/channels/stable/00",
        Some(&token_b),
        b"x".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // But Token B may still write immutable objects (no lease needed).
    let status = put(
        &app,
        "/acme/infra/prod/cdn/objects/ab/cdef",
        Some(&token_b),
        b"loose-object".to_vec(),
    )
    .await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "immutable write should not need the lease: {status}"
    );
}

#[tokio::test]
async fn private_managed_registry_read_requires_token() {
    let scratch = tempfile::tempdir().unwrap();
    let surface = scratch.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    common::standard_registry(&surface);
    let files = collect_surface(&surface);

    let (db, _root) = empty_managed("private").await;
    let app = router(app_state(Arc::clone(&db)).await).await;
    let publish = bearer(
        "pub",
        Principal::service_account(1),
        "acme/infra/prod/cdn",
        &[Permission::Publish, Permission::Read],
    );

    // Publish the surface.
    for (rel, bytes) in &files {
        let status = put(
            &app,
            &format!("/acme/infra/prod/cdn/{rel}"),
            Some(&publish),
            bytes.clone(),
        )
        .await;
        assert!(
            status == StatusCode::CREATED || status == StatusCode::OK,
            "{rel}: {status}"
        );
    }

    // Anonymous GET of a private registry's machine path is hidden (404).
    let (status, _) = get(&app, "/acme/infra/prod/cdn/HEAD", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "anon private read hidden");

    // A Read-scoped bearer token sees it.
    let reader = bearer(
        "rd",
        Principal::service_account(1),
        "acme/infra/prod/cdn",
        &[Permission::Read],
    );
    let (status, _) = get(&app, "/acme/infra/prod/cdn/HEAD", Some(&reader)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "read token sees private machine path"
    );
}

#[tokio::test]
async fn unowned_phase1_registry_is_not_writable() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);

    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.register_registry("demo", std::slice::from_ref(&fixture.trust_key), true)
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;

    // Even with a valid Publish token, a phase-1 registry with no storage
    // binding rejects the PUT: it is read-only through the facade.
    let token = bearer(
        "pub",
        Principal::service_account(1),
        "demo",
        &[Permission::Publish],
    );
    let status = put(&app, "/demo/HEAD", Some(&token), b"x".to_vec()).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn head_probes_surface_file_presence() {
    let (db, _root) = empty_managed("public").await;
    let app = router(app_state(Arc::clone(&db)).await).await;
    let token = bearer(
        "pub",
        Principal::service_account(1),
        "acme/infra/prod/cdn",
        &[Permission::Publish],
    );

    // Absent before upload.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/acme/infra/prod/cdn/HEAD")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Present after upload.
    let status = put(
        &app,
        "/acme/infra/prod/cdn/HEAD",
        Some(&token),
        b"ref: refs/heads/stable\n".to_vec(),
    )
    .await;
    assert!(status == StatusCode::CREATED || status == StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/acme/infra/prod/cdn/HEAD")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
