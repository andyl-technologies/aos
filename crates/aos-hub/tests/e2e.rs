//! End-to-end: fixture surface → index (verified) → facade + pages.
//!
//! The local-first loop from RFC-0004's testing story, tier 3: a complete
//! registry surface on disk, indexed fail-closed with real signature
//! verification, then served — machine paths byte-faithful with the right
//! cache headers, human pages rendered from the verified index.

mod common;

use std::sync::Arc;

use aos_hub::db::Database;
use aos_hub::fetch::LocalFsFetch;
use aos_hub::indexer::index_and_record;
use aos_hub::server::{router, AppState};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

async fn get(app: &axum::Router, uri: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap()
        .to_vec();
    (status, headers, body)
}

#[tokio::test]
async fn fixture_surface_indexes_and_serves() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);

    // Register fail-closed with the fixture's trust anchor and index.
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.register_registry(
        "demo",
        surface.to_str().unwrap(),
        std::slice::from_ref(&fixture.trust_key),
        true,
    )
    .await
    .unwrap();
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    let fetch = LocalFsFetch::new(&surface);
    let outcome = index_and_record(&db, &fetch, &registry).await.unwrap();
    assert_eq!(outcome.packages, 1);
    assert_eq!(outcome.releases, 1);
    assert_eq!(outcome.channels, 1);

    // The index reflects the verified surface.
    let status = db.index_status(registry.id).await.unwrap().unwrap();
    assert_eq!(status.state, "fresh");
    assert_eq!(status.name.as_deref(), Some("demo"));
    let packages = db.list_packages(registry.id).await.unwrap();
    assert_eq!(packages[0].name, "curl");
    let channels = db.list_channels(registry.id).await.unwrap();
    assert_eq!(channels[0].frontier.as_deref(), Some("1.0.0"));
    assert_eq!(channels[0].partitions.iter().flatten().count(), 256);
    let releases = db.list_releases(registry.id).await.unwrap();
    assert!(
        releases[0].signer.is_some(),
        "release must record its signer"
    );

    // Serve and exercise every audience.
    let app = router(Arc::new(
        AppState::new(Arc::clone(&db), "http://127.0.0.1:8420".into()).await,
    ))
    .await;

    // Machine surface: byte-faithful with the right header classes.
    let (status, headers, body) = get(&app, "/demo/HEAD").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"ref: refs/heads/stable\n");
    assert_eq!(
        headers[header::CACHE_CONTROL],
        "public, max-age=60, must-revalidate"
    );

    let (status, _, body) = get(&app, "/demo/info/refs").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, std::fs::read(surface.join("info/refs")).unwrap());

    // A loose object is immutable and byte-identical.
    let object_path = {
        let refs = String::from_utf8(std::fs::read(surface.join("info/refs")).unwrap()).unwrap();
        let commit_hex = refs.lines().next().unwrap().split('\t').next().unwrap();
        format!("objects/{}/{}", &commit_hex[..2], &commit_hex[2..])
    };
    let (status, headers, body) = get(&app, &format!("/demo/{object_path}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, std::fs::read(surface.join(&object_path)).unwrap());
    assert_eq!(
        headers[header::CACHE_CONTROL],
        "public, max-age=31536000, immutable"
    );

    // Nix binary cache surface.
    let (status, headers, _) = get(&app, "/demo/h7j3k8l2m9n4.narinfo").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "text/x-nix-narinfo");
    let (status, headers, _) = get(&app, "/demo/nar/h7j3k8l2m9n4-fixturehash.nar").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers[header::CACHE_CONTROL],
        "public, max-age=31536000, immutable"
    );
    let (status, _, body) = get(&app, "/demo/nix-cache-info").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with(b"StoreDir:"));

    // A channel partition is a machine path too.
    let (status, _, body) = get(&app, "/demo/channels/stable/00").await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8(body).unwrap().contains("tag stable"));

    // Human pages render from the verified index.
    let (status, _, body) = get(&app, "/demo/").await;
    assert_eq!(status, StatusCode::OK);
    let home = String::from_utf8(body).unwrap();
    assert!(home.contains("Fixture registry"));
    assert!(home.contains("stable"));
    assert!(home.contains("apr add http://127.0.0.1:8420/demo/"));

    let (status, _, body) = get(&app, "/demo/-/packages/curl").await;
    assert_eq!(status, StatusCode::OK);
    let page = String::from_utf8(body).unwrap();
    assert!(page.contains("URL transfers"));
    assert!(page.contains("x86_64-linux"));

    let (status, _, body) = get(&app, "/demo/-/channels/stable").await;
    assert_eq!(status, StatusCode::OK);
    let page = String::from_utf8(body).unwrap();
    assert!(page.contains("256 partitions") || page.contains("256 of 256"));

    let (status, _, body) = get(&app, "/demo/-/releases").await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8(body).unwrap().contains("1.0.0"));

    // Instance home and health.
    let (status, _, body) = get(&app, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8(body).unwrap().contains("/demo/"));
    let (status, _, _) = get(&app, "/healthz").await;
    assert_eq!(status, StatusCode::OK);

    // Non-machine, non-page paths 404 rather than leaking files.
    let (status, _, _) = get(&app, "/demo/hub.db").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = get(&app, "/missing/HEAD").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tampered_partition_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);

    // Tamper one partition's signed bytes (the target oid).
    let partition = surface.join("channels/stable/07");
    let mut payload = std::fs::read(&partition).unwrap();
    payload[8] = if payload[8] == b'f' { b'0' } else { b'f' };
    std::fs::write(&partition, payload).unwrap();

    let db = Database::open_in_memory().await.unwrap();
    db.register_registry(
        "demo",
        surface.to_str().unwrap(),
        std::slice::from_ref(&fixture.trust_key),
        true,
    )
    .await
    .unwrap();
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    let fetch = LocalFsFetch::new(&surface);
    let err = index_and_record(&db, &fetch, &registry).await.unwrap_err();
    assert!(format!("{err:#}").contains("channels/stable/07"));
    let status = db.index_status(registry.id).await.unwrap().unwrap();
    assert_eq!(status.state, "failed");
}

#[tokio::test]
async fn untrusted_key_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    common::standard_registry(&surface);

    // Pin a *different* key than the one that signed the surface. The
    // committed roster must not rescue it: the roster only extends trust
    // after the commit itself verifies against pinned anchors.
    let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let wrong_anchor = aos_hub::surface::sshsig::trusted_key_line("demo", &other.verifying_key());

    let db = Database::open_in_memory().await.unwrap();
    db.register_registry("demo", surface.to_str().unwrap(), &[wrong_anchor], true)
        .await
        .unwrap();
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    let fetch = LocalFsFetch::new(&surface);
    let err = index_and_record(&db, &fetch, &registry).await.unwrap_err();
    assert!(format!("{err:#}").contains("not trusted"), "got: {err:#}");
}

#[tokio::test]
async fn connectrpc_read_path_serves_index() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);

    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.register_registry(
        "demo",
        surface.to_str().unwrap(),
        std::slice::from_ref(&fixture.trust_key),
        true,
    )
    .await
    .unwrap();
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    index_and_record(&db, &LocalFsFetch::new(&surface), &registry)
        .await
        .unwrap();

    let app = router(Arc::new(
        AppState::new(db, "http://127.0.0.1:8420".into()).await,
    ))
    .await;

    let post = |uri: &'static str, body: &'static str| {
        let app = app.clone();
        async move {
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(uri)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        }
    };

    // PackageService over Connect-JSON.
    let (status, body) = post(
        "/aos.hub.v1.PackageService/ListPackages",
        r#"{"slug":"demo"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.contains("curl"), "body: {body}");
    assert!(body.contains("8.5.0"), "body: {body}");

    // ChannelService returns the full partition map.
    let (status, body) = post(
        "/aos.hub.v1.ChannelService/GetChannel",
        r#"{"slug":"demo","name":"stable"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.contains("1.0.0"), "body: {body}");

    // RegistryService reports verified index state and trust anchors.
    let (status, body) = post(
        "/aos.hub.v1.RegistryService/GetRegistry",
        r#"{"slug":"demo"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.contains("fresh"), "body: {body}");
    assert!(body.contains("AAAAC3NzaC1lZDI1NTE5"), "body: {body}");

    // Unknown registries are NotFound, not empty success.
    let (status, body) = post(
        "/aos.hub.v1.RegistryService/GetRegistry",
        r#"{"slug":"missing"}"#,
    )
    .await;
    assert_ne!(status, StatusCode::OK, "body: {body}");
    assert!(body.contains("not_found"), "body: {body}");

    // The renamed identity service is mounted. An anonymous request reaches
    // the handler and is rejected by authentication rather than routing.
    let (status, body) = post("/aos.hub.v1.IdentityService/ListTokens", "{}").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");

    // The RFC-0012 cutover is deliberately hard: neither the former package
    // nor any of the ambiguous service names remains mounted as an alias.
    for uri in [
        "/aos.registry.v1.RegistryService/ListRegistries",
        "/aos.hub.v1.OrgService/ListOrgs",
        "/aos.hub.v1.StorageService/ListBindings",
        "/aos.hub.v1.ConfigService/ListChangesets",
        "/aos.hub.v1.IamService/ListTokens",
        "/aos.hub.v1.CacheService/ListCaches",
    ] {
        let (status, _) = post(uri, "{}").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "legacy route mounted: {uri}");
    }
}

/// An RPC request whose body exceeds the small inbound RPC cap is rejected
/// before the handler runs, while a normal small RPC body is served — proving
/// the `DefaultBodyLimit` is scoped to the RPC surface.
#[tokio::test]
async fn rpc_inbound_body_cap_rejects_oversized_request() {
    use aos_hub::server::RPC_MAX_BODY_BYTES;

    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(Arc::new(
        AppState::new(db, "http://127.0.0.1:8420".into()).await,
    ))
    .await;

    let post = |body: Vec<u8>| {
        let app = app.clone();
        async move {
            // Set an explicit Content-Length (real Connect clients always do)
            // so the body-limit layer can reject an over-cap request up front
            // with 413, exactly as it would in production.
            let len = body.len();
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/aos.hub.v1.PackageService/ListPackages")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::CONTENT_LENGTH, len)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        }
    };

    // A body just over the cap is rejected with 413 Payload Too Large; the
    // handler (which would otherwise return NotFound for an unknown slug) is
    // never reached.
    let oversized = post(vec![b' '; RPC_MAX_BODY_BYTES + 1]).await;
    assert_eq!(
        oversized,
        StatusCode::PAYLOAD_TOO_LARGE,
        "an over-cap RPC body must be rejected"
    );

    // A small, well-formed body is accepted by the layer and handled normally
    // (NotFound for the missing registry — not a 413).
    let small = post(br#"{"slug":"missing"}"#.to_vec()).await;
    assert_ne!(
        small,
        StatusCode::PAYLOAD_TOO_LARGE,
        "a small RPC body must not be capped"
    );
}
