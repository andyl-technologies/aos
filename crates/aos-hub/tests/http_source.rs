//! HTTP-source e2e: registration-only registries indexed over real HTTP.
//!
//! The fixture surface is served by an actual TCP listener inside the
//! test, the hub indexes it through [`HttpFetch`] exactly as it would a
//! public CDN, and the facade answers machine paths with redirects so
//! bulk bytes never transit the hub.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use aos_hub::db::Database;
use aos_hub::fetch::{safe_join, HttpFetch};
use aos_hub::indexer::index_and_record;
use aos_hub::server::{router, AppState};
use axum::body::Body;
use axum::extract::{Path as AxPath, State};
use axum::http::{header, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tower::ServiceExt;

/// Minimal static file server over the fixture directory.
async fn serve_file(State(root): State<Arc<PathBuf>>, AxPath(path): AxPath<String>) -> Response {
    let Ok(full) = safe_join(&root, &path) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match std::fs::read(full) {
        Ok(bytes) => bytes.into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

#[tokio::test]
async fn http_source_indexes_and_facade_redirects() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);

    // A real upstream HTTP server on an ephemeral port.
    let upstream = axum::Router::new()
        .route("/{*path}", get(serve_file))
        .with_state(Arc::new(surface.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, upstream).await.unwrap();
    });

    // Index over HTTP, fail-closed, with full verification.
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.register_registry("demo", std::slice::from_ref(&fixture.trust_key), true)
        .await
        .unwrap();
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    let fetch = HttpFetch::new(&upstream_url).await;
    let outcome = index_and_record(&db, &fetch, &registry).await.unwrap();
    assert_eq!(outcome.packages, 1);
    assert_eq!(outcome.channels, 1);
    assert_eq!(
        db.index_status(registry.id).await.unwrap().unwrap().state,
        "fresh"
    );

    // The facade redirects machine paths to the upstream.
    let app = router(Arc::new(
        AppState::new(db, "http://127.0.0.1:8420".into()).await,
    ))
    .await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/demo/HEAD")
                .header(header::HOST, "127.0.0.1:8420")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers()[header::LOCATION],
        format!("{upstream_url}/HEAD"),
    );

    // Human pages still render locally from the index.
    let response = app
        .oneshot(
            Request::builder()
                .uri("/demo/-/packages")
                .header(header::HOST, "127.0.0.1:8420")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    assert!(String::from_utf8(body.to_vec()).unwrap().contains("curl"));
}
