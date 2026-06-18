//! Frontends e2e: probe a frontend against an in-test server and render the
//! freshness on the registry health page.
//!
//! A frontend's surface is a real signed fixture served over a local axum file
//! server; [`probe_frontends`] fetches its `info/refs`, records the observed
//! frontier + lag, and the health page renders the frontend table.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use aos_hub::db::Database;
use aos_hub::fetch::{hardened_client, safe_join, HttpFetch};
use aos_hub::indexer::index_and_record;
use aos_hub::probe::probe_frontends;
use aos_hub::server::{router, AppState};
use axum::body::Body;
use axum::extract::{Path as AxPath, State};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tower::ServiceExt;

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
async fn frontend_probe_records_status_and_health_page_renders_it() {
    // The frontend points at a `127.0.0.1` test server; opt out of the SSRF
    // local/internal-address rejection (production never sets this).
    std::env::set_var("AOS_HUB_ALLOW_LOCAL_REMOTES", "1");
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);

    // Serve the fixture surface as the frontend's domain on an ephemeral port.
    let app = axum::Router::new()
        .route("/{*path}", get(serve_file))
        .with_state(Arc::new(surface.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Register and index the registry so its local frontier is known.
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let upstream_url = format!("http://{addr}");
    db.register_registry(
        "demo",
        &upstream_url,
        std::slice::from_ref(&fixture.trust_key),
        true,
    )
    .await
    .unwrap();
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    let fetch = HttpFetch::new(&upstream_url).await;
    index_and_record(&db, &fetch, &registry).await.unwrap();

    // A frontend whose domain carries an explicit http:// scheme so the probe
    // hits the in-test plain-HTTP server (the production default is https://).
    let domain = format!("http://{addr}");
    let fe = db
        .create_frontend(
            registry.id,
            &domain,
            "",
            "direct",
            true,
            true,
            true,
            100,
            true,
        )
        .await
        .unwrap();

    // The probe reads the frontend's info/refs, reports `ok`, observes the
    // frontier, and records zero lag (the frontend serves the same surface the
    // local index was built from).
    let probes = probe_frontends(&db, &hardened_client().await, &registry)
        .await
        .unwrap();
    assert_eq!(probes.len(), 1);
    assert_eq!(probes[0].frontend_id, fe);
    assert_eq!(probes[0].status.as_str(), "ok");
    assert_eq!(probes[0].observed_frontier.as_deref(), Some("1.0.0"));
    assert_eq!(probes[0].lag_releases, Some(0));
    let rows = db.list_frontend_probes(registry.id).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status.as_deref(), Some("ok"));

    // The health page renders the frontend table with the domain and mode.
    let state = Arc::new(AppState::new(Arc::clone(&db), upstream_url.clone()).await);
    let app = router(state).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/demo/-/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("Frontends"), "frontend section rendered");
    assert!(html.contains(&addr.to_string()), "frontend domain shown");
    assert!(html.contains("direct"), "frontend mode shown");
}
