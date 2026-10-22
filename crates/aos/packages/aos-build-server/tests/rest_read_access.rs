//! Exercises view-scoped authorization on the REST cache endpoints.

use std::sync::Arc;

use aos_build_server::{
    auth::create_access_token,
    build::BuildManager,
    config::ServerConfig,
    drain::DrainState,
    routes::{AppState, router},
    sign::NarInfoSigner,
    store::NixStore,
    tokens::TokenStore,
    views::ViewManager,
};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use tempfile::TempDir;
use tower::ServiceExt;

const JWT_SECRET: &[u8] = b"rest-read-access-test-secret";

fn test_state(directory: &TempDir) -> Arc<AppState> {
    let database = directory.path().join("store.sqlite");
    drop(rusqlite::Connection::open(&database).unwrap());

    let mut config = ServerConfig::default();
    config.views[0].name = "alpha".into();
    config.views[0].anonymous_read = false;

    let mut beta = config.views[0].clone();
    beta.name = "beta".into();

    let mut public = config.views[0].clone();
    public.name = "public".into();
    public.anonymous_read = true;

    config.views.push(beta);
    config.views.push(public);

    Arc::new(AppState {
        store: NixStore::open(&database).unwrap(),
        views: ViewManager::new(directory.path().to_path_buf(), config.views.clone()).unwrap(),
        config,
        store_dir: "/nix/store".into(),
        jwt_secret: JWT_SECRET.to_vec(),
        tokens: TokenStore::open(&directory.path().join("tokens.sqlite")).unwrap(),
        build_mgr: Arc::new(BuildManager::new()),
        drain: Arc::new(DrainState::new()),
        signer: NarInfoSigner::load(None).unwrap(),
    })
}

fn access_token(state: &AppState, views: &[&str], permissions: &[&str]) -> String {
    let (_, record) = state
        .tokens
        .create_token(
            &views
                .iter()
                .map(|value| (*value).to_string())
                .collect::<Vec<_>>(),
            &permissions
                .iter()
                .map(|value| (*value).to_string())
                .collect::<Vec<_>>(),
            None,
            None,
            None,
        )
        .unwrap();

    create_access_token(JWT_SECRET, &record, 300).unwrap()
}

async fn request_status(
    state: Arc<AppState>,
    method: &str,
    uri: &str,
    token: Option<&str>,
) -> StatusCode {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }

    router(state)
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn cache_info_requires_view_read_permission() {
    let directory = tempfile::tempdir().unwrap();
    let state = test_state(&directory);
    let alpha_reader = access_token(&state, &["alpha"], &["read"]);
    let alpha_builder = access_token(&state, &["alpha"], &["build"]);
    let beta_reader = access_token(&state, &["beta"], &["read"]);

    assert_eq!(
        request_status(Arc::clone(&state), "GET", "/alpha/nix-cache-info", None,).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request_status(
            Arc::clone(&state),
            "GET",
            "/alpha/nix-cache-info",
            Some(&beta_reader),
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request_status(
            Arc::clone(&state),
            "GET",
            "/alpha/nix-cache-info",
            Some(&alpha_builder),
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request_status(
            Arc::clone(&state),
            "GET",
            "/alpha/nix-cache-info",
            Some(&alpha_reader),
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        request_status(state, "GET", "/public/nix-cache-info", None).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn upload_progress_requires_view_read_permission() {
    let directory = tempfile::tempdir().unwrap();
    let state = test_state(&directory);
    let alpha_reader = access_token(&state, &["alpha"], &["read"]);
    let alpha_builder = access_token(&state, &["alpha"], &["build"]);
    let beta_reader = access_token(&state, &["beta"], &["read"]);
    let uri = "/alpha/store/0123456789abcdfghijklmnpqrsvwxyz";

    assert_eq!(
        request_status(Arc::clone(&state), "HEAD", uri, Some(&beta_reader)).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request_status(Arc::clone(&state), "HEAD", uri, Some(&alpha_builder)).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request_status(state, "HEAD", uri, Some(&alpha_reader)).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn artifact_reads_require_view_read_permission_before_store_lookup() {
    let directory = tempfile::tempdir().unwrap();
    let state = test_state(&directory);
    let alpha_reader = access_token(&state, &["alpha"], &["read"]);
    let beta_reader = access_token(&state, &["beta"], &["read"]);
    let hash = "0123456789abcdfghijklmnpqrsvwxyz";

    for uri in [
        format!("/alpha/{hash}.narinfo"),
        format!("/alpha/nar/{hash}-package.nar.zst"),
    ] {
        assert_eq!(
            request_status(Arc::clone(&state), "GET", &uri, Some(&beta_reader),).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            request_status(Arc::clone(&state), "GET", &uri, Some(&alpha_reader),).await,
            StatusCode::NOT_FOUND
        );
    }

    assert_eq!(
        request_status(state, "GET", &format!("/public/{hash}.narinfo"), None,).await,
        StatusCode::NOT_FOUND
    );
}
