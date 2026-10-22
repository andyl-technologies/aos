//! Exercises resumable HTTP upload sessions through the public router.

use std::sync::Arc;

use aos_build_server::{
    auth,
    build::BuildManager,
    config::{ServerConfig, ViewConfig},
    drain::DrainState,
    routes::{AppState, router},
    sign::NarInfoSigner,
    store::NixStore,
    tokens::TokenStore,
    views::ViewManager,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const STORE_HASH: &str = "0123456789abcdfghijklmnpqrsvwxyz";

fn test_state(directory: &tempfile::TempDir) -> (Arc<AppState>, String, String) {
    let database = directory.path().join("store.sqlite");
    drop(rusqlite::Connection::open(&database).unwrap());

    let mut config = ServerConfig::default();
    let mut second_view: ViewConfig = config.views[0].clone();
    second_view.name = "second".into();
    config.views.push(second_view);

    let tokens = TokenStore::open(&directory.path().join("tokens.sqlite")).unwrap();
    let (_, first_record) = tokens
        .create_token(
            &["default".into(), "second".into()],
            &["build".into()],
            None,
            None,
            None,
        )
        .unwrap();
    let (_, second_record) = tokens
        .create_token(
            &["default".into(), "second".into()],
            &["build".into()],
            None,
            None,
            None,
        )
        .unwrap();
    let first_token = auth::create_access_token(&[42; 32], &first_record, 3600).unwrap();
    let second_token = auth::create_access_token(&[42; 32], &second_record, 3600).unwrap();

    let state = Arc::new(AppState {
        store: NixStore::open(&database).unwrap(),
        views: ViewManager::new(directory.path().to_path_buf(), config.views.clone()).unwrap(),
        config,
        store_dir: directory.path().join("store").display().to_string(),
        jwt_secret: vec![42; 32],
        tokens,
        build_mgr: Arc::new(BuildManager::new()),
        drain: Arc::new(DrainState::new()),
        signer: NarInfoSigner::load(None).unwrap(),
    });

    (state, first_token, second_token)
}

async fn request(address: std::net::SocketAddr, request: String) -> String {
    let mut connection = tokio::net::TcpStream::connect(address).await.unwrap();
    connection.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    connection.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

fn put_request(view: &str, token: &str, range: &str, body: &str) -> String {
    format!(
        "PUT /{view}/store/{STORE_HASH} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Range: {range}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn head_request(view: &str, token: &str) -> String {
    format!(
        "HEAD /{view}/store/{STORE_HASH} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    )
}

#[tokio::test]
async fn resumable_uploads_are_contiguous_and_private_to_the_request_identity() {
    let directory = tempfile::tempdir().unwrap();
    let (state, first_token, second_token) = test_state(&directory);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });

    let first = request(
        address,
        put_request("default", &first_token, "bytes 0-1/4", "ab"),
    )
    .await;
    assert!(first.starts_with("HTTP/1.1 202"), "{first}");

    let same_session = request(address, head_request("default", &first_token)).await;
    assert!(same_session.starts_with("HTTP/1.1 200"), "{same_session}");
    assert!(
        same_session.contains("content-length: 2\r\n"),
        "{same_session}"
    );
    assert!(
        same_session.contains("upload-length: 4\r\n"),
        "{same_session}"
    );

    let other_principal = request(address, head_request("default", &second_token)).await;
    assert!(
        other_principal.starts_with("HTTP/1.1 404"),
        "{other_principal}"
    );
    let other_view = request(address, head_request("second", &first_token)).await;
    assert!(other_view.starts_with("HTTP/1.1 404"), "{other_view}");

    let gap = request(
        address,
        put_request("default", &first_token, "bytes 3-3/4", "d"),
    )
    .await;
    assert!(gap.starts_with("HTTP/1.1 409"), "{gap}");
    let overlap = request(
        address,
        put_request("default", &first_token, "bytes 1-1/4", "b"),
    )
    .await;
    assert!(overlap.starts_with("HTTP/1.1 409"), "{overlap}");

    let resumed = request(
        address,
        put_request("default", &first_token, "bytes 2-2/4", "c"),
    )
    .await;
    assert!(resumed.starts_with("HTTP/1.1 202"), "{resumed}");

    let malformed = request(
        address,
        put_request("default", &first_token, "bytes 3-2/4", "d"),
    )
    .await;
    assert!(malformed.starts_with("HTTP/1.1 400"), "{malformed}");
    let oversized = request(
        address,
        put_request(
            "default",
            &first_token,
            "bytes 3-3/18446744073709551615",
            "d",
        ),
    )
    .await;
    assert!(oversized.starts_with("HTTP/1.1 413"), "{oversized}");

    server.abort();
}
