//! Verifies canonical store-hash handling at the REST and RPC boundaries.

use std::sync::Arc;

use aos_build_api::aos::cache::v1::{CacheServiceClient, GetNarInfoRequest};
use aos_build_server::{
    build::BuildManager,
    config::ServerConfig,
    drain::DrainState,
    routes::{AppState, router},
    sign::NarInfoSigner,
    store::NixStore,
    tokens::TokenStore,
    views::ViewManager,
};
use connectrpc::client::{ClientConfig, HttpClient};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn test_state(directory: &tempfile::TempDir) -> Arc<AppState> {
    let database = directory.path().join("store.sqlite");
    drop(rusqlite::Connection::open(&database).unwrap());

    let config = ServerConfig::default();
    Arc::new(AppState {
        store: NixStore::open(&database).unwrap(),
        views: ViewManager::new(directory.path().to_path_buf(), config.views.clone()).unwrap(),
        config,
        store_dir: directory.path().join("store").display().to_string(),
        jwt_secret: vec![42; 32],
        tokens: TokenStore::open(&directory.path().join("tokens.sqlite")).unwrap(),
        build_mgr: Arc::new(BuildManager::new()),
        drain: Arc::new(DrainState::new()),
        signer: NarInfoSigner::load(None).unwrap(),
    })
}

#[tokio::test]
async fn malformed_hashes_are_rejected_before_view_filesystem_access() {
    let directory = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socket_address = listener.local_addr().unwrap();
    let base_url = format!("http://{socket_address}");
    let server = tokio::spawn(async move {
        axum::serve(listener, router(test_state(&directory)))
            .await
            .unwrap()
    });

    let mut connection = tokio::net::TcpStream::connect(socket_address)
        .await
        .unwrap();
    connection
        .write_all(
            b"GET /default/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.narinfo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    connection.read_to_end(&mut response).await.unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 400"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    let config = ClientConfig::new(base_url.parse().unwrap());
    let client = CacheServiceClient::new(HttpClient::plaintext(), config);
    let error = client
        .get_nar_info(GetNarInfoRequest {
            view: "default".into(),
            store_hash: "../../00000000000000000000000000000000".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(error.to_string().contains("invalid store hash"), "{error}");

    server.abort();
}
