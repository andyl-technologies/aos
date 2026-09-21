//! Exercises the public RPC client against the server's HTTP router.

use std::sync::Arc;
use std::time::Duration;

use aos_remote::AosClient;
use aos_server::{
    build::BuildManager,
    config::ServerConfig,
    drain::DrainState,
    routes::{AppState, router},
    sign::NarInfoSigner,
    store::NixStore,
    tokens::TokenStore,
    views::ViewManager,
};

#[tokio::test]
async fn token_exchange_read_permissions_and_streamed_uploads_round_trip() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("store.sqlite");
    drop(rusqlite::Connection::open(&database).unwrap());

    let mut config = ServerConfig::default();
    config.views[0].anonymous_read = false;
    let tokens = TokenStore::open(&directory.path().join("tokens.sqlite")).unwrap();
    let (secret, _) = tokens
        .create_token(&["default".into()], &["read".into()], None, None, None)
        .unwrap();
    let state = Arc::new(AppState {
        store: NixStore::open(&database).unwrap(),
        views: ViewManager::new(directory.path().to_path_buf(), config.views.clone()),
        config,
        store_dir: "/nix/store".into(),
        jwt_secret: vec![42; 32],
        tokens,
        build_mgr: Arc::new(BuildManager::new()),
        drain: Arc::new(DrainState::new()),
        signer: NarInfoSigner::load(None).unwrap(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });

    tokio::time::timeout(Duration::from_secs(30), async {
        assert!(
            AosClient::connect(&address, "default", "invalid")
                .await
                .is_err()
        );
        let client = AosClient::connect(&address, "default", &secret)
            .await
            .unwrap();
        assert_eq!(
            client.get_cache_info().await.unwrap().store_dir,
            "/nix/store"
        );

        let unauthenticated =
            AosClient::connect_with_token(&address, "default", "invalid").unwrap();
        assert!(unauthenticated.get_cache_info().await.is_err());

        // Exercise several chunks beyond the 4 MiB per-message limit. A read-only token must be rejected
        // after the stream is consumed, before any store import is attempted.
        let payload = vec![1; 5 * 1024 * 1024 + 17];
        let upload = client
            .upload("0123456789abcdefghijklmnopqrstuv", &payload)
            .await
            .unwrap_err();
        assert!(
            upload.to_string().contains("build permission required"),
            "{upload}"
        );
        let pack = client.upload_pack(&payload).await.unwrap_err();
        assert!(
            pack.to_string().contains("build permission required"),
            "{pack}"
        );
    })
    .await
    .expect("RPC requests must complete without a blocked upload producer");

    server.abort();
}
