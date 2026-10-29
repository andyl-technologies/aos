//! Signed Direct uploads through actual persistent guards and verification queues.

use std::os::unix::fs::PermissionsExt as _;
use std::process::Stdio;

use aos_hub_native::authority_server::AuthorityServer;

use super::*;

const PROVIDER_MATERIAL: &[u8] = b"fixture-access:fixture-secret:fixture-region";

struct ProviderResolver;

#[async_trait::async_trait]
impl SecretVersionResolver for ProviderResolver {
    async fn resolve(&self, _: &str) -> Result<ResolvedSecretVersion> {
        Ok(ResolvedSecretVersion::from_bytes(
            PROVIDER_MATERIAL.to_vec(),
        ))
    }
}

fn private_file(path: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

#[tokio::test]
#[ignore = "requires the AOS Node, Miniflare and current bundled Worker"]
async fn actual_signed_uploads_drain_verification_queues() {
    let _tls = TLS_TEST_GATE.lock().await;
    let mut fixture = fixture_with_material(
        Database::open_in_memory().await.unwrap(),
        &["presign", "read", "write"],
        PROVIDER_MATERIAL,
    )
    .await;
    let bootstrap = exported(&fixture).await;
    let root = Path::new(&std::env::var("AOS_DIRECT_QUEUE_ROOT").unwrap()).to_owned();
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

    let configuration = &mut fixture.configuration;
    configuration.issuance_enabled = true;
    for directory in [
        configuration.journal_file.parent().unwrap(),
        configuration.hub_root.as_path(),
    ] {
        std::fs::create_dir(directory).unwrap();
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    private_file(
        &configuration.publisher_key_file,
        b"queue-publisher-key-at-least-thirty-two-bytes",
    );
    private_file(
        &configuration.renewal_key_file,
        b"queue-renewal-key-at-least-thirty-two-bytes",
    );
    private_file(
        &configuration.signing_seed_file,
        hex::encode([7; 32]).as_bytes(),
    );
    let publication = fixture.directory.path().join("initial-publication.json");
    private_file(
        &publication,
        &serde_json::to_vec(&bootstrap.publication).unwrap(),
    );
    configuration.initialize(&publication).unwrap();
    let issuer = AuthorityServer::open(configuration).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer_origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, issuer.router()).await.unwrap() });

    private_file(
        &root.join("setup.json"),
        &serde_json::to_vec(&serde_json::json!({
            "bootstrap": bootstrap, "issuer": issuer_origin,
            "application": std::str::from_utf8(KEY).unwrap(),
            "renewal": "queue-renewal-key-at-least-thirty-two-bytes",
        }))
        .unwrap(),
    );
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let output = std::fs::File::create(root.join("runtime.private.log")).unwrap();
    let mut child = std::process::Command::new(std::env::var("AOS_COPY_NODE").unwrap())
        .arg(repository.join("pkgs/tools/aos-hub-direct-queue-e2e.mjs"))
        .arg(&root)
        .arg(std::env::var("AOS_COPY_DIST").unwrap())
        .arg(repository.join("tests/fixtures"))
        .stdout(output.try_clone().unwrap())
        .stderr(Stdio::from(output))
        .spawn()
        .unwrap();

    let ready = root.join("ready.json");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    while !ready.exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "queue runtime exited during setup"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "queue runtime readiness timed out"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    let ready: serde_json::Value = serde_json::from_slice(&std::fs::read(ready).unwrap()).unwrap();
    std::env::set_var(
        "SSL_CERT_FILE",
        repository.join("tests/fixtures/hub-hybrid-fleet-ca.crt"),
    );
    let client = RemoteStorageWorkClient::new(
        ready["origin"].as_str().unwrap(),
        "qualification-deployment".into(),
        KEY,
    )
    .unwrap();
    let receipt = hydrate(&fixture.db, &bootstrap, &client, &ProviderResolver)
        .await
        .unwrap();
    assert!(receipt.binding_hydrated);
    private_file(&root.join("hydrated"), b"ready");

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(150);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if tokio::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("queue runtime exceeded its original deadline");
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    server.abort();
    std::env::remove_var("SSL_CERT_FILE");
    assert!(
        status.success(),
        "signed queue test failed; inspect private runtime log"
    );
}
