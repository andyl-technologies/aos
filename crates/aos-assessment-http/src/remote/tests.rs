//! Real TLS qualification of paired challenge and provider-result authentication.

use std::collections::BTreeMap;
use std::sync::Mutex;

use aos_assessment_runtime::ports::EvidenceStore;
use aos_assessment_runtime::provider::{
    ProviderLimits, SourceRequest, SourceResponse, SourceTransport, execute_source,
};
use aos_contract::Sha256Digest;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use super::*;

#[derive(Default)]
struct Custody(Mutex<BTreeMap<Sha256Digest, Vec<u8>>>);

#[async_trait::async_trait]
impl EvidenceStore for Custody {
    async fn retain(&self, _: &str, bytes: &[u8]) -> Result<Sha256Digest> {
        let digest = Sha256Digest::of_bytes(bytes);
        self.0
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture custody lock"))?
            .insert(digest, bytes.to_vec());
        Ok(digest)
    }

    async fn read(&self, _: &str, digest: Sha256Digest, limit: u64) -> Result<Vec<u8>> {
        let bytes = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture custody lock"))?
            .get(&digest)
            .context("fixture evidence is absent")?
            .clone();
        anyhow::ensure!(
            bytes.len() as u64 <= limit,
            "fixture evidence exceeds read bound"
        );
        Ok(bytes)
    }
}

struct EmptyTags;

#[async_trait::async_trait]
impl SourceTransport for EmptyTags {
    async fn fetch(
        &self,
        plan: &ProviderWorkPlanV1,
        request: &SourceRequest,
    ) -> Result<SourceResponse> {
        anyhow::ensure!(
            plan.operation.source_requests()?.contains(request),
            "fixture source differs from plan"
        );
        Ok(SourceResponse {
            status: 200,
            body: b"[]".to_vec(),
            transferred_bytes: 2,
            validators: None,
        })
    }
}

async fn peer(tamper: bool) -> Result<(RemoteProviderTransport, JoinHandle<Result<()>>)> {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = provider.clone().install_default();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der())
                .into(),
        )?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let auth = Arc::new(ProviderWorkAuth::new(
        vec![7; 32],
        "fixture".into(),
        "coordinator".into(),
        "executor".into(),
    )?);
    let mut transport = RemoteProviderTransport::new(
        &format!("https://localhost:{}", address.port()),
        auth.clone(),
    )?;
    transport.client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(reqwest::Certificate::from_der(certificate.cert.der())?)
        .build()?;
    let task = tokio::spawn(async move {
        let (connection, _) =
            tokio::time::timeout(Duration::from_secs(10), listener.accept()).await??;
        let mut stream =
            tokio::time::timeout(Duration::from_secs(10), acceptor.accept(connection)).await??;
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            anyhow::ensure!(
                header.len() < 16 * 1024,
                "fixture request headers exceed limit"
            );
            let mut byte = [0];
            tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut byte)).await??;
            header.push(byte[0]);
        }
        let header = String::from_utf8(header)?.to_ascii_lowercase();
        let value = |name: &str| -> Result<String> {
            header
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{name}: ")))
                .map(str::to_owned)
                .context("fixture request header missing")
        };
        let count: usize = value("content-length")?.parse()?;
        anyhow::ensure!(count <= 256 * 1024, "fixture compact request bound");
        let mut body = vec![0; count];
        stream.read_exact(&mut body).await?;
        let signature = value(PROVIDER_SIGNATURE_HEADER)?;
        let (mut body, signature) =
            if header.starts_with(&format!("post {PROVIDER_CAPABILITIES_PATH} ")) {
                let challenge = auth.verify_challenge(&body, &signature, &PhysicalClock.now()?)?;
                auth.sign_capabilities(
                    &ProviderCapabilitiesV1 {
                        schema: "aos.provider-capabilities/v1".into(),
                        challenge,
                        executor_build: "qualified-fixture".into(),
                        adapters: vec![aos_assessment_providers::UPSTREAM_ADAPTER_VERSION.into()],
                        limits: ProviderLimits::default(),
                    },
                    &PhysicalClock.now()?,
                )?
            } else {
                anyhow::ensure!(
                    header.starts_with(&format!("post {PROVIDER_WORK_PATH} ")),
                    "fixture route mismatch"
                );
                let plan = auth.verify_plan(&body, &signature, &PhysicalClock.now()?)?;
                let result = execute_source(
                    &EmptyTags,
                    &Custody::default(),
                    &PhysicalClock,
                    &plan,
                    "qualified-fixture",
                    3600,
                )
                .await?;
                anyhow::ensure!(
                    result.usage.compressed_bytes == 2,
                    "fixture source bytes differ"
                );
                auth.sign_result(&result, &plan, &PhysicalClock.now()?)?
            };
        if tamper {
            body.push(b' ');
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{PROVIDER_SIGNATURE_HEADER}: {signature}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await?;
        stream.write_all(&body).await?;
        stream.shutdown().await?;
        Ok(())
    });
    Ok((transport, task))
}

fn challenge() -> Result<CapabilityChallenge> {
    let now = PhysicalClock.now()?;
    Ok(CapabilityChallenge {
        schema: "aos.provider-capability-challenge/v1".into(),
        deployment_id: "fixture".into(),
        issuer: "coordinator".into(),
        audience: "executor".into(),
        nonce: "00000000000000000000000000000002".into(),
        issued_at: now.clone(),
        expires_at: aos_assessment::time::Timestamp::from_unix_seconds(now.unix_seconds() + 60)?,
    })
}

#[tokio::test]
async fn remote_capabilities_and_work_are_verified_over_real_tls() -> Result<()> {
    let (transport, task) = peer(false).await?;
    let capabilities = transport.capabilities(&challenge()?).await?;
    assert_eq!(capabilities.executor_build, "qualified-fixture");
    task.await??;

    let (transport, task) = peer(false).await?;
    let result = transport.execute(&crate::tests::plan()?).await?;
    assert_eq!(result.executor_build, "qualified-fixture");
    assert!(!result.normalized_objects.is_empty());
    task.await??;
    Ok(())
}

#[tokio::test]
async fn authenticated_receipts_reject_even_semantically_equivalent_body_tampering() -> Result<()> {
    let (transport, task) = peer(true).await?;
    assert!(transport.capabilities(&challenge()?).await.is_err());
    task.await??;
    let (transport, task) = peer(true).await?;
    assert!(transport.execute(&crate::tests::plan()?).await.is_err());
    task.await??;
    Ok(())
}
