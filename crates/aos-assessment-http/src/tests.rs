//! Real TLS and streaming qualification of the native installed source port.

use aos_assessment_runtime::provider::{BudgetReservation, PROVIDER_WORK_PLAN_V1, ProviderLimits};
use aos_assessment_runtime::scan::TaskClaim;
use aos_contract::Sha256Digest;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use super::*;

fn plan() -> Result<ProviderWorkPlanV1> {
    let issued_at = PhysicalClock.now()?;
    let expires_at = Timestamp::from_unix_seconds(issued_at.unix_seconds() + 60)?;
    let operation = ProviderOperation::ObserveTags {
        repository: "example/fixture".into(),
        tag_prefix: "v".into(),
        page: 1,
    };
    Ok(ProviderWorkPlanV1 {
        schema: PROVIDER_WORK_PLAN_V1.into(),
        deployment_id: "fixture".into(),
        issuer: "coordinator".into(),
        audience: "executor".into(),
        plan_id: "plan".into(),
        claim: TaskClaim {
            scan_id: "scan".into(),
            task_id: "provider".into(),
            request_digest: Sha256Digest::of_bytes("request"),
            generation: 1,
            inventory_revision: 1,
            claim_token: "00000000000000000000000000000001".into(),
            attempt: 1,
            expires_at: expires_at.clone(),
        },
        issued_at,
        expires_at: expires_at.clone(),
        nonce: "00000000000000000000000000000002".into(),
        inventory_digest: Sha256Digest::of_bytes("inventory"),
        policy_digest: Sha256Digest::of_bytes("policy"),
        authorization_partition: "fixture-partition".into(),
        credential_ref: None,
        budget_reservation: BudgetReservation {
            source_budget: "github-public".into(),
            reservation_id: "reserved".into(),
            requests: 1,
            deadline: expires_at,
        },
        cache_ref: None,
        continuation: None,
        continuation_ref: None,
        adapter_version: operation.adapter_version().into(),
        operation,
        limits: ProviderLimits {
            requests: 1,
            concurrency: 1,
            ..ProviderLimits::default()
        },
    })
}

async fn head(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> Result<String> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        anyhow::ensure!(bytes.len() < 16 * 1024, "fixture request head overflow");
        let mut byte = [0];
        stream.read_exact(&mut byte).await?;
        bytes.push(byte[0]);
    }
    Ok(String::from_utf8(bytes)?)
}

async fn fixture(
    response: &'static [u8],
) -> Result<(NativeSourceTransport, JoinHandle<Result<String>>)> {
    // CONNECT keeps the production request URL and source hostname exact while
    // only the fixture's physical destination is an ephemeral loopback port.
    let certificate = rcgen::generate_simple_self_signed(vec!["api.github.com".into()])?;
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
    let client = source_client_builder(10)
        .add_root_certificate(reqwest::Certificate::from_der(certificate.cert.der())?)
        .proxy(reqwest::Proxy::https(format!("http://{address}"))?)
        .build()?;
    let transport = NativeSourceTransport::new(Arc::new(AnonymousCredentials));
    transport
        .clients
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture client lock"))?
        .insert(10, client);
    let task = tokio::spawn(async move {
        let (mut connection, _) =
            tokio::time::timeout(Duration::from_secs(10), listener.accept()).await??;
        let connect =
            tokio::time::timeout(Duration::from_secs(10), head(&mut connection)).await??;
        anyhow::ensure!(
            connect.starts_with("CONNECT api.github.com:443 "),
            "fixture got a different source authority"
        );
        connection
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await?;
        let mut tls =
            tokio::time::timeout(Duration::from_secs(10), acceptor.accept(connection)).await??;
        let request = tokio::time::timeout(Duration::from_secs(10), head(&mut tls)).await??;
        tls.write_all(response).await?;
        tls.shutdown().await?;
        Ok(request)
    });
    Ok((transport, task))
}

#[tokio::test]
async fn native_source_uses_real_tls_and_the_exact_installed_request() -> Result<()> {
    let (transport, task) = fixture(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nETag: exact-fixture\r\nConnection: close\r\n\r\n[]").await?;
    let plan = plan()?;
    let response = transport
        .fetch(&plan, &plan.operation.source_requests()?[0])
        .await?;
    assert_eq!(response.body, b"[]");
    assert_eq!(response.transferred_bytes, 2);
    assert_eq!(
        response
            .validators
            .context("response validators")?
            .etag
            .as_deref(),
        Some("exact-fixture")
    );
    let request = task.await??.to_ascii_lowercase();
    assert!(request.starts_with("get /repos/example/fixture/tags?per_page=20&page=1 http/1.1\r\n"));
    assert!(request.contains("accept-encoding: identity\r\n"));
    assert!(!request.contains("authorization:"));
    Ok(())
}

#[tokio::test]
async fn native_source_does_not_follow_cross_authority_redirects() -> Result<()> {
    let (transport, task) = fixture(b"HTTP/1.1 302 Found\r\nLocation: https://unadmitted.invalid/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
    let plan = plan()?;
    let response = transport
        .fetch(&plan, &plan.operation.source_requests()?[0])
        .await?;
    assert_eq!(response.status, 302);
    task.await??;
    Ok(())
}

#[tokio::test]
async fn native_source_streaming_ceiling_applies_without_content_length() -> Result<()> {
    let (transport, task) = fixture(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n9\r\n123456789\r\n0\r\n\r\n").await?;
    let mut plan = plan()?;
    plan.limits.response_bytes = 8;
    assert!(
        transport
            .fetch(&plan, &plan.operation.source_requests()?[0])
            .await
            .is_err()
    );
    task.await??;
    Ok(())
}

#[tokio::test]
async fn native_source_rejects_hidden_decompression() -> Result<()> {
    let (transport, task) = fixture(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]").await?;
    let plan = plan()?;
    assert!(
        transport
            .fetch(&plan, &plan.operation.source_requests()?[0])
            .await
            .is_err()
    );
    task.await??;
    Ok(())
}

#[tokio::test]
async fn arbitrary_request_substitution_is_rejected_before_network_or_secret_resolution()
-> Result<()> {
    let transport = NativeSourceTransport::new(Arc::new(AnonymousCredentials));
    let plan = plan()?;
    let mut request = plan.operation.source_requests()?.remove(0);
    request.url.set_host(Some("unadmitted.invalid"))?;
    assert!(transport.fetch(&plan, &request).await.is_err());
    Ok(())
}
